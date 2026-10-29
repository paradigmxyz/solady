// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Gas optimized P256 wrapper.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/P256.sol)
/// @author Modified from Daimo P256 Verifier (https://github.com/daimo-eth/p256-verifier/blob/master/src/P256.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/P256.sol)
/// @dev The checked port makes the assembly's static calls, in the same order, through the
/// trusted `_staticCallWord`, which sends all the gas left and the same 160 bytes of calldata,
/// and copies at most the first word of the answer into zeroed scratch space, as the assembly
/// does, where Solidity's `staticcall` copies the whole answer into new memory. An answer is
/// valid when it is at least a word and its first word is one, which is exactly when the
/// assembly's scratch word ends up one. A failed call that the assembly ends with `invalid()`
/// reverts with no data, as `invalid()` does, without spending the gas left.
/// @custom:solar-safe memory arithmetic
library P256 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Address of the Solidity P256 verifier.
    /// Please make sure the contract is deployed onto the chain you are working on.
    /// See: https://gist.github.com/Vectorized/599b0d8a94d21bc74700eb1354e2f55c
    /// Unlike RIP-7212, this verifier returns `uint256(0)` on failure, to
    /// facilitate easier existence check. This verifier will also never revert.
    address internal constant VERIFIER = 0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a;

    /// @dev The existence of this contract, as determined by non-empty bytecode,
    /// implies the existence of the RIP-7212 precompile.
    /// See: https://gist.github.com/Vectorized/3c69dcf4604b9e1216525cabcd06ee34
    /// This is to enable the optimization to skip the `VERIFIER` entirely
    /// when the `RIP_PRECOMPILE` returns empty returndata for an invalid signature.
    address internal constant CANARY = 0x0000000000001Ab2e8006Fd8B71907bf06a5BDEE;

    /// @dev Address of the RIP-7212 P256 verifier precompile.
    /// Currently, we don't support EIP-7212's precompile at 0x0b as it has not been finalized.
    /// See: https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md
    address internal constant RIP_PRECOMPILE = 0x0000000000000000000000000000000000000100;

    /// @dev The order of the secp256r1 elliptic curve.
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /// @dev `N/2`. Used for checking the malleability of the signature.
    uint256 private constant _HALF_N =
        0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                P256 VERIFICATION OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns if the signature (`r`, `s`) is valid for `hash` and public key (`x`, `y`).
    /// Does NOT include the malleability check.
    function verifySignatureAllowMalleability(
        bytes32 hash,
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y
    ) internal view returns (bool isValid) {
        bytes memory payload = abi.encode(hash, r, s, x, y);
        (, uint256 answerSize, bytes32 answer) = _staticCallWord(RIP_PRECOMPILE, gasleft(), payload);
        // RIP-7212 dictates that success returns `uint256(1)`.
        // But failure returns zero returndata, which is ambiguous.
        if (answerSize == 0) {
            if (CANARY.code.length == 0) {
                // The verifier will never revert when given sufficient gas.
                // The `invalid` upon `staticcall` failure is solely for gas estimation.
                bool success;
                (success, answerSize, answer) = _staticCallWord(VERIFIER, gasleft(), payload);
                if (!success) revert();
            }
            // Unlike RIP-7212, the verifier returns `uint256(0)` on failure.
            // We shall not revert even if the verifier does not exist,
            // to allow for workflows where reverting can cause trouble.
        }
        isValid = answerSize > 0x1f && answer == bytes32(uint256(1));
    }

    /// @dev Returns if the signature (`r`, `s`) is valid for `hash` and public key (`x`, `y`).
    /// Includes the malleability check.
    function verifySignature(bytes32 hash, bytes32 r, bytes32 s, bytes32 x, bytes32 y)
        internal
        view
        returns (bool isValid)
    {
        isValid = verifySignatureAllowMalleability(hash, r, s, x, y);
        // Optimize for happy path. Users are unlikely to pass in malleable signatures.
        if (uint256(s) > _HALF_N) isValid = false;
    }

    /// @dev Returns if the RIP-7212 precompile exists.
    function hasPrecompile() internal view returns (bool result) {
        // These values are taken from the standard Wycheproof test vectors.
        // https://github.com/C2SP/wycheproof/blob/aca47066256c167f0ce04d611d718cc85654341e/testvectors/ecdsa_webcrypto_test.json#L1197
        bytes memory payload = abi.encode(
            bytes32(0x532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25), // `hash`.
            uint256(0x5), // `r`.
            uint256(0x1), // `s`.
            bytes32(0x4a03ef9f92eb268cafa601072489a56380fa0dc43171d7712813b3a19a1eb5e5), // `x`.
            bytes32(0x3e213e28a608ce9a2f4a17fd830c6654018a79b3e0263d91a8ba90622df6f2f0) // `y`.
        );
        (bool success, uint256 answerSize, bytes32 answer) =
            _staticCallWord(RIP_PRECOMPILE, gasleft(), payload);
        // The `invalid` upon `staticcall` failure is solely for gas estimation.
        if (!success) revert();
        result = answerSize > 0x1f && answer == bytes32(uint256(1));
    }

    /// @dev Returns if either the RIP-7212 precompile or the verifier exists.
    /// Since `verifySignature` is made not reverting, this function can be used to
    /// manually implement a revert if the current chain does not have the contracts
    /// to support secp256r1 signature recovery.
    function hasPrecompileOrVerifier() internal view returns (bool result) {
        result = hasPrecompile();
        result = VERIFIER.code.length != 0 || result;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      OTHER OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `s` normalized to the lower half of the curve.
    function normalized(bytes32 s) internal pure returns (bytes32 result) {
        result = s;
        if (uint256(s) > _HALF_N) {
            // `N - s`, modulo `2**256` for an `s` above `N`, as the assembly subtracts.
            uint256 t = uint256(s);
            result = bytes32(t <= N ? N - t : type(uint256).max - (t - N) + 1);
        }
    }

    /// @dev Helper function for `abi.decode(encoded, (bytes32, bytes32))`.
    /// If `encoded.length < 64`, `(x, y)` will be `(0, 0)`, which is an invalid point.
    function tryDecodePoint(bytes memory encoded) internal pure returns (bytes32 x, bytes32 y) {
        if (encoded.length > 0x3f) (x, y) = abi.decode(encoded, (bytes32, bytes32));
    }

    /// @dev Helper function for `abi.decode(encoded, (bytes32, bytes32))`.
    /// If `encoded.length < 64`, `(x, y)` will be `(0, 0)`, which is an invalid point.
    function tryDecodePointCalldata(bytes calldata encoded)
        internal
        pure
        returns (bytes32 x, bytes32 y)
    {
        if (encoded.length > 0x3f) (x, y) = abi.decode(encoded, (bytes32, bytes32));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and copies at most the
    /// first word of the answer into scratch space zeroed before the call, as the assembly
    /// does. Returns whether the call succeeded, the answer's size and that word. Solidity's
    /// `staticcall` copies the whole answer into new memory instead.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _staticCallWord(address target, uint256 gasLimit, bytes memory payload)
        private
        view
        returns (bool success, uint256 size, bytes32 word)
    {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0)
            success := staticcall(gasLimit, target, add(payload, 0x20), mload(payload), 0x00, 0x20)
            size := returndatasize()
            word := mload(0x00)
        }
    }
}
