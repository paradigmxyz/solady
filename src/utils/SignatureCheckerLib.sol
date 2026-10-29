// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

/// @notice Signature verification helper that supports both ECDSA signatures from EOAs
/// and ERC1271 signatures from smart contract wallets like Argent and Gnosis safe.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SignatureCheckerLib.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/SignatureChecker.sol)
///
/// @dev Note:
/// - The signature checking functions use the ecrecover precompile (0x1).
/// - The `bytes memory signature` variants use the identity precompile (0x4)
///   to copy memory internally.
/// - Unlike ECDSA signatures, contract signatures are revocable.
/// - As of Solady version 0.0.134, all `bytes signature` variants accept both
///   regular 65-byte `(r, s, v)` and EIP-2098 `(r, vs)` short form signatures.
///   See: https://eips.ethereum.org/EIPS/eip-2098
///   This is for calldata efficiency on smart accounts prevalent on L2s.
///
/// WARNING! Do NOT use signatures as unique identifiers:
/// - Use a nonce in the digest to prevent replay attacks on the same contract.
/// - Use EIP-712 for the digest to prevent replay attacks across different chains and contracts.
///   EIP-712 also enables readable signing of typed data for better user safety.
/// This implementation does NOT check if a signature is non-malleable.
///
/// The checked port checks a signer without code with the `ecrecover` builtin, for 65-byte and
/// EIP-2098 64-byte signatures alike, and a signer with code with ERC1271. The ERC1271 call
/// sends the calldata the assembly builds, unpadded, and reads only the answer's length and
/// first word, so a compiler that bounds the copy of return data copies one word, as the
/// assembly does. An ERC6492 signature ends with the 32-byte magic suffix. Its inner signature
/// is the third field of the wrapped encoding; one whose range lies past the signature counts
/// as rejected by ERC1271, where the assembly reads whatever memory follows. Only the length of
/// a verifier's answer is read. An inner signature too long for memory, which only wrapper
/// offsets that wrap around can describe, makes the encoding of the ERC1271 call panic with
/// `Panic(0x41)`, where the assembly runs out of gas copying it.
/// @custom:solar-safe memory arithmetic
library SignatureCheckerLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               SIGNATURE CHECKING OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        if (signer.code.length == 0) return _recovers(signer, hash, signature);
        return isValidERC1271SignatureNow(signer, hash, signature);
    }

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNowCalldata(address signer, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        if (signer.code.length == 0) {
            address recovered = _tryRecoverCalldata(hash, signature);
            return recovered != address(0) && recovered == signer;
        }
        return isValidERC1271SignatureNowCalldata(signer, hash, signature);
    }

    /// @dev Returns whether the signature (`r`, `vs`) is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNow(address signer, bytes32 hash, bytes32 r, bytes32 vs)
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        if (signer.code.length == 0) {
            address recovered = _tryRecover(hash, r, vs);
            return recovered != address(0) && recovered == signer;
        }
        return isValidERC1271SignatureNow(signer, hash, r, vs);
    }

    /// @dev Returns whether the signature (`v`, `r`, `s`) is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNow(address signer, bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        if (signer.code.length == 0) {
            address recovered = ecrecover(hash, v, r, s);
            return recovered != address(0) && recovered == signer;
        }
        return isValidERC1271SignatureNow(signer, hash, v, r, s);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC1271 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: These ERC1271 operations do NOT have an ECDSA fallback.

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal
        view
        returns (bool isValid)
    {
        return _erc1271(
            signer,
            abi.encodePacked(_ERC1271_MAGIC, hash, uint256(0x40), signature.length, signature)
        );
    }

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNowCalldata(
        address signer,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bool isValid) {
        return _erc1271(
            signer,
            abi.encodePacked(_ERC1271_MAGIC, hash, uint256(0x40), signature.length, signature)
        );
    }

    /// @dev Returns whether the signature (`r`, `vs`) is valid for `hash`
    /// for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(address signer, bytes32 hash, bytes32 r, bytes32 vs)
        internal
        view
        returns (bool isValid)
    {
        return _erc1271(
            signer,
            abi.encodePacked(
                _ERC1271_MAGIC,
                hash,
                uint256(0x40),
                uint256(65),
                r,
                (uint256(vs) << 1) >> 1,
                uint8(27 + (uint256(vs) >> 255))
            )
        );
    }

    /// @dev Returns whether the signature (`v`, `r`, `s`) is valid for `hash`
    /// for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(address signer, bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (bool isValid)
    {
        return _erc1271(
            signer, abi.encodePacked(_ERC1271_MAGIC, hash, uint256(0x40), uint256(65), r, s, v)
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC6492 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: These ERC6492 operations now include an ECDSA fallback at the very end.
    // The calldata variants are excluded for brevity.

    /// @dev Returns whether `signature` is valid for `hash`.
    /// If the signature is postfixed with the ERC6492 magic number, it will attempt to
    /// deploy / prepare the `signer` smart account before doing a regular ERC1271 check.
    /// Note: This function is NOT reentrancy safe.
    /// The verifier must be deployed.
    /// Otherwise, the function will return false if `signer` is not yet deployed / prepared.
    /// See: https://gist.github.com/Vectorized/011d6becff6e0a73e42fe100f8d7ef04
    /// With a dedicated verifier, this function is safe to use in contracts
    /// that have been granted special permissions.
    function isValidERC6492SignatureNowAllowSideEffects(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal returns (bool isValid) {
        bool noCode = signer.code.length == 0;
        if (_isERC6492(signature)) {
            if (!noCode && _innerERC1271(signer, hash, signature)) return true;
            (, bytes memory answer) =
                _VERIFIER.call(abi.encodePacked(uint256(uint160(signer)), hash, signature));
            isValid = answer.length != 0;
        } else if (!noCode) {
            isValid = isValidERC1271SignatureNow(signer, hash, signature);
        }
        if (noCode && !isValid) isValid = _recovers(signer, hash, signature);
    }

    /// @dev Returns whether `signature` is valid for `hash`.
    /// If the signature is postfixed with the ERC6492 magic number, it will attempt
    /// to use a reverting verifier to deploy / prepare the `signer` smart account
    /// and do a `isValidSignature` check via the reverting verifier.
    /// Note: This function is reentrancy safe.
    /// The reverting verifier must be deployed.
    /// Otherwise, the function will return false if `signer` is not yet deployed / prepared.
    /// See: https://gist.github.com/Vectorized/846a474c855eee9e441506676800a9ad
    function isValidERC6492SignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal
        returns (bool isValid)
    {
        bool noCode = signer.code.length == 0;
        if (_isERC6492(signature)) {
            if (!noCode && _innerERC1271(signer, hash, signature)) return true;
            // The reverting verifier always reverts, with the result as its answer.
            (bool succeeded, bytes memory answer) = _REVERTING_VERIFIER.call(
                abi.encodePacked(uint256(uint160(signer)), hash, signature)
            );
            isValid = answer.length > (succeeded ? 1 : 0);
        } else if (!noCode) {
            isValid = isValidERC1271SignatureNow(signer, hash, signature);
        }
        if (noCode && !isValid) isValid = _recovers(signer, hash, signature);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an Ethereum Signed Message, created from a `hash`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /// @dev Returns an Ethereum Signed Message, created from `s`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    /// Note: Supports lengths of `s` up to 999999 bytes.
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {
        // The header is the prefix and the decimal length of `s`. Up to six
        // digits it fits in a word, spelled as an integer of one byte per
        // digit, so the header is a fixed prefix that this compiler writes over
        // the length word of `s` and hashes with it, as the assembly does.
        uint256 n = s.length;
        if (n < 10) {
            return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint8(48 + n), s));
        }
        if (n < 100) {
            return
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint16(_digits(n)), s));
        }
        if (n < 1000) {
            return
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint24(_digits(n)), s));
        }
        if (n < 10000) {
            return
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint32(_digits(n)), s));
        }
        if (n < 100000) {
            return
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint40(_digits(n)), s));
        }
        if (n < 1000000) {
            return
                keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint48(_digits(n)), s));
        }
        revert();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EMPTY CALLDATA HELPERS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an empty calldata bytes.
    function emptySignature() internal pure returns (bytes calldata signature) {
        return msg.data[0:0];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
    bytes4 private constant _ERC1271_MAGIC = 0x1626ba7e;

    /// @dev The suffix of an ERC6492 signature.
    bytes32 private constant _ERC6492_DETECTION_SUFFIX =
        0x6492649264926492649264926492649264926492649264926492649264926492;

    /// @dev The non-reverting ERC6492 verifier.
    address private constant _VERIFIER = 0x0000bc370E4DC924F427d84e2f4B9Ec81626ba7E;

    /// @dev The reverting ERC6492 verifier.
    address private constant _REVERTING_VERIFIER = 0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e;

    /// @dev Whether `signature` recovers to `signer`, which a failed recovery never does.
    function _recovers(address signer, bytes32 hash, bytes memory signature)
        private
        view
        returns (bool)
    {
        address recovered = _tryRecover(hash, signature);
        return recovered != address(0) && recovered == signer;
    }

    /// @dev The signer of `hash` under the 65-byte or EIP-2098 64-byte `signature`,
    /// or zero if recovery fails.
    function _tryRecover(bytes32 hash, bytes memory signature) private view returns (address) {
        uint256 length = signature.length;
        if (length == 64) {
            return _tryRecover(hash, _readBytes32(signature, 0), _readBytes32(signature, 32));
        }
        if (length == 65) {
            return ecrecover(
                hash, uint8(signature[64]), _readBytes32(signature, 0), _readBytes32(signature, 32)
            );
        }
        return address(0);
    }

    /// @dev `_tryRecover` of a calldata `signature`.
    function _tryRecoverCalldata(bytes32 hash, bytes calldata signature)
        private
        view
        returns (address)
    {
        if (signature.length == 64) {
            return _tryRecover(hash, bytes32(signature[0:32]), bytes32(signature[32:64]));
        }
        if (signature.length == 65) {
            return ecrecover(
                hash, uint8(signature[64]), bytes32(signature[0:32]), bytes32(signature[32:64])
            );
        }
        return address(0);
    }

    /// @dev The signer of `hash` under the EIP-2098 short signature (`r`, `vs`), or zero.
    function _tryRecover(bytes32 hash, bytes32 r, bytes32 vs) private view returns (address) {
        return
            ecrecover(hash, uint8(27 + (uint256(vs) >> 255)), r, bytes32((uint256(vs) << 1) >> 1));
    }

    /// @dev The decimal digits of `n`, one byte each, the last in the lowest byte.
    function _digits(uint256 n) private pure returns (uint256 digits) {
        for (uint256 shift;; shift += 8) {
            digits |= (48 + n % 10) << shift;
            n /= 10;
            if (n == 0) return digits;
        }
    }

    /// @dev Whether `signer` answers the ERC1271 call `payload` with at least a
    /// word, the first of which is the magic value.
    function _erc1271(address signer, bytes memory payload) private view returns (bool) {
        (bool success, bytes memory answer) = signer.staticcall(payload);
        return success && answer.length >= 32 && _readBytes32(answer, 0) == bytes32(_ERC1271_MAGIC);
    }

    /// @dev Whether `signature` ends with the ERC6492 magic suffix.
    function _isERC6492(bytes memory signature) private pure returns (bool) {
        uint256 n = signature.length;
        return n >= 32 && _readBytes32(signature, n - 32) == _ERC6492_DETECTION_SUFFIX;
    }

    /// @dev Whether `signer` accepts, with ERC1271, the inner signature of the
    /// ERC6492 `signature`: the `bytes` at the offset its third word gives.
    function _innerERC1271(address signer, bytes32 hash, bytes memory signature)
        private
        view
        returns (bool)
    {
        uint256 n = signature.length;
        if (n < 96) return false;
        uint256 offset = uint256(_readBytes32(signature, 64));
        if (offset > n - 32) return false;
        uint256 length = uint256(_readBytes32(signature, offset));
        if (length > n - 32 - offset) return false;
        // `isValidSignature(hash, inner)`, built around the inner signature's
        // bytes: the selector, the hash, the bytes' offset and length, then the
        // bytes, copied once.
        bytes memory payload = new bytes(100 + length);
        _writeBytes4(payload, 0, _ERC1271_MAGIC);
        _writeBytes32(payload, 4, hash);
        _writeBytes32(payload, 36, bytes32(uint256(0x40)));
        _writeBytes32(payload, 68, bytes32(length));
        _copy(payload, 100, signature, offset + 32, length);
        return _erc1271(signer, payload);
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev Writes `value` into `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytes4(bytes memory b, uint256 offset, bytes4 value) private pure {
        for (uint256 k; k < 4; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Writes `value` into `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytes32(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 32; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Copies `count` bytes from `src` at `srcOffset` to `dst` at
    /// `dstOffset`, front to back.
    /// @custom:solar-inline always
    function _copy(
        bytes memory dst,
        uint256 dstOffset,
        bytes memory src,
        uint256 srcOffset,
        uint256 count
    ) private pure {
        for (uint256 k; k < count; ++k) {
            dst[dstOffset + k] = src[srcOffset + k];
        }
    }
}
