// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

/// @notice Gas optimized ECDSA wrapper.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/ECDSA.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/ECDSA.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol)
///
/// @dev Note:
/// - The recovery functions use the ecrecover precompile (0x1).
/// - As of Solady version 0.0.68, the `recover` variants will revert upon recovery failure.
///   This is for more safety by default.
///   Use the `tryRecover` variants if you need to get the zero address back
///   upon recovery failure instead.
/// - As of Solady version 0.0.134, all `bytes signature` variants accept both
///   regular 65-byte `(r, s, v)` and EIP-2098 `(r, vs)` short form signatures.
///   See: https://eips.ethereum.org/EIPS/eip-2098
///   This is for calldata efficiency on smart accounts prevalent on L2s.
///
/// WARNING! Do NOT directly use signatures as unique identifiers:
/// - The recovery operations do NOT check if a signature is non-malleable.
/// - Use a nonce in the digest to prevent replay attacks on the same contract.
/// - Use EIP-712 for the digest to prevent replay attacks across different chains and contracts.
///   EIP-712 also enables readable signing of typed data for better user safety.
/// - If you need a unique hash from a signature, please use the `canonicalHash` functions.
///
/// The checked port recovers through the `ecrecover` builtin, whose zero result is the
/// precompile's empty answer: the `recover` variants revert with `InvalidSignature()` on it
/// and the `tryRecover` variants return it. Every `bytes` signature may be the regular 65-byte
/// `(r, s, v)` or the EIP-2098 64-byte `(r, vs)` form, as upstream, and no variant checks
/// malleability. A canonical hash negates `s` modulo 2**256 where the assembly does, so an `s`
/// above the curve order hashes as it does upstream instead of reverting. Two deliberate
/// differences: `toEthSignedMessageHash` reverts on a message longer than 999,999 bytes, where
/// the assembly runs out of gas, and a recovery whose precompile call itself fails reverts, as
/// the builtin does, where `tryRecover` returned zero.
/// @custom:solar-safe memory arithmetic
library ECDSA {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The order of the secp256k1 elliptic curve.
    uint256 internal constant N =
        0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    /// @dev `N/2 + 1`. Used for checking the malleability of the signature.
    uint256 private constant _HALF_N_PLUS_1 =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The signature is invalid.
    error InvalidSignature();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    RECOVERY OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function recover(bytes32 hash, bytes memory signature) internal view returns (address result) {
        result = tryRecover(hash, signature);
        if (result == address(0)) revert InvalidSignature();
    }

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function recoverCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (address result)
    {
        result = tryRecoverCalldata(hash, signature);
        if (result == address(0)) revert InvalidSignature();
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the EIP-2098 short form signature defined by `r` and `vs`.
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal view returns (address result) {
        result = tryRecover(hash, r, vs);
        if (result == address(0)) revert InvalidSignature();
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the signature defined by `v`, `r`, `s`.
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (address result)
    {
        result = ecrecover(hash, v, r, s);
        if (result == address(0)) revert InvalidSignature();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   TRY-RECOVER OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // WARNING!
    // These functions will NOT revert upon recovery failure.
    // Instead, they will return the zero address upon recovery failure.
    // It is critical that the returned address is NEVER compared against
    // a zero address (e.g. an uninitialized address variable).

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function tryRecover(bytes32 hash, bytes memory signature)
        internal
        view
        returns (address result)
    {
        uint256 length = signature.length;
        if (length == 64) {
            return tryRecover(hash, _readBytes32(signature, 0), _readBytes32(signature, 32));
        }
        if (length == 65) {
            return ecrecover(
                hash, uint8(signature[64]), _readBytes32(signature, 0), _readBytes32(signature, 32)
            );
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function tryRecoverCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        returns (address result)
    {
        if (signature.length == 64) {
            return tryRecover(hash, bytes32(signature[0:32]), bytes32(signature[32:64]));
        }
        if (signature.length == 65) {
            return ecrecover(
                hash, uint8(signature[64]), bytes32(signature[0:32]), bytes32(signature[32:64])
            );
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the EIP-2098 short form signature defined by `r` and `vs`.
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs)
        internal
        view
        returns (address result)
    {
        return ecrecover(
            hash, uint8(27 + (uint256(vs) >> 255)), r, bytes32((uint256(vs) << 1) >> 1)
        );
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the signature defined by `v`, `r`, `s`.
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (address result)
    {
        return ecrecover(hash, v, r, s);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an Ethereum Signed Message, created from a `hash`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /// @dev Returns an Ethereum Signed Message, created from `s`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign)
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
    /*                  CANONICAL HASH FUNCTIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // The following functions return the hash of the signature in its canonicalized format,
    // which is the 65-byte `abi.encodePacked(r, s, uint8(v))`, where `v` is either 27 or 28.
    // If `s` is greater than `N / 2` then it will be converted to `N - s`
    // and the `v` value will be flipped.
    // If the signature has an invalid length, or if `v` is invalid,
    // a uniquely corrupt hash will be returned.
    // These functions are useful for "poor-mans-VRF".

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHash(bytes memory signature) internal pure returns (bytes32 result) {
        uint256 length = signature.length;
        if (length != 64 && length != 65) {
            // `bytes4(keccak256("InvalidSignatureLength"))`.
            return bytes32(uint256(keccak256(signature)) ^ 0xd62f1ab2);
        }
        uint256 s = uint256(_readBytes32(signature, 32));
        uint8 v;
        if (length == 64) {
            v = uint8(27 + (s >> 255));
            s = (s << 1) >> 1;
        } else {
            v = uint8(signature[64]);
        }
        return _canonical(_readBytes32(signature, 0), v, s);
    }

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHashCalldata(bytes calldata signature)
        internal
        pure
        returns (bytes32 result)
    {
        if (signature.length != 64 && signature.length != 65) {
            // `bytes4(keccak256("InvalidSignatureLength"))`.
            return bytes32(uint256(keccak256(signature)) ^ 0xd62f1ab2);
        }
        uint256 s = uint256(bytes32(signature[32:64]));
        uint8 v;
        if (signature.length == 64) {
            v = uint8(27 + (s >> 255));
            s = (s << 1) >> 1;
        } else {
            v = uint8(signature[64]);
        }
        return _canonical(bytes32(signature[0:32]), v, s);
    }

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHash(bytes32 r, bytes32 vs) internal pure returns (bytes32 result) {
        return
            keccak256(
                abi.encodePacked(r, (uint256(vs) << 1) >> 1, uint8(27 + (uint256(vs) >> 255)))
            );
    }

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHash(uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes32 result) {
        return _canonical(r, v, uint256(s));
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

    /// @dev The hash of `r`, `s` and `v` with `s` in the lower half of the
    /// curve order: an upper `s` is negated modulo 2**256, which is `N - s` for
    /// any `s` up to `N`, and `v` flips between 27 and 28.
    function _canonical(bytes32 r, uint8 v, uint256 s) private pure returns (bytes32) {
        if (s >= _HALF_N_PLUS_1) {
            v ^= 7;
            s = s <= N ? N - s : type(uint256).max - (s - N) + 1;
        }
        return keccak256(abi.encodePacked(r, s, v));
    }

    /// @dev The decimal digits of `n`, one ASCII byte each, as an integer.
    function _digits(uint256 n) private pure returns (uint256 digits) {
        for (uint256 shift;; shift += 8) {
            digits |= (48 + n % 10) << shift;
            n /= 10;
            if (n == 0) return digits;
        }
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }
}
