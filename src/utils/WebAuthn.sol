// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Base64} from "./Base64.sol";
import {P256} from "./P256.sol";

/// @notice WebAuthn helper.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/WebAuthn.sol)
/// @author Modified from Daimo WebAuthn (https://github.com/daimo-eth/p256-verifier/blob/master/src/WebAuthn.sol)
/// @author Modified from Coinbase WebAuthn (https://github.com/base-org/webauthn-sol/blob/main/src/WebAuthn.sol)
/// @dev The checked port compares the client data JSON's type and challenge with the
/// expected bytes a word at a time, where the assembly compares their hashes, and checks
/// every index before it reads, so an index past the JSON gives `false` where the assembly's
/// reads past it can run out of gas. The message hash is the `sha256` builtin over a copy of
/// the authenticator data and the JSON's hash, which the assembly writes after the
/// authenticator data and restores; a failed precompile call reverts with no data, as the
/// assembly's `invalid()` does. `tryDecodeAuth` makes the assembly's bounds checks, with the
/// same wrap-around of a length added to an address, through the trusted `_addr`, and returns
/// the two strings as aliases into `encodedAuth` through the trusted `_bytesAt`, as the
/// assembly does; a length word that does not lie in `encodedAuth` fails, where the assembly
/// reads the memory after it. The compact codecs copy with `abi.encodePacked`, calldata slices
/// and byte-copy loops.
/// @custom:solar-safe memory arithmetic
library WebAuthn {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Helps make encoding and decoding easier, alleviates stack-too-deep.
    struct WebAuthnAuth {
        // The WebAuthn authenticator data.
        // See: https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata.
        bytes authenticatorData;
        // The WebAuthn client data JSON.
        // See: https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson.
        string clientDataJSON;
        // Start index of "challenge":"..." in `clientDataJSON`.
        uint256 challengeIndex;
        // Start index of "type":"..." in `clientDataJSON`.
        uint256 typeIndex;
        // The r value of secp256r1 signature.
        bytes32 r;
        // The s value of secp256r1 signature.
        bytes32 s;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              WEBAUTHN VERIFICATION OPERATIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Verifies a Webauthn Authentication Assertion.
    /// See: https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion.
    ///
    /// We do not verify all the steps as described in the specification, only ones
    /// relevant to our context. Please carefully read through this list before usage.
    ///
    /// Specifically, we do verify the following:
    /// - Verify that `authenticatorData` (which comes from the authenticator,
    ///   such as iCloud Keychain) indicates a well-formed assertion with the
    ///   "User Present" bit set. If `requireUserVerification` is set, checks that the
    ///   authenticator enforced user verification. User verification should be required
    ///   if, and only if, `options.userVerification` is set to required in the request.
    /// - Verifies that the client JSON is of type "webauthn.get",
    ///   i.e. the client was responding to a request to assert authentication.
    /// - Verifies that the client JSON contains the requested challenge.
    /// - Verifies that (r, s) constitute a valid signature over both the
    ///   `authData` and client JSON, for public key (x, y).
    ///
    /// We make some assumptions about the particular use case of this verifier,
    /// so we do NOT verify the following:
    /// - Does NOT verify that the origin in the `clientDataJSON` matches the
    ///   Relying Party's origin: it is considered the authenticator's responsibility to
    ///   ensure that the user is interacting with the correct RP. This is enforced by
    ///   most high quality authenticators properly, particularly the iCloud Keychain
    ///   and Google Password Manager were tested.
    /// - Does NOT verify That `topOrigin` in `clientDataJSON` is well-formed:
    ///   We assume it would never be present, i.e. the credentials are never used in a
    ///   cross-origin/iframe context. The website/app set up should disallow cross-origin
    ///   usage of the credentials. This is the default behavior for created credentials
    ///   in common settings.
    /// - Does NOT verify that the `rpIdHash` in `authenticatorData` is the SHA-256 hash
    ///   of the RP ID expected by the Relying Party:
    ///   this means that we rely on the authenticator to properly enforce
    ///   credentials to be used only by the correct RP.
    ///   This is generally enforced with features like Apple App Site Association
    ///   and Google Asset Links. To protect from edge cases in which a previously-linked
    ///   RP ID is removed from the authorized RP IDs, we recommend that messages
    ///   signed by the authenticator include some expiry mechanism.
    /// - Does NOT verify the credential backup state: this assumes the credential backup
    ///   state is NOT used as part of Relying Party business logic or policy.
    /// - Does NOT verify the values of the client extension outputs:
    ///   this assumes that the Relying Party does not use client extension outputs.
    /// - Does NOT verify the signature counter: signature counters are intended to enable
    ///   risk scoring for the Relying Party. This assumes risk scoring is not used as part
    ///   of Relying Party business logic or policy.
    /// - Does NOT verify the attestation object: this assumes that
    ///   response.attestationObject is NOT present in the response,
    ///   i.e. the RP does not intend to verify an attestation.
    function verify(
        bytes memory challenge,
        bool requireUserVerification,
        WebAuthnAuth memory auth,
        bytes32 x,
        bytes32 y
    ) internal view returns (bool) {
        string memory encoded = Base64.encode(challenge, true, true);
        bytes memory clientDataJSON = bytes(auth.clientDataJSON);
        // 11. Verify JSON's type. Also checks for possible addition overflows.
        // 12. Verify JSON's challenge. Includes a check for the closing '"'.
        if (!_checkClientData(clientDataJSON, auth.challengeIndex, auth.typeIndex, bytes(encoded)))
        {
            return false;
        }
        // Skip 13., 14., 15.
        bytes memory authenticatorData = auth.authenticatorData;
        // 16. Verify that the "User Present" flag is set (bit 0).
        // 17. Verify that the "User Verified" flag is set (bit 2), if required.
        // See: https://www.w3.org/TR/webauthn-2/#flags.
        uint256 u = requireUserVerification ? 5 : 1;
        if (authenticatorData.length <= 0x20 || (uint8(authenticatorData[0x20]) & u) != u) {
            return false;
        }
        // 19. Compute `sha256(clientDataJSON)`.
        // 20. Compute `sha256(authenticatorData ‖ sha256(clientDataJSON))`.
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(clientDataJSON)));
        // `P256.verifySignature` returns false if `s > N/2` due to the malleability check.
        return P256.verifySignature(messageHash, auth.r, auth.s, x, y);
    }

    /// @dev Plain variant of verify.
    function verify(
        bytes memory challenge,
        bool requireUserVerification,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint256 challengeIndex,
        uint256 typeIndex,
        bytes32 r,
        bytes32 s,
        bytes32 x,
        bytes32 y
    ) internal view returns (bool) {
        return verify(
            challenge,
            requireUserVerification,
            WebAuthnAuth(authenticatorData, clientDataJSON, challengeIndex, typeIndex, r, s),
            x,
            y
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                ENCODING / DECODING HELPERS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `abi.encode(auth)`.
    function encodeAuth(WebAuthnAuth memory auth) internal pure returns (bytes memory) {
        return abi.encode(auth);
    }

    /// @dev Performs a best-effort attempt to `abi.decode(auth)`. Won't revert.
    /// If any fields cannot be successfully extracted, `decoded` will not be populated,
    /// which will cause `verify` to return false (as `clientDataJSON` is empty).
    function tryDecodeAuth(bytes memory encodedAuth)
        internal
        pure
        returns (WebAuthnAuth memory decoded)
    {
        uint256 n = encodedAuth.length;
        if (n < 0xc0) return decoded;
        // Offsets in `encodedAuth`: `p` of the encoded tuple, `a` and `c` of the length
        // words of `authenticatorData` and `clientDataJSON`. Each is bounded before it is
        // added to, as the assembly's address checks bound it.
        uint256 p = uint256(_readBytes32(encodedAuth, 0)); // Start of `encodedAuth`.
        if (p > n - 0xc0) return decoded;
        (uint256 a, uint256 c, uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s) =
            _readHead(encodedAuth, p);
        if (a > n - p || c > n - p) return decoded;
        a += p;
        c += p;
        if (!_endsIn(encodedAuth, a) || !_endsIn(encodedAuth, c)) return decoded;
        bytes memory authenticatorData = _bytesAt(encodedAuth, a);
        bytes memory clientDataJSON = _bytesAt(encodedAuth, c);
        decoded.authenticatorData = authenticatorData; // `authenticatorData`.
        decoded.clientDataJSON = string(clientDataJSON); // `clientDataJSON`.
        decoded.challengeIndex = challengeIndex; // `challengeIndex`.
        decoded.typeIndex = typeIndex; // `typeIndex`.
        decoded.r = r; // `r`.
        decoded.s = s; // `s`.
    }

    /// @dev Returns the compact encoding of `auth`:
    /// ```
    ///     abi.encodePacked(
    ///         uint16(auth.authenticatorData.length),
    ///         bytes(auth.authenticatorData),
    ///         bytes(auth.clientDataJSON),
    ///         uint16(auth.challengeIndex),
    ///         uint16(auth.typeIndex),
    ///         bytes32(auth.r),
    ///         bytes32(auth.s)
    ///     )
    /// ```
    /// Returns the empty string if any length or index exceeds 16 bits.
    function tryEncodeAuthCompact(WebAuthnAuth memory auth)
        internal
        pure
        returns (bytes memory result)
    {
        bytes memory authenticatorData = auth.authenticatorData;
        bytes memory clientDataJSON = bytes(auth.clientDataJSON);
        uint256 c = auth.challengeIndex; // `challengeIndex`.
        uint256 t = auth.typeIndex; // `typeIndex`.
        // If none of the lengths are more than `0xffff`.
        if ((t | c | authenticatorData.length | clientDataJSON.length) >> 16 == 0) {
            result = abi.encodePacked(
                uint16(authenticatorData.length),
                authenticatorData,
                clientDataJSON,
                uint16(c),
                uint16(t),
                auth.r,
                auth.s
            );
        }
    }

    /// @dev Approximately the same gas as `tryDecodeAuth`, but helps save on calldata.
    /// If any fields cannot be successfully extracted, `decoded` will not be populated,
    /// which will cause `verify` to return false (as `clientDataJSON` is empty).
    function tryDecodeAuthCompact(bytes memory encodedAuth)
        internal
        pure
        returns (WebAuthnAuth memory decoded)
    {
        uint256 n = encodedAuth.length;
        if (n >= 0x46) {
            // Length of `authenticatorData`.
            uint256 l = uint256(_readBytes32(encodedAuth, 0)) >> 240;
            uint256 j = n - 0x44; // Start of `challengeIndex`.
            if (l + 2 <= j) {
                uint256 w = uint256(_readBytes32(encodedAuth, j)); // `challengeIndex`, `typeIndex`.
                bytes32 r = _readBytes32(encodedAuth, j + 4); // `r`.
                bytes32 s = _readBytes32(encodedAuth, j + 0x24); // `s`.
                decoded.authenticatorData = _slice(encodedAuth, 2, l); // `authenticatorData`.
                // `clientDataJSON`.
                decoded.clientDataJSON = string(_slice(encodedAuth, l + 2, j - l - 2));
                decoded.challengeIndex = w >> 240; // `challengeIndex`.
                decoded.typeIndex = (w >> 224) & 0xffff; // `typeIndex`.
                decoded.r = r; // `r`.
                decoded.s = s; // `s`.
            }
        }
    }

    /// @dev Calldata variant of `tryDecodeAuthCompact`.
    function tryDecodeAuthCompactCalldata(bytes calldata encodedAuth)
        internal
        pure
        returns (WebAuthnAuth memory decoded)
    {
        uint256 n = encodedAuth.length;
        if (n >= 0x46) {
            // Length of `authenticatorData`.
            uint256 l = abi.decode(encodedAuth[:0x20], (uint256)) >> 240;
            uint256 j = n - 0x44; // Start of `challengeIndex`.
            if (l + 2 <= j) {
                // `challengeIndex`, `typeIndex`.
                uint256 w = abi.decode(encodedAuth[j:j + 0x20], (uint256));
                decoded.authenticatorData = encodedAuth[2:l + 2]; // `authenticatorData`.
                decoded.clientDataJSON = string(encodedAuth[l + 2:j]); // `clientDataJSON`.
                decoded.challengeIndex = w >> 240; // `challengeIndex`.
                decoded.typeIndex = (w >> 224) & 0xffff; // `typeIndex`.
                // `r`, `s`.
                (decoded.r, decoded.s) = abi.decode(encodedAuth[j + 4:], (bytes32, bytes32));
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Whether `clientDataJSON` holds `"type":"webauthn.get"` at `t`, and `"challenge":"`,
    /// `encoded` and a closing `"` at `c`, with both indices below `2**128` so that no sum
    /// overflows, as the assembly checks with hashes of the same bytes. Every range is
    /// checked before it is read.
    /// @custom:solar-inline
    function _checkClientData(
        bytes memory clientDataJSON,
        uint256 c,
        uint256 t,
        bytes memory encoded
    ) private pure returns (bool) {
        uint256 n = clientDataJSON.length;
        uint256 l = encoded.length;
        if ((t | c) >> 128 != 0 || n < 21 || t > n - 21) return false; // `t + 0x14 < n`.
        uint256 q = l + 0x0d; // Length of `encoded` prefixed with '"challenge":"'.
        uint256 end = q + c;
        if (end >= n) return false;
        if (_readBytesN(clientDataJSON, t, 21) != bytes32('"type":"webauthn.get"')) return false;
        if (l < 0x20) {
            return _readBytesN(clientDataJSON, c, 13) == bytes32('"challenge":"')
                && _readBytesN(clientDataJSON, c + 13, l) == _readBytesN(encoded, 0, l)
                && clientDataJSON[end] == '"';
        }
        // The `q + 1` bytes from `c` a word at a time: the first word is the prefix and the
        // start of `encoded`, the last ends with the closing quote.
        bytes32 first = bytes32('"challenge":"') | (_readBytes32(encoded, 0) >> 104);
        if (_readBytes32(clientDataJSON, c) != first) return false;
        for (uint256 k = 0x20; k + 0x20 <= q; k += 0x20) {
            if (_readBytes32(clientDataJSON, c + k) != _readBytes32(encoded, k - 13)) return false;
        }
        bytes32 last = (_readBytes32(encoded, l - 0x20) << 8) | bytes32(uint256(0x22));
        return _readBytes32(clientDataJSON, end - 31) == last;
    }

    /// @dev The six words of the encoded tuple at `p` in `encodedAuth`, which lie in it.
    /// The tuple of `abi.encode(auth)` follows its offset, and is decoded in one go.
    /// @custom:solar-inline
    function _readHead(bytes memory encodedAuth, uint256 p)
        private
        pure
        returns (
            uint256 a,
            uint256 c,
            uint256 challengeIndex,
            uint256 typeIndex,
            bytes32 r,
            bytes32 s
        )
    {
        if (p == 0x20) {
            (, a, c, challengeIndex, typeIndex, r, s) = abi.decode(
                encodedAuth, (uint256, uint256, uint256, uint256, uint256, bytes32, bytes32)
            );
        } else {
            a = uint256(_readBytes32(encodedAuth, p));
            c = uint256(_readBytes32(encodedAuth, p + 0x20));
            challengeIndex = uint256(_readBytes32(encodedAuth, p + 0x40));
            typeIndex = uint256(_readBytes32(encodedAuth, p + 0x60));
            r = _readBytes32(encodedAuth, p + 0x80);
            s = _readBytes32(encodedAuth, p + 0xa0);
        }
    }

    /// @dev Whether the `bytes` whose length word is at `offset` in `b` ends within `b`, as
    /// the assembly tests it: the address after the length word plus the length, with
    /// wrap-around, is at most the end of `b`. A length word that does not lie in `b` fails.
    /// @custom:solar-inline
    function _endsIn(bytes memory b, uint256 offset) private pure returns (bool) {
        uint256 n = b.length;
        if (n < 0x20 || offset > n - 0x20) return false;
        uint256 length = uint256(_readBytes32(b, offset));
        // Without wrap-around the sum is at most the end of `b`, and a sum that wraps around
        // is below the address after the length word, which is at most the end of `b`.
        return
            length <= n - 0x20 - offset || length > type(uint256).max - (_addr(b) + 0x40 + offset);
    }

    /// @dev A copy of the `count` bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _slice(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes memory result)
    {
        result = new bytes(count);
        for (uint256 k; k < count; ++k) {
            result[k] = b[offset + k];
        }
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev The `count` bytes of `b` at `offset`, at most a word, left-aligned.
    /// @custom:solar-inline
    function _readBytesN(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes32 result)
    {
        for (uint256 k; k < count; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev The address of `b`. Solidity cannot convert a reference to a number.
    /// @custom:solar-trusted
    /// @custom:solar-inline
    function _addr(bytes memory b) private pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := b
        }
    }

    /// @dev The `bytes` whose length word is at `offset` in `b`, as an alias into `b`, as the
    /// assembly returns it. Solidity cannot make a reference into another object. The length
    /// word must lie in `b`; the bytes extend past `b` only for a length whose end wraps
    /// around, which the assembly lets through as well.
    /// @custom:solar-trusted
    /// @custom:solar-inline
    function _bytesAt(bytes memory b, uint256 offset) private pure returns (bytes memory result) {
        if (b.length < 0x20 || offset > b.length - 0x20) revert();
        /// @solidity memory-safe-assembly
        assembly {
            result := add(add(b, 0x20), offset)
        }
    }
}
