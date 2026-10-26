// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library to encode strings in Base64.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/Base64.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/Base64.sol)
/// @author Modified from (https://github.com/Brechtpd/base64/blob/main/base64.sol) by Brecht Devos - <brecht@loopring.org>.
/// @dev The checked port works a word at a time in both directions without a lookup table: `encode`
/// turns twenty-four bytes into thirty-two characters and `decode` thirty-two characters into
/// twenty-four bytes with arithmetic on every byte of a word at once, the input's tail read as one
/// shorter word. Output buffers have their final length from allocation, with bounded writes
/// at the tail. An ABI round trip provides zero padding without changing an object's length.
/// An output of at most a word is decoded from an ABI tuple. `encode` writes the standard
/// alphabet with padding, or the URL-safe one and no padding on request. `decode` accepts the
/// documented standard, URL and IMAP
/// alphabets and padding modes. One deliberate difference: where upstream's output is undefined,
/// `decode` reverts with `InvalidBase64()`: on a character outside those alphabets, padding
/// anywhere but the end of a padded input, or a length no encoding has. It does not reject unused
/// low bits in a final group, which RFC 4648 leaves to the decoder.
/// @custom:solar-safe memory arithmetic
library Base64 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    ENCODING / DECODING                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes `data` using the base64 encoding described in RFC 4648.
    /// See: https://datatracker.ietf.org/doc/html/rfc4648
    /// @param fileSafe  Whether to replace '+' with '-' and '/' with '_'.
    /// @param noPadding Whether to strip away the padding.
    function encode(bytes memory data, bool fileSafe, bool noPadding)
        internal
        pure
        returns (string memory result)
    {
        uint256 n = data.length;
        if (n <= 24) {
            if (n == 0) return result;
            // All of it is one shorter word, zeros past its bytes, and the
            // output one word, decoded with its final length:
            // the characters the bytes need, then padding to a multiple of four.
            uint256 used = (n * 4 + 2) / 3;
            uint256 total = noPadding ? used : (n + 2) / 3 * 4;
            uint256 chars = _encodeWord(uint256(_readBytesN(data, 0, n & 31)) >> 64, fileSafe);
            return string(_fromWord(_padded(chars, used, total), total));
        }
        // Four characters for every three bytes, the last group padded to
        // four unless `noPadding`.
        uint256 length = noPadding ? (n * 4 + 2) / 3 : (n + 2) / 3 * 4;
        bytes memory out = _newBytes(length);
        uint256 i;
        uint256 j;
        // Twenty-four bytes are thirty-two characters, one word of output.
        while (i + 24 <= n) {
            _writeBytes32(
                out, j, bytes32(_encodeWord(uint256(uint192(_readBytes24(data, i))), fileSafe))
            );
            i += 24;
            j += 32;
        }
        if (i < n) {
            // The rest is one shorter word, zeros past its bytes, of which
            // the output keeps the characters the bytes need, then padding.
            uint256 rest = n - i;
            uint256 chars = _encodeWord(uint256(_readBytesN(data, i, rest)) >> 64, fileSafe);
            _writeBytesN(
                out, j, bytes32(_padded(chars, (rest * 4 + 2) / 3, length - j)), length - j
            );
        }
        return string(out);
    }

    /// @dev Encodes `data` using the base64 encoding described in RFC 4648.
    /// Equivalent to `encode(data, false, false)`.
    function encode(bytes memory data) internal pure returns (string memory result) {
        return encode(data, false, false);
    }

    /// @dev Encodes `data` using the base64 encoding described in RFC 4648.
    /// Equivalent to `encode(data, fileSafe, false)`.
    function encode(bytes memory data, bool fileSafe) internal pure returns (string memory result) {
        return encode(data, fileSafe, false);
    }

    /// @dev Decodes base64 encoded `data`.
    ///
    /// Supports:
    /// - RFC 4648 (both standard and file-safe mode).
    /// - RFC 3501 (63: ',').
    ///
    /// Does not support:
    /// - Line breaks.
    ///
    /// Note: For performance reasons,
    /// this function will NOT revert on invalid `data` inputs.
    /// Outputs for invalid inputs will simply be undefined behaviour.
    /// It is the user's responsibility to ensure that the `data`
    /// is a valid base64 encoded string.
    /// The checked port reverts with `InvalidBase64()` on such an input instead.
    function decode(string memory data) internal pure returns (bytes memory result) {
        bytes memory input = bytes(data);
        uint256 n = input.length;
        // Padding is at most two characters, at the end of a padded input.
        if (n != 0 && n % 4 == 0 && input[n - 1] == "=") {
            --n;
            if (input[n - 1] == "=") --n;
        }
        uint256 tail = n % 4;
        if (tail == 1) revert InvalidBase64();
        uint256 length = (n >> 2) * 3;
        if (tail != 0) length += tail - 1;
        if (n < 32) {
            if (n == 0) return result;
            // All of it is one shorter word filled up with `A`, which decodes to
            // zero bits, and the output one word, decoded with its final length.
            (uint256 packed, uint256 invalid) =
                _decodeWord(uint256(_readBytesN(input, 0, n & 31)) | (LETTER_A >> (n << 3)));
            if (invalid != 0) revert InvalidBase64();
            return _fromWord(packed & ~(type(uint256).max >> (length << 3)), length);
        }
        result = _newBytes(length);
        uint256 bad;
        uint256 i;
        uint256 j;
        // Thirty-two characters are twenty-four bytes. Write only those bytes,
        // leaving the padding untouched and staying within the allocated length.
        while (i + 32 <= n) {
            (uint256 packed, uint256 invalid) = _decodeWord(uint256(_readBytes32(input, i)));
            bad |= invalid;
            _writeBytesN(result, j, bytes32(packed), 24);
            i += 32;
            j += 24;
        }
        if (i < n) {
            // The rest, a final group of two or three characters included, is
            // one shorter word filled up with `A`, which decodes to zero bits,
            // of which the output keeps the bytes the characters make.
            uint256 rest = (n - i) & 31;
            uint256 word = uint256(_readBytesN(input, i, rest)) | (LETTER_A >> (rest << 3));
            (uint256 packed, uint256 invalid) = _decodeWord(word);
            bad |= invalid;
            _writeBytesN(result, j, bytes32(packed), length - j);
        }
        if (bad != 0) revert InvalidBase64();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev One copy of the value in every byte.
    uint256 private constant ONES =
        0x0101010101010101010101010101010101010101010101010101010101010101;

    /// @dev The top bit of every byte.
    uint256 private constant HIGHS =
        0x8080808080808080808080808080808080808080808080808080808080808080;

    /// @dev The low seven bits of every byte.
    uint256 private constant LOWS =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    /// @dev The character `A`, which decodes to zero, in every byte.
    uint256 private constant LETTER_A =
        0x4141414141414141414141414141414141414141414141414141414141414141;

    /// @dev Masks for spreading twenty-four packed bytes into eight groups of
    /// three, one group to each four-byte lane. Each step moves the upper half
    /// of every group up and leaves the lower half where it is.
    uint256 private constant MASK_96 =
        0x0000000000000000000000000000000000000000ffffffffffffffffffffffff;

    uint256 private constant SPREAD_HIGH_48 =
        0x00000000ffffffffffff00000000000000000000ffffffffffff000000000000;

    uint256 private constant SPREAD_LOW_48 =
        0x00000000000000000000ffffffffffff00000000000000000000ffffffffffff;

    uint256 private constant SPREAD_HIGH_24 =
        0x0000ffffff0000000000ffffff0000000000ffffff0000000000ffffff000000;

    uint256 private constant SPREAD_LOW_24 =
        0x0000000000ffffff0000000000ffffff0000000000ffffff0000000000ffffff;

    /// @dev Masks for cutting each lane's twenty-four bits in two halves of twelve,
    /// one to each two-byte half of the lane, then each half in two values of six,
    /// one to each byte.
    uint256 private constant SPLIT_HIGH_12 =
        0x00fff00000fff00000fff00000fff00000fff00000fff00000fff00000fff000;

    uint256 private constant SPLIT_LOW_12 =
        0x00000fff00000fff00000fff00000fff00000fff00000fff00000fff00000fff;

    uint256 private constant SPLIT_HIGH_6 =
        0x0fc00fc00fc00fc00fc00fc00fc00fc00fc00fc00fc00fc00fc00fc00fc00fc0;

    uint256 private constant SPLIT_LOW_6 =
        0x003f003f003f003f003f003f003f003f003f003f003f003f003f003f003f003f;

    /// @dev Two padding characters, left-aligned.
    uint256 private constant PADDING = 0x3d3d << 240;

    /// @dev Masks for gathering thirty-two sextets, one to a byte, into twenty-four
    /// bytes: each step joins the two halves of every lane twice its width.
    uint256 private constant HIGH_8 =
        0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00;

    uint256 private constant LOW_8 =
        0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;

    uint256 private constant HIGH_16 =
        0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000;

    uint256 private constant LOW_16 =
        0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;

    uint256 private constant HIGH_32 =
        0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000;

    uint256 private constant LOW_32 =
        0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;

    uint256 private constant HIGH_64 =
        0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000;

    uint256 private constant LOW_64 =
        0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;

    uint256 private constant HIGH_128 =
        0xffffffffffffffffffffffffffffffff00000000000000000000000000000000;

    uint256 private constant LOW_128 =
        0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff;

    /// @dev The input is not Base64.
    error InvalidBase64();

    /// @dev The thirty-two characters of the twenty-four bytes packed into the
    /// low bits of `packed`, in the URL-safe alphabet if `fileSafe`.
    /// @custom:solar-inline
    function _encodeWord(uint256 packed, bool fileSafe) private pure returns (uint256) {
        // Spread the eight groups of three bytes one to a four-byte lane,
        // halving the packing each step, then each lane's twenty-four bits
        // into two twelve-bit halves and those into four six-bit values, one
        // to a byte.
        uint256 x = ((packed >> 96) << 128) | (packed & MASK_96);
        x = ((x & SPREAD_HIGH_48) << 16) | (x & SPREAD_LOW_48);
        x = ((x & SPREAD_HIGH_24) << 8) | (x & SPREAD_LOW_24);
        x = ((x & SPLIT_HIGH_12) << 4) | (x & SPLIT_LOW_12);
        uint256 v = ((x & SPLIT_HIGH_6) << 2) | (x & SPLIT_LOW_6);
        // Each threshold the alphabet steps at is found by adding its distance
        // to 128, which carries into a byte's high bit exactly at the
        // threshold: a one marks every byte at or above it. No adjustment
        // carries out of its own byte, so the whole word steps at once. Of the
        // last two values, 62 and 63, the odd one is the last.
        uint256 letter = ((v + 102 * ONES) >> 7) & ONES;
        uint256 digit = ((v + 76 * ONES) >> 7) & ONES;
        uint256 last2 = ((v + 66 * ONES) >> 7) & ONES;
        // The URL-safe alphabet differs only in its last two characters.
        return v + 65 * ONES + 6 * letter + (fileSafe ? 49 : 3) * (last2 & v)
            - (75 * digit + (fileSafe ? 13 : 15) * last2);
    }

    /// @dev The first `used` characters of `chars`, then padding up to `total`
    /// characters, then zeros.
    /// @custom:solar-inline
    function _padded(uint256 chars, uint256 used, uint256 total) private pure returns (uint256) {
        uint256 w = (chars & ~(type(uint256).max >> (used << 3))) | (PADDING >> (used << 3));
        return w & ~(type(uint256).max >> (total << 3));
    }

    /// @dev The twenty-four bytes thirty-two characters encode, left-aligned,
    /// and a nonzero `bad` when a character is not Base64.
    /// @custom:solar-inline
    function _decodeWord(uint256 w) private pure returns (uint256 packed, uint256 bad) {
        // A byte with its top bit set is not ASCII; the rest is classified by
        // its low seven bits. Adding a threshold's distance to 128 carries into
        // a byte's top bit exactly when the byte is at least the threshold, and
        // never out of the byte. The valid characters are the ranges between
        // alternate thresholds, so the top bits of all of them, exclusive-ored,
        // mark the valid bytes. A character's value is the byte plus 19, less
        // a step at each threshold the value steps at: `+` and `,` are 62 and
        // 63, `-` is 62, `/` is 63, `0` is 52, `A` is 0, `_` is 63, `a` is 26.
        uint256 x = w & LOWS;
        uint256 t = x + 85 * ONES; // 43, `+`.
        uint256 v = t;
        t = x + 83 * ONES; // 45, `-`.
        uint256 down = ((t >> 7) & ONES) * 2;
        v ^= x + 82 * ONES; // 46.
        t = x + 81 * ONES; // 47, `/`.
        v ^= t;
        down += (t >> 7) & ONES;
        t = x + 80 * ONES; // 48, `0`.
        down += ((t >> 7) & ONES) * 12;
        v ^= x + 70 * ONES; // 58.
        t = x + 63 * ONES; // 65, `A`.
        v ^= t;
        down += ((t >> 7) & ONES) * 69;
        v ^= x + 37 * ONES; // 91.
        t = x + 33 * ONES; // 95, `_`.
        v ^= t;
        uint256 up = ((t >> 7) & ONES) * 33;
        v ^= x + 32 * ONES; // 96.
        t = x + 31 * ONES; // 97, `a`.
        v ^= t;
        down += ((t >> 7) & ONES) * 39;
        v ^= x + 5 * ONES; // 123.
        bad = (w | ~v) & HIGHS;
        uint256 s = x + 19 * ONES + up - down;
        // Join the sextets: two to twelve bits, four to twenty-four, then the
        // eight groups of three bytes into twenty-four contiguous bytes.
        s = ((s & HIGH_8) >> 2) | (s & LOW_8);
        s = ((s & HIGH_16) >> 4) | (s & LOW_16);
        s = ((s & HIGH_32) >> 8) | (s & LOW_32);
        s = ((s & HIGH_64) >> 16) | (s & LOW_64);
        s = ((s & HIGH_128) >> 32) | (s & LOW_128);
        packed = s << 64;
    }

    /// @dev The 24 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _readBytes24(bytes memory b, uint256 offset) private pure returns (bytes24 result) {
        for (uint256 k; k < 24; ++k) {
            result |= bytes24(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev The leading `count` bytes of `b` from `offset`, at most a word, left-aligned.
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

    /// @dev Writes `value` to the 32 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _writeBytes32(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 32; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Writes the leading `count` bytes of `value`, at most a word, to `b` at `offset`.
    /// @custom:solar-inline
    function _writeBytesN(bytes memory b, uint256 offset, bytes32 value, uint256 count)
        private
        pure
    {
        for (uint256 k; k < count; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Decodes a single ABI bytes value. `n <= 32` and `word` is zero after `n` bytes.
    /// @custom:solar-inline
    function _fromWord(uint256 word, uint256 n) private pure returns (bytes memory) {
        return abi.decode(abi.encode(uint256(32), n, word), (bytes));
    }

    /// @dev Allocates the final length with zero padding through an ABI round trip.
    /// Legacy solc's `new bytes(n)` alone may leave dirty bytes after the last element.
    /// @custom:solar-inline
    function _newBytes(uint256 n) private pure returns (bytes memory) {
        return abi.decode(abi.encode(new bytes(n)), (bytes));
    }
}
