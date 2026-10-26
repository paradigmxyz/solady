// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library to encode strings in Base58.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/Base58.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Base58.sol)
/// @dev The checked port works a word at a time, in groups of 32 Base58 digits, the most a
/// word holds. `encode` reads the bytes eight at a time into digits in base `58 ** 32` by
/// Horner's rule, or takes a number of at most 32 bytes whole; each such digit spells a word
/// of characters: divisions split it into groups of four Base58 digits, one to each lane of
/// a word, a multiplication by a reciprocal divides every lane by 58 at once, and carries
/// into each byte's top bit pick the characters. `decode` finds the digits of 32 characters
/// a word with the same carries, joins them in pairs, fours and so on into a digit in base
/// `58 ** 32`, and builds the number in 64-bit limbs by Horner's rule; `decodeWord` builds
/// it in a word, checking for overflow a group at a time. Buffers have their final length
/// from allocation, and an ABI round trip zeroes their padding without assembly. At a
/// character below `1`, upstream's `decodeWord` reads its table below zero and runs out of
/// gas; the port reverts
/// there with no data, as an out-of-gas call does.
/// @custom:solar-safe memory arithmetic
library Base58 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev An unrecognized character or overflow was encountered during decoding.
    error Base58DecodingError();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    ENCODING / DECODING                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes `data` into a Base58 string.
    function encode(bytes memory data) internal pure returns (string memory result) {
        uint256 l = data.length;
        if (l == uint256(0)) return result;
        // The leading zero bytes, each encoded as a `1`.
        uint256 z;
        while (z + 32 <= l && _readBytes32(data, z) == 0) z += 32;
        while (z < l && data[z] == 0) ++z;
        if (l - z <= 32) {
            return _encodeWord(uint256(_readBytesN(data, z, l - z)) >> (8 * (32 - (l - z))), z);
        }
        // The rest as a number in base `58 ** 32`, its least significant digit first, by
        // Horner's rule eight bytes at a time, the first step taking what is left over.
        // A digit holds at least 23 bytes.
        uint256[] memory groups = new uint256[]((l - z) / 23 + 1);
        uint256 g;
        uint256 r = (l - z) % 8;
        if (r == 0) r = 8;
        for (uint256 i = z; i < l; r = 8) {
            uint256 carry = uint256(_readBytesN(data, i, r)) >> (256 - 8 * r);
            i += r;
            for (uint256 k; k < g; ++k) {
                uint256 x = (groups[k] << 64) | carry;
                groups[k] = x % _P32;
                carry = x / _P32;
            }
            if (carry != 0) groups[g++] = carry;
        }
        // The string is the number's last Base58 digits after zeros, which are `1`s: one for
        // each leading zero byte, and the digits, written a word of 32 from the end at a time.
        uint256 top = _expand(groups[g - 1]);
        uint256 len = z + 32 * g - _leadingZeroBytes(top);
        bytes memory out = _newBytes(len);
        for (uint256 k; k + 1 < g; ++k) {
            len = _writeEnd(out, len, _encodeChars(_expand(groups[k])));
        }
        len = _writeEnd(out, len, _encodeChars(top));
        while (len != 0) len = _writeEnd(out, len, _ONES * 49);
        result = string(out);
    }

    /// @dev Encodes the `data` word into a Base58 string.
    function encodeWord(bytes32 data) internal pure returns (string memory result) {
        uint256 v = uint256(data);
        result = _encodeWord(v, v == 0 ? 32 : _leadingZeroBytes(v));
    }

    /// @dev Decodes `encoded`, a Base58 string, into the original bytes.
    function decode(string memory encoded) internal pure returns (bytes memory result) {
        bytes memory s = bytes(encoded);
        uint256 n = s.length;
        if (n == uint256(0)) return result;
        // The leading `1`s, each decoded as a zero byte.
        uint256 z;
        while (z + 32 <= n && uint256(_readBytes32(s, z)) == _ONES * 49) z += 32;
        while (z < n && s[z] == "1") ++z;
        // The rest as a number in 64-bit limbs, the least significant first, by Horner's
        // rule 32 characters at a time, the first step taking what is left over. A limb
        // holds at least 10 characters.
        uint256[] memory limbs = new uint256[]((n - z) / 10 + 1);
        uint256 g;
        uint256 r = (n - z) % 32;
        if (r == 0) r = 32;
        for (uint256 i = z; i < n; r = 32) {
            (uint256 digits, uint256 bad) = _decodeChars(_chars(s, i, r));
            if (bad != 0) revert Base58DecodingError();
            i += r;
            uint256 carry = _value(digits);
            for (uint256 k; k < g; ++k) {
                uint256 x = limbs[k] * _P32 + carry;
                limbs[k] = x & type(uint64).max;
                carry = x >> 64;
            }
            for (; carry != 0; carry >>= 64) {
                limbs[g++] = carry & type(uint64).max;
            }
        }
        // `z` zero bytes, then the number's bytes from its first nonzero one, written a word
        // of four limbs at a time from the end.
        uint256 len = z;
        if (g != 0) len += 8 * g - _leadingZeroBytes(limbs[g - 1] << 192);
        result = _newBytes(len);
        for (uint256 k; len != 0; k += 4) {
            uint256 word;
            for (uint256 j; j < 4 && k + j < g; ++j) {
                word |= limbs[k + j] << (64 * j);
            }
            len = _writeEnd(result, len, word);
        }
    }

    /// @dev Decodes `encoded`, a Base58 string, into the original word.
    function decodeWord(string memory encoded) internal pure returns (bytes32 result) {
        bytes memory s = bytes(encoded);
        uint256 n = s.length;
        if (n == uint256(0)) return result;
        // Horner's rule 32 characters at a time, the first step taking what is left over.
        // The number only grows, so a step overflows exactly when one of its characters
        // would.
        uint256 v;
        uint256 r = n % 32;
        if (r == 0) r = 32;
        for (uint256 i; i < n; r = 32) {
            uint256 chars = _chars(s, i, r);
            (uint256 digits, uint256 bad) = _decodeChars(chars);
            if (bad != 0) {
                uint256 skip = 256 - 8 * r;
                _decodeWordRevert(v, chars << skip, digits << skip, bad << skip);
            }
            i += r;
            uint256 c = _value(digits);
            if (v > (type(uint256).max - c) / _P32) revert Base58DecodingError();
            v = v * _P32 + c;
        }
        result = bytes32(v);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `58 ** 32`, the base of a group of 32 Base58 digits.
    uint256 private constant _P32 = 58 ** 32;

    /// @dev One in every byte.
    uint256 private constant _ONES =
        0x0101010101010101010101010101010101010101010101010101010101010101;

    /// @dev The top bit of every byte.
    uint256 private constant _HIGHS =
        0x8080808080808080808080808080808080808080808080808080808080808080;

    /// @dev The low seven bits of every byte.
    uint256 private constant _LOWS =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    /// @dev The 18 low bits of every 64-bit lane, which hold a quotient in `_expandLanes`.
    uint256 private constant _QUOTIENTS =
        0x000000000003ffff000000000003ffff000000000003ffff000000000003ffff;

    /// @dev `z` `1`s, then the Base58 digits of `v`. The string is the last of the 64 digits
    /// that two words hold, after zeros, which are `1`s: one for each of the `z`, and the
    /// digits.
    function _encodeWord(uint256 v, uint256 z) private pure returns (string memory) {
        uint256 lo = v < 58 ** 12 ? _expandTop(v) : _expand(v % _P32);
        uint256 hi = v < _P32 ? 0 : _expandTop(v / _P32);
        uint256 len = z;
        if (v != 0) len += hi != 0 ? 64 - _leadingZeroBytes(hi) : 32 - _leadingZeroBytes(lo);
        bytes memory out = _newBytes(len);
        len = _writeEnd(out, len, _encodeChars(lo));
        if (len != 0) len = _writeEnd(out, len, _encodeChars(hi));
        while (len != 0) len = _writeEnd(out, len, _ONES * 49);
        return string(out);
    }

    /// @dev Writes the last `min(len, 32)` bytes of `word` into `b`, ending at `len`, and
    /// returns where they start.
    function _writeEnd(bytes memory b, uint256 len, uint256 word) private pure returns (uint256) {
        if (len >= 32) {
            len -= 32;
            _writeBytes32(b, len, bytes32(word));
            return len;
        }
        _writeBytesN(b, 0, bytes32(word << (256 - 8 * len)), len);
        return 0;
    }

    /// @dev The 32 Base58 digits of `v`, below `58 ** 32`, one to a byte, the least
    /// significant in the lowest byte. Divisions split `v` into eight groups of four digits,
    /// and each lane of two words takes a group, the even ones in one word and the odd ones
    /// in the other, so each word yields 16 digits in the lanes' low four bytes.
    function _expand(uint256 v) private pure returns (uint256) {
        uint256 hi = v / 58 ** 16;
        uint256 lo = v % 58 ** 16;
        uint256 a = hi / 58 ** 8;
        uint256 b = hi % 58 ** 8;
        uint256 c = lo / 58 ** 8;
        uint256 d = lo % 58 ** 8;
        uint256 even =
            (d % 58 ** 4) | ((c % 58 ** 4) << 64) | ((b % 58 ** 4) << 128) | ((a % 58 ** 4) << 192);
        uint256 odd =
            (d / 58 ** 4) | ((c / 58 ** 4) << 64) | ((b / 58 ** 4) << 128) | ((a / 58 ** 4) << 192);
        return _expandLanes(even) | (_expandLanes(odd) << 32);
    }

    /// @dev The 12 Base58 digits of `v`, below `58 ** 12`, one to a byte, the least significant
    /// in the lowest byte: three groups of four digits in three lanes of one word, their digits
    /// then moved together.
    function _expandTop(uint256 v) private pure returns (uint256) {
        uint256 lo = v % 58 ** 8;
        uint256 x = _expandLanes((lo % 58 ** 4) | ((lo / 58 ** 4) << 64) | ((v / 58 ** 8) << 128));
        return (x & 0xffffffff) | ((x >> 32) & 0xffffffff00000000)
            | ((x >> 64) & 0xffffffff0000000000000000);
    }

    /// @dev The four Base58 digits of the number below `58 ** 4` in each 64-bit lane of `x`,
    /// in the lane's low four bytes, the least significant lowest. Below `58 ** 4`, `y / 58`
    /// is `y * 18512791 >> 30`, whose product stays below `2 ** 48`, so one multiplication
    /// divides all four lanes; masking the quotients drops what the shift brings in from the
    /// next lane.
    function _expandLanes(uint256 x) private pure returns (uint256) {
        uint256 q1 = ((x * 18512791) >> 30) & _QUOTIENTS;
        uint256 q2 = ((q1 * 18512791) >> 30) & _QUOTIENTS;
        uint256 q3 = ((q2 * 18512791) >> 30) & _QUOTIENTS;
        return (x - q1 * 58) | ((q1 - q2 * 58) << 8) | ((q2 - q3 * 58) << 16) | (q3 << 24);
    }

    /// @dev The characters of the Base58 digits in the bytes of `d`: past `1` to `9`, the
    /// alphabet skips ahead 7 at digit 9, 1 at 17 and at 22, 6 at 33 and 1 at 44.
    /// @custom:solar-noinline
    function _encodeChars(uint256 d) private pure returns (uint256) {
        return d + 49 * _ONES + 7 * _atLeast(d, 9) + _atLeast(d, 17) + _atLeast(d, 22) + 6
            * _atLeast(d, 33) + _atLeast(d, 44);
    }

    /// @dev The Base58 digit of each byte of `w`, and the top bit of each byte that is not
    /// a Base58 character in `bad`. A byte below 128 plus a threshold's distance to 128
    /// carries into its top bit exactly when the byte reaches the threshold, and the
    /// characters lie between alternate thresholds. A digit is the byte less how far the
    /// alphabet has skipped ahead, taken from the byte with its top bit set, so that no byte
    /// borrows from the next.
    /// @custom:solar-noinline
    function _decodeChars(uint256 w) private pure returns (uint256 digits, uint256 bad) {
        uint256 x = w & _LOWS;
        // The thresholds 49, 58, 65, 73, 74, 79, 80, 91, 97, 108, 109 and 123.
        uint256 valid = (x + 79 * _ONES) ^ (x + 70 * _ONES) ^ (x + 63 * _ONES) ^ (x + 55 * _ONES)
            ^ (x + 54 * _ONES) ^ (x + 49 * _ONES) ^ (x + 48 * _ONES) ^ (x + 37 * _ONES)
            ^ (x + 31 * _ONES) ^ (x + 20 * _ONES) ^ (x + 19 * _ONES) ^ (x + 5 * _ONES);
        bad = (~valid | w) & _HIGHS;
        uint256 skipped = 49 * _ONES + 7 * _atLeast(x, 65) + _atLeast(x, 74) + _atLeast(x, 80) + 6
            * _atLeast(x, 97) + _atLeast(x, 109);
        digits = ((x | _HIGHS) - skipped) & _LOWS;
    }

    /// @dev One in each byte of `x`, every byte below 128, that is at least `t`, at most 128:
    /// the byte plus `t`'s distance to 128 carries into its top bit, and out of no byte.
    /// @custom:solar-inline
    function _atLeast(uint256 x, uint256 t) private pure returns (uint256) {
        return ((x + (128 - t) * _ONES) & _HIGHS) >> 7;
    }

    /// @dev The number whose 32 Base58 digits are the bytes of `d`, the most significant
    /// first, joining pairs, fours, eights and sixteens of digits in lanes of twice the width.
    function _value(uint256 d) private pure returns (uint256 v) {
        uint256 m = 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;
        v = ((d >> 8) & m) * 58 + (d & m);
        m = 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;
        v = ((v >> 16) & m) * 58 ** 2 + (v & m);
        m = 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;
        v = ((v >> 32) & m) * 58 ** 4 + (v & m);
        m = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
        v = ((v >> 64) & m) * 58 ** 8 + (v & m);
        v = (v >> 128) * 58 ** 16 + (v & type(uint128).max);
    }

    /// @dev The `r` characters of `s` at `i`, right-aligned in a word after `1`s.
    function _chars(bytes memory s, uint256 i, uint256 r) private pure returns (uint256) {
        if (r == 32) return uint256(_readBytes32(s, i));
        return (uint256(_readBytesN(s, i, r)) >> (256 - 8 * r)) | ((_ONES * 49) << (8 * r));
    }

    /// @dev The number of leading zero bytes of `x`, which is not zero: 31 less its base-256
    /// logarithm, by the binary search of `log2` to whole bytes.
    function _leadingZeroBytes(uint256 x) private pure returns (uint256) {
        uint256 r = (x > type(uint128).max ? 1 : 0) << 7;
        r |= ((x >> r) > type(uint64).max ? 1 : 0) << 6;
        r |= ((x >> r) > type(uint32).max ? 1 : 0) << 5;
        r |= ((x >> r) > type(uint16).max ? 1 : 0) << 4;
        r |= ((x >> r) > type(uint8).max ? 1 : 0) << 3;
        return 31 - (r >> 3);
    }

    /// @dev Reverts as upstream's `decodeWord` does, carrying on from `v` a character at a time
    /// through `chars`, the first on top, with their `digits` and `bad` marks, one of which is
    /// set.
    function _decodeWordRevert(uint256 v, uint256 chars, uint256 digits, uint256 bad) private pure {
        while (true) {
            // Upstream reads its table below zero at such a character: out of gas.
            if (chars >> 248 < 49) revert();
            uint256 digit = digits >> 248;
            if (bad >> 255 != 0 || v > (type(uint256).max - digit) / 58) {
                revert Base58DecodingError();
            }
            v = v * 58 + digit;
            chars <<= 8;
            digits <<= 8;
            bad <<= 8;
        }
    }

    /// @dev A new buffer of `n` zero bytes, with zero padding from an ABI round trip.
    /// Legacy solc's `new bytes(n)` alone may leave dirty bytes after the last element.
    /// @custom:solar-inline
    function _newBytes(uint256 n) private pure returns (bytes memory b) {
        b = abi.decode(abi.encode(new bytes(n)), (bytes));
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
}
