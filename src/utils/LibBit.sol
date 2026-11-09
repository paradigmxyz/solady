// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import {Bits} from "solar:core/Bits.sol";

import {LibBytes} from "./LibBytes.sol";

/// @notice Library for bit twiddling and boolean operations.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibBit.sol)
/// @author Inspired by (https://graphics.stanford.edu/~seander/bithacks.html)
/// @dev The checked port spells the bit tricks in Solidity. Raw boolean operations require
/// clean boolean inputs, as upstream's do. The bit scans use the portable core bodies, which the
/// compiler replaces with native instructions when the target supports them. Population and
/// zero-byte counts sum their lanes through a wrapping product in the trusted `_rawMul`.
/// @custom:solar-safe memory arithmetic
library LibBit {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  BIT TWIDDLING OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Find last set.
    /// Returns the index of the most significant bit of `x`,
    /// counting from the least significant bit position.
    /// If `x` is zero, returns 256.
    function fls(uint256 x) internal pure returns (uint256 r) {
        return Bits.highestSetBit(x);
    }

    /// @dev Count leading zeros.
    /// Returns the number of zeros preceding the most significant one bit.
    /// If `x` is zero, returns 256.
    function clz(uint256 x) internal pure returns (uint256 r) {
        return Bits.leadingZeros(x);
    }

    /// @dev Find first set.
    /// Returns the index of the least significant bit of `x`,
    /// counting from the least significant bit position.
    /// If `x` is zero, returns 256.
    /// Equivalent to `ctz` (count trailing zeros), which gives
    /// the number of zeros following the least significant one bit.
    function ffs(uint256 x) internal pure returns (uint256 r) {
        return Bits.trailingZeros(x);
    }

    /// @dev Returns the number of set bits in `x`.
    function popCount(uint256 x) internal pure returns (uint256 c) {
        // Sum bits in ever wider lanes: pairs, nibbles, bytes, then all bytes
        // at once through a product that stacks them into the top byte. No
        // lane carries into its neighbour, so the lane steps cannot overflow;
        // the product wraps on purpose. That byte holds at most 255, so the
        // lowest bit is counted apart and the lanes see 255 bits.
        uint256 lowest = x & 1;
        x >>= 1;
        x = x - ((x >> 1) & 0x5555555555555555555555555555555555555555555555555555555555555555);
        x = (x & 0x3333333333333333333333333333333333333333333333333333333333333333)
            + ((x >> 2) & 0x3333333333333333333333333333333333333333333333333333333333333333);
        x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
        return (_rawMul(x, 0x0101010101010101010101010101010101010101010101010101010101010101)
                    >> 248) + lowest;
    }

    /// @dev Returns the number of zero bytes in `x`.
    /// To get the number of non-zero bytes, simply do `32 - countZeroBytes(x)`.
    /// @custom:solar-inline always
    function countZeroBytes(uint256 x) internal pure returns (uint256 c) {
        // A zero byte keeps its top bit clear through `(x & m) + m` and `| x`,
        // so the complement marks it with `0x80`. Shifted down to one per zero
        // byte, the marks sum into the product's top byte, which holds at most
        // 32; the product wraps on purpose.
        uint256 m = type(uint256).max / 255 * 127;
        return _rawMul(~(((x & m) + m) | x | m) >> 7, type(uint256).max / 255) >> 248;
    }

    /// @dev Returns the number of zero bytes in `s`.
    /// To get the number of non-zero bytes, simply do `s.length - countZeroBytes(s)`.
    function countZeroBytes(bytes memory s) internal pure returns (uint256 c) {
        // Both loops count a word at a time. The tail's word is read with only its
        // bytes, and the bytes past them are set, so they never count as zero.
        uint256 n = s.length;
        uint256 i;
        while (i + 32 <= n) {
            c += countZeroBytes(uint256(_readBytes32(s, i)));
            i += 32;
        }
        if (i < n) {
            uint256 rest = n - i;
            c += countZeroBytes(
                uint256(_readBytesN(s, i, rest)) | (type(uint256).max >> (8 * rest))
            );
        }
    }

    /// @dev Returns the number of zero bytes in `s`.
    /// To get the number of non-zero bytes, simply do `s.length - countZeroBytes(s)`.
    function countZeroBytesCalldata(bytes calldata s) internal pure returns (uint256 c) {
        uint256 n = s.length;
        uint256 i;
        while (i + 32 <= n) {
            c += countZeroBytes(uint256(bytes32(s[i:i + 32])));
            i += 32;
        }
        if (i < n) {
            uint256 rest = n - i;
            c += countZeroBytes(uint256(bytes32(s[i:])) | (type(uint256).max >> (8 * rest)));
        }
    }

    /// @dev Returns whether `x` is a power of 2.
    function isPo2(uint256 x) internal pure returns (bool result) {
        return x != 0 && (x & (x - 1)) == 0;
    }

    /// @dev Returns `x` reversed at the bit level.
    function reverseBits(uint256 x) internal pure returns (uint256 r) {
        uint256 m0 = type(uint256).max / 17;
        uint256 m1 = m0 ^ (m0 << 2);
        uint256 m2 = m1 ^ (m1 << 1);
        r = reverseBytes(x);
        r = (m2 & (r >> 1)) | ((m2 & r) << 1);
        r = (m1 & (r >> 2)) | ((m1 & r) << 2);
        return (m0 & (r >> 4)) | ((m0 & r) << 4);
    }

    /// @dev Returns `x` reversed at the byte level.
    function reverseBytes(uint256 x) internal pure returns (uint256 r) {
        uint256 m0 = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
        uint256 m1 = m0 ^ (m0 << 32);
        uint256 m2 = m1 ^ (m1 << 16);
        uint256 m3 = m2 ^ (m2 << 8);
        r = (m3 & (x >> 8)) | ((m3 & x) << 8);
        r = (m2 & (r >> 16)) | ((m2 & r) << 16);
        r = (m1 & (r >> 32)) | ((m1 & r) << 32);
        r = (m0 & (r >> 64)) | ((m0 & r) << 64);
        return (r >> 128) | (r << 128);
    }

    /// @dev Returns the common prefix of `x` and `y` at the bit level.
    function commonBitPrefix(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 s = 256 - clz(x ^ y);
        return (x >> s) << s;
    }

    /// @dev Returns the common prefix of `x` and `y` at the nibble level.
    function commonNibblePrefix(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 s = (64 - (clz(x ^ y) >> 2)) << 2;
        return (x >> s) << s;
    }

    /// @dev Returns the common prefix of `x` and `y` at the byte level.
    function commonBytePrefix(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 s = (32 - (clz(x ^ y) >> 3)) << 3;
        return (x >> s) << s;
    }

    /// @dev hex"ABCD" -> hex"0A0B0C0D".
    function toNibbles(bytes memory s) internal pure returns (bytes memory result) {
        uint256 n = s.length;
        // Below one block the input fits one word, zero-padded by the
        // conversion: its nibbles fill one word, of which the output takes
        // the first `2 * n` bytes. An empty input has none to spread.
        if (n < 16) {
            if (n == 0) return "";
            result = _newBytes(n * 2);
            _writeBytesN(result, bytes32(_spread(uint256(bytes32(s)) >> 128)), n * 2);
            return result;
        }
        result = _newBytes(n * 2);
        uint256 i;
        uint256 o;
        // Sixteen input bytes make one word of output. The spreading is
        // written out here rather than called, so that the loop is straight
        // code whose reads and writes the loop condition already bounds.
        while (i + 16 <= n) {
            uint256 x = uint128(_readBytes16(s, i));
            x = (x | (x << 64)) & _MASK_64;
            x = (x | (x << 32)) & _MASK_32;
            x = (x | (x << 16)) & _MASK_16;
            x = (x | (x << 8)) & _MASK_8;
            _writeBytes32(result, o, bytes32((x | (x << 4)) & _MASK_4));
            i += 16;
            o += 32;
        }
        if (i == n) return result;
        // What is left is shorter than a block. One more block pulled back to
        // end where the input ends covers it, rewriting the nibbles it shares
        // with the block before.
        uint256 tail = uint128(_readBytes16(s, n - 16));
        _writeBytes32(result, (n - 16) * 2, bytes32(_spread(tail)));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     BOOLEAN OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // A Solidity bool on the stack or memory is represented as a 256-bit word.
    // Non-zero values are true, zero is false.
    // A clean bool is either 0 (false) or 1 (true) under the hood.
    // Usually, if not always, the bool result of a regular Solidity expression,
    // or the argument of a public/external function will be a clean bool.
    // You can usually use the raw variants for more performance.
    // If uncertain, test (best with exact compiler settings).
    // Or use the non-raw variants (compiler can sometimes optimize out the double `iszero`s).

    /// @dev Returns `x & y`. Inputs must be clean.
    function rawAnd(bool x, bool y) internal pure returns (bool z) {
        return x && y;
    }

    /// @dev Returns `x & y`.
    function and(bool x, bool y) internal pure returns (bool z) {
        return x && y;
    }

    /// @dev Returns `w & x & y`.
    function and(bool w, bool x, bool y) internal pure returns (bool z) {
        return w && x && y;
    }

    /// @dev Returns `v & w & x & y`.
    function and(bool v, bool w, bool x, bool y) internal pure returns (bool z) {
        return v && w && x && y;
    }

    /// @dev Returns `x | y`. Inputs must be clean.
    function rawOr(bool x, bool y) internal pure returns (bool z) {
        return x || y;
    }

    /// @dev Returns `x | y`.
    function or(bool x, bool y) internal pure returns (bool z) {
        return x || y;
    }

    /// @dev Returns `w | x | y`.
    function or(bool w, bool x, bool y) internal pure returns (bool z) {
        return w || x || y;
    }

    /// @dev Returns `v | w | x | y`.
    function or(bool v, bool w, bool x, bool y) internal pure returns (bool z) {
        return v || w || x || y;
    }

    /// @dev Returns 1 if `b` is true, else 0. Input must be clean.
    function rawToUint(bool b) internal pure returns (uint256 z) {
        return b ? 1 : 0;
    }

    /// @dev Returns 1 if `b` is true, else 0.
    function toUint(bool b) internal pure returns (uint256 z) {
        return b ? 1 : 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Nibble-spreading masks, one per halving of the packing.
    uint256 private constant _MASK_64 =
        0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;

    uint256 private constant _MASK_32 =
        0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;

    uint256 private constant _MASK_16 =
        0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;

    uint256 private constant _MASK_8 =
        0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;

    uint256 private constant _MASK_4 =
        0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;

    /// @dev The nibbles of `x`, which must be below `2 ** 128`, one to a byte:
    /// eight bytes apart, then four, two, one, and finally one nibble.
    function _spread(uint256 x) private pure returns (uint256) {
        x = (x | (x << 64)) & _MASK_64;
        x = (x | (x << 32)) & _MASK_32;
        x = (x | (x << 16)) & _MASK_16;
        x = (x | (x << 8)) & _MASK_8;
        return (x | (x << 4)) & _MASK_4;
    }

    /// @dev `x * y` modulo `2**256`.
    /// @custom:solar-trusted
    function _rawMul(uint256 x, uint256 y) private pure returns (uint256 z) {
        unchecked {
            z = x * y;
        }
    }

    /// @dev Writes the leading `count` bytes of `value` at the start of `b`.
    /// @custom:solar-inline always
    function _writeBytesN(bytes memory b, bytes32 value, uint256 count) private pure {
        for (uint256 k; k < count; ++k) {
            b[k] = value[k];
        }
    }

    /// @dev The 16 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes16(bytes memory b, uint256 offset) private pure returns (bytes16 result) {
        for (uint256 k; k < 16; ++k) {
            result |= bytes16(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev Writes `value` into `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytes32(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 32; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev The leading `count` bytes of `b` from `offset`, at most a word, left-aligned.
    /// @custom:solar-inline always
    function _readBytesN(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes32 result)
    {
        for (uint256 k; k < count; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev Reserves and zeroes whole words before setting the logical length.
    /// Legacy solc only zeroes the logical length of `new bytes(n)`.
    /// @custom:solar-inline always
    function _newBytes(uint256 n) private pure returns (bytes memory) {
        // Keep the allocator's resource panic instead of overflowing the rounding addition.
        if (n > type(uint64).max) return new bytes(n);
        return LibBytes.truncate(new bytes((n + 31) & ~uint256(31)), n);
    }
}
