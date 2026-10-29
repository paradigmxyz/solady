// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

/// @notice Library for bit twiddling and boolean operations.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibBit.sol)
/// @author Inspired by (https://graphics.stanford.edu/~seander/bithacks.html)
/// @dev The checked port spells the bit tricks in Solidity. Raw boolean operations require
/// clean boolean inputs, as upstream's do. The bit scans find the byte holding the highest set
/// bit with five comparisons and finish inside it with a table. The population and zero-byte
/// counts sum their lanes through a product that wraps, and `ffs` negates by multiplying with
/// `2**256 - 1`: only the trusted `_rawMul` may wrap.
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
        // Zero is seeded with 256: every comparison is then false and its
        // slot contributes nothing.
        r = (x == 0 ? 256 : 0) | (x > type(uint128).max ? 128 : 0);
        r |= (x >> r) > type(uint64).max ? 64 : 0;
        r |= (x >> r) > type(uint32).max ? 32 : 0;
        r |= (x >> r) > type(uint16).max ? 16 : 0;
        r |= (x >> r) > type(uint8).max ? 8 : 0;
        r |= uint8(_HIGHEST[(_SELECTOR >> (x >> r)) & 31]);
    }

    /// @dev Count leading zeros.
    /// Returns the number of zeros preceding the most significant one bit.
    /// If `x` is zero, returns 256.
    function clz(uint256 x) internal pure returns (uint256 r) {
        // The same search as `fls`. `r` only holds bits at or above three and
        // the slot value has all of those set, so the exclusive-or subtracts.
        // Zero reaches the last slot, 255, and the final term makes it 256.
        r = x > type(uint128).max ? 128 : 0;
        r |= (x >> r) > type(uint64).max ? 64 : 0;
        r |= (x >> r) > type(uint32).max ? 32 : 0;
        r |= (x >> r) > type(uint16).max ? 16 : 0;
        r |= (x >> r) > type(uint8).max ? 8 : 0;
        r = (r ^ uint8(_LEADING[(_SELECTOR >> (x >> r)) & 31])) + (x == 0 ? 1 : 0);
    }

    /// @dev Find first set.
    /// Returns the index of the least significant bit of `x`,
    /// counting from the least significant bit position.
    /// If `x` is zero, returns 256.
    /// Equivalent to `ctz` (count trailing zeros), which gives
    /// the number of zeros following the least significant one bit.
    function ffs(uint256 x) internal pure returns (uint256 r) {
        // Isolate the lowest set bit: `x * (2**256 - 1)` is `-x` modulo `2**256`.
        // A zero stays zero, which the lookups below map to 256.
        x &= _rawMul(x, type(uint256).max);
        // The upper three bits of the index come from a De Bruijn-like lookup of
        // the product's top six bits (credit to adhusson,
        // https://blog.adhusson.com/cheap-find-first-set-evm/), the lower five
        // from a De Bruijn lookup of the bit within its 32-bit lane.
        r =
            ((uint256(0x8040405543005266443200005020610674053026020000107506200176117077)
                        << ((_rawMul(
                                    x,
                                    0xb6db6db6ddddddddd34d34d349249249210842108c6318c639ce739cffffffff
                                )
                                >> 250)
                            << 2))
                    >> 252) << 5;
        r |= uint8(
            bytes32(
                0x00011c021d0e18031e16140f191104081f1b0d17151310071a0c12060b050a09
            )[(_rawMul(x >> r, 0x077cb531) >> 27) & 0x1f]
        );
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
    /// @custom:solar-inline
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

    /// @dev Selects a table slot from a byte value: shifted right by the byte
    /// and masked to five bits, it gives a distinct slot for each position the
    /// byte's highest set bit can have, and slot 30 for a zero byte.
    uint256 private constant _SELECTOR = 0x8421084210842108cc6318c6db6d54be;

    /// @dev The highest set bit's index within a byte, per selector slot.
    bytes32 private constant _HIGHEST =
        0x0706060506020504060203020504030106050205030304010505030400000000;

    /// @dev The same table complemented to 255, so that a leading-zero count
    /// is the byte position exclusive-ored with the slot.
    bytes32 private constant _LEADING =
        0xf8f9f9faf9fdfafbf9fdfcfdfafbfcfef9fafdfafcfcfbfefafafcfbffffffff;

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
    /// @custom:solar-inline
    function _writeBytesN(bytes memory b, bytes32 value, uint256 count) private pure {
        for (uint256 k; k < count; ++k) {
            b[k] = value[k];
        }
    }

    /// @dev The 16 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _readBytes16(bytes memory b, uint256 offset) private pure returns (bytes16 result) {
        for (uint256 k; k < 16; ++k) {
            result |= bytes16(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev Writes `value` into `b` at `offset`.
    /// @custom:solar-inline
    function _writeBytes32(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 32; ++k) {
            b[offset + k] = value[k];
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

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev Allocates bytes with zero right padding, including over dirty memory.
    /// Legacy solc only zeroes the logical length of `new bytes(n)`.
    /// @custom:solar-inline
    function _newBytes(uint256 n) private pure returns (bytes memory) {
        if (n & 31 == 0) return new bytes(n);
        return abi.decode(abi.encode(new bytes(n)), (bytes));
    }
}
