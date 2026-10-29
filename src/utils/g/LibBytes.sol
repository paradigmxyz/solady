// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev Goated bytes storage struct that totally MOGs, no cap, fr.
/// Uses less gas and bytecode than Solidity's native bytes storage. It's meta af.
/// Packs length with the first 31 bytes if <255 bytes, so it’s mad tight.
struct BytesStorage {
    bytes32 _spacer;
}

using LibBytes for BytesStorage global;

/// @notice Library for byte related operations.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/LibBytes.sol)
/// @dev The checked port's searches, copies and comparisons are the ones LibString uses, in
/// checked Solidity; a read outside an object reverts where upstream reads whatever memory
/// follows it. The `BytesStorage` layout is upstream's: a value of up to 254 bytes keeps its
/// length in the low byte of the struct's slot and its first 31 bytes above it, a longer one
/// keeps `0xff` there and its length above, and the rest of the value fills the words derived
/// from the slot, which the trusted helpers move in whole words: Solidity has no spelling of a
/// slot derived from a struct's. Stores write zeros past the end of the value, where upstream
/// copies whatever memory or calldata follows it. `uint8At` returns zero from the length on,
/// as upstream does since its stale-byte fix; the pinned release could return a byte left
/// there by a longer value. A fresh result that does not fill its last word is either built in
/// whole words and cut to its length by `_truncate`, or gets a zero word after its end from
/// `_zeroPad`, as legacy solc's `new bytes(n)` clears only `n` bytes.
/// @custom:solar-safe memory arithmetic
library LibBytes {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The constant returned when the `search` is not found in the bytes.
    uint256 internal constant NOT_FOUND = type(uint256).max;

    /// @dev Bit 7 clear in every byte, and bit 0 set in every byte: the lanes
    /// of the word-at-a-time scans.
    uint256 private constant LANES_7F =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    uint256 private constant LANES_01 =
        0x0101010101010101010101010101010101010101010101010101010101010101;

    /// @dev The high bit of every byte.
    uint256 private constant _HIGH_BITS =
        0x8080808080808080808080808080808080808080808080808080808080808080;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  BYTE STORAGE OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sets the value of the bytes storage `$` to `s`.
    function set(BytesStorage storage $, bytes memory s) internal {
        uint256 n = s.length;
        // Below 255 bytes, the length in the low byte and the first 31 bytes
        // above it, zero past the end, and the rest from byte 31 on in the
        // derived words. Otherwise `0xff` and the length above it, and the
        // whole value in the derived words.
        if (n < 32) {
            $._spacer = bytes32((uint256(bytes32(s)) & ~uint256(0xff)) | n);
            return;
        }
        uint256 i = 31;
        if (n < 0xff) {
            $._spacer = bytes32((uint256(_readBytes32(s, 0)) & ~uint256(0xff)) | n);
        } else {
            $._spacer = bytes32((n << 8) | 0xff);
            i = 0;
        }
        _sstoreFrom($, s, i);
    }

    /// @dev Sets the value of the bytes storage `$` to `s`.
    function setCalldata(BytesStorage storage $, bytes calldata s) internal {
        uint256 n = s.length;
        uint256 i = 31;
        uint256 packed = (uint256(bytes32(s)) & ~uint256(0xff)) | n;
        if (n > 0xfe) {
            packed = (n << 8) | 0xff;
            i = 0;
        }
        $._spacer = bytes32(packed);
        if (n > i) _sstoreCalldataFrom($, s, i);
    }

    /// @dev Sets the value of the bytes storage `$` to the empty bytes.
    function clear(BytesStorage storage $) internal {
        delete $._spacer;
    }

    /// @dev Returns whether the value stored is `$` is the empty bytes "".
    function isEmpty(BytesStorage storage $) internal view returns (bool) {
        return uint256($._spacer) & 0xff == 0;
    }

    /// @dev Returns the length of the value stored in `$`.
    function length(BytesStorage storage $) internal view returns (uint256 result) {
        uint256 packed = uint256($._spacer);
        result = packed & 0xff;
        if (result == 0xff) result = packed >> 8;
    }

    /// @dev Returns the value stored in `$`.
    function get(BytesStorage storage $) internal view returns (bytes memory result) {
        uint256 packed = uint256($._spacer);
        uint256 n = packed & 0xff;
        if (n < 32) {
            // The bytes above the length byte, up to the length, and zeros.
            result = abi.encodePacked(bytes32(packed & ~(type(uint256).max >> (n << 3))));
            _truncate(result, n);
            return result;
        }
        // The bytes from `i` on come from the derived words.
        uint256 i = 31;
        if (n == 0xff) {
            n = packed >> 8;
            i = 0;
        }
        // Before the allocation, so that `result` is the last one.
        uint256 slot = _dataSlot(_slot($));
        result = new bytes(n);
        // The first 31 bytes, and a length byte that the derived words overwrite.
        if (i != 0) _writeBytes32(result, 0, bytes32(packed));
        if (n > i) _sloadInto(slot, result, i);
    }

    /// @dev Returns the uint8 at index `i`. If out-of-bounds, returns 0.
    function uint8At(BytesStorage storage $, uint256 i) internal view returns (uint8 result) {
        uint256 packed = uint256($._spacer);
        uint256 n = packed & 0xff;
        if (n != 0xff) {
            if (i >= n) return 0;
            if (i < 31) return uint8(bytes32(packed)[i]);
            uint256 j = i - 31;
            return uint8(_sload(_add(_dataSlot(_slot($)), j >> 5))[j & 31]);
        }
        if (i >= packed >> 8) return 0;
        return uint8(_sload(_add(_dataSlot(_slot($)), i >> 5))[i & 31]);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      BYTES OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `subject` all occurrences of `needle` replaced with `replacement`.
    function replace(bytes memory subject, bytes memory needle, bytes memory replacement)
        internal
        pure
        returns (bytes memory result)
    {
        return _replace(subject, needle, replacement);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right, starting from `from`.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function indexOf(bytes memory subject, bytes memory needle, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        return _indexOf(subject, needle, from);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right, starting from `from`. Optimized for byte needles.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function indexOfByte(bytes memory subject, bytes1 needle, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        uint256 n = subject.length;
        // The needle in every byte: a word of the subject XOR it has a zero
        // byte exactly where the needle occurs.
        uint256 h = uint256(uint8(needle)) * LANES_01;
        // Whole words, then the bytes past the last one, whose zero padding a
        // zero needle would match.
        uint256 i = from;
        uint256 hits;
        for (; n >= 32 && i <= n - 32; i += 32) {
            hits = _zeroBytes(uint256(_readBytes32(subject, i)) ^ h);
            if (hits != 0) return i + _leadingByte(hits);
        }
        if (i >= n) return NOT_FOUND;
        hits = _zeroBytes(uint256(_readBytesN(subject, i, n - i)) ^ h)
            & ~(type(uint256).max >> ((n - i) << 3));
        return hits == 0 ? NOT_FOUND : i + _leadingByte(hits);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right. Optimized for byte needles.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function indexOfByte(bytes memory subject, bytes1 needle)
        internal
        pure
        returns (uint256 result)
    {
        return indexOfByte(subject, needle, 0);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function indexOf(bytes memory subject, bytes memory needle) internal pure returns (uint256) {
        return indexOf(subject, needle, 0);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from right to left, starting from `from`.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function lastIndexOf(bytes memory subject, bytes memory needle, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        return _lastIndexOf(subject, needle, from);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from right to left.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function lastIndexOf(bytes memory subject, bytes memory needle)
        internal
        pure
        returns (uint256)
    {
        return lastIndexOf(subject, needle, type(uint256).max);
    }

    /// @dev Returns true if `needle` is found in `subject`, false otherwise.
    function contains(bytes memory subject, bytes memory needle) internal pure returns (bool) {
        return indexOf(subject, needle) != NOT_FOUND;
    }

    /// @dev Returns whether `subject` starts with `needle`.
    function startsWith(bytes memory subject, bytes memory needle)
        internal
        pure
        returns (bool result)
    {
        // The range's hash against the needle's, equal exactly when the bytes
        // are, barring a keccak collision.
        return needle.length <= subject.length
            && _keccak256Range(subject, 0, needle.length) == keccak256(needle);
    }

    /// @dev Returns whether `subject` ends with `needle`.
    function endsWith(bytes memory subject, bytes memory needle)
        internal
        pure
        returns (bool result)
    {
        return needle.length <= subject.length
            && _keccak256Range(subject, subject.length - needle.length, needle.length)
                == keccak256(needle);
    }

    /// @dev Returns `subject` repeated `times`.
    function repeat(bytes memory subject, uint256 times)
        internal
        pure
        returns (bytes memory result)
    {
        return _repeat(subject, times);
    }

    /// @dev Returns a copy of `subject` sliced from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function slice(bytes memory subject, uint256 start, uint256 end)
        internal
        pure
        returns (bytes memory result)
    {
        if (end > subject.length) end = subject.length;
        if (start > subject.length) start = subject.length;
        if (start >= end) return "";
        result = new bytes(end - start);
        _copyFresh(result, 0, subject, start, end - start);
        _zeroPad(result);
    }

    /// @dev Returns a copy of `subject` sliced from `start` to the end of the bytes.
    /// `start` is a byte offset.
    function slice(bytes memory subject, uint256 start)
        internal
        pure
        returns (bytes memory result)
    {
        // The end is the length itself, so only the start needs a bound.
        uint256 n = subject.length;
        if (start >= n) return "";
        result = new bytes(n - start);
        _copyFresh(result, 0, subject, start, n - start);
        _zeroPad(result);
    }

    /// @dev Returns a copy of `subject` sliced from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets. Faster than Solidity's native slicing.
    function sliceCalldata(bytes calldata subject, uint256 start, uint256 end)
        internal
        pure
        returns (bytes calldata result)
    {
        uint256 n = subject.length;
        if (end > n) end = n;
        if (start > n) start = n;
        // An empty slice still starts at `start`, as the original's does.
        if (start > end) end = start;
        return subject[start:end];
    }

    /// @dev Returns a copy of `subject` sliced from `start` to the end of the bytes.
    /// `start` is a byte offset. Faster than Solidity's native slicing.
    function sliceCalldata(bytes calldata subject, uint256 start)
        internal
        pure
        returns (bytes calldata result)
    {
        if (start > subject.length) start = subject.length;
        return subject[start:];
    }

    /// @dev Reduces the size of `subject` to `n`.
    /// If `n` is greater than the size of `subject`, this will be a no-op.
    function truncate(bytes memory subject, uint256 n) internal pure returns (bytes memory result) {
        if (n < subject.length) _truncate(subject, n);
        return subject;
    }

    /// @dev Returns a copy of `subject`, with the length reduced to `n`.
    /// If `n` is greater than the size of `subject`, this will be a no-op.
    function truncatedCalldata(bytes calldata subject, uint256 n)
        internal
        pure
        returns (bytes calldata result)
    {
        return subject[:n < subject.length ? n : subject.length];
    }

    /// @dev Returns all the indices of `needle` in `subject`.
    /// The indices are byte offsets.
    function indicesOf(bytes memory subject, bytes memory needle)
        internal
        pure
        returns (uint256[] memory result)
    {
        return _indicesOf(subject, needle);
    }

    /// @dev Returns an arrays of bytess based on the `delimiter` inside of the `subject` bytes.
    function split(bytes memory subject, bytes memory delimiter)
        internal
        pure
        returns (bytes[] memory result)
    {
        return _split(subject, delimiter);
    }

    /// @dev Returns a concatenated bytes of `a` and `b`.
    /// Cheaper than `bytes.concat()` and does not de-align the free memory pointer.
    /// @custom:solar-inline always
    function concat(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        // A word of zeros after the bytes pads their last word, inside the allocation, under
        // every compiler (legacy solc's `bytes.concat` neither clears nor allocates it), and is
        // cut off again.
        result = abi.encodePacked(a, b, bytes32(0));
        _truncate(result, result.length - 32);
    }

    /// @dev Returns whether `a` equals `b`.
    function eq(bytes memory a, bytes memory b) internal pure returns (bool result) {
        return keccak256(a) == keccak256(b);
    }

    /// @dev Returns whether `a` equals `b`, where `b` is a null-terminated small bytes.
    function eqs(bytes memory a, bytes32 b) internal pure returns (bool result) {
        uint256 tail = _nullTail(b);
        // `b`'s null marks must start exactly where `a` ends.
        if (a.length > 32 || tail != _HIGH_BITS >> (a.length * 8)) return false;
        // The conversion pads `a` with zeros after its bytes, and the mask
        // clears `b` from its first null byte on.
        return bytes32(a) == b & bytes32(_smallStringMask(tail));
    }

    /// @dev Returns 0 if `a == b`, -1 if `a < b`, +1 if `a > b`.
    /// If `a` == b[:a.length]`, and `a.length < b.length`, returns -1.
    function cmp(bytes memory a, bytes memory b) internal pure returns (int256 result) {
        uint256 n = a.length < b.length ? a.length : b.length;
        // Words compare as big-endian integers, so the first differing word
        // orders the bytes. A common prefix shorter than a word is masked to
        // its length; a longer one ends with the word ending at its end, whose
        // bytes already compared are equal.
        uint256 u;
        uint256 v;
        if (n < 32) {
            uint256 mask = ~(type(uint256).max >> (n << 3));
            u = uint256(bytes32(a)) & mask;
            v = uint256(bytes32(b)) & mask;
        } else {
            for (uint256 i; i + 32 < n; i += 32) {
                uint256 p = uint256(_readBytes32(a, i));
                uint256 q = uint256(_readBytes32(b, i));
                if (p != q) return p < q ? int256(-1) : int256(1);
            }
            u = uint256(_readBytes32(a, n - 32));
            v = uint256(_readBytes32(b, n - 32));
        }
        if (u != v) return u < v ? int256(-1) : int256(1);
        if (a.length == b.length) return 0;
        return a.length < b.length ? int256(-1) : int256(1);
    }

    /// @dev Directly returns `a` without copying.
    function directReturn(bytes memory a) internal pure {
        _return(abi.encode(a));
    }

    /// @dev Directly returns `a` with minimal copying.
    function directReturn(bytes[] memory a) internal pure {
        _return(abi.encode(a));
    }

    /// @dev Returns the word at `offset`, without any bounds checks.
    function load(bytes memory a, uint256 offset) internal pure returns (bytes32 result) {
        return _readBytes32(a, offset);
    }

    /// @dev Returns the word at `offset`, without any bounds checks.
    function loadCalldata(bytes calldata a, uint256 offset) internal pure returns (bytes32 result) {
        return _calldataReadBytes32(a, offset);
    }

    /// @dev Returns a slice representing a static struct in the calldata. Performs bounds checks.
    function staticStructInCalldata(bytes calldata a, uint256 offset)
        internal
        pure
        returns (bytes calldata result)
    {
        // The struct needs a whole word, as the original requires.
        if (a.length < 32 || offset > a.length - 32) revert();
        return a[offset:];
    }

    /// @dev Returns a slice representing a dynamic struct in the calldata. Performs bounds checks.
    function dynamicStructInCalldata(bytes calldata a, uint256 offset)
        internal
        pure
        returns (bytes calldata result)
    {
        if (a.length < 32 || offset > a.length - 32) revert();
        uint256 s = uint256(_calldataReadBytes32(a, offset));
        if (s >> 64 != 0) revert();
        // A relative offset past the end reverts here, where the original's
        // length wraps.
        return a[s:];
    }

    /// @dev Returns bytes in calldata. Performs bounds checks.
    function bytesInCalldata(bytes calldata a, uint256 offset)
        internal
        pure
        returns (bytes calldata result)
    {
        if (a.length < 32 || offset > a.length - 32) revert();
        uint256 s = uint256(_calldataReadBytes32(a, offset));
        if (s >> 64 != 0 || s > a.length - 32) revert();
        uint256 n = uint256(_calldataReadBytes32(a, s));
        if (n >> 64 != 0 || s + n > a.length - 32) revert();
        return a[s + 32:s + 32 + n];
    }

    /// @dev Checks if `x` is in `a`. Assumes `a` has been checked.
    /// Solidity cannot read a calldata slice's offset, so this keeps the
    /// upstream assembly.
    /// @custom:solar-trusted
    function checkInCalldata(bytes calldata x, bytes calldata a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            if or(
                or(lt(x.offset, a.offset), gt(add(x.offset, x.length), add(a.length, a.offset))),
                shr(64, or(x.length, x.offset))
            ) { revert(0x00, 0x00) }
        }
    }

    /// @dev Checks if `x` is in `a`. Assumes `a` has been checked.
    /// @custom:solar-trusted
    function checkInCalldata(bytes[] calldata x, bytes calldata a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let e := sub(add(a.length, a.offset), 0x20)
            if or(lt(x.offset, a.offset), shr(64, x.offset)) { revert(0x00, 0x00) }
            for { let i := 0 } iszero(eq(x.length, i)) { i := add(i, 1) } {
                let o := calldataload(add(x.offset, shl(5, i)))
                let t := add(o, x.offset)
                let l := calldataload(t)
                if or(shr(64, or(l, o)), gt(add(t, l), e)) { revert(0x00, 0x00) }
            }
        }
    }

    /// @dev Returns empty calldata bytes. For silencing the compiler.
    function emptyCalldata() internal pure returns (bytes calldata result) {
        return msg.data[0:0];
    }

    /// @dev Returns the most significant 20 bytes as an address.
    function msbToAddress(bytes32 x) internal pure returns (address) {
        return address(bytes20(x));
    }

    /// @dev Returns the least significant 20 bytes as an address.
    function lsbToAddress(bytes32 x) internal pure returns (address) {
        return address(uint160(uint256(x)));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Stores the bytes of `b` from `offset` on, at least one, in the words `$` derives,
    /// 32 to a word, the last word zero past them. Solidity cannot name a slot it did not
    /// allocate.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _sstoreFrom(BytesStorage storage $, bytes memory b, uint256 offset) private {
        if (offset >= b.length) _outOfBounds();
        uint256 slot = _dataSlot(_slot($));
        /// @solidity memory-safe-assembly
        assembly {
            let src := add(add(b, 0x20), offset)
            let end := add(add(b, 0x20), mload(b))
            // The last word starts where at most 32 bytes remain.
            let last := add(src, and(sub(sub(end, src), 1), not(31)))
            if lt(src, last) {
                for {} 1 {} {
                    sstore(slot, mload(src))
                    slot := add(slot, 1)
                    src := add(src, 0x20)
                    if iszero(lt(src, last)) { break }
                }
            }
            sstore(slot, and(mload(src), not(shr(shl(3, sub(end, src)), not(0)))))
        }
    }

    /// @dev `_sstoreFrom` from calldata.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _sstoreCalldataFrom(BytesStorage storage $, bytes calldata b, uint256 offset) private {
        if (offset >= b.length) _outOfBounds();
        uint256 slot = _dataSlot(_slot($));
        /// @solidity memory-safe-assembly
        assembly {
            let src := add(b.offset, offset)
            let end := add(b.offset, b.length)
            let last := add(src, and(sub(sub(end, src), 1), not(31)))
            if lt(src, last) {
                for {} 1 {} {
                    sstore(slot, calldataload(src))
                    slot := add(slot, 1)
                    src := add(src, 0x20)
                    if iszero(lt(src, last)) { break }
                }
            }
            sstore(slot, and(calldataload(src), not(shr(shl(3, sub(end, src)), not(0)))))
        }
    }

    /// @dev Writes the slots from `slot` on, 32 bytes to a word, into `b` from `offset`, which
    /// must be below its length, to its end, then a zero word at the end, which clears the
    /// rest of the last word written and can reach up to 32 bytes past `b`'s allocation:
    /// `b` must be the last allocation, as for `_truncate`'s word past the end in LibString.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _sloadInto(uint256 slot, bytes memory b, uint256 offset) private view {
        if (offset >= b.length) _outOfBounds();
        /// @solidity memory-safe-assembly
        assembly {
            let dst := add(add(b, 0x20), offset)
            let end := add(add(b, 0x20), mload(b))
            for {} 1 {} {
                mstore(dst, sload(slot))
                slot := add(slot, 1)
                dst := add(dst, 0x20)
                if iszero(lt(dst, end)) { break }
            }
            mstore(end, 0)
        }
    }

    /// @dev Shrinks `b` to its first `n` bytes in place. Solidity cannot spell
    /// a shorter length for an existing buffer.
    /// @custom:solar-trusted
    function _truncate(bytes memory b, uint256 n) private pure {
        if (n > b.length) n = new uint256[](0)[0];
        /// @solidity memory-safe-assembly
        assembly {
            mstore(b, n)
        }
    }

    /// @dev Zeroizes the word after `b`'s last byte, the rest of `b`'s last word with it, which
    /// legacy solc's `new bytes(n)` leaves dirty. `b` must be the last allocation, so that the
    /// rest of that word is free memory.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _zeroPad(bytes memory b) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(add(add(b, 0x20), mload(b)), 0)
        }
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
    function _writeBytes32(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 32; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Writes the leading `count` bytes of `value`, at most a word, to `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytesN(bytes memory b, uint256 offset, bytes32 value, uint256 count)
        private
        pure
    {
        for (uint256 k; k < count; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _calldataReadBytes32(bytes calldata b, uint256 offset)
        private
        pure
        returns (bytes32 result)
    {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev `subject` with each non-overlapping occurrence of `needle`
    /// replaced by `replacement`. The result is built in a buffer with a word
    /// of slack, so a piece of up to a word is stored as one word, whose bytes
    /// past the piece the next piece or the final length covers.
    function _replace(bytes memory subject, bytes memory needle, bytes memory replacement)
        private
        pure
        returns (bytes memory)
    {
        if (needle.length > subject.length) return subject;
        bytes32 rhead = _head(replacement);
        if (needle.length == 0) {
            bytes memory expanded =
                new bytes(subject.length + (subject.length + 1) * replacement.length + 32);
            uint256 o;
            for (uint256 i; i <= subject.length; ++i) {
                o = _putReplacement(expanded, o, replacement, rhead);
                if (i < subject.length) expanded[o++] = subject[i];
            }
            _truncate(expanded, o);
            return expanded;
        }
        // A replacement no longer than the needle never grows the subject. A
        // longer one grows it by at most `growth` per needle-length piece; while
        // that bound stays within a few times the subject, it sizes the result
        // and saves counting the matches first.
        uint256 size = subject.length;
        if (replacement.length > needle.length) {
            uint256 growth = replacement.length - needle.length;
            uint256 most = subject.length / needle.length;
            if (most * growth > 4 * subject.length + 1024) {
                most = _count(subject, subject.length - needle.length, needle, _head(needle));
                if (most == 0) return subject;
            }
            size += most * growth;
        }
        if (subject.length < 33 && replacement.length < 33) {
            return _replaceShort(subject, needle, replacement, size);
        }
        bytes memory out = new bytes(size + 32);
        _truncate(out, _replaceInto(out, subject, needle, replacement, rhead));
        return out;
    }

    /// @dev `_replace` for a subject and a replacement of at most a word each,
    /// and a needle of one byte or more that fits the subject: the subject is
    /// one word, compared with the needle at each offset in turn, and every
    /// piece of the result, built in a buffer with room for `size` bytes and a
    /// word of slack, is written as one word, zero past the piece.
    function _replaceShort(
        bytes memory subject,
        bytes memory needle,
        bytes memory replacement,
        uint256 size
    ) private pure returns (bytes memory out) {
        out = new bytes(size + 32);
        uint256 s = uint256(bytes32(subject));
        uint256 head = uint256(bytes32(needle));
        uint256 m = needle.length;
        uint256 mask = ~(type(uint256).max >> (m << 3));
        uint256 last = subject.length - m;
        uint256 o;
        uint256 copied;
        for (uint256 at; at <= last;) {
            if ((s << (at << 3)) & mask != head) {
                ++at;
                continue;
            }
            _writeBytes32(out, o, bytes32(s << (copied << 3)));
            o += at - copied;
            _writeBytes32(out, o, bytes32(replacement));
            o += replacement.length;
            copied = at + m;
            at = copied;
        }
        _writeBytes32(out, o, bytes32(s << (copied << 3)));
        _truncate(out, o + subject.length - copied);
    }

    /// @dev Writes `_replace`'s result into `out`, which has room for it and a
    /// word of slack, and returns its length. `rhead` is the replacement's
    /// first word.
    function _replaceInto(
        bytes memory out,
        bytes memory subject,
        bytes memory needle,
        bytes memory replacement,
        bytes32 rhead
    ) private pure returns (uint256 o) {
        uint256 last = subject.length - needle.length;
        bytes32 head = _head(needle);
        uint256 copied;
        uint256 at = _find(subject, 0, last, needle, head);
        while (at != NOT_FOUND) {
            o = _copyPiece(out, o, subject, copied, at - copied);
            // The match at `at`, then each match right after the previous one.
            do {
                o = _putReplacement(out, o, replacement, rhead);
                copied = at + needle.length;
                at = copied;
            } while (copied <= last && _matchAt(subject, copied, needle, head));
            at = copied >= last ? NOT_FOUND : _scan(subject, copied + 1, last, needle, head);
        }
        o = _copyPiece(out, o, subject, copied, subject.length - copied);
    }

    /// @dev Stores `replacement` into `out` at `o`, and returns the offset
    /// after it. Up to a word goes as its first word `rhead`, which also writes
    /// the bytes after it: `out` needs a word of slack.
    /// @custom:solar-inline always
    function _putReplacement(bytes memory out, uint256 o, bytes memory replacement, bytes32 rhead)
        private
        pure
        returns (uint256)
    {
        if (replacement.length <= 32) _writeBytes32(out, o, rhead);
        else _copyFresh(out, o, replacement, 0, replacement.length);
        return o + replacement.length;
    }

    /// @dev Copies the `count` bytes of `src` at `from` into `dst` at `o`, and
    /// returns the offset after them. Up to a word goes as one word, which also
    /// writes the bytes after the copied ones: `dst` needs a word of slack.
    /// @custom:solar-inline always
    function _copyPiece(bytes memory dst, uint256 o, bytes memory src, uint256 from, uint256 count)
        private
        pure
        returns (uint256)
    {
        if (count == 0) return o;
        if (count <= 32) _writeBytes32(dst, o, bytes32(_wordAt(src, from)));
        else _copyFresh(dst, o, src, from, count);
        return o + count;
    }

    /// @dev The byte offset of the first occurrence of `needle` at or after
    /// `from`, or `NOT_FOUND`. An empty needle is found at `from`, or at the
    /// end of a subject shorter than `from`.
    function _indexOf(bytes memory subject, bytes memory needle, uint256 from)
        private
        pure
        returns (uint256)
    {
        bytes memory s = bytes(subject);
        bytes memory n = bytes(needle);
        if (n.length == 0) return from > s.length ? s.length : from;
        if (n.length > s.length) return NOT_FOUND;
        uint256 last = s.length - n.length;
        if (from > last) return NOT_FOUND;
        return _find(s, from, last, n, _head(n));
    }

    /// @dev The byte offset of the last occurrence of `needle` at or before
    /// `from`, or `NOT_FOUND`.
    function _lastIndexOf(bytes memory subject, bytes memory needle, uint256 from)
        private
        pure
        returns (uint256)
    {
        bytes memory s = bytes(subject);
        bytes memory n = bytes(needle);
        if (n.length > s.length) return NOT_FOUND;
        uint256 last = s.length - n.length;
        if (from > last) from = last;
        bytes32 head = _head(n);
        for (uint256 i = from + 1; i != 0;) {
            --i;
            if (_matchAt(s, i, n, head)) return i;
        }
        return NOT_FOUND;
    }

    /// @dev The byte offsets of each non-overlapping occurrence of `needle`.
    function _indicesOf(bytes memory subject, bytes memory needle)
        private
        pure
        returns (uint256[] memory found)
    {
        bytes memory s = bytes(subject);
        bytes memory n = bytes(needle);
        if (n.length > s.length) return new uint256[](0);
        if (n.length == 0) {
            uint256[] memory every = new uint256[](s.length + 1);
            for (uint256 i; i <= s.length; ++i) {
                every[i] = i;
            }
            return every;
        }
        uint256 last = s.length - n.length;
        bytes32 head = _head(n);
        // At most `last / n.length + 1` matches fit. A bound of a few words
        // sizes the result, which is cut down after; a larger one is counted.
        uint256 most = last / n.length + 1;
        if (most > 64) most = _count(s, last, n, head);
        found = new uint256[](most);
        uint256 count;
        uint256 at = _find(s, 0, last, n, head);
        while (at != NOT_FOUND) {
            // The match at `at`, then each match right after the previous one.
            do {
                found[count++] = at;
                at += n.length;
            } while (at <= last && _matchAt(s, at, n, head));
            at = at >= last ? NOT_FOUND : _scan(s, at + 1, last, n, head);
        }
        if (count != most) _truncateWords(found, count);
    }

    /// @dev `subject` repeated `times` times, or empty bytes when either
    /// is zero. Up to a word, the copies are shifted side by side into one
    /// fresh word; longer, one copy of the subject is followed by the filled
    /// prefix doubled in place, each copy reading only bytes already written.
    function _repeat(bytes memory subject, uint256 times) private pure returns (bytes memory) {
        bytes memory s = bytes(subject);
        if (times == 0 || s.length == 0) return "";
        uint256 total = s.length * times;
        if (total < 33) {
            uint256 copy = uint256(bytes32(s));
            uint256 word;
            for (uint256 o; o < total; o += s.length) {
                word |= copy >> (o << 3);
            }
            bytes memory short = abi.encodePacked(bytes32(word));
            _truncate(short, total);
            return short;
        }
        bytes memory out = new bytes(total);
        _copyFresh(out, 0, s, 0, s.length);
        uint256 filled = s.length;
        while (filled < total) {
            uint256 rest = total - filled;
            uint256 step = filled < rest ? filled : rest;
            _copyInto(out, filled, out, 0, step);
            filled += step;
        }
        _zeroPad(out);
        return out;
    }

    /// @dev `subject` split at each non-overlapping `delimiter` occurrence.
    function _split(bytes memory subject, bytes memory delimiter)
        private
        pure
        returns (bytes[] memory result)
    {
        bytes memory s = bytes(subject);
        bytes memory d = bytes(delimiter);
        if (d.length == 0) {
            result = new bytes[](s.length);
            for (uint256 i; i < s.length; ++i) {
                // One fresh word, cut to the byte.
                bytes memory part = abi.encodePacked(bytes32(s[i]));
                _truncate(part, 1);
                result[i] = part;
            }
            return result;
        }
        if (d.length > s.length) {
            result = new bytes[](1);
            result[0] = _sliceFresh(s, 0, s.length);
            return result;
        }
        uint256 last = s.length - d.length;
        bytes32 head = _head(d);
        // At most one part more than `last / d.length + 1` delimiters. A bound
        // of a few words sizes the result, which is cut down after; a larger
        // one is counted.
        uint256 most = last / d.length + 2;
        if (most > 64) most = _count(s, last, d, head) + 1;
        result = new bytes[](most);
        uint256 count;
        uint256 previous;
        for (uint256 at = _find(s, 0, last, d, head); at != NOT_FOUND;) {
            result[count++] = _sliceFresh(s, previous, at);
            previous = at + d.length;
            at = previous > last ? NOT_FOUND : _find(s, previous, last, d, head);
        }
        result[count++] = _sliceFresh(s, previous, s.length);
        if (count != most) _truncateParts(result, count);
    }

    /// @dev The number of non-overlapping occurrences of `needle` in `subject`
    /// at offsets up to `last`, as `_find` takes them.
    function _count(bytes memory subject, uint256 last, bytes memory needle, bytes32 head)
        private
        pure
        returns (uint256 count)
    {
        uint256 at = _find(subject, 0, last, needle, head);
        while (at != NOT_FOUND) {
            do {
                ++count;
                at += needle.length;
            } while (at <= last && _matchAt(subject, at, needle, head));
            at = at >= last ? NOT_FOUND : _scan(subject, at + 1, last, needle, head);
        }
    }

    /// @dev The first offset in `[from, last]` at which `needle` occurs in
    /// `subject`, or `NOT_FOUND`; `last + needle.length` fits the subject and
    /// `head` is as `_matchAt` takes it. The offset `from`
    /// itself, where the next match of a run is, is tried before any scan.
    /// @custom:solar-inline always
    function _find(
        bytes memory subject,
        uint256 from,
        uint256 last,
        bytes memory needle,
        bytes32 head
    ) private pure returns (uint256) {
        if (_matchAt(subject, from, needle, head)) return from;
        return _scan(subject, from + 1, last, needle, head);
    }

    /// @dev `_find` past its first offset. Thirty-two offsets go at once: the
    /// needle's first byte is compared with every byte of a word, a longer
    /// needle's second byte with every byte of the word one byte further on,
    /// and only the offsets where both occur are matched.
    function _scan(
        bytes memory subject,
        uint256 from,
        uint256 last,
        bytes memory needle,
        bytes32 head
    ) private pure returns (uint256) {
        uint256 first = (uint256(head) >> 248) * LANES_01;
        uint256 second = ((uint256(head) >> 240) & 0xff) * LANES_01;
        bool pair = needle.length > 1;
        for (uint256 i = from; i <= last; i += 32) {
            uint256 hits = _zeroBytes(_wordAt(subject, i) ^ first);
            // `i + 1 <= last + 1 < subject.length` for a needle of two bytes or more.
            if (pair) hits &= _zeroBytes(_wordAt(subject, i + 1) ^ second);
            // Offsets past `last` do not count.
            if (last - i < 31) hits &= ~(type(uint256).max >> (8 * (last - i + 1)));
            while (hits != 0) {
                uint256 lane = _leadingByte(hits);
                if (_matchAt(subject, i + lane, needle, head)) return i + lane;
                hits &= ~(uint256(1) << (255 - 8 * lane));
            }
        }
        return NOT_FOUND;
    }

    /// @dev Whether `needle` occurs in `subject` at `at`, where `at + needle.length`
    /// fits the subject. `head` is the needle's first bytes, up to a word: the
    /// word of the subject at `at` decides a needle of up to a word, and the
    /// rest of a longer one is compared a word at a time. Upstream compares the
    /// hashes of the two ranges; equal bytes are equal hashes, and a different
    /// range with the needle's hash is a keccak-256 collision.
    /// @custom:solar-inline always
    function _matchAt(bytes memory subject, uint256 at, bytes memory needle, bytes32 head)
        private
        pure
        returns (bool)
    {
        // The leading bytes of the needle's length, at most a word of them.
        if (_readBytesN(subject, at, needle.length) != head) return false;
        return needle.length <= 32 || _tailMatchesAt(subject, at, needle);
    }

    /// @dev Whether the bytes of `needle` past its first word occur in `subject`
    /// past `at + 32`, where `at + needle.length` fits the subject.
    function _tailMatchesAt(bytes memory subject, uint256 at, bytes memory needle)
        private
        pure
        returns (bool)
    {
        for (uint256 i = 32; i < needle.length; i += 32) {
            uint256 count = needle.length - i < 32 ? needle.length - i : 32;
            if (_readBytesN(subject, at + i, count) != _readBytesN(needle, i, count)) return false;
        }
        return true;
    }

    /// @dev The first bytes of `needle`, up to a word, left-aligned.
    /// @custom:solar-inline always
    function _head(bytes memory needle) private pure returns (bytes32) {
        return _readBytesN(needle, 0, needle.length);
    }

    /// @dev The bytes of `b` from `i`, up to a word, left-aligned: the word at
    /// `i` zero-padded past the end of `b`, where `i < b.length`.
    /// @custom:solar-inline always
    function _wordAt(bytes memory b, uint256 i) private pure returns (uint256) {
        uint256 rest = b.length - i;
        return rest < 32 ? uint256(_readBytesN(b, i, rest)) : uint256(_readBytes32(b, i));
    }

    /// @dev `0x80` in each byte of `z` that is zero, and zero in every other
    /// byte: the low seven bits of a byte plus `0x7f` carry into its top bit
    /// unless they are all clear, and never into the next byte.
    /// @custom:solar-inline always
    function _zeroBytes(uint256 z) private pure returns (uint256) {
        return ~(((z & LANES_7F) + LANES_7F) | z | LANES_7F);
    }

    /// @dev The index, from the top, of the first byte of `x` with its top bit
    /// set. `x` has only top bits set, and at least one: spread down to every
    /// later byte, the marks leave unmarked exactly the bytes before the first,
    /// which a multiplication by a one in every byte counts into the top byte.
    function _leadingByte(uint256 x) private pure returns (uint256 r) {
        x |= x >> 8;
        x |= x >> 16;
        x |= x >> 32;
        x |= x >> 64;
        x |= x >> 128;
        return _rawMul((~x & _HIGH_BITS) >> 7, LANES_01) >> 248;
    }

    /// @dev The keccak-256 hash of the `count` bytes of `b` at `offset`.
    function _keccak256Range(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes32)
    {
        if (count > b.length || offset > b.length - count) count = _outOfBounds();
        bytes memory range = new bytes(count);
        for (uint256 k; k < count; ++k) {
            range[k] = b[offset + k];
        }
        return keccak256(range);
    }

    /// @dev A new buffer holding the bytes of `s` from `start` to `end`.
    /// @custom:solar-inline always
    function _sliceFresh(bytes memory s, uint256 start, uint256 end)
        private
        pure
        returns (bytes memory part)
    {
        part = new bytes(end - start);
        _copyFresh(part, 0, s, start, end - start);
        _zeroPad(part);
    }

    /// @dev Copies `count` bytes from `src` at `srcOffset` to `dst` at
    /// `dstOffset`, front to back. Callers pass a `dst` they have just
    /// allocated; Solar inlines the loop into them and copies with `mcopy`,
    /// behind a test that keeps the loop if `src` reaches into `dst`.
    /// @custom:solar-inline always
    function _copyFresh(
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

    /// @dev Copies `count` bytes from `src` at `srcOffset` to `dst` at
    /// `dstOffset`. The ranges may overlap: the result is as if the source
    /// were read in full before the first write.
    function _copyInto(
        bytes memory dst,
        uint256 dstOffset,
        bytes memory src,
        uint256 srcOffset,
        uint256 count
    ) private pure {
        // Both ranges are validated before anything is written, so a copy
        // running downwards fails on its range the way one running upwards
        // does, rather than on the arithmetic reaching its far end.
        if (
            count > dst.length || dstOffset > dst.length - count || count > src.length
                || srcOffset > src.length - count
        ) count = _outOfBounds();
        if (dstOffset > srcOffset) {
            for (uint256 k = count; k > 0; --k) {
                dst[dstOffset + k - 1] = src[srcOffset + k - 1];
            }
        } else {
            for (uint256 k; k < count; ++k) {
                dst[dstOffset + k] = src[srcOffset + k];
            }
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

    /// @dev `0x80` in every byte of `s` from its first zero byte on. A byte
    /// carries into its own high bit exactly when it is not zero, so the kept
    /// high bits mark the zero bytes; each mark then spreads to every lower
    /// byte, which the first zero byte's mark reaches first.
    function _nullTail(bytes32 s) private pure returns (uint256 marks) {
        uint256 x = uint256(s);
        marks = ~(x | ((x & LANES_7F) + LANES_7F) | LANES_7F);
        marks |= marks >> 8;
        marks |= marks >> 16;
        marks |= marks >> 32;
        marks |= marks >> 64;
        marks |= marks >> 128;
    }

    /// @dev Keeps the bytes before the first null byte, from the string's
    /// `_nullTail` marks: a marked byte minus its mark shifted to the byte's
    /// low bit leaves the seven bits below the mark, which the mark completes
    /// to the whole byte. A shift never exceeds its operand, so the difference
    /// cannot wrap.
    function _smallStringMask(uint256 tail) private pure returns (uint256) {
        return ~((tail - (tail >> 7)) | tail);
    }

    /// @dev Shrinks `a` to its first `n` words in place. Solidity cannot spell
    /// a shorter length for an existing array.
    /// @custom:solar-trusted
    function _truncateWords(uint256[] memory a, uint256 n) private pure {
        if (n > a.length) n = new uint256[](0)[0];
        /// @solidity memory-safe-assembly
        assembly {
            mstore(a, n)
        }
    }

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the
    /// portable spelling of a failed range check.
    function _outOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }

    /// @dev Shrinks `a` to its first `n` parts in place. Solidity cannot spell
    /// a shorter length for an existing array.
    /// @custom:solar-trusted
    function _truncateParts(bytes[] memory a, uint256 n) private pure {
        if (n > a.length) n = new uint256[](0)[0];
        /// @solidity memory-safe-assembly
        assembly {
            mstore(a, n)
        }
    }

    /// @dev Ends the call, returning `data`. Solidity cannot end a call from a
    /// library function without assembly.
    /// @custom:solar-trusted
    function _return(bytes memory data) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            return(add(data, 0x20), mload(data))
        }
    }

    /// @dev The storage slot of `$`.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _slot(BytesStorage storage $) private pure returns (uint256 slot) {
        /// @solidity memory-safe-assembly
        assembly {
            slot := $.slot
        }
    }

    /// @dev The first of the words the value at `slot` continues in.
    function _dataSlot(uint256 slot) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(slot)));
    }

    /// @dev The word in storage slot `slot`. Solidity cannot name a slot it did not allocate.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _sload(uint256 slot) private view returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            value := sload(slot)
        }
    }

    /// @dev `a + b` modulo `2**256`.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev `x * y` modulo `2**256`.
    /// @custom:solar-trusted
    function _rawMul(uint256 x, uint256 y) private pure returns (uint256 z) {
        unchecked {
            z = x * y;
        }
    }
}
