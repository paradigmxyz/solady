// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for efficiently performing keccak256 hashes.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/EfficientHashLib.sol)
/// @dev To avoid stack-too-deep, you can use:
/// ```
/// bytes32[] memory buffer = EfficientHashLib.malloc(10);
/// EfficientHashLib.set(buffer, 0, value0);
/// ..
/// EfficientHashLib.set(buffer, 9, value9);
/// bytes32 finalHash = EfficientHashLib.hash(buffer);
/// ```
///
/// The checked port hashes every fixed arity with the plain `keccak256(abi.encode(...))`
/// the source would write anyway, and the compiler decides where the words live: one or two
/// words go to scratch space, more are built at the free pointer without moving it. A range is
/// copied into a new buffer and hashed there. `free` rewinds the free-memory pointer as
/// upstream does, in trusted assembly, since checked Solidity cannot move it. `malloc` returns
/// zeroed words from `new`, and `set` reverts with `Panic(0x32)` for an index past the buffer,
/// where upstream writes past it. `set`, `hash` and `free` of a buffer are tagged for inlining.
/// @custom:solar-safe memory arithmetic
library EfficientHashLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               MALLOC-LESS HASHING OPERATIONS               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `keccak256(abi.encode(v0))`.
    function hash(bytes32 v0) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0));
    }

    /// @dev Returns `keccak256(abi.encode(v0))`.
    function hash(uint256 v0) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1))`.
    function hash(bytes32 v0, bytes32 v1) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1))`.
    function hash(uint256 v0, uint256 v1) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1, v2))`.
    function hash(bytes32 v0, bytes32 v1, bytes32 v2) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1, v2))`.
    function hash(uint256 v0, uint256 v1, uint256 v2) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1, v2, v3))`.
    function hash(bytes32 v0, bytes32 v1, bytes32 v2, bytes32 v3) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3));
    }

    /// @dev Returns `keccak256(abi.encode(v0, v1, v2, v3))`.
    function hash(uint256 v0, uint256 v1, uint256 v2, uint256 v3) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v4))`.
    function hash(bytes32 v0, bytes32 v1, bytes32 v2, bytes32 v3, bytes32 v4)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(v0, v1, v2, v3, v4));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v4))`.
    function hash(uint256 v0, uint256 v1, uint256 v2, uint256 v3, uint256 v4)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(v0, v1, v2, v3, v4));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v5))`.
    function hash(bytes32 v0, bytes32 v1, bytes32 v2, bytes32 v3, bytes32 v4, bytes32 v5)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v5))`.
    function hash(uint256 v0, uint256 v1, uint256 v2, uint256 v3, uint256 v4, uint256 v5)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v6))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v6))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v7))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v7))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v8))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7,
        bytes32 v8
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v8))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v9))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7,
        bytes32 v8,
        bytes32 v9
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v9))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v10))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7,
        bytes32 v8,
        bytes32 v9,
        bytes32 v10
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v10))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v11))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7,
        bytes32 v8,
        bytes32 v9,
        bytes32 v10,
        bytes32 v11
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v11))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v12))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7,
        bytes32 v8,
        bytes32 v9,
        bytes32 v10,
        bytes32 v11,
        bytes32 v12
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v12))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v13))`.
    function hash(
        bytes32 v0,
        bytes32 v1,
        bytes32 v2,
        bytes32 v3,
        bytes32 v4,
        bytes32 v5,
        bytes32 v6,
        bytes32 v7,
        bytes32 v8,
        bytes32 v9,
        bytes32 v10,
        bytes32 v11,
        bytes32 v12,
        bytes32 v13
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13));
    }

    /// @dev Returns `keccak256(abi.encode(v0, .., v13))`.
    function hash(
        uint256 v0,
        uint256 v1,
        uint256 v2,
        uint256 v3,
        uint256 v4,
        uint256 v5,
        uint256 v6,
        uint256 v7,
        uint256 v8,
        uint256 v9,
        uint256 v10,
        uint256 v11,
        uint256 v12,
        uint256 v13
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*             BYTES32 BUFFER HASHING OPERATIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `keccak256(abi.encode(buffer[0], .., buffer[buffer.length - 1]))`.
    /// @custom:solar-inline always
    function hash(bytes32[] memory buffer) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(buffer));
    }

    /// @dev Sets `buffer[i]` to `value`, without a bounds check.
    /// Returns the `buffer` for function chaining.
    /// @custom:solar-inline always
    function set(bytes32[] memory buffer, uint256 i, bytes32 value)
        internal
        pure
        returns (bytes32[] memory)
    {
        buffer[i] = value;
        return buffer;
    }

    /// @dev Sets `buffer[i]` to `value`, without a bounds check.
    /// Returns the `buffer` for function chaining.
    /// @custom:solar-inline always
    function set(bytes32[] memory buffer, uint256 i, uint256 value)
        internal
        pure
        returns (bytes32[] memory)
    {
        buffer[i] = bytes32(value);
        return buffer;
    }

    /// @dev Returns `new bytes32[](n)`, without zeroing out the memory.
    function malloc(uint256 n) internal pure returns (bytes32[] memory buffer) {
        return new bytes32[](n);
    }

    /// @dev Frees memory that has been allocated for `buffer`.
    /// No-op if `buffer.length` is zero, or if new memory has been allocated after `buffer`.
    /// Solidity cannot move the free memory pointer, so this keeps the upstream assembly.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function free(bytes32[] memory buffer) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let n := mload(buffer)
            mstore(shl(6, lt(iszero(n), eq(add(shl(5, add(1, n)), buffer), mload(0x40)))), buffer)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      EQUALITY CHECKS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `a == abi.decode(b, (bytes32))`.
    function eq(bytes32 a, bytes memory b) internal pure returns (bool) {
        return b.length == 32 && _readBytes32(b, 0) == a;
    }

    /// @dev Returns `abi.decode(a, (bytes32)) == a`.
    function eq(bytes memory a, bytes32 b) internal pure returns (bool) {
        return eq(b, a);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               BYTE SLICE HASHING OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the keccak256 of the slice from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function hash(bytes memory b, uint256 start, uint256 end) internal pure returns (bytes32) {
        uint256 n = b.length;
        if (end > n) end = n;
        if (start > end) start = end;
        return _keccak256Range(b, start, end - start);
    }

    /// @dev Returns the keccak256 of the slice from `start` to the end of the bytes.
    function hash(bytes memory b, uint256 start) internal pure returns (bytes32) {
        return hash(b, start, b.length);
    }

    /// @dev Returns the keccak256 of the bytes.
    function hash(bytes memory b) internal pure returns (bytes32) {
        return keccak256(b);
    }

    /// @dev Returns the keccak256 of the slice from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function hashCalldata(bytes calldata b, uint256 start, uint256 end)
        internal
        pure
        returns (bytes32)
    {
        uint256 n = b.length;
        if (end > n) end = n;
        if (start > end) start = end;
        return keccak256(b[start:end]);
    }

    /// @dev Returns the keccak256 of the slice from `start` to the end of the bytes.
    function hashCalldata(bytes calldata b, uint256 start) internal pure returns (bytes32) {
        return hashCalldata(b, start, b.length);
    }

    /// @dev Returns the keccak256 of the bytes.
    function hashCalldata(bytes calldata b) internal pure returns (bytes32) {
        return keccak256(b);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      SHA2-256 HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `sha256(abi.encode(b))`. Yes, it's more efficient.
    function sha2(bytes32 b) internal view returns (bytes32) {
        return sha256(abi.encode(b));
    }

    /// @dev Returns the sha256 of the slice from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function sha2(bytes memory b, uint256 start, uint256 end) internal view returns (bytes32) {
        uint256 n = b.length;
        if (end > n) end = n;
        if (start > end) start = end;
        bytes memory part = _slice(b, start, end - start);
        return sha256(part);
    }

    /// @dev Returns the sha256 of the slice from `start` to the end of the bytes.
    function sha2(bytes memory b, uint256 start) internal view returns (bytes32) {
        return sha2(b, start, b.length);
    }

    /// @dev Returns the sha256 of the bytes.
    function sha2(bytes memory b) internal view returns (bytes32) {
        return sha256(b);
    }

    /// @dev Returns the sha256 of the slice from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function sha2Calldata(bytes calldata b, uint256 start, uint256 end)
        internal
        view
        returns (bytes32)
    {
        uint256 n = b.length;
        if (end > n) end = n;
        if (start > end) start = end;
        return sha256(b[start:end]);
    }

    /// @dev Returns the sha256 of the slice from `start` to the end of the bytes.
    function sha2Calldata(bytes calldata b, uint256 start) internal view returns (bytes32) {
        return sha2Calldata(b, start, b.length);
    }

    /// @dev Returns the sha256 of the bytes.
    function sha2Calldata(bytes calldata b) internal view returns (bytes32) {
        return sha256(b);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev A copy of the `count` bytes of `b` at `offset`. Reverts with
    /// `Panic(0x32)` unless they all lie inside `b`, before allocating.
    function _slice(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes memory result)
    {
        if (offset > b.length || count > b.length - offset) offset = _outOfBounds();
        result = new bytes(count);
        for (uint256 k; k < count; ++k) {
            result[k] = b[offset + k];
        }
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

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the
    /// portable spelling of a failed range check.
    function _outOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }
}
