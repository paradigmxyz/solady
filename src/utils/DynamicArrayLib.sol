// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for memory arrays with automatic capacity resizing.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/DynamicArrayLib.sol)
/// @dev The checked port reads and writes elements with checked indexing, so an
/// access outside an array reverts with `Panic(0x32)` where upstream touches the
/// neighbouring memory, and `malloc` returns zeroed elements. A small trusted
/// allocator keeps upstream's prime-checksummed capacity word before a dynamic
/// array's data and its growth policies, expanding in place when the array ends at
/// the free memory pointer and moving it otherwise; trusted helpers set a length the
/// capacity covers, free memory, cast between array types and return an array
/// directly.
/// @custom:solar-safe memory arithmetic
library DynamicArrayLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Type to represent a dynamic array in memory.
    /// You can directly assign to `data`, and the `p` function will
    /// take care of the memory allocation.
    ///
    /// Note: The capacity is a prime-checksummed word before the array. If you assign
    /// an array you did not allocate (e.g. from calldata), that word can
    /// masquerade as a capacity, making `p` skip reallocation and write out of bounds.
    /// Arrays brought in via `wrap` carry the same risk, as `wrap` assigns to `data` too.
    /// If you are not assigning to `data` or using `wrap`, you don't have to worry about it.
    struct DynamicArray {
        uint256[] data;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The constant returned when the element is not found in the array.
    uint256 internal constant NOT_FOUND = type(uint256).max;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  UINT256 ARRAY OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Low level minimalist uint256 array operations.
    // If you don't need syntax sugar, it's recommended to use these.
    // Some of these functions return the same array for function chaining.
    // e.g. `array.set(0, 1).set(1, 2)`.

    /// @dev Returns a uint256 array with `n` elements. The elements are not zeroized.
    /// @custom:solar-inline always
    function malloc(uint256 n) internal pure returns (uint256[] memory result) {
        result = new uint256[](n);
    }

    /// @dev Zeroizes all the elements of `a`.
    function zeroize(uint256[] memory a) internal pure returns (uint256[] memory result) {
        result = a;
        for (uint256 i; i < result.length; ++i) {
            result[i] = 0;
        }
    }

    /// @dev Returns the element at `a[i]`, without bounds checking.
    /// @custom:solar-inline always
    function get(uint256[] memory a, uint256 i) internal pure returns (uint256 result) {
        result = a[i];
    }

    /// @dev Returns the element at `a[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getUint256(uint256[] memory a, uint256 i) internal pure returns (uint256 result) {
        result = a[i];
    }

    /// @dev Returns the element at `a[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getAddress(uint256[] memory a, uint256 i) internal pure returns (address result) {
        result = address(uint160(a[i]));
    }

    /// @dev Returns the element at `a[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getBool(uint256[] memory a, uint256 i) internal pure returns (bool result) {
        result = a[i] != 0;
    }

    /// @dev Returns the element at `a[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getBytes32(uint256[] memory a, uint256 i) internal pure returns (bytes32 result) {
        result = bytes32(a[i]);
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(uint256[] memory a, uint256 i, uint256 data)
        internal
        pure
        returns (uint256[] memory result)
    {
        result = a;
        result[i] = data;
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(uint256[] memory a, uint256 i, address data)
        internal
        pure
        returns (uint256[] memory result)
    {
        result = a;
        result[i] = uint160(data);
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(uint256[] memory a, uint256 i, bool data)
        internal
        pure
        returns (uint256[] memory result)
    {
        result = a;
        result[i] = _toUint(data);
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(uint256[] memory a, uint256 i, bytes32 data)
        internal
        pure
        returns (uint256[] memory result)
    {
        result = a;
        result[i] = uint256(data);
    }

    /// @dev Casts `a` to `address[]`.
    /// @custom:solar-trusted
    function asAddressArray(uint256[] memory a) internal pure returns (address[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }

    /// @dev Casts `a` to `bool[]`.
    /// @custom:solar-trusted
    function asBoolArray(uint256[] memory a) internal pure returns (bool[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }

    /// @dev Casts `a` to `bytes32[]`.
    /// @custom:solar-trusted
    function asBytes32Array(uint256[] memory a) internal pure returns (bytes32[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }

    /// @dev Casts `a` to `uint256[]`.
    /// @custom:solar-trusted
    function toUint256Array(address[] memory a) internal pure returns (uint256[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }

    /// @dev Casts `a` to `uint256[]`.
    /// @custom:solar-trusted
    function toUint256Array(bool[] memory a) internal pure returns (uint256[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }

    /// @dev Casts `a` to `uint256[]`.
    /// @custom:solar-trusted
    function toUint256Array(bytes32[] memory a) internal pure returns (uint256[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }

    /// @dev Reduces the size of `a` to `n`.
    /// If `n` is greater than the size of `a`, this will be a no-op.
    /// @custom:solar-inline always
    function truncate(uint256[] memory a, uint256 n)
        internal
        pure
        returns (uint256[] memory result)
    {
        result = a;
        if (n < result.length) _setLength(result, n);
    }

    /// @dev Clears the array and attempts to free the memory if possible.
    /// @custom:solar-trusted
    function free(uint256[] memory a) internal pure returns (uint256[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
            let n := mload(result)
            mstore(shl(6, lt(iszero(n), eq(add(shl(5, add(1, n)), result), mload(0x40)))), result)
            mstore(result, 0)
        }
    }

    /// @dev Equivalent to `keccak256(abi.encodePacked(a))`.
    function hash(uint256[] memory a) internal pure returns (bytes32 result) {
        result = keccak256(abi.encodePacked(a));
    }

    /// @dev Returns a copy of `a` sliced from `start` to `end` (exclusive).
    function slice(uint256[] memory a, uint256 start, uint256 end)
        internal
        pure
        returns (uint256[] memory result)
    {
        uint256 arrayLen = a.length;
        if (arrayLen <= end) end = arrayLen;
        if (arrayLen <= start) start = arrayLen;
        if (start < end) {
            result = new uint256[](end - start);
            for (uint256 i; i < result.length; ++i) {
                result[i] = a[start + i];
            }
        }
    }

    /// @dev Returns a copy of `a` sliced from `start` to the end of the array.
    function slice(uint256[] memory a, uint256 start)
        internal
        pure
        returns (uint256[] memory result)
    {
        result = slice(a, start, type(uint256).max);
    }

    /// @dev Returns a copy of the array.
    function copy(uint256[] memory a) internal pure returns (uint256[] memory result) {
        result = new uint256[](a.length);
        for (uint256 i; i < result.length; ++i) {
            result[i] = a[i];
        }
    }

    /// @dev Returns if `needle` is in `a`.
    function contains(uint256[] memory a, uint256 needle) internal pure returns (bool) {
        return ~indexOf(a, needle, 0) != 0;
    }

    /// @dev Returns the first index of `needle`, scanning forward from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(uint256[] memory a, uint256 needle, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        uint256 n = a.length;
        uint256 i = from;
        // Eight elements a step while they last, compared in one chain that only
        // says whether the needle is among them; the step that has it then finds it.
        if (n > 7) {
            while (i < n - 7) {
                if (
                    a[i + 7] == needle || a[i + 6] == needle || a[i + 5] == needle
                        || a[i + 4] == needle || a[i + 3] == needle || a[i + 2] == needle
                        || a[i + 1] == needle || a[i] == needle
                ) {
                    if (a[i] == needle) return i;
                    if (a[i + 1] == needle) return i + 1;
                    if (a[i + 2] == needle) return i + 2;
                    if (a[i + 3] == needle) return i + 3;
                    if (a[i + 4] == needle) return i + 4;
                    if (a[i + 5] == needle) return i + 5;
                    if (a[i + 6] == needle) return i + 6;
                    return i + 7;
                }
                i += 8;
            }
        }
        for (; i < n; ++i) {
            if (a[i] == needle) return i;
        }
        return NOT_FOUND;
    }

    /// @dev Returns the first index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(uint256[] memory a, uint256 needle) internal pure returns (uint256 result) {
        result = indexOf(a, needle, 0);
    }

    /// @dev Returns the last index of `needle`, scanning backwards from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(uint256[] memory a, uint256 needle, uint256 from)
        internal
        pure
        returns (uint256 result)
    {
        uint256 n = a.length;
        if (n == 0) return NOT_FOUND;
        uint256 i = from < n ? from : n - 1;
        // Sixteen elements a step while they last, compared in one chain that only
        // says whether the needle is among them; the step that has it then finds it.
        while (i >= 16) {
            if (
                a[i] == needle || a[i - 1] == needle || a[i - 2] == needle || a[i - 3] == needle
                    || a[i - 4] == needle || a[i - 5] == needle || a[i - 6] == needle
                    || a[i - 7] == needle || a[i - 8] == needle || a[i - 9] == needle
                    || a[i - 10] == needle || a[i - 11] == needle || a[i - 12] == needle
                    || a[i - 13] == needle || a[i - 14] == needle || a[i - 15] == needle
            ) {
                if (a[i] == needle) return i;
                if (a[i - 1] == needle) return i - 1;
                if (a[i - 2] == needle) return i - 2;
                if (a[i - 3] == needle) return i - 3;
                if (a[i - 4] == needle) return i - 4;
                if (a[i - 5] == needle) return i - 5;
                if (a[i - 6] == needle) return i - 6;
                if (a[i - 7] == needle) return i - 7;
                if (a[i - 8] == needle) return i - 8;
                if (a[i - 9] == needle) return i - 9;
                if (a[i - 10] == needle) return i - 10;
                if (a[i - 11] == needle) return i - 11;
                if (a[i - 12] == needle) return i - 12;
                if (a[i - 13] == needle) return i - 13;
                if (a[i - 14] == needle) return i - 14;
                return i - 15;
            }
            i -= 16;
        }
        while (a[i] != needle) {
            if (i == 0) return NOT_FOUND;
            --i;
        }
        return i;
    }

    /// @dev Returns the first index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(uint256[] memory a, uint256 needle)
        internal
        pure
        returns (uint256 result)
    {
        result = lastIndexOf(a, needle, NOT_FOUND);
    }

    /// @dev Directly returns `a` without copying.
    /// @custom:solar-trusted
    function directReturn(uint256[] memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let retStart := sub(a, 0x20)
            mstore(retStart, 0x20)
            return(retStart, add(0x40, shl(5, mload(a))))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  DYNAMIC ARRAY OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Some of these functions return the same array for function chaining.
    // e.g. `a.p("1").p("2")`.

    /// @dev Shorthand for `a.data.length`.
    function length(DynamicArray memory a) internal pure returns (uint256) {
        return a.data.length;
    }

    /// @dev Wraps `a` in a dynamic array struct.
    function wrap(uint256[] memory a) internal pure returns (DynamicArray memory result) {
        result.data = a;
    }

    /// @dev Wraps `a` in a dynamic array struct.
    function wrap(address[] memory a) internal pure returns (DynamicArray memory result) {
        result.data = toUint256Array(a);
    }

    /// @dev Wraps `a` in a dynamic array struct.
    function wrap(bool[] memory a) internal pure returns (DynamicArray memory result) {
        result.data = toUint256Array(a);
    }

    /// @dev Wraps `a` in a dynamic array struct.
    function wrap(bytes32[] memory a) internal pure returns (DynamicArray memory result) {
        result.data = toUint256Array(a);
    }

    /// @dev Clears the array without deallocating the memory.
    function clear(DynamicArray memory a) internal pure returns (DynamicArray memory result) {
        _deallocate(result);
        result = a;
        _setLength(result.data, 0);
    }

    /// @dev Clears the array and attempts to free the memory if possible.
    function free(DynamicArray memory a) internal pure returns (DynamicArray memory result) {
        _deallocate(result);
        result = a;
        _free(result);
    }

    /// @dev Resizes the array to contain `n` elements. New elements will be zeroized.
    function resize(DynamicArray memory a, uint256 n)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        reserve(result, n);
        uint256[] memory arrData = result.data;
        uint256 arrLen = arrData.length;
        _setLength(arrData, n);
        // New elements are zeroized.
        for (uint256 i = arrLen; i < n; ++i) {
            arrData[i] = 0;
        }
    }

    /// @dev Increases the size of `a` to `n`.
    /// If `n` is less than the size of `a`, this will be a no-op.
    /// This method does not zeroize any newly created elements.
    function expand(DynamicArray memory a, uint256 n)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        if (n >= a.data.length) {
            reserve(result, n);
            _setLength(result.data, n);
        }
    }

    /// @dev Reduces the size of `a` to `n`.
    /// If `n` is greater than the size of `a`, this will be a no-op.
    function truncate(DynamicArray memory a, uint256 n)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        if (n < result.data.length) _setLength(result.data, n);
    }

    /// @dev Reserves at least `minimum` amount of contiguous memory.
    function reserve(DynamicArray memory a, uint256 minimum)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        _reserve(result, minimum);
    }

    /// @dev Appends `data` to `a`.
    function p(DynamicArray memory a, uint256 data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        uint256 n = a.data.length;
        _grow(result, n + 1);
        uint256[] memory arrData = result.data;
        _setLength(arrData, n + 1);
        arrData[n] = data;
    }

    /// @dev Appends `data` to `a`.
    function p(DynamicArray memory a, address data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = p(a, uint256(uint160(data)));
    }

    /// @dev Appends `data` to `a`.
    function p(DynamicArray memory a, bool data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = p(a, _toUint(data));
    }

    /// @dev Appends `data` to `a`.
    function p(DynamicArray memory a, bytes32 data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = p(a, uint256(data));
    }

    /// @dev Shorthand for returning an empty array.
    function p() internal pure returns (DynamicArray memory result) {}

    /// @dev Shorthand for `p(p(), data)`.
    function p(uint256 data) internal pure returns (DynamicArray memory result) {
        p(result, uint256(data));
    }

    /// @dev Shorthand for `p(p(), data)`.
    function p(address data) internal pure returns (DynamicArray memory result) {
        p(result, uint256(uint160(data)));
    }

    /// @dev Shorthand for `p(p(), data)`.
    function p(bool data) internal pure returns (DynamicArray memory result) {
        p(result, _toUint(data));
    }

    /// @dev Shorthand for `p(p(), data)`.
    function p(bytes32 data) internal pure returns (DynamicArray memory result) {
        p(result, uint256(data));
    }

    /// @dev Removes and returns the last element of `a`.
    /// Returns 0 and does not pop anything if the array is empty.
    function pop(DynamicArray memory a) internal pure returns (uint256 result) {
        uint256[] memory arrData = a.data;
        uint256 n = arrData.length;
        if (n != 0) {
            uint256 v = arrData[n - 1];
            result = v;
            _setLength(arrData, n - 1);
        }
    }

    /// @dev Removes and returns the last element of `a`.
    /// Returns 0 and does not pop anything if the array is empty.
    function popUint256(DynamicArray memory a) internal pure returns (uint256 result) {
        uint256[] memory arrData = a.data;
        uint256 n = arrData.length;
        if (n != 0) {
            uint256 v = arrData[n - 1];
            result = v;
            _setLength(arrData, n - 1);
        }
    }

    /// @dev Removes and returns the last element of `a`.
    /// Returns 0 and does not pop anything if the array is empty.
    function popAddress(DynamicArray memory a) internal pure returns (address result) {
        uint256[] memory arrData = a.data;
        uint256 n = arrData.length;
        if (n != 0) {
            uint256 v = arrData[n - 1];
            result = address(uint160(v));
            _setLength(arrData, n - 1);
        }
    }

    /// @dev Removes and returns the last element of `a`.
    /// Returns 0 and does not pop anything if the array is empty.
    function popBool(DynamicArray memory a) internal pure returns (bool result) {
        uint256[] memory arrData = a.data;
        uint256 n = arrData.length;
        if (n != 0) {
            uint256 v = arrData[n - 1];
            result = v != 0;
            _setLength(arrData, n - 1);
        }
    }

    /// @dev Removes and returns the last element of `a`.
    /// Returns 0 and does not pop anything if the array is empty.
    function popBytes32(DynamicArray memory a) internal pure returns (bytes32 result) {
        uint256[] memory arrData = a.data;
        uint256 n = arrData.length;
        if (n != 0) {
            uint256 v = arrData[n - 1];
            result = bytes32(v);
            _setLength(arrData, n - 1);
        }
    }

    /// @dev Returns the element at `a.data[i]`, without bounds checking.
    /// @custom:solar-inline always
    function get(DynamicArray memory a, uint256 i) internal pure returns (uint256 result) {
        result = a.data[i];
    }

    /// @dev Returns the element at `a.data[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getUint256(DynamicArray memory a, uint256 i) internal pure returns (uint256 result) {
        result = a.data[i];
    }

    /// @dev Returns the element at `a.data[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getAddress(DynamicArray memory a, uint256 i) internal pure returns (address result) {
        result = address(uint160(a.data[i]));
    }

    /// @dev Returns the element at `a.data[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getBool(DynamicArray memory a, uint256 i) internal pure returns (bool result) {
        result = a.data[i] != 0;
    }

    /// @dev Returns the element at `a.data[i]`, without bounds checking.
    /// @custom:solar-inline always
    function getBytes32(DynamicArray memory a, uint256 i) internal pure returns (bytes32 result) {
        result = bytes32(a.data[i]);
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(DynamicArray memory a, uint256 i, uint256 data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        result.data[i] = data;
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(DynamicArray memory a, uint256 i, address data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        result.data[i] = uint160(data);
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(DynamicArray memory a, uint256 i, bool data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        result.data[i] = _toUint(data);
    }

    /// @dev Sets `a.data[i]` to `data`, without bounds checking.
    /// @custom:solar-inline always
    function set(DynamicArray memory a, uint256 i, bytes32 data)
        internal
        pure
        returns (DynamicArray memory result)
    {
        _deallocate(result);
        result = a;
        result.data[i] = uint256(data);
    }

    /// @dev Returns the underlying array as a `uint256[]`.
    function asUint256Array(DynamicArray memory a) internal pure returns (uint256[] memory result) {
        result = a.data;
    }

    /// @dev Returns the underlying array as a `address[]`.
    /// @custom:solar-trusted
    function asAddressArray(DynamicArray memory a) internal pure returns (address[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(a)
        }
    }

    /// @dev Returns the underlying array as a `bool[]`.
    /// @custom:solar-trusted
    function asBoolArray(DynamicArray memory a) internal pure returns (bool[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(a)
        }
    }

    /// @dev Returns the underlying array as a `bytes32[]`.
    /// @custom:solar-trusted
    function asBytes32Array(DynamicArray memory a) internal pure returns (bytes32[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(a)
        }
    }

    /// @dev Returns a copy of `a` sliced from `start` to `end` (exclusive).
    function slice(DynamicArray memory a, uint256 start, uint256 end)
        internal
        pure
        returns (DynamicArray memory result)
    {
        result.data = slice(a.data, start, end);
    }

    /// @dev Returns a copy of `a` sliced from `start` to the end of the array.
    function slice(DynamicArray memory a, uint256 start)
        internal
        pure
        returns (DynamicArray memory result)
    {
        result.data = slice(a.data, start, type(uint256).max);
    }

    /// @dev Returns a copy of `a`.
    function copy(DynamicArray memory a) internal pure returns (DynamicArray memory result) {
        result.data = copy(a.data);
    }

    /// @dev Returns if `needle` is in `a`.
    function contains(DynamicArray memory a, uint256 needle) internal pure returns (bool) {
        return ~indexOf(a.data, needle, 0) != 0;
    }

    /// @dev Returns if `needle` is in `a`.
    function contains(DynamicArray memory a, address needle) internal pure returns (bool) {
        return ~indexOf(a.data, uint160(needle), 0) != 0;
    }

    /// @dev Returns if `needle` is in `a`.
    function contains(DynamicArray memory a, bytes32 needle) internal pure returns (bool) {
        return ~indexOf(a.data, uint256(needle), 0) != 0;
    }

    /// @dev Returns the first index of `needle`, scanning forward from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(DynamicArray memory a, uint256 needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return indexOf(a.data, needle, from);
    }

    /// @dev Returns the first index of `needle`, scanning forward from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(DynamicArray memory a, address needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return indexOf(a.data, uint160(needle), from);
    }

    /// @dev Returns the first index of `needle`, scanning forward from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(DynamicArray memory a, bytes32 needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return indexOf(a.data, uint256(needle), from);
    }

    /// @dev Returns the first index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(DynamicArray memory a, uint256 needle) internal pure returns (uint256) {
        return indexOf(a.data, needle, 0);
    }

    /// @dev Returns the first index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(DynamicArray memory a, address needle) internal pure returns (uint256) {
        return indexOf(a.data, uint160(needle), 0);
    }

    /// @dev Returns the first index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function indexOf(DynamicArray memory a, bytes32 needle) internal pure returns (uint256) {
        return indexOf(a.data, uint256(needle), 0);
    }

    /// @dev Returns the last index of `needle`, scanning backwards from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(DynamicArray memory a, uint256 needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return lastIndexOf(a.data, needle, from);
    }

    /// @dev Returns the last index of `needle`, scanning backwards from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(DynamicArray memory a, address needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return lastIndexOf(a.data, uint160(needle), from);
    }

    /// @dev Returns the last index of `needle`, scanning backwards from `from`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(DynamicArray memory a, bytes32 needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return lastIndexOf(a.data, uint256(needle), from);
    }

    /// @dev Returns the last index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(DynamicArray memory a, uint256 needle) internal pure returns (uint256) {
        return lastIndexOf(a.data, needle, NOT_FOUND);
    }

    /// @dev Returns the last index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(DynamicArray memory a, address needle) internal pure returns (uint256) {
        return lastIndexOf(a.data, uint160(needle), NOT_FOUND);
    }

    /// @dev Returns the last index of `needle`.
    /// If `needle` is not in `a`, returns `NOT_FOUND`.
    function lastIndexOf(DynamicArray memory a, bytes32 needle) internal pure returns (uint256) {
        return lastIndexOf(a.data, uint256(needle), NOT_FOUND);
    }

    /// @dev Equivalent to `keccak256(abi.encodePacked(a.data))`.
    function hash(DynamicArray memory a) internal pure returns (bytes32 result) {
        result = keccak256(abi.encodePacked(a.data));
    }

    /// @dev Directly returns `a` without copying.
    /// @custom:solar-trusted
    function directReturn(DynamicArray memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let arrData := mload(a)
            let retStart := sub(arrData, 0x20)
            mstore(retStart, 0x20)
            return(retStart, add(0x40, shl(5, mload(arrData))))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Helper for deallocating an automatically allocated array pointer.
    /// @custom:solar-trusted
    function _deallocate(DynamicArray memory result) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x40, result) // Deallocate, as we have already allocated.
        }
    }

    /// @dev Casts the bool into a uint256.
    function _toUint(bool b) private pure returns (uint256 result) {
        result = b ? 1 : 0;
    }

    /// @dev Reserves at least `minimum` elements of contiguous memory for `a`, as
    /// upstream's `reserve` does: the capacity is the word before the data, multiplied
    /// by a prime so that no other word passes for one.
    /// @custom:solar-trusted
    function _reserve(DynamicArray memory a, uint256 minimum) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(lt(minimum, 0xffffffff)) { invalid() } // For extra safety.
            for { let arrData := mload(a) } 1 {} {
                // Some random prime number to multiply `cap`, so that
                // we know that the `cap` is for a dynamic array.
                // Selected to be larger than any memory pointer realistically.
                let prime := 8188386068317523
                // Special case for `arrData` pointing to zero pointer.
                if eq(arrData, 0x60) {
                    let newCap := shl(5, add(1, minimum))
                    let capSlot := mload(0x40)
                    mstore(capSlot, mul(prime, newCap)) // Store the capacity.
                    let newArrData := add(0x20, capSlot)
                    mstore(newArrData, 0) // Store the length.
                    mstore(0x40, add(newArrData, add(0x20, newCap))) // Allocate memory.
                    mstore(a, newArrData)
                    break
                }
                let w := not(0x1f)
                let cap := mload(add(arrData, w)) // `mload(sub(arrData, w))`.
                // Extract `cap`, initializing it to zero if it is not a multiple of `prime`.
                cap := mul(div(cap, prime), iszero(mod(cap, prime)))
                let newCap := shl(5, minimum)
                // If we don't need to grow the memory.
                if iszero(and(gt(minimum, mload(arrData)), gt(newCap, cap))) { break }
                // If the memory is contiguous, we can simply expand it.
                if eq(mload(0x40), add(arrData, add(0x20, cap))) {
                    mstore(add(arrData, w), mul(prime, newCap)) // Store the capacity.
                    mstore(0x40, add(arrData, add(0x20, newCap))) // Expand the memory allocation.
                    break
                }
                let capSlot := mload(0x40)
                let newArrData := add(capSlot, 0x20)
                mstore(0x40, add(newArrData, add(0x20, newCap))) // Reallocate the memory.
                mstore(a, newArrData) // Store the `newArrData`.
                // Copy `arrData` one word at a time, backwards.
                for { let o := add(0x20, shl(5, mload(arrData))) } 1 {} {
                    mstore(add(newArrData, o), mload(add(arrData, o)))
                    o := add(o, w) // `sub(o, 0x20)`.
                    if iszero(o) { break }
                }
                mstore(capSlot, mul(prime, newCap)) // Store the capacity.
                mstore(newArrData, mload(arrData)) // Store the length.
                break
            }
        }
    }

    /// @dev Makes room in `a` for `newArrLen` elements, as upstream's append does: an
    /// array that ends at the free memory pointer expands in place, any other moves,
    /// with its contents and length, to newly allocated memory.
    /// @custom:solar-trusted
    function _grow(DynamicArray memory a, uint256 newArrLen) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let arrData := mload(a)
            let newArrBytesLen := shl(5, newArrLen)
            // Some random prime number to multiply `cap`, so that
            // we know that the `cap` is for a dynamic array.
            // Selected to be larger than any memory pointer realistically.
            let prime := 8188386068317523
            let cap := mload(sub(arrData, 0x20))
            // Extract `cap`, initializing it to zero if it is not a multiple of `prime`.
            cap := mul(div(cap, prime), iszero(mod(cap, prime)))

            // Expand / Reallocate memory if required.
            // Note that we need to allocate an extra word for the length.
            for {} iszero(lt(newArrBytesLen, cap)) {} {
                // Approximately more than double the capacity to ensure more than enough space.
                let newCap := add(cap, or(cap, newArrBytesLen))
                // If the memory is contiguous, we can simply expand it.
                if iszero(or(xor(mload(0x40), add(arrData, add(0x20, cap))), iszero(cap))) {
                    mstore(sub(arrData, 0x20), mul(prime, newCap)) // Store the capacity.
                    mstore(0x40, add(arrData, add(0x20, newCap))) // Expand the memory allocation.
                    break
                }
                // Set the `newArrData` to point to the word after `cap`.
                let newArrData := add(mload(0x40), 0x20)
                mstore(0x40, add(newArrData, add(0x20, newCap))) // Reallocate the memory.
                mstore(a, newArrData) // Store the `newArrData`.
                let w := not(0x1f)
                // Copy `arrData` one word at a time, backwards, its length included.
                for { let o := newArrBytesLen } 1 {} {
                    mstore(add(newArrData, o), mload(add(arrData, o)))
                    if iszero(o) { break }
                    o := add(o, w) // `sub(o, 0x20)`.
                }
                mstore(add(newArrData, w), mul(prime, newCap)) // Store the memory.
                break
            }
        }
    }

    /// @dev Frees `a`'s memory if it ends at the free memory pointer, and empties it.
    /// @custom:solar-trusted
    function _free(DynamicArray memory a) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let arrData := mload(a)
            if iszero(eq(arrData, 0x60)) {
                let prime := 8188386068317523
                let cap := mload(sub(arrData, 0x20))
                // Extract `cap`, initializing it to zero if it is not a multiple of `prime`.
                cap := mul(div(cap, prime), iszero(mod(cap, prime)))
                // If `cap` is non-zero and the memory is contiguous, we can free it.
                if lt(iszero(cap), eq(mload(0x40), add(arrData, add(0x20, cap)))) {
                    mstore(0x40, sub(arrData, 0x20))
                }
                mstore(a, 0x60)
            }
        }
    }

    /// @dev Sets the length of `a`, which its capacity covers, to `n`.
    /// @custom:solar-trusted
    function _setLength(uint256[] memory a, uint256 n) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(a, n)
        }
    }
}
