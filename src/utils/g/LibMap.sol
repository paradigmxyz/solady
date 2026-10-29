// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev A uint8 map in storage.
struct Uint8Map {
    mapping(uint256 => uint256) map;
}

/// @dev A uint16 map in storage.
struct Uint16Map {
    mapping(uint256 => uint256) map;
}

/// @dev A uint32 map in storage.
struct Uint32Map {
    mapping(uint256 => uint256) map;
}

/// @dev A uint40 map in storage. Useful for storing timestamps up to 34841 A.D.
struct Uint40Map {
    mapping(uint256 => uint256) map;
}

/// @dev A uint64 map in storage.
struct Uint64Map {
    mapping(uint256 => uint256) map;
}

/// @dev A uint128 map in storage.
struct Uint128Map {
    mapping(uint256 => uint256) map;
}

using LibMap for Uint8Map global;
using LibMap for Uint16Map global;
using LibMap for Uint32Map global;
using LibMap for Uint40Map global;
using LibMap for Uint64Map global;
using LibMap for Uint128Map global;

/// @notice Library for storage of packed unsigned integers.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/LibMap.sol)
/// @dev The checked port updates a packed value as the assembly does, flipping
/// the bits where the stored value and the new one differ, over the same mapping
/// slots. The generic `bitWidth` operations keep the assembly's results for a
/// zero width, which divides by zero, and for widths of 256 and more, whose mask
/// wraps to every bit; a search of zero width returns what the assembly's loop
/// ends with without reading the slots. The generic `get` and `set` are inlined,
/// so a constant width folds into shifts and masks. A search's index arithmetic
/// wraps as the assembly's does, through the trusted `_add` and `_sub`: the
/// midpoint stays between the bounds, and the offset from `start` wraps back for
/// a zero start.
/// @custom:solar-safe memory arithmetic
library LibMap {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     GETTERS / SETTERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the uint8 value at `index` in `map`.
    function get(Uint8Map storage map, uint256 index) internal view returns (uint8 result) {
        result = uint8(map.map[index >> 5] >> ((index & 31) << 3));
    }

    /// @dev Updates the uint8 value at `index` in `map`.
    function set(Uint8Map storage map, uint256 index, uint8 value) internal {
        uint256 s = index >> 5; // Storage slot.
        uint256 o = (index & 31) << 3; // Storage slot offset (bits).
        uint256 v = map.map[s]; // Storage slot value.
        map.map[s] = v ^ ((((v >> o) ^ value) & 0xff) << o);
    }

    /// @dev Returns the uint16 value at `index` in `map`.
    function get(Uint16Map storage map, uint256 index) internal view returns (uint16 result) {
        result = uint16(map.map[index >> 4] >> ((index & 15) << 4));
    }

    /// @dev Updates the uint16 value at `index` in `map`.
    function set(Uint16Map storage map, uint256 index, uint16 value) internal {
        uint256 s = index >> 4; // Storage slot.
        uint256 o = (index & 15) << 4; // Storage slot offset (bits).
        uint256 v = map.map[s]; // Storage slot value.
        map.map[s] = v ^ ((((v >> o) ^ value) & 0xffff) << o);
    }

    /// @dev Returns the uint32 value at `index` in `map`.
    function get(Uint32Map storage map, uint256 index) internal view returns (uint32 result) {
        result = uint32(map.map[index >> 3] >> ((index & 7) << 5));
    }

    /// @dev Updates the uint32 value at `index` in `map`.
    function set(Uint32Map storage map, uint256 index, uint32 value) internal {
        uint256 s = index >> 3; // Storage slot.
        uint256 o = (index & 7) << 5; // Storage slot offset (bits).
        uint256 v = map.map[s]; // Storage slot value.
        map.map[s] = v ^ ((((v >> o) ^ value) & 0xffffffff) << o);
    }

    /// @dev Returns the uint40 value at `index` in `map`.
    function get(Uint40Map storage map, uint256 index) internal view returns (uint40 result) {
        result = uint40(map.map[index / 6] >> ((index % 6) * 40));
    }

    /// @dev Updates the uint40 value at `index` in `map`.
    function set(Uint40Map storage map, uint256 index, uint40 value) internal {
        uint256 s = index / 6; // Storage slot.
        uint256 o = (index % 6) * 40; // Storage slot offset (bits).
        uint256 v = map.map[s]; // Storage slot value.
        map.map[s] = v ^ ((((v >> o) ^ value) & 0xffffffffff) << o);
    }

    /// @dev Returns the uint64 value at `index` in `map`.
    function get(Uint64Map storage map, uint256 index) internal view returns (uint64 result) {
        result = uint64(map.map[index >> 2] >> ((index & 3) << 6));
    }

    /// @dev Updates the uint64 value at `index` in `map`.
    function set(Uint64Map storage map, uint256 index, uint64 value) internal {
        uint256 s = index >> 2; // Storage slot.
        uint256 o = (index & 3) << 6; // Storage slot offset (bits).
        uint256 v = map.map[s]; // Storage slot value.
        map.map[s] = v ^ ((((v >> o) ^ value) & 0xffffffffffffffff) << o);
    }

    /// @dev Returns the uint128 value at `index` in `map`.
    function get(Uint128Map storage map, uint256 index) internal view returns (uint128 result) {
        result = uint128(map.map[index >> 1] >> ((index & 1) << 7));
    }

    /// @dev Updates the uint128 value at `index` in `map`.
    function set(Uint128Map storage map, uint256 index, uint128 value) internal {
        uint256 s = index >> 1; // Storage slot.
        uint256 o = (index & 1) << 7; // Storage slot offset (bits).
        uint256 v = map.map[s]; // Storage slot value.
        map.map[s] = v ^ ((((v >> o) ^ value) & 0xffffffffffffffffffffffffffffffff) << o);
    }

    /// @dev Returns the value at `index` in `map`.
    /// @custom:solar-inline always
    function get(mapping(uint256 => uint256) storage map, uint256 index, uint256 bitWidth)
        internal
        view
        returns (uint256 result)
    {
        uint256 d = _rawDiv(256, bitWidth); // Bucket size.
        uint256 m = _mask(bitWidth); // Value mask.
        result = (map[_rawDiv(index, d)] >> _offset(index, d, bitWidth)) & m;
    }

    /// @dev Updates the value at `index` in `map`.
    /// @custom:solar-inline always
    function set(
        mapping(uint256 => uint256) storage map,
        uint256 index,
        uint256 value,
        uint256 bitWidth
    ) internal {
        uint256 d = _rawDiv(256, bitWidth); // Bucket size.
        uint256 m = _mask(bitWidth); // Value mask.
        uint256 o = _offset(index, d, bitWidth); // Storage slot offset (bits).
        uint256 s = _rawDiv(index, d); // Storage slot.
        uint256 v = map[s];
        map[s] = v ^ ((((v >> o) ^ value) & m) << o);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       BINARY SEARCH                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // The following functions search in the range of [`start`, `end`)
    // (i.e. `start <= index < end`).
    // The range must be sorted in ascending order.
    // `index` precedence: equal to > nearest before > nearest after.
    // An invalid search range will simply return `(found = false, index = start)`.

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(Uint8Map storage map, uint8 needle, uint256 start, uint256 end)
        internal
        view
        returns (bool found, uint256 index)
    {
        return searchSorted(map.map, needle, start, end, 8);
    }

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(Uint16Map storage map, uint16 needle, uint256 start, uint256 end)
        internal
        view
        returns (bool found, uint256 index)
    {
        return searchSorted(map.map, needle, start, end, 16);
    }

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(Uint32Map storage map, uint32 needle, uint256 start, uint256 end)
        internal
        view
        returns (bool found, uint256 index)
    {
        return searchSorted(map.map, needle, start, end, 32);
    }

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(Uint40Map storage map, uint40 needle, uint256 start, uint256 end)
        internal
        view
        returns (bool found, uint256 index)
    {
        return searchSorted(map.map, needle, start, end, 40);
    }

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(Uint64Map storage map, uint64 needle, uint256 start, uint256 end)
        internal
        view
        returns (bool found, uint256 index)
    {
        return searchSorted(map.map, needle, start, end, 64);
    }

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(Uint128Map storage map, uint128 needle, uint256 start, uint256 end)
        internal
        view
        returns (bool found, uint256 index)
    {
        return searchSorted(map.map, needle, start, end, 128);
    }

    /// @dev Returns whether `map` contains `needle`, and the index of `needle`.
    function searchSorted(
        mapping(uint256 => uint256) storage map,
        uint256 needle,
        uint256 start,
        uint256 end,
        uint256 bitWidth
    ) internal view returns (bool found, uint256 index) {
        // Every value of zero width is zero, and the assembly ends without a match at
        // `start`.
        if (bitWidth == 0) return (false, start);
        if (start >= end) end = start;
        uint256 t;
        uint256 o = _sub(start, 1); // Offset to derive the actual index.
        uint256 l = 1; // Low.
        uint256 d = _rawDiv(256, bitWidth); // Bucket size.
        uint256 m = _mask(bitWidth); // Value mask.
        uint256 h = end - start; // High.
        while (true) {
            index = _add(l & h, (l ^ h) >> 1);
            if (l > h) break;
            uint256 at = _add(index, o);
            t = (map[_rawDiv(at, d)] >> _offset(at, d, bitWidth)) & m;
            if (t == needle) break;
            if (needle <= t) h = _sub(index, 1);
            else l = _add(index, 1);
        }
        bool none = index == 0;
        found = t == needle && !none;
        index = _add(o, none ? 1 : index);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `x / y`, returning 0 if `y` is zero.
    /// @custom:solar-inline always
    function _rawDiv(uint256 x, uint256 y) private pure returns (uint256 z) {
        if (y != 0) z = x / y;
    }

    /// @dev Returns `x % y`, returning 0 if `y` is zero.
    /// @custom:solar-inline always
    function _rawMod(uint256 x, uint256 y) private pure returns (uint256 z) {
        if (y != 0) z = x % y;
    }

    /// @dev Returns `(index % d) * bitWidth`, the bit offset of `index` in its bucket
    /// of `d` values: below 256, as `d * bitWidth <= 256` whenever `d` is not zero.
    /// The masks keep both factors whole and let the product skip its overflow check.
    /// @custom:solar-inline always
    function _offset(uint256 index, uint256 d, uint256 bitWidth) private pure returns (uint256) {
        return (_rawMod(index, d) & 0xffff) * (bitWidth & 0xffff);
    }

    /// @dev Returns `(1 << bitWidth) - 1`, every bit for a width of 256 or more: the
    /// shift clears all of them then, as the assembly's subtraction wraps.
    /// @custom:solar-inline always
    function _mask(uint256 bitWidth) private pure returns (uint256) {
        return ~(type(uint256).max << bitWidth);
    }

    /// @dev `a + b` modulo `2**256`.
    /// @custom:solar-trusted
    function _add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev `a - b` modulo `2**256`.
    /// @custom:solar-trusted
    function _sub(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a - b;
        }
    }
}
