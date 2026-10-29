// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev An enumerable address set in storage.
struct AddressSet {
    Entries _values;
    mapping(uint256 => uint256) _positions;
}

/// @dev An enumerable bytes32 set in storage.
struct Bytes32Set {
    uint256 _lazyLength;
    Entries _values;
    mapping(uint256 => uint256) _positions;
}

/// @dev An enumerable uint256 set in storage.
struct Uint256Set {
    Bytes32Set _inner;
}

/// @dev An enumerable int256 set in storage.
struct Int256Set {
    Bytes32Set _inner;
}

/// @dev An enumerable uint8 set in storage. Useful for enums.
struct Uint8Set {
    uint256 data;
}

/// @dev One typed storage word in a set.
struct Entry {
    uint256 value;
}

/// @dev Keep the lazy entries adjacent without hashing their indices.
struct Entries {
    Entry[3] small;
    mapping(uint256 => Entry) large;
}

using EnumerableSetLib for AddressSet global;
using EnumerableSetLib for Bytes32Set global;
using EnumerableSetLib for Uint256Set global;
using EnumerableSetLib for Int256Set global;
using EnumerableSetLib for Uint8Set global;
using EnumerableSetLib for Entry global;
using EnumerableSetLib for Entries global;

/// @notice Library for managing enumerable sets in storage.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/EnumerableSetLib.sol)
///
/// @dev Note:
/// In many applications, the number of elements in an enumerable set is small.
/// This enumerable set implementation avoids storing the length and indices
/// for up to 3 elements. Once the length exceeds 3 for the first time, the length
/// and indices will be initialized. The amortized cost of adding elements is O(1).
///
/// The AddressSet implementation packs the length with the 0th entry.
///
/// All enumerable sets except Uint8Set use a pop and swap mechanism to remove elements.
/// This means that the iteration order of elements can change between element removals.
///
/// The assembly-free port stores the first three entries in adjacent typed slots,
/// with mappings for further entries and positions and an explicit lazy length for
/// word sets. Integer sets wrap a bytes32 set. The first
/// three entries still avoid position writes; removal keeps insertion order until
/// the set first exceeds three entries, then uses pop-and-swap. Address entries
/// retain the packed length in entry zero. This changes storage layout and is for
/// new deployments, not upgrades over the original raw-slot layout.
/// @custom:solar-safe memory arithmetic
library EnumerableSetLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The index must be less than the length.
    error IndexOutOfBounds();

    /// @dev The value cannot be the zero sentinel.
    error ValueIsZeroSentinel();

    /// @dev Cannot accommodate a new unique value with the capacity.
    error ExceedsCapacity();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The index to represent a value that does not exist.
    uint256 internal constant NOT_FOUND = type(uint256).max;

    /// @dev A sentinel value to denote the zero value in storage.
    /// No elements can be equal to this value.
    /// `uint72(bytes9(keccak256(bytes("_ZERO_SENTINEL"))))`.
    uint256 private constant _ZERO_SENTINEL = 0xfbb67fda52d4bfb8bf;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     GETTERS / SETTERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the number of elements in the set.
    function length(AddressSet storage set) internal view returns (uint256 result) {
        uint256 rootPacked = set._values.small[0].value;
        uint256 n = uint96(rootPacked);
        result = n >> 1;
        if (n == 0 && rootPacked >> 96 != 0) {
            result = 1;
            if (set._values.small[1].value != 0) {
                result = 2;
                if (set._values.small[2].value != 0) result = 3;
            }
        }
    }

    /// @dev Returns the number of elements in the set.
    function length(Bytes32Set storage set) internal view returns (uint256 result) {
        uint256 n = set._lazyLength;
        result = n >> 1;
        if (n == 0 && set._values.small[0].value != 0) {
            result = 1;
            if (set._values.small[1].value != 0) {
                result = 2;
                if (set._values.small[2].value != 0) result = 3;
            }
        }
    }

    /// @dev Returns the number of elements in the set.
    function length(Uint256Set storage set) internal view returns (uint256 result) {
        result = length(set._inner);
    }

    /// @dev Returns the number of elements in the set.
    function length(Int256Set storage set) internal view returns (uint256 result) {
        result = length(set._inner);
    }

    /// @dev Returns the number of elements in the set.
    function length(Uint8Set storage set) internal view returns (uint256 result) {
        for (uint256 packed = set.data; packed != 0; ++result) {
            packed &= packed - 1;
        }
    }

    /// @dev Returns whether `value` is in the set.
    function contains(AddressSet storage set, address value) internal view returns (bool result) {
        uint256 v = _addressWord(value);
        uint256 rootPacked = set._values.small[0].value;
        if (uint96(rootPacked) == 0) {
            return rootPacked >> 96 == v || set._values.small[1].value >> 96 == v
                || set._values.small[2].value >> 96 == v;
        }
        result = set._positions[v] != 0;
    }

    /// @dev Returns whether `value` is in the set.
    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool result) {
        uint256 v = _word(value);
        if (set._lazyLength == 0) {
            return set._values.small[0].value == v || set._values.small[1].value == v
                || set._values.small[2].value == v;
        }
        result = set._positions[v] != 0;
    }

    /// @dev Returns whether `value` is in the set.
    function contains(Uint256Set storage set, uint256 value) internal view returns (bool result) {
        result = contains(set._inner, bytes32(value));
    }

    /// @dev Returns whether `value` is in the set.
    function contains(Int256Set storage set, int256 value) internal view returns (bool result) {
        result = contains(set._inner, bytes32(uint256(value)));
    }

    /// @dev Returns whether `value` is in the set.
    function contains(Uint8Set storage set, uint8 value) internal view returns (bool result) {
        result = (set.data >> value) & 1 != 0;
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    function add(AddressSet storage set, address value) internal returns (bool result) {
        uint256 v = _addressWord(value);
        uint256 rootPacked = set._values.small[0].value;
        uint256 n = uint96(rootPacked);
        if (n == 0) {
            uint256 v0 = rootPacked >> 96;
            if (v0 == 0) {
                set._values.small[0].value = v << 96;
                return true;
            }
            if (v0 == v) return false;
            uint256 v1 = set._values.small[1].value >> 96;
            if (v1 == 0) {
                set._values.small[1].value = v << 96;
                return true;
            }
            if (v1 == v) return false;
            uint256 v2 = set._values.small[2].value >> 96;
            if (v2 == 0) {
                set._values.small[2].value = v << 96;
                return true;
            }
            if (v2 == v) return false;
            set._positions[v0] = 1;
            set._positions[v1] = 2;
            set._positions[v2] = 3;
            rootPacked |= 7;
            n = 7;
        }
        if (set._positions[v] == 0) {
            n >>= 1;
            result = true;
            set._positions[v] = n + 1;
            if (n == 0) {
                set._values.small[0].value = (v << 96) | 3;
            } else {
                _entry(set._values, n).value = v << 96;
                // The length bits are far below their maximum, so the sum stays in them.
                set._values.small[0].value = rootPacked + 2;
            }
        }
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    function add(Bytes32Set storage set, bytes32 value) internal returns (bool result) {
        uint256 v = _word(value);
        uint256 n = set._lazyLength;
        if (n == 0) {
            uint256 v0 = set._values.small[0].value;
            if (v0 == 0) {
                set._values.small[0].value = v;
                return true;
            }
            if (v0 == v) return false;
            uint256 v1 = set._values.small[1].value;
            if (v1 == 0) {
                set._values.small[1].value = v;
                return true;
            }
            if (v1 == v) return false;
            uint256 v2 = set._values.small[2].value;
            if (v2 == 0) {
                set._values.small[2].value = v;
                return true;
            }
            if (v2 == v) return false;
            set._positions[v0] = 1;
            set._positions[v1] = 2;
            set._positions[v2] = 3;
            n = 7;
        }
        if (set._positions[v] == 0) {
            n >>= 1;
            _entry(set._values, n).value = v;
            set._positions[v] = n + 1;
            set._lazyLength = ((n + 1) << 1) | 1;
            result = true;
        }
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    function add(Uint256Set storage set, uint256 value) internal returns (bool result) {
        result = add(set._inner, bytes32(value));
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    function add(Int256Set storage set, int256 value) internal returns (bool result) {
        result = add(set._inner, bytes32(uint256(value)));
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    function add(Uint8Set storage set, uint8 value) internal returns (bool result) {
        uint256 packed = set.data;
        uint256 mask = uint256(1) << value;
        set.data = packed | mask;
        result = packed & mask == 0;
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    /// Reverts if the set grows bigger than the custom on-the-fly capacity `cap`.
    function add(AddressSet storage set, address value, uint256 cap)
        internal
        returns (bool result)
    {
        if (result = add(set, value)) {
            if (length(set) > cap) revert ExceedsCapacity();
        }
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    /// Reverts if the set grows bigger than the custom on-the-fly capacity `cap`.
    function add(Bytes32Set storage set, bytes32 value, uint256 cap)
        internal
        returns (bool result)
    {
        if (result = add(set, value)) {
            if (length(set) > cap) revert ExceedsCapacity();
        }
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    /// Reverts if the set grows bigger than the custom on-the-fly capacity `cap`.
    function add(Uint256Set storage set, uint256 value, uint256 cap)
        internal
        returns (bool result)
    {
        if (result = add(set, value)) {
            if (length(set) > cap) revert ExceedsCapacity();
        }
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    /// Reverts if the set grows bigger than the custom on-the-fly capacity `cap`.
    function add(Int256Set storage set, int256 value, uint256 cap) internal returns (bool result) {
        if (result = add(set, value)) if (length(set) > cap) revert ExceedsCapacity();
    }

    /// @dev Adds `value` to the set. Returns whether `value` was not in the set.
    /// Reverts if the set grows bigger than the custom on-the-fly capacity `cap`.
    function add(Uint8Set storage set, uint8 value, uint256 cap) internal returns (bool result) {
        if (result = add(set, value)) if (length(set) > cap) revert ExceedsCapacity();
    }

    /// @dev Removes `value` from the set. Returns whether `value` was in the set.
    function remove(AddressSet storage set, address value) internal returns (bool result) {
        uint256 v = _addressWord(value);
        uint256 rootPacked = set._values.small[0].value;
        uint256 n = uint96(rootPacked);
        if (n == 0) {
            if (rootPacked >> 96 == v) {
                set._values.small[0].value = set._values.small[1].value;
                set._values.small[1].value = set._values.small[2].value;
                set._values.small[2].value = 0;
                return true;
            }
            if (set._values.small[1].value >> 96 == v) {
                set._values.small[1].value = set._values.small[2].value;
                set._values.small[2].value = 0;
                return true;
            }
            if (set._values.small[2].value >> 96 == v) {
                set._values.small[2].value = 0;
                return true;
            }
            return false;
        }
        uint256 position = set._positions[v];
        if (position == 0) return false;
        // The index of the last element, which moves into the removed one's place.
        n = (n >> 1) - 1;
        if (position - 1 != n) {
            uint256 lastValue = _entry(set._values, n).value >> 96;
            _entry(set._values, position - 1).value = lastValue << 96;
            set._positions[lastValue] = position;
        }
        set._values.small[0].value = ((set._values.small[0].value >> 96) << 96) | (n << 1) | 1;
        set._positions[v] = 0;
        result = true;
    }

    /// @dev Removes `value` from the set. Returns whether `value` was in the set.
    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool result) {
        uint256 v = _word(value);
        uint256 n = set._lazyLength;
        if (n == 0) {
            if (set._values.small[0].value == v) {
                set._values.small[0].value = set._values.small[1].value;
                set._values.small[1].value = set._values.small[2].value;
                set._values.small[2].value = 0;
                return true;
            }
            if (set._values.small[1].value == v) {
                set._values.small[1].value = set._values.small[2].value;
                set._values.small[2].value = 0;
                return true;
            }
            if (set._values.small[2].value == v) {
                set._values.small[2].value = 0;
                return true;
            }
            return false;
        }
        uint256 position = set._positions[v];
        if (position == 0) return false;
        // The index of the last element, which moves into the removed one's place.
        n = (n >> 1) - 1;
        if (position - 1 != n) {
            uint256 lastValue = _entry(set._values, n).value;
            _entry(set._values, position - 1).value = lastValue;
            set._positions[lastValue] = position;
        }
        set._lazyLength = (n << 1) | 1;
        set._positions[v] = 0;
        result = true;
    }

    /// @dev Removes `value` from the set. Returns whether `value` was in the set.
    function remove(Uint256Set storage set, uint256 value) internal returns (bool result) {
        result = remove(set._inner, bytes32(value));
    }

    /// @dev Removes `value` from the set. Returns whether `value` was in the set.
    function remove(Int256Set storage set, int256 value) internal returns (bool result) {
        result = remove(set._inner, bytes32(uint256(value)));
    }

    /// @dev Removes `value` from the set. Returns whether `value` was in the set.
    function remove(Uint8Set storage set, uint8 value) internal returns (bool result) {
        uint256 packed = set.data;
        uint256 mask = uint256(1) << value;
        set.data = packed & ~mask;
        result = packed & mask != 0;
    }

    /// @dev Shorthand for `isAdd ? set.add(value, cap) : set.remove(value)`.
    function update(AddressSet storage set, address value, bool isAdd, uint256 cap)
        internal
        returns (bool)
    {
        return isAdd ? add(set, value, cap) : remove(set, value);
    }

    /// @dev Shorthand for `isAdd ? set.add(value, cap) : set.remove(value)`.
    function update(Bytes32Set storage set, bytes32 value, bool isAdd, uint256 cap)
        internal
        returns (bool)
    {
        return isAdd ? add(set, value, cap) : remove(set, value);
    }

    /// @dev Shorthand for `isAdd ? set.add(value, cap) : set.remove(value)`.
    function update(Uint256Set storage set, uint256 value, bool isAdd, uint256 cap)
        internal
        returns (bool)
    {
        return isAdd ? add(set, value, cap) : remove(set, value);
    }

    /// @dev Shorthand for `isAdd ? set.add(value, cap) : set.remove(value)`.
    function update(Int256Set storage set, int256 value, bool isAdd, uint256 cap)
        internal
        returns (bool)
    {
        return isAdd ? add(set, value, cap) : remove(set, value);
    }

    /// @dev Shorthand for `isAdd ? set.add(value, cap) : set.remove(value)`.
    function update(Uint8Set storage set, uint8 value, bool isAdd, uint256 cap)
        internal
        returns (bool)
    {
        return isAdd ? add(set, value, cap) : remove(set, value);
    }

    /// @dev Returns all of the values in the set.
    /// Note: This can consume more gas than the block gas limit for large sets.
    function values(AddressSet storage set) internal view returns (address[] memory result) {
        uint256 rootPacked = set._values.small[0].value;
        uint256 n = uint96(rootPacked);
        uint256 v0 = rootPacked >> 96;
        if (n == 0) {
            // At most three values, in the root slot and the two after it.
            uint256 v1;
            uint256 v2;
            if (v0 != 0) {
                n = 1;
                v1 = set._values.small[1].value >> 96;
                if (v1 != 0) {
                    n = 2;
                    v2 = set._values.small[2].value >> 96;
                    if (v2 != 0) n = 3;
                }
            }
            result = new address[](n);
            if (n != 0) result[0] = _wordAddress(v0);
            if (n > 1) result[1] = _wordAddress(v1);
            if (n > 2) result[2] = _wordAddress(v2);
            return result;
        }
        n >>= 1;
        result = new address[](n);
        if (n != 0) result[0] = _wordAddress(v0);
        for (uint256 i = 1; i < n; ++i) {
            result[i] = _wordAddress(_entry(set._values, i).value >> 96);
        }
    }

    /// @dev Returns all of the values in the set.
    /// Note: This can consume more gas than the block gas limit for large sets.
    function values(Bytes32Set storage set) internal view returns (bytes32[] memory result) {
        uint256 n = set._lazyLength;
        if (n == 0) {
            // At most three values, in the root slot and the two after it.
            uint256 v1;
            uint256 v2;
            uint256 v0 = set._values.small[0].value;
            if (v0 != 0) {
                n = 1;
                v1 = set._values.small[1].value;
                if (v1 != 0) {
                    n = 2;
                    v2 = set._values.small[2].value;
                    if (v2 != 0) n = 3;
                }
            }
            result = new bytes32[](n);
            if (n != 0) result[0] = _wordValue(v0);
            if (n > 1) result[1] = _wordValue(v1);
            if (n > 2) result[2] = _wordValue(v2);
            return result;
        }
        n >>= 1;
        result = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            result[i] = _wordValue(_entry(set._values, i).value);
        }
    }

    /// @dev Returns all of the values in the set.
    /// Note: This can consume more gas than the block gas limit for large sets.
    function values(Uint256Set storage set) internal view returns (uint256[] memory result) {
        uint256 n = length(set);
        result = new uint256[](n);
        for (uint256 i; i < n; ++i) {
            result[i] = uint256(_wordValue(_entry(set._inner._values, i).value));
        }
    }

    /// @dev Returns all of the values in the set.
    /// Note: This can consume more gas than the block gas limit for large sets.
    function values(Int256Set storage set) internal view returns (int256[] memory result) {
        uint256 n = length(set);
        result = new int256[](n);
        for (uint256 i; i < n; ++i) {
            result[i] = int256(uint256(_wordValue(_entry(set._inner._values, i).value)));
        }
    }

    /// @dev Returns all of the values in the set.
    function values(Uint8Set storage set) internal view returns (uint8[] memory result) {
        uint256 packed = set.data;
        result = new uint8[](length(set));
        uint256 k;
        for (uint256 o; packed != 0;) {
            if (packed & 0xffff == 0) {
                o += 16;
                packed >>= 16;
                continue;
            }
            if (packed & 1 != 0) result[k++] = uint8(o);
            ++o;
            packed >>= 1;
        }
    }

    /// @dev Returns the element at index `i` in the set. Reverts if `i` is out-of-bounds.
    function at(AddressSet storage set, uint256 i) internal view returns (address result) {
        result = _wordAddress(_entry(set._values, i).value >> 96);
        if (i >= length(set)) revert IndexOutOfBounds();
    }

    /// @dev Returns the element at index `i` in the set. Reverts if `i` is out-of-bounds.
    function at(Bytes32Set storage set, uint256 i) internal view returns (bytes32 result) {
        result = _wordValue(_entry(set._values, i).value);
        if (i >= length(set)) revert IndexOutOfBounds();
    }

    /// @dev Returns the element at index `i` in the set. Reverts if `i` is out-of-bounds.
    function at(Uint256Set storage set, uint256 i) internal view returns (uint256 result) {
        result = uint256(at(set._inner, i));
    }

    /// @dev Returns the element at index `i` in the set. Reverts if `i` is out-of-bounds.
    function at(Int256Set storage set, uint256 i) internal view returns (int256 result) {
        result = int256(uint256(at(set._inner, i)));
    }

    /// @dev Returns the element at index `i` in the set. Reverts if `i` is out-of-bounds.
    function at(Uint8Set storage set, uint256 i) internal view returns (uint8 result) {
        uint256 packed = set.data;
        if (i >= 256) revert IndexOutOfBounds();
        // Clear the `i` lowest set bits.
        for (uint256 j; j != i; ++j) {
            if (packed == 0) revert IndexOutOfBounds();
            packed &= packed - 1;
        }
        if (packed == 0) revert IndexOutOfBounds();
        // Find first set subroutine, optimized for smaller bytecode size.
        // `packed` is not zero, so `~packed + 1` cannot wrap.
        uint256 x = packed & (~packed + 1);
        uint256 r = x >> 128 != 0 ? 128 : 0;
        r |= (x >> r) >> 64 != 0 ? 64 : 0;
        r |= (x >> r) > 0xffffffff ? 32 : 0;
        // For the lower 5 bits of the result, use a De Bruijn lookup.
        result = uint8(
            r
                | uint8(
                    bytes32(
                        0x001f0d1e100c1d070f090b19131c1706010e11080a1a141802121b1503160405
                    )[(0xd76453e0 / (x >> r)) & 0x1f]
                )
        );
    }

    /// @dev Returns the index of `value`. Returns `NOT_FOUND` if the value does not exist.
    function indexOf(AddressSet storage set, address value) internal view returns (uint256 result) {
        result = NOT_FOUND;
        if (uint160(value) == _ZERO_SENTINEL) return result;
        uint256 v = _addressWord(value);
        uint256 rootPacked = set._values.small[0].value;
        if (uint96(rootPacked) == 0) {
            if (rootPacked >> 96 == v) return 0;
            if (set._values.small[1].value >> 96 == v) return 1;
            if (set._values.small[2].value >> 96 == v) return 2;
            return result;
        }
        uint256 position = set._positions[v];
        if (position != 0) result = position - 1;
    }

    /// @dev Returns the index of `value`. Returns `NOT_FOUND` if the value does not exist.
    function indexOf(Bytes32Set storage set, bytes32 value) internal view returns (uint256 result) {
        result = NOT_FOUND;
        if (uint256(value) == _ZERO_SENTINEL) return result;
        uint256 v = _word(value);
        if (set._lazyLength == 0) {
            if (set._values.small[0].value == v) return 0;
            if (set._values.small[1].value == v) return 1;
            if (set._values.small[2].value == v) return 2;
            return result;
        }
        uint256 position = set._positions[v];
        if (position != 0) result = position - 1;
    }

    /// @dev Returns the index of `value`. Returns `NOT_FOUND` if the value does not exist.
    function indexOf(Uint256Set storage set, uint256 i) internal view returns (uint256 result) {
        result = indexOf(set._inner, bytes32(i));
    }

    /// @dev Returns the index of `value`. Returns `NOT_FOUND` if the value does not exist.
    function indexOf(Int256Set storage set, int256 i) internal view returns (uint256 result) {
        result = indexOf(set._inner, bytes32(uint256(i)));
    }

    /// @dev Returns the index of `value`. Returns `NOT_FOUND` if the value does not exist.
    function indexOf(Uint8Set storage set, uint8 value) internal view returns (uint256 result) {
        result = NOT_FOUND;
        uint256 packed = set.data;
        uint256 m = uint256(1) << value;
        if (packed & m != 0) {
            result = 0;
            for (uint256 p = packed & (m - 1); p != 0; ++result) {
                p &= p - 1;
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The word that stands for address `value` in a set: zero is the sentinel.
    /// Reverts if `value` is the sentinel itself.
    /// @custom:solar-inline always
    function _addressWord(address value) private pure returns (uint256 v) {
        v = uint160(value);
        if (v == _ZERO_SENTINEL) revert ValueIsZeroSentinel();
        if (v == 0) v = _ZERO_SENTINEL;
    }

    /// @dev The word that stands for `value` in a set: zero is the sentinel.
    /// Reverts if `value` is the sentinel itself.
    /// @custom:solar-inline always
    function _word(bytes32 value) private pure returns (uint256 v) {
        v = uint256(value);
        if (v == _ZERO_SENTINEL) revert ValueIsZeroSentinel();
        if (v == 0) v = _ZERO_SENTINEL;
    }

    /// @dev The address a stored word stands for: the sentinel is zero.
    function _wordAddress(uint256 v) private pure returns (address) {
        return v == _ZERO_SENTINEL ? address(0) : address(uint160(v));
    }

    /// @dev The value a stored word stands for: the sentinel is zero.
    function _wordValue(uint256 v) private pure returns (bytes32) {
        return v == _ZERO_SENTINEL ? bytes32(0) : bytes32(v);
    }

    /// @dev Selects an entry without hashing the first three indices.
    /// @custom:solar-inline always
    function _entry(Entries storage entries, uint256 i)
        private
        view
        returns (Entry storage result)
    {
        if (i < 3) return entries.small[i];
        return entries.large[i];
    }
}
