// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev A heap in storage.
struct Heap {
    uint256[] data;
}

/// @dev A heap in memory.
struct MemHeap {
    uint256[] data;
}

using MinHeapLib for Heap global;
using MinHeapLib for MemHeap global;

/// @notice Library for managing a min-heap in storage or memory.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/MinHeapLib.sol)
/// @dev The checked port keeps upstream's layouts. A storage heap is `data`'s length
/// and items, read and written through trusted raw storage helpers, so a pop leaves
/// the vacated slot as upstream does. A memory heap keeps upstream's prime-checksummed
/// capacity word before `data` and its growth policy through a small trusted
/// allocator, which also sets a length the capacity covers. The sift loops and
/// `smallest` are checked Solidity: for more than a 32nd of a memory heap's items,
/// `smallest` pops them off a copy of the heap, and otherwise it runs upstream's
/// priority queue in arrays freed on return. A `reserve` whose `minimum` does not
/// round up to a multiple of 32 within a word reverts, and `reserve` always makes room
/// for the items a heap already has.
/// @custom:solar-safe memory arithmetic
library MinHeapLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The heap is empty.
    error HeapIsEmpty();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The prime that checksums a memory heap's capacity.
    uint256 private constant _PRIME = 204053801631428327883786711931463459222251954273621;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OPERATIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Tips:
    // - To use as a max-heap, bitwise negate the input and output values (e.g. `heap.push(~x)`).
    // - To use on tuples, pack the tuple values into a single integer.
    // - To use on signed integers, convert the signed integers into
    //   their ordered unsigned counterparts via `uint256(x) + (1 << 255)`.

    /// @dev Returns the minimum value of the heap.
    /// Reverts if the heap is empty.
    function root(Heap storage heap) internal view returns (uint256 result) {
        uint256 slot = _slot(heap);
        if (_sload(slot) == 0) revert HeapIsEmpty();
        result = _sload(_dataSlot(slot));
    }

    /// @dev Returns the minimum value of the heap.
    /// Reverts if the heap is empty.
    function root(MemHeap memory heap) internal pure returns (uint256 result) {
        uint256[] memory data = heap.data;
        if (data.length == 0) revert HeapIsEmpty();
        result = data[0];
    }

    /// @dev Reserves at least `minimum` slots of memory for the heap.
    /// Helps avoid reallocation if you already know the max size of the heap.
    function reserve(MemHeap memory heap, uint256 minimum) internal pure {
        uint256[] memory data = heap.data;
        if (minimum > _capacity(data)) {
            uint256 newCap = (minimum + 0x1f) & ~uint256(0x1f); // Round up to multiple of 32.
            uint256 n = data.length;
            _reallocate(heap, newCap < n ? n : newCap);
        }
    }

    /// @dev Returns an array of the `k` smallest items in the heap,
    /// sorted in ascending order, without modifying the heap.
    /// If the heap has less than `k` items, all items in the heap will be returned.
    function smallest(Heap storage heap, uint256 k) internal view returns (uint256[] memory a) {
        uint256 slot = _slot(heap);
        uint256 sOffset = _dataSlot(slot);
        uint256 n = _sload(slot); // The number of items in the heap.
        uint256 m = k < n ? k : n; // `min(k, n)`.
        a = new uint256[](m);
        if (m == 0) return a;
        // The priority queue's values and the heap positions they come from.
        uint256[] memory values = new uint256[](m);
        uint256[] memory indices = new uint256[](m);
        values[0] = _sload(sOffset); // Store the root into the priority queue.
        uint256 e = 1; // The number of items in the priority queue.
        for (uint256 o; true;) {
            a[o] = values[0];
            if (++o == m) break;
            // Each output adds at most one item, so the queue never outgrows `m`.
            assert(e <= m);
            uint256 childPos = (indices[0] << 1) | 1;
            if (childPos >= n) {
                --e;
                _pSiftup(values, indices, e, values[e], indices[e]);
                continue;
            }
            _pSiftup(values, indices, e, _sload(_add(sOffset, childPos)), childPos);
            ++childPos;
            if (childPos != n) {
                _pSiftdown(values, indices, e, _sload(_add(sOffset, childPos)), childPos);
                ++e;
            }
        }
        _deallocate(values);
    }

    /// @dev Returns an array of the `k` smallest items in the heap,
    /// sorted in ascending order, without modifying the heap.
    /// If the heap has less than `k` items, all items in the heap will be returned.
    function smallest(MemHeap memory heap, uint256 k) internal pure returns (uint256[] memory a) {
        uint256[] memory data = heap.data;
        uint256 n = data.length; // The number of items in the heap.
        uint256 m = k < n ? k : n; // `min(k, n)`.
        a = new uint256[](m);
        if (m == 0) return a;
        // For more than a 32nd of the items, popping them off a copy of the heap costs less
        // than the priority queue.
        if (m << 5 >= n) {
            uint256[] memory h = new uint256[](n);
            for (uint256 i; i < n; ++i) {
                h[i] = data[i];
            }
            for (uint256 o; true;) {
                a[o] = h[0];
                if (++o == m) break;
                uint256 last = h.length - 1;
                uint256 value = h[last];
                _setLength(h, last);
                _sift(h, 0, 1, value);
            }
            _deallocate(h);
            return a;
        }
        // The priority queue's values and the heap positions they come from.
        uint256[] memory values = new uint256[](m);
        uint256[] memory indices = new uint256[](m);
        values[0] = data[0]; // Store the root into the priority queue.
        uint256 e = 1; // The number of items in the priority queue.
        for (uint256 o; true;) {
            a[o] = values[0];
            if (++o == m) break;
            // Each output adds at most one item, so the queue never outgrows `m`.
            assert(e <= m);
            uint256 childPos = (indices[0] << 1) | 1;
            if (childPos >= n) {
                --e;
                _pSiftup(values, indices, e, values[e], indices[e]);
                continue;
            }
            _pSiftup(values, indices, e, data[childPos], childPos);
            ++childPos;
            if (childPos != n) {
                _pSiftdown(values, indices, e, data[childPos], childPos);
                ++e;
            }
        }
        _deallocate(values);
    }

    /// @dev Returns the number of items in the heap.
    function length(Heap storage heap) internal view returns (uint256) {
        return heap.data.length;
    }

    /// @dev Returns the number of items in the heap.
    function length(MemHeap memory heap) internal pure returns (uint256) {
        return heap.data.length;
    }

    /// @dev Pushes the `value` onto the min-heap.
    function push(Heap storage heap, uint256 value) internal {
        _set(heap, value, 0, 3);
    }

    /// @dev Pushes the `value` onto the min-heap.
    function push(MemHeap memory heap, uint256 value) internal pure {
        _set(heap, value, 0, 3);
    }

    /// @dev Pops the minimum value from the min-heap.
    /// Reverts if the heap is empty.
    function pop(Heap storage heap) internal returns (uint256 popped) {
        (, popped) = _set(heap, 0, 0, 2);
    }

    /// @dev Pops the minimum value from the min-heap.
    /// Reverts if the heap is empty.
    function pop(MemHeap memory heap) internal pure returns (uint256 popped) {
        (, popped) = _set(heap, 0, 0, 2);
    }

    /// @dev Pushes the `value` onto the min-heap, and pops the minimum value.
    function pushPop(Heap storage heap, uint256 value) internal returns (uint256 popped) {
        (, popped) = _set(heap, value, 0, 4);
    }

    /// @dev Pushes the `value` onto the min-heap, and pops the minimum value.
    function pushPop(MemHeap memory heap, uint256 value) internal pure returns (uint256 popped) {
        (, popped) = _set(heap, value, 0, 4);
    }

    /// @dev Pops the minimum value, and pushes the new `value` onto the min-heap.
    /// Reverts if the heap is empty.
    function replace(Heap storage heap, uint256 value) internal returns (uint256 popped) {
        (, popped) = _set(heap, value, 0, 1);
    }

    /// @dev Pops the minimum value, and pushes the new `value` onto the min-heap.
    /// Reverts if the heap is empty.
    function replace(MemHeap memory heap, uint256 value) internal pure returns (uint256 popped) {
        (, popped) = _set(heap, value, 0, 1);
    }

    /// @dev Pushes the `value` onto the min-heap, and pops the minimum value
    /// if the length of the heap exceeds `maxLength`.
    ///
    /// Reverts if `maxLength` is zero.
    ///
    /// - If the queue is not full:
    ///   (`success` = true, `hasPopped` = false, `popped` = 0)
    /// - If the queue is full, and `value` is not greater than the minimum value:
    ///   (`success` = false, `hasPopped` = false, `popped` = 0)
    /// - If the queue is full, and `value` is greater than the minimum value:
    ///   (`success` = true, `hasPopped` = true, `popped` = <minimum value>)
    ///
    /// Useful for implementing a bounded priority queue.
    ///
    /// It is technically possible for the heap size to exceed `maxLength`
    /// if `enqueue` has been previously called with a larger `maxLength`.
    /// In such a case, the heap will be treated exactly as if it is full,
    /// conditionally popping the minimum value if `value` is greater than it.
    ///
    /// Under normal usage, which keeps `maxLength` constant throughout
    /// the lifetime of a heap, this out-of-spec edge case will not be triggered.
    function enqueue(Heap storage heap, uint256 value, uint256 maxLength)
        internal
        returns (bool success, bool hasPopped, uint256 popped)
    {
        uint256 status;
        (status, popped) = _set(heap, value, maxLength, 0);
        hasPopped = status == 3;
        success = status != 0;
    }

    /// @dev Pushes the `value` onto the min-heap, and pops the minimum value
    /// if the length of the heap exceeds `maxLength`.
    ///
    /// Reverts if `maxLength` is zero.
    ///
    /// - If the queue is not full:
    ///   (`success` = true, `hasPopped` = false, `popped` = 0)
    /// - If the queue is full, and `value` is not greater than the minimum value:
    ///   (`success` = false, `hasPopped` = false, `popped` = 0)
    /// - If the queue is full, and `value` is greater than the minimum value:
    ///   (`success` = true, `hasPopped` = true, `popped` = <minimum value>)
    ///
    /// Useful for implementing a bounded priority queue.
    function enqueue(MemHeap memory heap, uint256 value, uint256 maxLength)
        internal
        pure
        returns (bool success, bool hasPopped, uint256 popped)
    {
        uint256 status;
        (status, popped) = _set(heap, value, maxLength, 0);
        hasPopped = status == 3;
        success = status != 0;
    }

    /// @dev Increments the free memory pointer by a word and fills the word with 0.
    /// This is if you want to take extra precaution that the memory word slot before
    /// the `data` array in `MemHeap` doesn't contain a non-zero multiple of prime
    /// to masquerade as a prime-checksummed capacity.
    /// If you are not directly assigning some array to `data`,
    /// you don't have to worry about it.
    /// @custom:solar-trusted
    function bumpFreeMemoryPointer() internal pure {
        uint256 zero;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            mstore(m, zero)
            mstore(0x40, add(m, 0x20))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Helper function for heap operations.
    /// Designed for code conciseness, bytecode compactness, and decent performance.
    function _set(Heap storage heap, uint256 value, uint256 maxLength, uint256 mode)
        private
        returns (uint256 status, uint256 popped)
    {
        uint256 slot = _slot(heap);
        uint256 n = _sload(slot);
        uint256 sOffset = _dataSlot(slot); // Array storage slot offset.
        uint256 pos;
        uint256 childPos;
        // Operations are ordered from most likely usage to least likely usage.
        if (mode == 0) {
            // Mode: `enqueue`.
            if (maxLength == 0) revert HeapIsEmpty();
            // If queue is full.
            if (n >= maxLength) {
                uint256 r = _sload(sOffset);
                if (r >= value) return (0, 0);
                status = 3;
                childPos = 1;
                popped = r;
            } else {
                status = 1;
                pos = n;
                // Increment and update the length.
                _sstore(slot, n + 1);
                childPos = n;
            }
        } else if (mode <= 2) {
            if (n == 0) revert HeapIsEmpty();
            // Mode: `pop`.
            if (mode == 2) {
                // Decrement and update the length.
                --n;
                _sstore(slot, n);
                // Set the `value` to the last item.
                value = _sload(_add(sOffset, n));
                popped = value;
                if (n == 0) return (0, popped);
            }
            // Mode: `replace`.
            popped = _sload(sOffset);
            childPos = 1;
        } else if (mode == 3) {
            // Mode: `push`.
            // Increment and update the length.
            pos = n;
            _sstore(slot, n + 1);
            childPos = n;
        } else {
            // Mode: `pushPop`.
            popped = value;
            if (n == 0) return (0, popped);
            uint256 r = _sload(sOffset);
            if (r >= value) return (0, popped);
            popped = r;
            childPos = 1;
        }
        // Siftup.
        while (childPos < n) {
            uint256 child = _sload(_add(sOffset, childPos));
            uint256 rightPos = childPos + 1;
            if (rightPos < n) {
                uint256 right = _sload(_add(sOffset, rightPos));
                if (right <= child) {
                    child = right;
                    childPos = rightPos;
                }
            }
            _sstore(_add(sOffset, pos), child);
            pos = childPos;
            childPos = (pos << 1) | 1;
        }
        // Siftdown.
        while (pos != 0) {
            uint256 parentPos = (pos - 1) >> 1;
            uint256 parent = _sload(_add(sOffset, parentPos));
            if (value >= parent) break;
            _sstore(_add(sOffset, pos), parent);
            pos = parentPos;
        }
        _sstore(_add(sOffset, pos), value);
    }

    /// @dev Helper function for heap operations.
    /// Designed for code conciseness, bytecode compactness, and decent performance.
    function _set(MemHeap memory heap, uint256 value, uint256 maxLength, uint256 mode)
        private
        pure
        returns (uint256 status, uint256 popped)
    {
        uint256[] memory data = heap.data;
        uint256 n = data.length;
        // Allocation / reallocation.
        uint256 cap = _capacity(data);
        if (n >= cap) {
            uint256 newCap = cap == 0 ? 0x20 : cap << 1;
            while (newCap <= n) newCap += newCap;
            data = _reallocate(heap, newCap);
        }
        uint256 pos;
        // `type(uint256).max` skips the siftup.
        uint256 childPos = type(uint256).max;
        // Operations are ordered from most likely usage to least likely usage.
        if (mode == 0) {
            // Mode: `enqueue`.
            if (maxLength == 0) revert HeapIsEmpty();
            // If the queue is full.
            if (n >= maxLength) {
                popped = data[0];
                if (popped >= value) return (0, 0);
                status = 3;
                childPos = 1;
            } else {
                status = 1;
                pos = n;
                // Increment and update the length.
                _setLength(data, n + 1);
            }
        } else if (mode <= 2) {
            if (n == 0) revert HeapIsEmpty();
            // Mode: `pop`.
            if (mode == 2) {
                // Set the `value` to the last item.
                value = data[n - 1];
                // Decrement and update the length.
                _setLength(data, n - 1);
                if (n == 1) return (0, value);
            }
            // Mode: `replace`.
            popped = data[0];
            childPos = 1;
        } else if (mode == 3) {
            // Mode: `push`.
            pos = n;
            // Increment and update the length.
            _setLength(data, n + 1);
        } else {
            // Mode: `pushPop`.
            if (n == 0 || data[0] >= value) return (0, value);
            popped = data[0];
            childPos = 1;
        }
        _sift(data, pos, childPos, value);
    }

    /// @dev Moves the hole at `pos` down to the smaller child, the right one on a tie,
    /// starting with the left child at `childPos`, which skips this step from the end of
    /// the heap on. Then moves `value` up from where the hole stops, past the larger
    /// parents, and stores it.
    /// @custom:solar-inline always
    function _sift(uint256[] memory data, uint256 pos, uint256 childPos, uint256 value)
        private
        pure
    {
        // Siftup. The hole is the parent of the odd left child, `childPos >> 1`.
        while (childPos < data.length) {
            uint256 parentPos = childPos >> 1;
            uint256 child = data[childPos];
            uint256 rightPos = childPos + 1;
            if (rightPos < data.length) {
                uint256 right = data[rightPos];
                if (right <= child) {
                    child = right;
                    childPos = rightPos;
                }
            }
            data[parentPos] = child;
            pos = childPos;
            childPos = (pos << 1) | 1;
        }
        // The hole is inside the heap.
        assert(pos < data.length);
        // Siftdown.
        while (pos != 0) {
            uint256 parentPos = (pos - 1) >> 1;
            uint256 parent = data[parentPos];
            if (value >= parent) break;
            data[pos] = parent;
            pos = parentPos;
        }
        data[pos] = value;
    }

    /// @dev Removes the root of the priority queue of `smallest`, which holds `e` items
    /// after the removal, and inserts `v` from heap position `i`: the hole moves down
    /// along the smaller children, the left one on a tie, then `v` moves up from where
    /// it stops. The hole is the parent of the odd left child, `c >> 1`.
    /// @custom:solar-inline always
    function _pSiftup(
        uint256[] memory values,
        uint256[] memory indices,
        uint256 e,
        uint256 v,
        uint256 i
    ) private pure {
        uint256 p;
        for (uint256 c = 1; c < e; c = (p << 1) | 1) {
            uint256 h = c >> 1;
            uint256 cv = values[c];
            if (c + 1 < e) {
                uint256 rv = values[c + 1];
                if (cv > rv) {
                    cv = rv;
                    ++c;
                }
            }
            values[h] = cv;
            indices[h] = indices[c];
            p = c;
        }
        _pSiftdown(values, indices, p, v, i);
    }

    /// @dev Places `v` from heap position `i` in the hole at `p` of the priority queue
    /// of `smallest`, moving it up past the larger parents.
    /// @custom:solar-inline always
    function _pSiftdown(
        uint256[] memory values,
        uint256[] memory indices,
        uint256 p,
        uint256 v,
        uint256 i
    ) private pure {
        while (p != 0) {
            uint256 u = (p - 1) >> 1;
            uint256 uv = values[u];
            if (v >= uv) break;
            values[p] = uv;
            indices[p] = indices[u];
            p = u;
        }
        values[p] = v;
        indices[p] = i;
    }

    /// @dev Returns the capacity of `data`. The word before it holds the negated product
    /// of the capacity and `_PRIME`; any other word means no capacity.
    function _capacity(uint256[] memory data) private pure returns (uint256 cap) {
        cap = ~_wordBefore(data);
        cap = cap % _PRIME == 0 ? cap / _PRIME : 0;
    }

    /// @dev Returns the word before `data`.
    /// @custom:solar-trusted
    function _wordBefore(uint256[] memory data) private pure returns (uint256 w) {
        /// @solidity memory-safe-assembly
        assembly {
            w := mload(sub(data, 0x20))
        }
    }

    /// @dev Moves `heap.data` to newly allocated memory with room for `newCap` items,
    /// which must cover its length, behind its capacity word, and returns it.
    /// @custom:solar-trusted
    function _reallocate(MemHeap memory heap, uint256 newCap)
        private
        pure
        returns (uint256[] memory data)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let old := mload(heap)
            let n := mload(old)
            if gt(n, newCap) { invalid() } // For extra safety.
            let prime := 204053801631428327883786711931463459222251954273621
            mstore(mload(0x40), not(mul(newCap, prime))) // Store the capacity.
            data := add(mload(0x40), 0x20)
            mstore(data, n) // Store the length.
            mstore(0x40, add(add(data, 0x20), shl(5, newCap))) // Allocate `heap.data` memory.
            // Copy the items one word at a time, backwards.
            for { let i := shl(5, n) } i { i := add(i, not(0x1f)) } {
                mstore(add(data, i), mload(add(old, i)))
            }
            mstore(heap, data) // Update `heap.data`.
        }
    }

    /// @dev Sets the length of `data`, which its capacity covers, to `n`.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _setLength(uint256[] memory data, uint256 n) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(data, n)
        }
    }

    /// @dev Frees the memory from `a` on, which nothing uses any more.
    /// @custom:solar-trusted
    function _deallocate(uint256[] memory a) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x40, a)
        }
    }

    /// @dev The storage slot of `heap`.
    /// @custom:solar-trusted
    function _slot(Heap storage heap) private pure returns (uint256 slot) {
        /// @solidity memory-safe-assembly
        assembly {
            slot := heap.slot
        }
    }

    /// @dev The storage slot of the first item of the heap at `slot`.
    function _dataSlot(uint256 slot) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(slot)));
    }

    /// @dev Returns the word in storage slot `slot`.
    /// @custom:solar-trusted
    function _sload(uint256 slot) private view returns (uint256 value) {
        /// @solidity memory-safe-assembly
        assembly {
            value := sload(slot)
        }
    }

    /// @dev Stores `value` in storage slot `slot`.
    /// @custom:solar-trusted
    function _sstore(uint256 slot, uint256 value) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, value)
        }
    }

    /// @dev `a + b` modulo `2**256`.
    /// @custom:solar-trusted
    function _add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }
}
