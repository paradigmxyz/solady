// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev A red-black-tree in storage.
struct Tree {
    uint256 _spacer;
}

using RedBlackTreeLib for Tree global;

/// @notice Library for managing a red-black-tree in storage.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/RedBlackTreeLib.sol)
/// @author Modified from BokkyPooBahsRedBlackTreeLibrary (https://github.com/bokkypoobah/BokkyPooBahsRedBlackTreeLibrary)
/// @dev This implementation does not support the zero (i.e. empty) value.
///      This implementation supports up to 2147483647 values.
///
/// The checked port keeps upstream's storage layout and node packing, and reads and writes
/// the same slots and words in the same order. Node slots are offsets of a hashed base that
/// Solidity cannot name, so trusted helpers read and write a slot by number and read the
/// tree's slot number. The Yul functions of `_update` are private functions that take and
/// return the root index, which upstream keeps in scratch memory with the node count, and
/// `_revert` raises the custom error of an error code. `values` fills an array from `new`
/// with bounds-checked writes: if the node count disagrees with the nodes under the root,
/// which only a direct storage write can cause, it reverts or leaves zeros where upstream
/// writes past or short of its array.
/// @custom:solar-safe memory arithmetic
library RedBlackTreeLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The value cannot be zero.
    error ValueIsEmpty();

    /// @dev Cannot insert a value that already exists.
    error ValueAlreadyExists();

    /// @dev Cannot remove a value that does not exist.
    error ValueDoesNotExist();

    /// @dev The pointer is out of bounds.
    error PointerOutOfBounds();

    /// @dev The tree is full.
    error TreeIsFull();

    /// @dev `bytes4(keccak256(bytes("ValueAlreadyExists()")))`.
    uint256 internal constant ERROR_VALUE_ALREADY_EXISTS = 0xbb33e6ac;

    /// @dev `bytes4(keccak256(bytes("ValueDoesNotExist()")))`.
    uint256 internal constant ERROR_VALUE_DOES_NOT_EXISTS = 0xb113638a;

    /// @dev `bytes4(keccak256(bytes("PointerOutOfBounds()")))`.
    uint256 internal constant ERROR_POINTER_OUT_OF_BOUNDS = 0xccd52fbc;

    /// @dev `bytes4(keccak256(bytes("TreeIsFull()")))`.
    uint256 internal constant ERROR_TREE_IS_FULL = 0xed732d0c;

    // Custom storage:
    // ```
    // mstore(0x20, tree.slot)
    // mstore(0x00, _NODES_SLOT_SEED)
    // let nodes := shl(_NODES_SLOT_SHIFT, keccak256(0x00, 0x40))
    //
    // let root := shr(128, sload(nodes))
    // let totalNodes := and(sload(nodes), _BITMASK_KEY)
    //
    // let nodePacked := sload(or(nodes, nodeIndex))
    // let nodeLeft   := and(nodePacked, _BITMASK_KEY)
    // let nodeRight  := and(shr(_BITPOS_RIGHT, nodePacked), _BITMASK_KEY)
    // let nodeParent := and(shr(_BITPOS_PARENT, nodePacked), _BITMASK_KEY)
    // let nodeRed    := and(shr(_BITPOS_RED, nodePacked), 1)
    //
    // let nodeValue := shr(_BITPOS_PACKED_VALUE, nodePacked)
    // if iszero(nodeValue) {
    //     nodeValue := sload(or(_BIT_FULL_VALUE_SLOT, or(nodes, nodeIndex)))
    // }
    // ```
    //
    // Bits Layout of the Root Index Slot:
    // - [0..30]    `totalNodes`
    // - [128..159] `rootNodeIndex`
    //
    // Bits Layout of a Node:
    // - [0..30]   `leftChildIndex`
    // - [31..61]  `rightChildIndex`
    // - [62..92]  `parentIndex`
    // - [93]      `isRed`
    // - [96..255] `nodePackedValue`

    uint256 private constant _NODES_SLOT_SEED = 0x1dc27bb5462fdadcb;
    uint256 private constant _NODES_SLOT_SHIFT = 32;
    uint256 private constant _BITMASK_KEY = (1 << 31) - 1;
    uint256 private constant _BITPOS_LEFT = 0;
    uint256 private constant _BITPOS_RIGHT = 31;
    uint256 private constant _BITPOS_PARENT = 31 * 2;
    uint256 private constant _BITPOS_RED = 31 * 3;
    uint256 private constant _BITMASK_RED = 1 << (31 * 3);
    uint256 private constant _BITPOS_PACKED_VALUE = 96;
    uint256 private constant _BITMASK_PACKED_VALUE = (1 << 160) - 1;
    uint256 private constant _BIT_FULL_VALUE_SLOT = 1 << 31;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OPERATIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the number of unique values in the tree.
    function size(Tree storage tree) internal view returns (uint256 result) {
        uint256 nodes = _nodes(tree);
        result = _sload(nodes) & _BITMASK_KEY;
    }

    /// @dev Returns an array of all the values in the tree in ascending sorted order.
    /// WARNING! This function can exhaust the block gas limit if the tree is big.
    /// It is intended for usage in off-chain view functions.
    function values(Tree storage tree) internal view returns (uint256[] memory result) {
        uint256 nodes = _nodes(tree);
        uint256 rootPacked = _sload(nodes);
        result = new uint256[](rootPacked & _BITMASK_KEY);
        uint256 root = rootPacked >> 128;
        if (root != uint256(0)) _visit(nodes, root, result, 0); // Start from the root node.
    }

    /// @dev Returns a pointer to the value `x`.
    /// If the value `x` is not in the tree, the returned pointer will be empty.
    /// @custom:solar-inline always
    function find(Tree storage tree, uint256 x) internal view returns (bytes32 result) {
        (uint256 nodes,, uint256 key) = _find(tree, x);
        result = _pack(nodes, key);
    }

    /// @dev Returns a pointer to the nearest value to `x`.
    /// In a tie-breaker, the returned pointer will point to the smaller value.
    /// If the tree is empty, the returned pointer will be empty.
    function nearest(Tree storage tree, uint256 x) internal view returns (bytes32 result) {
        (uint256 nodes, uint256 cursor, uint256 key) = _find(tree, x);
        if (cursor == uint256(0)) return result; // Nothing found -- empty tree.
        if (key != uint256(0)) return _pack(nodes, key); // Exact match.
        bytes32 a = _pack(nodes, cursor);
        uint256 aValue = value(a);
        bytes32 b = x < aValue ? prev(a) : next(a);
        if (b == bytes32(0)) return a; // Only node found.
        uint256 bValue = value(b);
        uint256 aDist = x < aValue ? aValue - x : x - aValue;
        uint256 bDist = x < bValue ? bValue - x : x - bValue;
        return (aDist == bDist ? aValue < bValue : aDist < bDist) ? a : b;
    }

    /// @dev Returns a pointer to the nearest value lesser or equal to `x`.
    /// If there is no value lesser or equal to `x`, the returned pointer will be empty.
    function nearestBefore(Tree storage tree, uint256 x) internal view returns (bytes32 result) {
        (uint256 nodes, uint256 cursor, uint256 key) = _find(tree, x);
        if (cursor == uint256(0)) return result; // Nothing found -- empty tree.
        if (key != uint256(0)) return _pack(nodes, key); // Exact match.
        bytes32 a = _pack(nodes, cursor);
        return value(a) < x ? a : prev(a);
    }

    /// @dev Returns a pointer to the nearest value greater or equal to `x`.
    /// If there is no value greater or equal to `x`, the returned pointer will be empty.
    function nearestAfter(Tree storage tree, uint256 x) internal view returns (bytes32 result) {
        (uint256 nodes, uint256 cursor, uint256 key) = _find(tree, x);
        if (cursor == uint256(0)) return result; // Nothing found -- empty tree.
        if (key != uint256(0)) return _pack(nodes, key); // Exact match.
        bytes32 a = _pack(nodes, cursor);
        return value(a) > x ? a : next(a);
    }

    /// @dev Returns whether the value `x` exists.
    function exists(Tree storage tree, uint256 x) internal view returns (bool result) {
        (,, uint256 key) = _find(tree, x);
        result = key != 0;
    }

    /// @dev Inserts the value `x` into the tree.
    /// Reverts if the value `x` already exists.
    function insert(Tree storage tree, uint256 x) internal {
        uint256 err = tryInsert(tree, x);
        if (err != 0) _revert(err);
    }

    /// @dev Inserts the value `x` into the tree.
    /// Returns a non-zero error code upon failure instead of reverting
    /// (except for reverting if `x` is an empty value).
    function tryInsert(Tree storage tree, uint256 x) internal returns (uint256 err) {
        (uint256 nodes, uint256 cursor, uint256 key) = _find(tree, x);
        err = _update(nodes, cursor, key, x, 0);
    }

    /// @dev Removes the value `x` from the tree.
    /// Reverts if the value does not exist.
    function remove(Tree storage tree, uint256 x) internal {
        uint256 err = tryRemove(tree, x);
        if (err != 0) _revert(err);
    }

    /// @dev Removes the value `x` from the tree.
    /// Returns a non-zero error code upon failure instead of reverting
    /// (except for reverting if `x` is an empty value).
    function tryRemove(Tree storage tree, uint256 x) internal returns (uint256 err) {
        (uint256 nodes,, uint256 key) = _find(tree, x);
        err = _update(nodes, 0, key, 0, 1);
    }

    /// @dev Removes the value at pointer `ptr` from the tree.
    /// Reverts if `ptr` is empty (i.e. value does not exist),
    /// or if `ptr` is out of bounds.
    /// After removal, `ptr` may point to another existing value.
    /// For safety, do not reuse `ptr` after calling remove on it.
    function remove(bytes32 ptr) internal {
        uint256 err = tryRemove(ptr);
        if (err != 0) _revert(err);
    }

    /// @dev Removes the value at pointer `ptr` from the tree.
    /// Returns a non-zero error code upon failure instead of reverting.
    function tryRemove(bytes32 ptr) internal returns (uint256 err) {
        (uint256 nodes, uint256 key) = _unpack(ptr);
        err = _update(nodes, 0, key, 0, 1);
    }

    /// @dev Returns the value at pointer `ptr`.
    /// If `ptr` is empty, the result will be zero.
    function value(bytes32 ptr) internal view returns (uint256 result) {
        if (ptr == bytes32(0)) return result;
        uint256 packed = _sload(uint256(ptr));
        result = packed >> _BITPOS_PACKED_VALUE;
        if (result == uint256(0)) result = _sload(uint256(ptr) | _BIT_FULL_VALUE_SLOT);
    }

    /// @dev Returns a pointer to the smallest value in the tree.
    /// If the tree is empty, the returned pointer will be empty.
    function first(Tree storage tree) internal view returns (bytes32 result) {
        result = _end(tree, _BITPOS_LEFT);
    }

    /// @dev Returns a pointer to the largest value in the tree.
    /// If the tree is empty, the returned pointer will be empty.
    function last(Tree storage tree) internal view returns (bytes32 result) {
        result = _end(tree, _BITPOS_RIGHT);
    }

    /// @dev Returns the pointer to the next largest value.
    /// If there is no next value, or if `ptr` is empty,
    /// the returned pointer will be empty.
    function next(bytes32 ptr) internal view returns (bytes32 result) {
        result = _step(ptr, _BITPOS_LEFT, _BITPOS_RIGHT);
    }

    /// @dev Returns the pointer to the next smallest value.
    /// If there is no previous value, or if `ptr` is empty,
    /// the returned pointer will be empty.
    function prev(bytes32 ptr) internal view returns (bytes32 result) {
        result = _step(ptr, _BITPOS_RIGHT, _BITPOS_LEFT);
    }

    /// @dev Returns whether the pointer is empty.
    function isEmpty(bytes32 ptr) internal pure returns (bool result) {
        result = ptr == bytes32(0);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Unpacks the pointer `ptr` to its components.
    function _unpack(bytes32 ptr) private pure returns (uint256 nodes, uint256 key) {
        nodes = (uint256(ptr) >> _NODES_SLOT_SHIFT) << _NODES_SLOT_SHIFT;
        key = _BITMASK_KEY & uint256(ptr);
    }

    /// @dev Packs `nodes` and `key` into a single pointer.
    function _pack(uint256 nodes, uint256 key) private pure returns (bytes32 result) {
        if (key != uint256(0)) result = bytes32(nodes | key);
    }

    /// @dev Returns the pointer to either end of the tree.
    function _end(Tree storage tree, uint256 L) private view returns (bytes32 result) {
        uint256 nodes = _nodes(tree);
        uint256 key = _sload(nodes) >> 128;
        if (key != uint256(0)) {
            while (true) {
                uint256 packed = _sload(nodes | key);
                uint256 left = (packed >> L) & _BITMASK_KEY;
                if (left == uint256(0)) break;
                key = left;
            }
        }
        result = _pack(nodes, key);
    }

    /// @dev Step the pointer `ptr` forwards or backwards.
    /// @custom:solar-inline always
    function _step(bytes32 ptr, uint256 L, uint256 R) private view returns (bytes32 result) {
        if (ptr == bytes32(0)) return ptr;
        (uint256 nodes, uint256 target) = _unpack(ptr);
        uint256 packed = _sload(uint256(ptr));
        uint256 key = (packed >> R) & _BITMASK_KEY;
        if (key == uint256(0)) {
            key = (packed >> _BITPOS_PARENT) & _BITMASK_KEY;
            while (key != uint256(0)) {
                packed = _sload(nodes | key);
                if (target != (packed >> R) & _BITMASK_KEY) break;
                target = key;
                key = (packed >> _BITPOS_PARENT) & _BITMASK_KEY;
            }
        } else {
            while (true) {
                packed = _sload(nodes | key);
                uint256 left = (packed >> L) & _BITMASK_KEY;
                if (left == uint256(0)) break;
                key = left;
            }
        }
        result = _pack(nodes, key);
    }

    /// @dev Inserts or delete the value `x` from the tree.
    function _update(uint256 nodes, uint256 cursor, uint256 key, uint256 x, uint256 mode)
        private
        returns (uint256 err)
    {
        uint256 rootPacked = _sload(nodes);
        uint256 root = rootPacked >> 128;
        uint256 totalNodes = uint128(rootPacked);
        if (mode == uint256(0)) {
            if (key != uint256(0)) {
                err = ERROR_VALUE_ALREADY_EXISTS;
            } else if (totalNodes >= _BITMASK_KEY) {
                err = ERROR_TREE_IS_FULL;
            } else {
                ++totalNodes;
                root = _insert(nodes, cursor, totalNodes, x, root);
            }
        } else {
            if (key > totalNodes) {
                err = ERROR_POINTER_OUT_OF_BOUNDS;
            } else if (key == uint256(0)) {
                err = ERROR_VALUE_DOES_NOT_EXISTS;
            } else {
                root = _remove(nodes, key, root, totalNodes);
                --totalNodes;
            }
        }
        _sstore(nodes, (root << 128) | totalNodes);
    }

    /// @dev Returns the pointer to the `nodes` for the tree.
    function _nodes(Tree storage tree) private pure returns (uint256 nodes) {
        nodes = uint256(keccak256(abi.encode(_NODES_SLOT_SEED, _slot(tree)))) << _NODES_SLOT_SHIFT;
    }

    /// @dev Finds `x` in `tree`. The `key` will be zero if `x` is not found.
    /// @custom:solar-inline always
    function _find(Tree storage tree, uint256 x)
        private
        view
        returns (uint256 nodes, uint256 cursor, uint256 key)
    {
        if (x == uint256(0)) revert ValueIsEmpty();
        nodes = _nodes(tree);
        for (uint256 probe = _sload(nodes) >> 128; probe != uint256(0);) {
            cursor = probe;
            uint256 nodePacked = _sload(nodes | probe);
            uint256 nodeValue = nodePacked >> _BITPOS_PACKED_VALUE;
            if (nodeValue == uint256(0)) {
                nodeValue = _sload(nodes | probe | _BIT_FULL_VALUE_SLOT);
            }
            if (nodeValue == x) {
                key = cursor;
                break;
            }
            probe = (x > nodeValue ? nodePacked >> _BITPOS_RIGHT : nodePacked) & _BITMASK_KEY;
        }
    }

    /// @dev Helper to revert `err` efficiently.
    /// `err` is one of the four error codes that `_update` returns.
    function _revert(uint256 err) private pure {
        if (err == ERROR_VALUE_ALREADY_EXISTS) revert ValueAlreadyExists();
        if (err == ERROR_VALUE_DOES_NOT_EXISTS) revert ValueDoesNotExist();
        if (err == ERROR_POINTER_OUT_OF_BOUNDS) revert PointerOutOfBounds();
        revert TreeIsFull();
    }

    /// @dev Appends the values of the subtree at the non-null node `current` to `result` in
    /// ascending order, from index `i`. Returns the index after the last value appended.
    function _visit(uint256 nodes, uint256 current, uint256[] memory result, uint256 i)
        private
        view
        returns (uint256)
    {
        do {
            current = nodes | current; // Current node's storage slot.
            uint256 packed = _sload(current);
            uint256 left = packed & _BITMASK_KEY;
            if (left != uint256(0)) i = _visit(nodes, left, result, i); // Visit left child.
            uint256 v = packed >> _BITPOS_PACKED_VALUE; // Current value.
            if (v == uint256(0)) v = _sload(current | _BIT_FULL_VALUE_SLOT);
            result[i] = v; // Append the value to `result`.
            ++i;
            current = (packed >> _BITPOS_RIGHT) & _BITMASK_KEY; // Visit right child.
        } while (current != uint256(0));
        return i;
    }

    /// @dev Returns the index at bit position `bitpos` of `packed`.
    /// @custom:solar-inline always
    function _getKey(uint256 packed, uint256 bitpos) private pure returns (uint256) {
        return _BITMASK_KEY & (packed >> bitpos);
    }

    /// @dev Returns `packed` with the index at bit position `bitpos` set to `key`.
    /// @custom:solar-inline always
    function _setKey(uint256 packed, uint256 bitpos, uint256 key) private pure returns (uint256) {
        return (~(_BITMASK_KEY << bitpos) & packed) | (key << bitpos);
    }

    /// @dev Sets the parent index of the node in slot `s` to `parent`.
    /// @custom:solar-inline always
    function _setParent(uint256 s, uint256 parent) private {
        _sstore(s, _setKey(_sload(s), _BITPOS_PARENT, parent));
    }

    /// @dev Points the `L` child link of the node in slot `s` to `cursor` if it holds `key`,
    /// and its `R` child link otherwise.
    /// @custom:solar-inline always
    function _relink(uint256 s, uint256 key, uint256 cursor, uint256 L, uint256 R) private {
        uint256 packed = _sload(s);
        _sstore(s, _setKey(packed, key == _getKey(packed, L) ? L : R, cursor));
    }

    /// @dev Rotates the subtree at node `key` towards `L`, where `R` is the other side.
    /// Returns the new root index.
    /// @custom:solar-inline always
    function _rotate(uint256 nodes, uint256 key, uint256 L, uint256 R, uint256 root)
        private
        returns (uint256)
    {
        uint256 packed = _sload(nodes | key);
        uint256 cursor = _getKey(packed, R);
        uint256 parent = _getKey(packed, _BITPOS_PARENT);
        uint256 cursorPacked = _sload(nodes | cursor);
        uint256 cursorLeft = _getKey(cursorPacked, L);

        if (cursorLeft != uint256(0)) _setParent(nodes | cursorLeft, key);

        if (parent == uint256(0)) {
            root = cursor;
        } else {
            _relink(nodes | parent, key, cursor, L, R);
        }
        packed = _setKey(packed, R, cursorLeft);
        _sstore(nodes | key, _setKey(packed, _BITPOS_PARENT, cursor));
        cursorPacked = _setKey(cursorPacked, _BITPOS_PARENT, parent);
        _sstore(nodes | cursor, _setKey(cursorPacked, L, key));
        return root;
    }

    /// @dev Inserts `x` as the new node `key` under node `cursor`.
    /// Returns the new root index.
    function _insert(uint256 nodes, uint256 cursor, uint256 key, uint256 x, uint256 root)
        private
        returns (uint256)
    {
        uint256 packed = _BITMASK_RED | (cursor << _BITPOS_PARENT);
        uint256 nodePointer = nodes | key;

        if (x <= _BITMASK_PACKED_VALUE) {
            packed = (x << _BITPOS_PACKED_VALUE) | packed;
        } else {
            _sstore(nodePointer | _BIT_FULL_VALUE_SLOT, x);
        }
        _sstore(nodePointer, packed);

        if (cursor == uint256(0)) {
            root = key;
        } else {
            uint256 s = nodes | cursor;
            uint256 cPacked = _sload(s);
            uint256 cValue = cPacked >> _BITPOS_PACKED_VALUE;
            if (cValue == uint256(0)) cValue = _sload(s | _BIT_FULL_VALUE_SLOT);
            _sstore(s, _setKey(cPacked, x < cValue ? _BITPOS_LEFT : _BITPOS_RIGHT, key));
        }

        // Insert fixup workflow:

        return _insertFixup(nodes, key, root);
    }

    /// @dev Restores the red-black properties after an insertion, from node `key` up.
    /// Returns the new root index.
    function _insertFixup(uint256 nodes, uint256 key, uint256 root) private returns (uint256) {
        while (key != root) {
            uint256 parent = _getKey(_sload(nodes | key), _BITPOS_PARENT);
            uint256 parentPacked = _sload(nodes | parent);
            if (_BITMASK_RED & parentPacked == uint256(0)) break;

            uint256 grandParent = _getKey(parentPacked, _BITPOS_PARENT);
            uint256 grandParentPacked = _sload(nodes | grandParent);

            uint256 R = parent == _getKey(grandParentPacked, 0) ? _BITPOS_RIGHT : 0;

            uint256 c = _getKey(grandParentPacked, R);
            uint256 cPacked = _sload(nodes | c);
            if (_BITMASK_RED & cPacked == uint256(0)) {
                if (key == _getKey(parentPacked, R)) {
                    key = parent;
                    root = _rotate(nodes, key, R ^ _BITPOS_RIGHT, R, root);
                    parent = _getKey(_sload(nodes | key), _BITPOS_PARENT);
                    parentPacked = _sload(nodes | parent);
                }
                _sstore(nodes | parent, parentPacked & ~_BITMASK_RED);
                {
                    uint256 s = nodes | grandParent;
                    _sstore(s, _sload(s) | _BITMASK_RED);
                }
                root = _rotate(nodes, grandParent, R, R ^ _BITPOS_RIGHT, root);
                break;
            }
            _sstore(nodes | parent, parentPacked & ~_BITMASK_RED);
            _sstore(nodes | c, cPacked & ~_BITMASK_RED);
            _sstore(nodes | grandParent, grandParentPacked | _BITMASK_RED);
            key = grandParent;
        }
        uint256 rootSlot = nodes | root;
        _sstore(rootSlot, _sload(rootSlot) & ~_BITMASK_RED);
        return root;
    }

    /// @dev Restores the red-black properties after a removal, from node `key` up.
    /// Returns the new root index.
    function _removeFixup(uint256 nodes, uint256 key, uint256 root) private returns (uint256) {
        while (key != root) {
            uint256 parent;
            {
                uint256 packed = _sload(nodes | key);
                if (_BITMASK_RED & packed != uint256(0)) break;
                parent = _getKey(packed, _BITPOS_PARENT);
            }
            uint256 R;
            uint256 cursor;
            uint256 cursorPacked;
            {
                uint256 parentPacked = _sload(nodes | parent);

                R = key == _getKey(parentPacked, 0) ? _BITPOS_RIGHT : 0;

                cursor = _getKey(parentPacked, R);
                cursorPacked = _sload(nodes | cursor);

                if (_BITMASK_RED & cursorPacked != uint256(0)) {
                    _sstore(nodes | cursor, cursorPacked & ~_BITMASK_RED);
                    _sstore(nodes | parent, parentPacked | _BITMASK_RED);
                    root = _rotate(nodes, parent, R ^ _BITPOS_RIGHT, R, root);
                    cursor = _getKey(_sload(nodes | parent), R);
                    cursorPacked = _sload(nodes | cursor);
                }
            }

            uint256 cursorLeft = _getKey(cursorPacked, R ^ _BITPOS_RIGHT);
            uint256 cursorLeftPacked = _sload(nodes | cursorLeft);
            uint256 cursorRight = _getKey(cursorPacked, R);
            uint256 cursorRightPacked = _sload(nodes | cursorRight);

            if (_BITMASK_RED & (cursorLeftPacked | cursorRightPacked) == uint256(0)) {
                _sstore(nodes | cursor, cursorPacked | _BITMASK_RED);
                key = parent;
                continue;
            }

            if (_BITMASK_RED & cursorRightPacked == uint256(0)) {
                _sstore(nodes | cursorLeft, cursorLeftPacked & ~_BITMASK_RED);
                _sstore(nodes | cursor, cursorPacked | _BITMASK_RED);
                root = _rotate(nodes, cursor, R, R ^ _BITPOS_RIGHT, root);
                cursor = _getKey(_sload(nodes | parent), R);
                cursorPacked = _sload(nodes | cursor);
                cursorRight = _getKey(cursorPacked, R);
                cursorRightPacked = _sload(nodes | cursorRight);
            }

            {
                uint256 parentPacked = _sload(nodes | parent);
                _sstore(
                    nodes | cursor, cursorPacked ^ (_BITMASK_RED & (cursorPacked ^ parentPacked))
                );
                _sstore(nodes | parent, parentPacked & ~_BITMASK_RED);
            }
            _sstore(nodes | cursorRight, cursorRightPacked & ~_BITMASK_RED);
            root = _rotate(nodes, parent, R ^ _BITPOS_RIGHT, R, root);
            break;
        }
        uint256 s = nodes | key;
        _sstore(s, _sload(s) & ~_BITMASK_RED);
        return root;
    }

    /// @dev Points the child link of node `parent` that holds `b` to `a`, or makes `a` the
    /// root if `parent` is null. Returns the new root index.
    /// @custom:solar-inline always
    function _replaceParent(uint256 nodes, uint256 parent, uint256 a, uint256 b, uint256 root)
        private
        returns (uint256)
    {
        if (parent == uint256(0)) return a;
        uint256 s = nodes | parent;
        uint256 p = _sload(s);
        uint256 t = b != _getKey(p, _BITPOS_LEFT) ? _BITPOS_RIGHT : 0;
        _sstore(s, _setKey(p, t, a));
        return root;
    }

    /// @dev Removes node `key` of the `totalNodes` nodes. Returns the new root index.
    /// In `_remove`, the parent of the null value (index 0) may be temporarily set
    /// to a non-zero value. This is an optimization that unifies the removal cases.
    function _remove(uint256 nodes, uint256 key, uint256 root, uint256 totalNodes)
        private
        returns (uint256)
    {
        uint256 cursor = key;
        {
            uint256 packed = _sload(nodes | key);
            uint256 left = _getKey(packed, _BITPOS_LEFT);
            uint256 right = _getKey(packed, _BITPOS_RIGHT);
            if (left != uint256(0) && right != uint256(0)) {
                for (cursor = right;;) {
                    uint256 cursorLeft = _getKey(_sload(nodes | cursor), _BITPOS_LEFT);
                    if (cursorLeft == uint256(0)) break;
                    cursor = cursorLeft;
                }
            }
        }

        uint256 cursorPacked = _sload(nodes | cursor);
        uint256 probe = _getKey(cursorPacked, _BITPOS_LEFT);
        probe = _getKey(cursorPacked, probe == uint256(0) ? _BITPOS_RIGHT : 0);

        {
            uint256 yParent = _getKey(cursorPacked, _BITPOS_PARENT);
            _setParent(nodes | probe, yParent);
            root = _replaceParent(nodes, yParent, probe, cursor, root);
        }

        if (cursor != key) {
            uint256 packed = _sload(nodes | key);
            root = _replaceParent(nodes, _getKey(packed, _BITPOS_PARENT), cursor, key, root);

            _setParent(nodes | _getKey(packed, _BITPOS_LEFT), cursor);
            _setParent(nodes | _getKey(packed, _BITPOS_RIGHT), cursor);

            // Copy `left`, `right`, `red` from `key` to `cursor`.
            _sstore(
                nodes | cursor,
                cursorPacked ^ ((packed ^ cursorPacked) & ((1 << _BITPOS_PACKED_VALUE) - 1))
            );

            cursor = key; // The removed node's slot, now unlinked.
        }

        if (_BITMASK_RED & cursorPacked == uint256(0)) root = _removeFixup(nodes, probe, root);

        // Remove last workflow:

        return _removeLast(nodes, cursor, totalNodes, root);
    }

    /// @dev Moves the last node, at index `lastKey`, into the unlinked slot of node `cursor`.
    /// Returns the new root index.
    function _removeLast(uint256 nodes, uint256 cursor, uint256 lastKey, uint256 root)
        private
        returns (uint256)
    {
        uint256 lastPacked = _sload(nodes | lastKey);
        uint256 lastValue = lastPacked >> _BITPOS_PACKED_VALUE;
        uint256 lastFullValue = 0;
        if (lastValue == uint256(0)) {
            lastValue = _sload(_BIT_FULL_VALUE_SLOT | nodes | lastKey);
            lastFullValue = lastValue;
        }

        uint256 cursorValue = _sload(nodes | cursor) >> _BITPOS_PACKED_VALUE;
        uint256 cursorFullValue = 0;
        if (cursorValue == uint256(0)) {
            cursorValue = _sload(_BIT_FULL_VALUE_SLOT | nodes | cursor);
            cursorFullValue = cursorValue;
        }

        if (lastValue != cursorValue) {
            _sstore(nodes | cursor, lastPacked);
            if (lastFullValue != cursorFullValue) {
                _sstore(_BIT_FULL_VALUE_SLOT | nodes | cursor, lastFullValue);
            }
            uint256 lastParent = _getKey(lastPacked, _BITPOS_PARENT);
            root = _replaceParent(nodes, lastParent, cursor, lastKey, root);
            uint256 lastRight = _getKey(lastPacked, _BITPOS_RIGHT);
            if (lastRight != uint256(0)) _setParent(nodes | lastRight, cursor);
            uint256 lastLeft = _getKey(lastPacked, _BITPOS_LEFT);
            if (lastLeft != uint256(0)) _setParent(nodes | lastLeft, cursor);
        }
        _sstore(nodes | lastKey, 0);
        if (lastFullValue != uint256(0)) _sstore(_BIT_FULL_VALUE_SLOT | nodes | lastKey, 0);
        return root;
    }

    /// @dev The storage slot of `tree`.
    /// Solidity does not expose a storage pointer's slot number.
    /// @custom:solar-trusted
    function _slot(Tree storage tree) private pure returns (uint256 s) {
        /// @solidity memory-safe-assembly
        assembly {
            s := tree.slot
        }
    }

    /// @dev Returns the word in storage slot `s`.
    /// Solidity cannot name a slot it did not allocate.
    /// @custom:solar-trusted
    function _sload(uint256 s) private view returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := sload(s)
        }
    }

    /// @dev Stores `w` in storage slot `s`.
    /// Solidity cannot name a slot it did not allocate.
    /// @custom:solar-trusted
    function _sstore(uint256 s, uint256 w) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(s, w)
        }
    }
}
