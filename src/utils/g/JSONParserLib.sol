// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev A pointer to a parsed JSON node.
struct Item {
    // Do NOT modify these fields directly.
    uint256 _data;
    Tree[] _tree;
    string _key;
    string _value;
    Item[] _children;
}

/// @dev Shared node table. A singleton array makes a default item's reference empty.
struct Tree {
    bytes _source;
    Item[] _items;
    uint256 _length;
}

using JSONParserLib for Item global;
using JSONParserLib for Tree global;

/// @notice Library for parsing JSONs.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/JSONParserLib.sol)
/// @dev The assembly-free port keeps typed references to the source, nodes, and lazy caches.
/// The iterative parser packs source offsets and node indices rather than memory addresses.
/// Growing the node table preserves node identity. Reading children links them to their parent,
/// and repeated reads share the same cached array and strings. The opaque `Item` layout changes.
/// Strings and numeric values retain the checked parser's grammar and overflow checks.
/// @custom:solar-safe memory arithmetic
library JSONParserLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The input is invalid.
    error ParsingFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // There are 6 types of variables in JSON (excluding undefined).

    /// @dev For denoting that an item has not been initialized.
    /// A item returned from `parse` will never be of an undefined type.
    /// Parsing an invalid JSON string will simply revert.
    uint8 internal constant TYPE_UNDEFINED = 0;

    /// @dev Type representing an array (e.g. `[1,2,3]`).
    uint8 internal constant TYPE_ARRAY = 1;

    /// @dev Type representing an object (e.g. `{"a":"A","b":"B"}`).
    uint8 internal constant TYPE_OBJECT = 2;

    /// @dev Type representing a number (e.g. `-1.23e+21`).
    uint8 internal constant TYPE_NUMBER = 3;

    /// @dev Type representing a string (e.g. `"hello"`).
    uint8 internal constant TYPE_STRING = 4;

    /// @dev Type representing a boolean (i.e. `true` or `false`).
    uint8 internal constant TYPE_BOOLEAN = 5;

    /// @dev Type representing null (i.e. `null`).
    uint8 internal constant TYPE_NULL = 6;

    // Private constants for packing `_data`.

    uint256 private constant _BITPOS_ID = 32 * 7 - 8;
    uint256 private constant _BITPOS_KEY_LENGTH = 32 * 6 - 8;
    uint256 private constant _BITPOS_KEY = 32 * 5 - 8;
    uint256 private constant _BITPOS_VALUE_LENGTH = 32 * 4 - 8;
    uint256 private constant _BITPOS_VALUE = 32 * 3 - 8;
    uint256 private constant _BITPOS_CHILD = 32 * 2 - 8;
    uint256 private constant _BITPOS_SIBLING_OR_PARENT = 32 * 1 - 8;
    uint256 private constant _BITMASK_POINTER = 0xffffffff;
    uint256 private constant _BITMASK_TYPE = 7;
    uint256 private constant _KEY_INITED = 1 << 3;
    uint256 private constant _VALUE_INITED = 1 << 4;
    uint256 private constant _CHILDREN_INITED = 1 << 5;
    uint256 private constant _PARENT_IS_ARRAY = 1 << 6;
    uint256 private constant _PARENT_IS_OBJECT = 1 << 7;

    /// @dev An item's parent flags, and its index or key.
    uint256 private constant _META = (_BITMASK_POINTER << _BITPOS_KEY_LENGTH)
        | (_BITMASK_POINTER << _BITPOS_KEY) | _PARENT_IS_ARRAY | _PARENT_IS_OBJECT;

    // Character classes, one bit per byte value.

    /// @dev ' ', '\t', '\n' and '\r'.
    uint256 private constant _WHITESPACE = 0x100002600;

    /// @dev '0' to '9'.
    uint256 private constant _DIGITS = 0x3ff000000000000;

    /// @dev '-' and '0' to '9', which start a number.
    uint256 private constant _NUMBER_STARTS = 0x3ff200000000000;

    /// @dev '0' to '9', 'a' to 'f' and 'A' to 'F'.
    uint256 private constant _HEX_DIGITS = 0x7e0000007e03ff000000000000;

    /// @dev The characters after a backslash that stand for themselves or for a
    /// control character: '"', '/', '\\', 'b', 'f', 'n', 'r' and 't'.
    uint256 private constant _ESCAPES = 0x144044100000000000800400000000;

    /// @dev The top bit of every byte, and the other bits.
    uint256 private constant _HIGH_BITS =
        0x8080808080808080808080808080808080808080808080808080808080808080;
    uint256 private constant _LOW_BITS =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    /// @dev 32 '0's.
    uint256 private constant _ZEROS =
        0x3030303030303030303030303030303030303030303030303030303030303030;

    /// @dev '"' and '\\'.
    uint256 private constant _QUOTE_OR_BACKSLASH = 0x100000000000000400000000;

    /// @dev The characters after a backslash that stand for themselves: '"', '/' and '\\'.
    uint256 private constant _SELF_ESCAPES = 0x100000000000800400000000;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   JSON PARSING OPERATION                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Parses the JSON string `s`, and returns the root.
    /// Reverts if `s` is not a valid JSON as specified in RFC 8259.
    /// Object items WILL simply contain all their children, inclusive of repeated keys,
    /// in the same order which they appear in the JSON string.
    ///
    /// Note: For efficiency, this function WILL NOT make a copy of `s`.
    /// The parsed tree WILL contain offsets to `s`.
    /// Do NOT pass in a string that WILL be modified later on.
    function parse(string memory s) internal pure returns (Item memory result) {
        bytes memory b = bytes(s);
        // Offsets and node indices fit in their packed 32-bit fields.
        _pointer(b.length);
        Tree[] memory tree = new Tree[](1);
        tree[0]._source = b;
        // The innermost open array or object, or zero.
        uint256 cur;
        // The previous sibling of the next item, or zero.
        uint256 last;
        // The next item's parent flag, which tells what `cur` is, and its index or key.
        uint256 meta;
        // The next item's position, and its first byte.
        (uint256 p, uint256 c) = _skipWhitespace(b, 0);
        while (true) {
            if (p >= b.length) _fail();
            uint256 data = meta | (last << _BITPOS_SIBLING_OR_PARENT) | (p << _BITPOS_VALUE);
            if (c == 91 || c == 123) {
                // '[' or '{'. Until it closes, its value length holds its parent's index.
                bool opensArray = c == 91;
                cur = _newItem(
                    tree,
                    data | (cur << _BITPOS_VALUE_LENGTH) | (opensArray ? TYPE_ARRAY : TYPE_OBJECT)
                );
                last = 0;
                meta = opensArray ? _PARENT_IS_ARRAY : _PARENT_IS_OBJECT;
                uint256 closing = c + 2;
                (p, c) = _skipWhitespace(b, p + 1);
                // ']' or '}' closes it at once, below.
                if (c != closing) {
                    if (!opensArray) (p, c, meta) = _parseKey(b, p);
                    continue;
                }
            } else {
                uint256 end;
                uint256 t = TYPE_NUMBER;
                if (c == 34) {
                    end = _parseString(b, p);
                    t = TYPE_STRING;
                } else if ((_NUMBER_STARTS >> c) & 1 != 0) {
                    (end, c) = _parseNumber(b, p, c);
                } else {
                    (end, t) = _parseLiteral(b, p);
                }
                last = _newItem(tree, data | ((end - p) << _BITPOS_VALUE_LENGTH) | t);
                // Only a number has read the byte at its end.
                if (t != TYPE_NUMBER || (_WHITESPACE >> c) & 1 != 0) {
                    (p, c) = _skipWhitespace(b, end);
                } else {
                    p = end;
                }
            }
            // Close arrays and objects until a comma starts the next item.
            while (true) {
                if (cur == 0) {
                    if (p < b.length) _fail();
                    return _item(tree, last);
                }
                bool inArray = meta & _PARENT_IS_ARRAY != 0;
                if (c == 44) {
                    // ','.
                    (p, c) = _skipWhitespace(b, p + 1);
                    if (inArray) meta += 1 << _BITPOS_KEY;
                    else (p, c, meta) = _parseKey(b, p);
                    break;
                }
                if (c != (inArray ? 93 : 125)) _fail();
                // The value length replaces the parent, and the last child is `last`.
                Item memory container = _item(tree, cur);
                uint256 d = container._data;
                uint256 parentIndex = (d >> _BITPOS_VALUE_LENGTH) & _BITMASK_POINTER;
                uint256 length = ++p - ((d >> _BITPOS_VALUE) & _BITMASK_POINTER);
                container._data = (d ^ (parentIndex << _BITPOS_VALUE_LENGTH))
                    | (length << _BITPOS_VALUE_LENGTH) | (last << _BITPOS_CHILD);
                // The parent's next item comes after `cur`, whose own parent flag, and
                // index or key, it continues from.
                meta = d & _META;
                last = cur;
                cur = parentIndex;
                (p, c) = _skipWhitespace(b, p);
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    JSON ITEM OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note:
    // - An item is a node in the JSON tree.
    // - The value of a string item WILL be double-quoted, JSON encoded.
    // - We make a distinction between `index` and `key`.
    //   - Items in arrays are located by `index` (uint256).
    //   - Items in objects are located by `key` (string).
    // - Keys are always strings, double-quoted, JSON encoded.
    //
    // These design choices are made to balance between efficiency and ease-of-use.

    /// @dev Returns the string value of the item.
    /// This is its exact string representation in the original JSON string.
    /// The returned string WILL have leading and trailing whitespace trimmed.
    /// All inner whitespace WILL be preserved, exactly as it is in the original JSON string.
    /// If the item's type is string, the returned string WILL be double-quoted, JSON encoded.
    ///
    /// Note: This function lazily instantiates and caches the returned string.
    /// Do NOT modify the returned string.
    function value(Item memory item) internal pure returns (string memory result) {
        result = _getStr(item, _BITPOS_VALUE, _BITPOS_VALUE_LENGTH, _VALUE_INITED);
    }

    /// @dev Returns the index of the item in the array.
    /// It the item's parent is not an array, returns 0.
    function index(Item memory item) internal pure returns (uint256 result) {
        uint256 d = item._data;
        if (d & _PARENT_IS_ARRAY != 0) result = (d >> _BITPOS_KEY) & _BITMASK_POINTER;
    }

    /// @dev Returns the key of the item in the object.
    /// It the item's parent is not an object, returns an empty string.
    /// The returned string WILL be double-quoted, JSON encoded.
    ///
    /// Note: This function lazily instantiates and caches the returned string.
    /// Do NOT modify the returned string.
    function key(Item memory item) internal pure returns (string memory result) {
        if (item._data & _PARENT_IS_OBJECT != 0) {
            result = _getStr(item, _BITPOS_KEY, _BITPOS_KEY_LENGTH, _KEY_INITED);
        }
    }

    /// @dev Returns the key of the item in the object.
    /// It the item is neither an array nor object, returns an empty array.
    ///
    /// Note: This function lazily instantiates and caches the returned array.
    /// Do NOT modify the returned array.
    function children(Item memory item) internal pure returns (Item[] memory result) {
        uint256 d = item._data;
        uint256 t = d & _BITMASK_TYPE;
        if (t != TYPE_ARRAY && t != TYPE_OBJECT) return result;
        if (d & _CHILDREN_INITED != 0) return item._children;
        uint256 h = (d >> _BITPOS_CHILD) & _BITMASK_POINTER;
        Tree[] memory tree = item._tree;
        // The children are linked from the last, each to its previous sibling.
        uint256 m;
        for (uint256 q = h; q != 0; ++m) {
            q = (_item(tree, q)._data >> _BITPOS_SIBLING_OR_PARENT) & _BITMASK_POINTER;
        }
        result = new Item[](m);
        uint256 self = (d >> _BITPOS_ID) & _BITMASK_POINTER;
        while (m != 0) {
            Item memory child = _item(tree, h);
            result[--m] = child;
            uint256 q = child._data;
            h = (q >> _BITPOS_SIBLING_OR_PARENT) & _BITMASK_POINTER;
            // The previous sibling's place now holds the parent.
            child._data = q ^ ((h ^ self) << _BITPOS_SIBLING_OR_PARENT);
        }
        item._children = result;
        item._data = d | _CHILDREN_INITED;
    }

    /// @dev Returns the number of children.
    /// It the item is neither an array nor object, returns zero.
    function size(Item memory item) internal pure returns (uint256 result) {
        result = children(item).length;
    }

    /// @dev Returns the item at index `i` for (array).
    /// If `item` is not an array, the result's type WILL be undefined.
    /// If there is no item with the index, the result's type WILL be undefined.
    function at(Item memory item, uint256 i) internal pure returns (Item memory result) {
        if (item._data & _BITMASK_TYPE == TYPE_ARRAY) {
            Item[] memory r = children(item);
            if (i < r.length) result = r[i];
        }
    }

    /// @dev Returns the item at key `k` for (object).
    /// If `item` is not an object, the result's type WILL be undefined.
    /// The key MUST be double-quoted, JSON encoded. This is for efficiency reasons.
    /// - Correct : `item.at('"k"')`.
    /// - Wrong   : `item.at("k")`.
    /// For duplicated keys, the last item with the key WILL be returned.
    /// If there is no item with the key, the result's type WILL be undefined.
    function at(Item memory item, string memory k) internal pure returns (Item memory result) {
        if (isObject(item)) {
            uint256 n = bytes(k).length;
            bytes32 kHash = keccak256(bytes(k));
            Item[] memory r = children(item);
            // We'll just do a linear search. The alternatives are very bloated.
            for (uint256 i = r.length; i != 0;) {
                Item memory c = r[--i];
                // Only a key of the same length can match.
                if ((c._data >> _BITPOS_KEY_LENGTH) & _BITMASK_POINTER != n) continue;
                if (keccak256(bytes(key(c))) == kHash) return c;
            }
        }
    }

    /// @dev Returns the item's type.
    function getType(Item memory item) internal pure returns (uint8 result) {
        result = uint8(item._data & _BITMASK_TYPE);
    }

    /// Note: All types are mutually exclusive.

    /// @dev Returns whether the item is of type undefined.
    function isUndefined(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_UNDEFINED;
    }

    /// @dev Returns whether the item is of type array.
    function isArray(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_ARRAY;
    }

    /// @dev Returns whether the item is of type object.
    function isObject(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_OBJECT;
    }

    /// @dev Returns whether the item is of type number.
    function isNumber(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_NUMBER;
    }

    /// @dev Returns whether the item is of type string.
    function isString(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_STRING;
    }

    /// @dev Returns whether the item is of type boolean.
    function isBoolean(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_BOOLEAN;
    }

    /// @dev Returns whether the item is of type null.
    function isNull(Item memory item) internal pure returns (bool result) {
        result = item._data & _BITMASK_TYPE == TYPE_NULL;
    }

    /// @dev Returns the item's parent.
    /// If the item does not have a parent, the result's type will be undefined.
    function parent(Item memory item) internal pure returns (Item memory result) {
        uint256 p = (item._data >> _BITPOS_SIBLING_OR_PARENT) & _BITMASK_POINTER;
        if (p != 0) result = _item(item._tree, p);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     UTILITY FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Parses an unsigned integer from a string (in decimal, i.e. base 10).
    /// Reverts if `s` is not a valid uint256 string matching the RegEx `^[0-9]+$`,
    /// or if the parsed number is too big for a uint256.
    function parseUint(string memory s) internal pure returns (uint256 result) {
        result = _parseDigits(bytes(s), 0);
    }

    /// @dev Parses a signed integer from a string (in decimal, i.e. base 10).
    /// Reverts if `s` is not a valid int256 string matching the RegEx `^[+-]?[0-9]+$`,
    /// or if the parsed number cannot fit within `[-2**255 .. 2**255 - 1]`.
    function parseInt(string memory s) internal pure returns (int256 result) {
        bytes memory b = bytes(s);
        bool isNegative;
        uint256 start;
        if (b.length != 0) {
            uint256 c = uint8(b[0]);
            isNegative = c == 45;
            if (isNegative || c == 43) start = 1;
        }
        uint256 x = _parseDigits(b, start);
        if (isNegative) {
            if (x > 1 << 255) _fail();
            result = x == 1 << 255 ? type(int256).min : -int256(x);
        } else {
            if (x >= 1 << 255) _fail();
            result = int256(x);
        }
    }

    /// @dev Parses an unsigned integer from a string (in hexadecimal, i.e. base 16).
    /// Reverts if `s` is not a valid uint256 hex string matching the RegEx
    /// `^(0[xX])?[0-9a-fA-F]+$`, or if the parsed number cannot fit within `[0 .. 2**256 - 1]`.
    function parseUintFromHex(string memory s) internal pure returns (uint256 result) {
        bytes memory b = bytes(s);
        uint256 n = b.length;
        uint256 i;
        // Skip two if starts with '0x' or '0X'.
        if (n > 1 && uint8(b[0]) == 48 && uint8(b[1]) | 32 == 120) i = 2;
        if (i >= n) _fail();
        if (n < 32) {
            // Too short for a word: a digit at a time. A nibble may not leave the word.
            do {
                uint256 c = uint8(b[i]);
                if ((((_HEX_DIGITS >> c) & 1) ^ 1) | (result >> 252) != 0) _fail();
                result = (result << 4) | ((c & 15) + 9 * (c >> 6));
            } while (++i < n);
            return result;
        }
        // 32 digits a word, the last word ending with the string.
        while (true) {
            (uint256 w, uint256 k) = _digitsWord(b, i);
            if (_hexDigits(w) != _HIGH_BITS || result >> (256 - (k << 2)) != 0) _fail();
            result = (result << (k << 2)) | _hexValue(w);
            i += k;
            if (i == n) return result;
        }
    }

    /// @dev Decodes a JSON encoded string.
    /// The string MUST be double-quoted, JSON encoded.
    /// Reverts if the string is invalid.
    /// As you can see, it's pretty complex for a deceptively simple looking task.
    function decodeString(string memory s) internal pure returns (string memory result) {
        bytes memory b = bytes(s);
        uint256 n = b.length;
        // Fail if not double-quoted.
        if (n < 2 || uint8(b[0]) != 34 || uint8(b[n - 1]) != 34) _fail();
        uint256 end = n - 1;
        // Runs of plain bytes are read a word at a time: from a zero-padded copy of a string
        // shorter than a word, and through the last word of a longer one, shifted to start at
        // the run.
        if (n < 32) {
            bytes memory padded = new bytes(32);
            _copyFresh(padded, b, 0, n);
            (b, n) = (padded, 32);
        }
        // Every escape decodes to fewer bytes than it takes, and whole words are written, which
        // needs a word of room past the end.
        bytes memory out = new bytes(end + 31);
        uint256 o;
        for (uint256 i = 1; i != end;) {
            // A run of plain bytes, which the closing '"' always stops.
            uint256 w = n - i >= 32
                ? uint256(_readBytes32(b, i))
                : uint256(_readBytes32(b, n - 32)) << ((32 - (n - i)) << 3);
            uint256 m = _quotesAndBackslashes(w);
            uint256 k = m == 0 ? 32 : _leadingZeroBytes(m);
            _writeBytes32(out, o, bytes32(w));
            o += k;
            i += k;
            if (k == 32 || i == end) continue;
            // A '"' before the end fails, and a '\\' escapes the byte after it.
            if (uint8(b[i]) == 34 || ++i == end) _fail();
            uint256 c = uint8(b[i++]);
            if (c == 117) {
                // 'u'.
                (c, i) = _decodeUnicodeCodePoint(b, i, end);
                o = _appendCodePointAsUTF8(out, o, c);
                continue;
            }
            if ((_SELF_ESCAPES >> c) & 1 == 0) {
                // `{'b':'\b', 'f':'\f', 'n':'\n', 'r':'\r', 't':'\t'}`.
                if (c == 98) c = 8;
                else if (c == 102) c = 12;
                else if (c == 110) c = 10;
                else if (c == 114) c = 13;
                else if (c == 116) c = 9;
                else _fail();
            }
            out[o++] = bytes1(uint8(c));
        }
        // Clear what the whole words wrote past the end.
        _writeBytes32(out, o, 0);
        result = string(_prefix(out, o));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Reverts with `ParsingFailed()`.
    function _fail() private pure {
        revert ParsingFailed();
    }

    /// @dev Returns `p`, which reverts, as upstream does, if it does not fit the 32 bits
    /// it is packed into. No source offset or node index reaches that in practice.
    /// @custom:solar-inline always
    function _pointer(uint256 p) private pure returns (uint256) {
        if (p > _BITMASK_POINTER) revert();
        return p;
    }

    /// @dev Appends a node and returns its one-based index. Existing node references survive growth.
    function _newItem(Tree[] memory tree, uint256 data) private pure returns (uint256 id) {
        Tree memory t = tree[0];
        uint256 n = t._length;
        id = _pointer(n + 1);
        if (n == t._items.length) {
            Item[] memory items = new Item[](n == 0 ? 4 : n * 2);
            for (uint256 i; i < n; ++i) {
                items[i] = t._items[i];
            }
            t._items = items;
        }
        Item memory item = t._items[n];
        item._data = data | (id << _BITPOS_ID);
        item._tree = tree;
        t._length = id;
    }

    /// @dev Returns the first position from `p` on that is not whitespace, and its byte,
    /// or, past the end, the '"' that upstream places there.
    /// @custom:solar-inline always
    function _skipWhitespace(bytes memory b, uint256 p) private pure returns (uint256, uint256 c) {
        while (p < b.length) {
            c = uint8(b[p]);
            if ((_WHITESPACE >> c) & 1 == 0) return (p, c);
            ++p;
        }
        return (p, 34);
    }

    /// @dev Returns the first position from `p` on that is not a digit, and its byte,
    /// or, past the end, the '"' that upstream places there.
    /// @custom:solar-inline always
    function _skipDigits(bytes memory b, uint256 p) private pure returns (uint256, uint256 c) {
        while (p < b.length) {
            c = uint8(b[p]);
            if ((_DIGITS >> c) & 1 == 0) return (p, c);
            ++p;
        }
        return (p, 34);
    }

    /// @dev Returns the byte of `b` at `p`, or, past its end, the '"' that upstream places there.
    /// @custom:solar-inline always
    function _charAt(bytes memory b, uint256 p) private pure returns (uint256) {
        return p < b.length ? uint8(b[p]) : 34;
    }

    /// @dev Returns the end and the type of the 'true', 'null' or 'false' at `p`.
    /// @custom:solar-inline always
    function _parseLiteral(bytes memory b, uint256 p) private pure returns (uint256, uint256) {
        uint256 n = b.length;
        if (n - p >= 4) {
            bytes4 w = _readBytes4(b, p);
            if (w == "true") return (p + 4, TYPE_BOOLEAN);
            if (w == "null") return (p + 4, TYPE_NULL);
            if (w == "fals" && n - p != 4 && b[p + 4] == "e") return (p + 5, TYPE_BOOLEAN);
        }
        _fail();
    }

    /// @dev Returns the end of the string at `p`. Like upstream, it does not check
    /// that a key starts with '"'.
    function _parseString(bytes memory b, uint256 p) private pure returns (uint256 end) {
        uint256 n = b.length;
        if (p >= n) _fail();
        while (true) {
            if (++p >= n) _fail();
            p = _skipToQuoteOrBackslash(b, p, n);
            if (p >= n) _fail();
            if (uint8(b[p]) == 34) return end = p + 1;
            // '\\'.
            if (++p >= n) _fail();
            uint256 c = uint8(b[p]);
            if (c == 117) {
                // 'u', then 4 hexadecimal digits.
                if (n - p <= 4) _fail();
                for (uint256 k = 1; k != 5; ++k) {
                    if ((_HEX_DIGITS >> uint8(b[p + k])) & 1 == 0) _fail();
                }
                p += 4;
            } else if ((_ESCAPES >> c) & 1 == 0) {
                _fail();
            }
        }
    }

    /// @dev Returns the first position from `p`, which is below `n`, the length of `b`,
    /// of a '"' or a '\\', or `n` if there is none. It tests a word at a time, the last
    /// one shifted so that it starts at `p`.
    /// @custom:solar-inline always
    function _skipToQuoteOrBackslash(bytes memory b, uint256 p, uint256 n)
        private
        pure
        returns (uint256)
    {
        if (n < 32) {
            while (p < n && (_QUOTE_OR_BACKSLASH >> uint8(b[p])) & 1 == 0) ++p;
            return p;
        }
        uint256 m;
        while (n - p >= 32) {
            m = _quotesAndBackslashes(uint256(_readBytes32(b, p)));
            if (m != 0) return p + _leadingZeroBytes(m);
            p += 32;
        }
        // The zero bytes shifted in are neither.
        m = _quotesAndBackslashes(uint256(_readBytes32(b, n - 32)) << ((32 - (n - p)) << 3));
        return m == 0 ? n : p + _leadingZeroBytes(m);
    }

    /// @dev Returns `w` with 0x80 in each byte that is a '"' or a '\\', and 0 in the others.
    /// @custom:solar-inline always
    function _quotesAndBackslashes(uint256 w) private pure returns (uint256) {
        uint256 low = 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;
        uint256 x = w ^ 0x2222222222222222222222222222222222222222222222222222222222222222;
        uint256 y = w ^ 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c;
        // Each byte's high bit becomes whether the byte is nonzero. No carry leaves a byte.
        x |= (x & low) + low;
        y |= (y & low) + low;
        return ~(x & y | low);
    }

    /// @dev Returns how many bytes of `m`, which is not zero, come before its first
    /// nonzero byte.
    /// @custom:solar-inline always
    function _leadingZeroBytes(uint256 m) private pure returns (uint256 r) {
        if (m >> 128 == 0) {
            r = 16;
            m <<= 128;
        }
        if (m >> 192 == 0) {
            r |= 8;
            m <<= 64;
        }
        if (m >> 224 == 0) {
            r |= 4;
            m <<= 32;
        }
        if (m >> 240 == 0) {
            r |= 2;
            m <<= 16;
        }
        if (m >> 248 == 0) r |= 1;
    }

    /// @dev Returns the end of the number at `p`, which starts with `c`, and the byte there,
    /// or, past the end, the '"' that upstream places there.
    /// @custom:solar-inline always
    function _parseNumber(bytes memory b, uint256 p, uint256 c)
        private
        pure
        returns (uint256, uint256)
    {
        if (c == 45) {
            // '-'.
            c = _charAt(b, ++p);
            if ((_DIGITS >> c) & 1 == 0) _fail();
        }
        // Nothing more after a leading '0'.
        if (c == 48) c = _charAt(b, ++p);
        else (p, c) = _skipDigits(b, p + 1);
        if (c == 46) {
            // '.'.
            uint256 q;
            (q, c) = _skipDigits(b, ++p);
            if (q == p) _fail();
            p = q;
        }
        if (c | 32 == 101) {
            // 'e' or 'E', then '+' or '-'.
            c = _charAt(b, ++p);
            if (c == 43 || c == 45) ++p;
            uint256 q;
            (q, c) = _skipDigits(b, p);
            if (q == p) _fail();
            p = q;
        }
        return (p, c);
    }

    /// @dev Parses the key at `p`, and the ':' after it. Returns the position and the
    /// first byte of the item after it, and the item's parent flag and key offsets.
    /// @custom:solar-inline always
    function _parseKey(bytes memory b, uint256 p)
        private
        pure
        returns (uint256, uint256 c, uint256 meta)
    {
        uint256 end = _parseString(b, p);
        meta = _PARENT_IS_OBJECT | (p << _BITPOS_KEY) | ((end - p) << _BITPOS_KEY_LENGTH);
        (p, c) = _skipWhitespace(b, end);
        // ':'.
        if (c != 58) _fail();
        (p, c) = _skipWhitespace(b, p + 1);
        return (p, c, meta);
    }

    /// @dev Returns the string at `bitpos` of `item`, copying it out of the parsed string
    /// and caching it on the first read.
    /// @custom:solar-inline always
    function _getStr(Item memory item, uint256 bitpos, uint256 bitposLength, uint256 inited)
        private
        pure
        returns (string memory result)
    {
        uint256 d = item._data;
        if (d == 0) return result;
        if (d & inited != 0) return inited == _KEY_INITED ? item._key : item._value;
        uint256 o = (d >> bitpos) & _BITMASK_POINTER;
        uint256 n = (d >> bitposLength) & _BITMASK_POINTER;
        bytes memory copy = new bytes((n + 31) & ~uint256(31));
        _copyFresh(copy, item._tree[0]._source, o, n);
        result = string(_prefix(copy, n));
        if (inited == _KEY_INITED) item._key = result;
        else item._value = result;
        item._data = d | inited;
    }

    /// @dev Decodes the 4 hexadecimal digits at `i`, which must end by `end`.
    function _decodeUnicodeEscapeSequence(bytes memory b, uint256 i, uint256 end)
        private
        pure
        returns (uint256)
    {
        if (end < 4 || i > end - 4) _fail();
        // The digits in the low bytes of a word, whose zero bytes above count as '0's.
        uint256 w = uint32(_readBytes4(b, i));
        if (_hexDigits(w) & 0x80808080 != 0x80808080) _fail();
        return _hexValue(w);
    }

    /// @dev Decodes the code point whose escape's digits are at `i`, with the low
    /// surrogate's escape after a high surrogate's.
    /// @custom:solar-inline always
    function _decodeUnicodeCodePoint(bytes memory b, uint256 i, uint256 end)
        private
        pure
        returns (uint256 u, uint256)
    {
        u = _decodeUnicodeEscapeSequence(b, i, end);
        i += 4;
        if (u >= 0xd800 && u <= 0xdbff) {
            // Fail if not followed by '\\u'.
            if (i + 1 >= end || uint8(b[i]) != 92 || uint8(b[i + 1]) != 117) _fail();
            uint256 t = _decodeUnicodeEscapeSequence(b, i + 2, end);
            i += 6;
            u = 0x10000 + ((u & 0x3ff) << 10) + (t & 0x3ff);
        }
        return (u, i);
    }

    /// @dev Writes `c` encoded as UTF-8 into `out` at `o`, as the start of a word that `out` has
    /// room for, and returns the position after the encoding.
    /// @custom:solar-inline always
    function _appendCodePointAsUTF8(bytes memory out, uint256 o, uint256 c)
        private
        pure
        returns (uint256)
    {
        uint256 e;
        uint256 n;
        if (c <= 0x7f) {
            (e, n) = (c, 1);
        } else if (c <= 0x7ff) {
            (e, n) = (0xc080 | ((c << 2) & 0x1f00) | (c & 0x3f), 2);
        } else if (c <= 0xffff) {
            (e, n) = (0xe08080 | ((c << 4) & 0x0f0000) | ((c << 2) & 0x3f00) | (c & 0x3f), 3);
        } else {
            e = 0xf0808080 | ((c << 6) & 0x07000000) | ((c << 4) & 0x3f0000) | ((c << 2) & 0x3f00)
                | (c & 0x3f);
            n = 4;
        }
        _writeBytes32(out, o, bytes32(e << (256 - (n << 3))));
        return o + n;
    }

    /// @dev Parses the digits of `b` from `i` on.
    function _parseDigits(bytes memory b, uint256 i) private pure returns (uint256 result) {
        uint256 n = b.length;
        if (i >= n) _fail();
        if (n < 32) {
            // Too short for a word: a digit at a time.
            do {
                uint256 digit = uint8(b[i]) ^ 48;
                if (digit > 9 || result > type(uint256).max / 10) _fail();
                result *= 10;
                if (digit > type(uint256).max - result) _fail();
                result += digit;
            } while (++i < n);
            return result;
        }
        // 32 digits a word, the last word ending with the string.
        while (true) {
            (uint256 w, uint256 k) = _digitsWord(b, i);
            if (_decimalDigits(w) != _HIGH_BITS) _fail();
            uint256 v = _decimalValue(w);
            uint256 scale = 10 ** k;
            if (result > (type(uint256).max - v) / scale) _fail();
            result = result * scale + v;
            i += k;
            if (i == n) return result;
        }
    }

    /// @dev Returns the next word of digits of `b`, which is at least 32 bytes long, from `i`,
    /// which is below its length, and how many digits it holds: 32, or the rest of `b` in the
    /// low bytes of its last word, after as many '0's.
    /// @custom:solar-inline always
    function _digitsWord(bytes memory b, uint256 i) private pure returns (uint256 w, uint256 k) {
        uint256 n = b.length;
        k = n - i;
        if (k >= 32) return (uint256(_readBytes32(b, i)), 32);
        uint256 low = type(uint256).max >> ((32 - k) << 3);
        w = (uint256(_readBytes32(b, n - 32)) & low) | (_ZEROS & ~low);
    }

    /// @dev Returns `w` with 0x80 in each byte that is a decimal digit, and 0 in the others.
    function _decimalDigits(uint256 w) private pure returns (uint256) {
        uint256 t = w & _LOW_BITS;
        // At least '0' and at most '9', each byte apart: no carry leaves a byte.
        return (t + 0x5050505050505050505050505050505050505050505050505050505050505050)
            & ~(t + 0x4646464646464646464646464646464646464646464646464646464646464646) & ~w
            & _HIGH_BITS;
    }

    /// @dev Returns `w` with 0x80 in each byte that is a hexadecimal digit, and 0 in the others.
    function _hexDigits(uint256 w) private pure returns (uint256) {
        uint256 t = w & _LOW_BITS;
        // A lowercase letter is a letter, either case, with 0x20 set.
        uint256 l = t | 0x2020202020202020202020202020202020202020202020202020202020202020;
        uint256 digits = (t + 0x5050505050505050505050505050505050505050505050505050505050505050)
            & ~(t + 0x4646464646464646464646464646464646464646464646464646464646464646);
        uint256 letters = (l + 0x1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f)
            & ~(l + 0x1919191919191919191919191919191919191919191919191919191919191919);
        return (digits | letters) & ~w & _HIGH_BITS;
    }

    /// @dev Returns the value of the 32 decimal digits in `w`.
    function _decimalValue(uint256 w) private pure returns (uint256 v) {
        // Each byte's digit, then pairs, fours, eights and sixteens of digits.
        v = w & 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
        uint256 m = 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;
        v = ((v >> 8) & m) * 10 + (v & m);
        m = 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;
        v = ((v >> 16) & m) * 100 + (v & m);
        m = 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;
        v = ((v >> 32) & m) * 10000 + (v & m);
        m = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
        v = ((v >> 64) & m) * 100000000 + (v & m);
        v = (v >> 128) * 10000000000000000 + (v & type(uint128).max);
    }

    /// @dev Returns the value of the 32 hexadecimal digits in `w`.
    function _hexValue(uint256 w) private pure returns (uint256 v) {
        // Each byte's digit: its low nibble, and 9 more for a letter.
        v = (w & 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f)
            + ((w >> 6) & 0x0101010101010101010101010101010101010101010101010101010101010101) * 9;
        // Pairs of nibbles into bytes, then pairs of bytes, halves and quarters together.
        v = (v | (v >> 4)) & 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;
        v = (v | (v >> 8)) & 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;
        v = (v | (v >> 16)) & 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;
        v = (v | (v >> 32)) & 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
        v = (v | (v >> 64)) & type(uint128).max;
    }

    /// @dev Copies `count` bytes from `src` at `srcOffset` to the start of `dst`, which the
    /// caller has just allocated. Solar copies with `mcopy`, behind a test that keeps the
    /// loop if `src` reaches into `dst`.
    /// @custom:solar-inline always
    function _copyFresh(bytes memory dst, bytes memory src, uint256 srcOffset, uint256 count)
        private
        pure
    {
        for (uint256 k; k < count; ++k) {
            dst[k] = src[srcOffset + k];
        }
    }

    /// @dev The 32 bytes of `b` at `p`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 p) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[p + k]) >> (8 * k);
        }
    }

    /// @dev Writes `w` into `b` at `p`.
    /// @custom:solar-inline always
    function _writeBytes32(bytes memory b, uint256 p, bytes32 w) private pure {
        for (uint256 k; k < 32; ++k) {
            b[p + k] = w[k];
        }
    }

    /// @dev The 4 bytes of `b` at `p`.
    /// @custom:solar-inline always
    function _readBytes4(bytes memory b, uint256 p) private pure returns (bytes4 result) {
        for (uint256 k; k < 4; ++k) {
            result |= bytes4(b[p + k]) >> (8 * k);
        }
    }

    /// @dev Looks up a nonzero node index in the shared table.
    /// @custom:solar-inline always
    function _item(Tree[] memory tree, uint256 id) private pure returns (Item memory) {
        return tree[0]._items[id - 1];
    }

    /// @dev Copies an exact prefix with zero padding. The caller cleared the last partial word.
    function _prefix(bytes memory b, uint256 n) private pure returns (bytes memory) {
        return abi.decode(abi.encodePacked(uint256(32), n, b), (bytes));
    }
}
