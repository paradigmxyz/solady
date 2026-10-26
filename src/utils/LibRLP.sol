// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

/// @notice Library for RLP encoding and CREATE address computation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibRLP.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/LibRLP.sol)
/// @dev The assembly-free port uses typed items in a growable memory list. Appending keeps
/// list and byte-string references, so changes to an appended value are visible when
/// encoding, including an initially empty nested list. The first two items are embedded;
/// further items use a growable tail. Short encodings pack into a word, while longer lists
/// measure their payloads before writing them. ABI envelopes produce exact
/// lengths and zero padding without casting pointers or truncating allocations.
/// The opaque `List` representation changes, but chaining and encoding semantics do not.
/// `computeAddress` returns a clean address, where upstream leaves its upper bits dirty.
/// @custom:solar-safe memory
library LibRLP {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev A pointer to a RLP item list in memory.
    struct List {
        // Do NOT modify these fields directly.
        Item _first;
        Item _second;
        Item[] _items;
        uint256 _length;
    }

    /// @dev A typed item: integer (0), bytes (2), list (3), or address (4).
    struct Item {
        uint256 _kind;
        uint256 _word;
        bytes _bytes;
        // A singleton only for nested lists; other item kinds allocate no child list.
        List[] _list;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 CREATE ADDRESS PREDICTION                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the address where a contract will be stored if deployed via
    /// `deployer` with `nonce` using the `CREATE` opcode.
    /// For the specification of the Recursive Length Prefix (RLP)
    /// encoding scheme, please refer to p. 19 of the Ethereum Yellow Paper
    /// (https://ethereum.github.io/yellowpaper/paper.pdf)
    /// and the Ethereum Wiki (https://eth.wiki/fundamentals/rlp).
    ///
    /// Based on the EIP-161 (https://github.com/ethereum/EIPs/blob/master/EIPS/eip-161.md)
    /// specification, all contract accounts on the Ethereum mainnet are initiated with
    /// `nonce = 1`. Thus, the first contract address created by another contract
    /// is calculated with a non-zero nonce.
    ///
    /// The theoretical allowed limit, based on EIP-2681
    /// (https://eips.ethereum.org/EIPS/eip-2681), for an account nonce is 2**64-2.
    ///
    /// Caution! This function will NOT check that the nonce is within the theoretical range.
    /// This is for performance, as exceeding the range is extremely impractical.
    /// It is the user's responsibility to ensure that the nonce is valid
    /// (e.g. no dirty bits after packing / unpacking).
    ///
    /// This is equivalent to:
    /// `address(uint160(uint256(keccak256(LibRLP.p(deployer).p(nonce).encode()))))`.
    ///
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function computeAddress(address deployer, uint256 nonce)
        internal
        pure
        returns (address deployed)
    {
        // The integer zero is treated as an empty byte string,
        // and as a result it only has a length prefix, 0x80,
        // computed via `0x80 + 0`.

        // A one-byte integer in the [0x00, 0x7f] range uses its
        // own value as a length prefix,
        // there is no additional `0x80 + length` prefix that precedes it.
        if (nonce <= 0x7f) {
            uint8 n = uint8(nonce | (nonce == 0 ? 0x80 : 0));
            return _address(keccak256(abi.encodePacked(hex"d694", deployer, n)));
        }
        // A nonce of up to eight bytes, as every account's is, makes a preimage of at most 31
        // bytes: a packed hash of fixed-size values, which needs no allocation.
        if (nonce <= type(uint8).max) {
            return _address(keccak256(abi.encodePacked(hex"d794", deployer, hex"81", uint8(nonce))));
        }
        if (nonce <= type(uint16).max) {
            return
                _address(keccak256(abi.encodePacked(hex"d894", deployer, hex"82", uint16(nonce))));
        }
        if (nonce <= type(uint24).max) {
            return
                _address(keccak256(abi.encodePacked(hex"d994", deployer, hex"83", uint24(nonce))));
        }
        if (nonce <= type(uint32).max) {
            return
                _address(keccak256(abi.encodePacked(hex"da94", deployer, hex"84", uint32(nonce))));
        }
        if (nonce <= type(uint40).max) {
            return
                _address(keccak256(abi.encodePacked(hex"db94", deployer, hex"85", uint40(nonce))));
        }
        if (nonce <= type(uint48).max) {
            return
                _address(keccak256(abi.encodePacked(hex"dc94", deployer, hex"86", uint48(nonce))));
        }
        if (nonce <= type(uint56).max) {
            return
                _address(keccak256(abi.encodePacked(hex"dd94", deployer, hex"87", uint56(nonce))));
        }
        if (nonce <= type(uint64).max) {
            return
                _address(keccak256(abi.encodePacked(hex"de94", deployer, hex"88", uint64(nonce))));
        }
        bytes memory encodedNonce = encode(nonce);
        deployed = _address(
            keccak256(
                abi.encodePacked(uint8(0xd5 + encodedNonce.length), hex"94", deployer, encodedNonce)
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  RLP ENCODING OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note:
    // - addresses are treated like byte strings of length 20, agnostic of leading zero bytes.
    // - uint256s are converted to byte strings, stripped of leading zero bytes, and encoded.
    // - bools are converted to uint256s (`b ? 1 : 0`), then encoded with the uint256.
    // - For bytes1 to bytes32, you must manually convert them to bytes memory
    //   with `abi.encodePacked(x)` before encoding.

    /// @dev Returns a new empty list.
    function p() internal pure returns (List memory result) {}

    /// @dev Returns a new list with `x` as the only element. Equivalent to `LibRLP.p().p(x)`.
    /// @custom:solar-inline
    function p(uint256 x) internal pure returns (List memory result) {
        result = _newList();
        result._first._word = x;
    }

    /// @dev Returns a new list with `x` as the only element. Equivalent to `LibRLP.p().p(x)`.
    /// @custom:solar-inline
    function p(address x) internal pure returns (List memory result) {
        result = _newList();
        result._first._kind = 4;
        result._first._word = uint160(x);
    }

    /// @dev Returns a new list with `x` as the only element. Equivalent to `LibRLP.p().p(x)`.
    /// @custom:solar-inline
    function p(bool x) internal pure returns (List memory result) {
        result = _newList();
        result._first._word = x ? 1 : 0;
    }

    /// @dev Returns a new list with `x` as the only element. Equivalent to `LibRLP.p().p(x)`.
    /// @custom:solar-inline
    function p(bytes memory x) internal pure returns (List memory result) {
        result = _newList();
        result._first._kind = 2;
        result._first._bytes = x;
    }

    /// @dev Returns a new list with `x` as the only element. Equivalent to `LibRLP.p().p(x)`.
    /// @custom:solar-inline
    function p(List memory x) internal pure returns (List memory result) {
        result = _newList();
        result._first._kind = 3;
        result._first._list = new List[](1);
        result._first._list[0] = x;
    }

    /// @dev Appends `x` to `list`. Returns `list` for function chaining.
    /// @custom:solar-inline
    function p(List memory list, uint256 x) internal pure returns (List memory result) {
        _append(list)._word = x;
        result = list;
    }

    /// @dev Appends `x` to `list`. Returns `list` for function chaining.
    /// @custom:solar-inline
    function p(List memory list, address x) internal pure returns (List memory result) {
        Item memory item = _append(list);
        item._kind = 4;
        item._word = uint160(x);
        result = list;
    }

    /// @dev Appends `x` to `list`. Returns `list` for function chaining.
    /// @custom:solar-inline
    function p(List memory list, bool x) internal pure returns (List memory result) {
        _append(list)._word = x ? 1 : 0;
        result = list;
    }

    /// @dev Appends `x` to `list`. Returns `list` for function chaining.
    /// @custom:solar-inline
    function p(List memory list, bytes memory x) internal pure returns (List memory result) {
        Item memory item = _append(list);
        item._kind = 2;
        item._bytes = x;
        result = list;
    }

    /// @dev Appends `x` to `list`. Returns `list` for function chaining.
    /// @custom:solar-inline
    function p(List memory list, List memory x) internal pure returns (List memory result) {
        Item memory item = _append(list);
        item._kind = 3;
        item._list = new List[](1);
        item._list[0] = x;
        result = list;
    }

    /// @dev Returns the RLP encoding of `list`.
    function encode(List memory list) internal pure returns (bytes memory result) {
        (uint256 word, uint256 length) = _packList(list);
        if (length <= 31) {
            // The one-byte prefix and total length are bounded by the packed payload.
            unchecked {
                return _encodedWord(((0xc0 + length) << 248) | (word >> 8), length + 1);
            }
        }
        uint256 n = _payloadLength(list);
        result = new bytes(_prefixLength(n) + n);
        _writeList(result, 0, list, n);
        // ABI encoding clears padding even when the caller left dirty free memory.
        result = abi.decode(abi.encode(result), (bytes));
    }

    /// @dev Returns the RLP encoding of `x`.
    function encode(uint256 x) internal pure returns (bytes memory result) {
        if (x <= 0x7f) return _encodedWord((x == 0 ? 0x80 : x) << 248, 1);
        uint256 n = _byteLength(x);
        uint256 left = x << (256 - 8 * n);
        result = abi.decode(
            abi.encode(uint256(32), n + 1, ((0x80 + n) << 248) | (left >> 8), left << 248), (bytes)
        );
    }

    /// @dev Returns the RLP encoding of `x`.
    function encode(address x) internal pure returns (bytes memory result) {
        result = _encodedWord((uint256(0x94) << 248) | (uint256(uint160(x)) << 88), 21);
    }

    /// @dev Returns the RLP encoding of `x`.
    function encode(bool x) internal pure returns (bytes memory result) {
        result = _encodedWord(uint256(x ? 0x01 : 0x80) << 248, 1);
    }

    /// @dev Returns the RLP encoding of `x`.
    function encode(bytes memory x) internal pure returns (bytes memory result) {
        uint256 n = x.length;
        // A single byte below 0x80 is its own encoding: `x` itself.
        if (n == 1 && uint8(x[0]) < 0x80) return x;
        bytes memory prefix = new bytes(_prefixLength(n));
        _writePrefix(prefix, 0, n, 0x80);
        result = abi.decode(
            abi.encodePacked(uint256(32), prefix.length + n, prefix, x, bytes32(0)), (bytes)
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Initializes the first embedded item; the second needs no further allocation.
    /// @custom:solar-inline
    function _newList() private pure returns (List memory result) {
        result._length = 1;
    }

    /// @dev Appends an item, preserving the identity of lists and existing items when growing.
    /// @custom:solar-inline
    function _append(List memory list) private pure returns (Item memory item) {
        // The index and doubled capacity fit whenever the backing allocation can exist.
        unchecked {
            uint256 n = list._length;
            list._length = n + 1;
            if (n == 0) return list._first;
            if (n == 1) return list._second;
            n -= 2;
            if (n == list._items.length) {
                Item[] memory items = new Item[](n == 0 ? 2 : n * 2);
                for (uint256 i; i < n; ++i) {
                    items[i] = list._items[i];
                }
                list._items = items;
            }
            item = list._items[n];
        }
    }

    /// @dev The first two items are embedded; longer lists use the growable tail.
    /// @custom:solar-inline
    function _item(List memory list, uint256 i) private pure returns (Item memory) {
        if (i == 0) return list._first;
        if (i == 1) return list._second;
        return list._items[i - 2];
    }

    /// @dev Counts the encoded bytes of the items, excluding this list's prefix.
    function _payloadLength(List memory list) private pure returns (uint256 n) {
        for (uint256 i; i < list._length; ++i) {
            Item memory item = _item(list, i);
            if (item._kind == 0) {
                n += item._word <= 0x7f ? 1 : 1 + _byteLength(item._word);
            } else if (item._kind == 4) {
                n += 21;
            } else if (item._kind == 2) {
                bytes memory x = item._bytes;
                n += x.length == 1 && uint8(x[0]) < 0x80 ? 1 : _prefixLength(x.length) + x.length;
            } else {
                uint256 k = _payloadLength(item._list[0]);
                n += _prefixLength(k) + k;
            }
        }
    }

    /// @dev Writes a measured list and returns the first byte after it.
    function _writeList(bytes memory out, uint256 o, List memory list, uint256 n)
        private
        pure
        returns (uint256)
    {
        o = _writePrefix(out, o, n, 0xc0);
        for (uint256 i; i < list._length; ++i) {
            Item memory item = _item(list, i);
            if (item._kind == 0) {
                o = _writeUint(out, o, item._word);
            } else if (item._kind == 4) {
                out[o++] = 0x94;
                _writeNumber(out, o, item._word, 20);
                o += 20;
            } else if (item._kind == 2) {
                bytes memory x = item._bytes;
                if (x.length != 1 || uint8(x[0]) >= 0x80) o = _writePrefix(out, o, x.length, 0x80);
                for (uint256 j; j < x.length; ++j) {
                    out[o++] = x[j];
                }
            } else {
                o = _writeList(out, o, item._list[0], _payloadLength(item._list[0]));
            }
        }
        return o;
    }

    /// @dev Writes an integer in its shortest encoding.
    function _writeUint(bytes memory out, uint256 o, uint256 x) private pure returns (uint256) {
        if (x <= 0x7f) {
            out[o] = bytes1(uint8(x == 0 ? 0x80 : x));
            return o + 1;
        }
        uint256 n = _byteLength(x);
        out[o++] = bytes1(uint8(0x80 + n));
        _writeNumber(out, o, x, n);
        return o + n;
    }

    /// @dev Writes the low `n` bytes of `x` in big-endian order.
    function _writeNumber(bytes memory out, uint256 o, uint256 x, uint256 n) private pure {
        while (n != 0) {
            out[o + --n] = bytes1(uint8(x));
            x >>= 8;
        }
    }

    /// @dev Writes a list or byte-string length prefix.
    function _writePrefix(bytes memory out, uint256 o, uint256 n, uint256 c)
        private
        pure
        returns (uint256)
    {
        if (n <= 55) {
            out[o] = bytes1(uint8(c + n));
            return o + 1;
        }
        uint256 k = _lengthOfLength(n);
        out[o++] = bytes1(uint8(c + 55 + k));
        _writeNumber(out, o, n, k);
        return o + k;
    }

    /// @dev The size of a length prefix.
    function _prefixLength(uint256 n) private pure returns (uint256) {
        return n <= 55 ? 1 : 1 + _lengthOfLength(n);
    }

    /// @dev Upstream rejects payload lengths requiring more than four bytes.
    /// @custom:solar-inline
    function _lengthOfLength(uint256 n) private pure returns (uint256) {
        if (n >> 32 != 0) revert();
        return _byteLength(n);
    }

    /// @dev The number of bytes of `x` from its first nonzero one, at least one: its base-256
    /// logarithm plus one, by the binary search of `log2` to whole bytes.
    /// @custom:solar-inline
    function _byteLength(uint256 x) private pure returns (uint256) {
        // The shift counts are at most 248, and the result is at most 32.
        unchecked {
            uint256 r = (x > type(uint128).max ? 1 : 0) << 7;
            r |= ((x >> r) > type(uint64).max ? 1 : 0) << 6;
            r |= ((x >> r) > type(uint32).max ? 1 : 0) << 5;
            r |= ((x >> r) > type(uint16).max ? 1 : 0) << 4;
            r |= ((x >> r) > type(uint8).max ? 1 : 0) << 3;
            return (r >> 3) + 1;
        }
    }

    /// @dev The address in the low 20 bytes of the hash `h`.
    function _address(bytes32 h) private pure returns (address) {
        return address(uint160(uint256(h)));
    }

    /// @dev Decodes a left-aligned encoding with explicit zero padding from an ABI envelope.
    function _encodedWord(uint256 word, uint256 n) private pure returns (bytes memory) {
        return abi.decode(abi.encode(uint256(32), n, word), (bytes));
    }

    /// @dev Packs a short list into a left-aligned word; a length of 32 requests the general path.
    function _packList(List memory list) private pure returns (uint256 word, uint256 length) {
        // Each item reports at most 32 bytes; reject totals above 31 before packing them.
        unchecked {
            if (list._length == 0) return (0, 0);
            (word, length) = _packItem(list._first);
            if (length == 32 || list._length == 1) return (word, length);
            (uint256 w, uint256 n) = _packItem(list._second);
            if (length + n > 31) return (0, 32);
            word |= w >> (8 * length);
            length += n;
            for (uint256 i = 2; i < list._length; ++i) {
                (w, n) = _packItem(list._items[i - 2]);
                if (length + n > 31) return (0, 32);
                word |= w >> (8 * length);
                length += n;
            }
        }
    }

    /// @dev Packs one item into a word, or returns length 32 when a list cannot hold it.
    /// @custom:solar-noinline
    function _packItem(Item memory item) private pure returns (uint256 w, uint256 n) {
        // Each packed item occupies at most 31 bytes, so the shift counts and prefixes fit.
        unchecked {
            if (item._kind == 0) {
                uint256 x = item._word;
                if (x <= 0x7f) return ((x == 0 ? 0x80 : x) << 248, 1);
                if (x <= type(uint8).max) return ((uint256(0x81) << 248) | (x << 240), 2);
                n = _byteLength(x);
                if (n >= 31) return (0, 32);
                return (((0x80 + n) << 248) | (x << (248 - 8 * n)), n + 1);
            }
            if (item._kind == 4) return ((uint256(0x94) << 248) | (item._word << 88), 21);
            if (item._kind == 2) {
                bytes memory x = item._bytes;
                n = x.length;
                if (n == 1 && uint8(x[0]) < 0x80) return (uint256(uint8(x[0])) << 248, 1);
                if (n >= 31) return (0, 32);
                // Converting dynamic bytes to bytes32 clears the unused low bytes.
                return (((0x80 + n) << 248) | (uint256(bytes32(x)) >> 8), n + 1);
            }
            return (0, 32);
        }
    }
}
