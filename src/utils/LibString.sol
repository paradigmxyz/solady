// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import {LibBytes} from "./LibBytes.sol";

/// @notice Library for converting numbers into strings and other string operations.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibString.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/LibString.sol)
///
/// @dev Note:
/// For performance and bytecode compactness, most of the string operations are restricted to
/// byte strings (7-bit ASCII), except where otherwise specified.
/// Usage of byte string operations on charsets with runes spanning two or more bytes
/// can lead to undefined behavior.
///
/// The checked port keeps upstream's split: the byte operations are LibBytes', and the string
/// storage operations go through `bytesStorage`, which views a `StringStorage` as a
/// `BytesStorage` at the same slot with upstream's packed layout. `bytesStorage` and
/// `directReturn` stay trusted assembly: Solidity cannot retype a storage reference, and a
/// `return` statement leaves only the function it is in. Strings built from whole words, the
/// decimal and short hexadecimal ones, the escapes, the checksummed addresses and the unpacked
/// strings, take their length from `_truncate` or `_setLength`, which shorten a fresh buffer in
/// place; the other fresh strings get a zero word after their end from `_zeroPad`, as legacy
/// solc's `new bytes(n)` clears only `n` bytes. `_rawMul` is wrap-around arithmetic for the
/// digit conversions and byte counts done a word at a time, whose lanes never carry into each
/// other.
/// @custom:solar-safe memory arithmetic
library LibString {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Goated string storage struct that totally MOGs, no cap, fr.
    /// Uses less gas and bytecode than Solidity's native string storage. It's meta af.
    /// Packs length with the first 31 bytes if <255 bytes, so it’s mad tight.
    struct StringStorage {
        bytes32 _spacer;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The length of the output is too small to contain all the hex digits.
    error HexLengthInsufficient();

    /// @dev The length of the string is more than 32 bytes.
    error TooBigForSmallString();

    /// @dev The input string must be a 7-bit ASCII.
    error StringNot7BitASCII();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The constant returned when the `search` is not found in the string.
    uint256 internal constant NOT_FOUND = type(uint256).max;

    /// @dev Lookup for '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.
    uint128 internal constant ALPHANUMERIC_7_BIT_ASCII = 0x7fffffe07fffffe03ff000000000000;

    /// @dev Lookup for 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'.
    uint128 internal constant LETTERS_7_BIT_ASCII = 0x7fffffe07fffffe0000000000000000;

    /// @dev Lookup for 'abcdefghijklmnopqrstuvwxyz'.
    uint128 internal constant LOWERCASE_7_BIT_ASCII = 0x7fffffe000000000000000000000000;

    /// @dev Lookup for 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
    uint128 internal constant UPPERCASE_7_BIT_ASCII = 0x7fffffe0000000000000000;

    /// @dev Lookup for '0123456789'.
    uint128 internal constant DIGITS_7_BIT_ASCII = 0x3ff000000000000;

    /// @dev Lookup for '0123456789abcdefABCDEF'.
    uint128 internal constant HEXDIGITS_7_BIT_ASCII = 0x7e0000007e03ff000000000000;

    /// @dev Lookup for '01234567'.
    uint128 internal constant OCTDIGITS_7_BIT_ASCII = 0xff000000000000;

    /// @dev Lookup for '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'.
    uint128 internal constant PRINTABLE_7_BIT_ASCII = 0x7fffffffffffffffffffffff00003e00;

    /// @dev Lookup for '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'.
    uint128 internal constant PUNCTUATION_7_BIT_ASCII = 0x78000001f8000001fc00fffe00000000;

    /// @dev Lookup for ' \t\n\r\x0b\x0c'.
    uint128 internal constant WHITESPACE_7_BIT_ASCII = 0x100003e00;

    /// @dev Nibble-spreading masks, one per halving of the packing.
    uint256 private constant MASK_64 =
        0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;

    uint256 private constant MASK_32 =
        0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;

    uint256 private constant MASK_16 =
        0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;

    uint256 private constant MASK_8 =
        0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;

    uint256 private constant MASK_4 =
        0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;

    /// @dev One copy of the value in every byte.
    uint256 private constant SPREAD_1 =
        0x0101010101010101010101010101010101010101010101010101010101010101;

    uint256 private constant SPREAD_5 =
        0x0505050505050505050505050505050505050505050505050505050505050505;

    uint256 private constant SPREAD_6 =
        0x0606060606060606060606060606060606060606060606060606060606060606;

    uint256 private constant SPREAD_ASCII_0 =
        0x3030303030303030303030303030303030303030303030303030303030303030;

    uint256 private constant SPREAD_2A =
        0x2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a;

    uint256 private constant SPREAD_1F =
        0x1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f;

    uint256 private constant SPREAD_20 =
        0x2020202020202020202020202020202020202020202020202020202020202020;

    uint256 private constant LANES_7F =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    uint256 private constant LANES_01 =
        0x0101010101010101010101010101010101010101010101010101010101010101;

    /// @dev The top bit of every byte lane.
    uint256 private constant _HIGH_BITS =
        0x8080808080808080808080808080808080808080808080808080808080808080;

    /// @dev Lowercase hexadecimal digits.
    bytes16 private constant _DIGITS = "0123456789abcdef";

    /// @dev Uppercase hexadecimal digits.
    bytes16 private constant _UPPER_DIGITS = "0123456789ABCDEF";

    /// @dev `_UPPER_DIGITS` as a word, which indexes without a shift.
    bytes32 private constant _UPPER_HEX = "0123456789ABCDEF";

    /// @dev `&quot;&amp;&#39;&lt;&gt;`, the entities `escapeHTML` writes.
    bytes32 private constant _HTML_ENTITIES =
        0x2671756f743b26616d703b262333393b266c743b2667743b0000000000000000;

    /// @dev For each byte `escapeHTML` replaces, at the index of its low five
    /// bits, the length of its entity times 32 plus the entity's offset in
    /// `_HTML_ENTITIES`.
    bytes32 private constant _HTML_ENTITY_SPANS =
        0x0000c0000000a6ab000000000000000000000000000000000000000090009400;

    /// @dev One bit for each byte JSON escapes in two characters: `"`, `\`, and
    /// the controls `\b`, `\t`, `\n`, `\f` and `\r` spell.
    uint256 private constant _JSON_SHORT_ESCAPED = 0x100000000000000400003700;

    /// @dev The second character of the two-character JSON escape of each byte
    /// in `_JSON_SHORT_ESCAPED`, at the index of the byte's low five bits.
    bytes32 private constant _JSON_SHORT_ESCAPES =
        0x000022000000000062746e00667200000000000000000000000000005c000000;

    /// @dev One bit per byte a URI component keeps: letters, digits and `-_.!~*'()`.
    uint256 private constant _URI_UNRESERVED = 0x47fffffe87fffffe03ff678200000000;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 STRING STORAGE OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sets the value of the string storage `$` to `s`.
    function set(StringStorage storage $, string memory s) internal {
        LibBytes.set(bytesStorage($), bytes(s));
    }

    /// @dev Sets the value of the string storage `$` to `s`.
    function setCalldata(StringStorage storage $, string calldata s) internal {
        LibBytes.setCalldata(bytesStorage($), bytes(s));
    }

    /// @dev Sets the value of the string storage `$` to the empty string.
    function clear(StringStorage storage $) internal {
        delete $._spacer;
    }

    /// @dev Returns whether the value stored is `$` is the empty string "".
    function isEmpty(StringStorage storage $) internal view returns (bool) {
        return uint256($._spacer) & 0xff == uint256(0);
    }

    /// @dev Returns the length of the value stored in `$`.
    function length(StringStorage storage $) internal view returns (uint256) {
        return LibBytes.length(bytesStorage($));
    }

    /// @dev Returns the value stored in `$`.
    function get(StringStorage storage $) internal view returns (string memory) {
        return string(LibBytes.get(bytesStorage($)));
    }

    /// @dev Returns the uint8 at index `i`. If out-of-bounds, returns 0.
    function uint8At(StringStorage storage $, uint256 i) internal view returns (uint8) {
        return LibBytes.uint8At(bytesStorage($), i);
    }

    /// @dev Helper to cast `$` to a `BytesStorage`.
    /// Solidity cannot retype a storage reference, so this keeps the upstream assembly.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function bytesStorage(StringStorage storage $)
        internal
        pure
        returns (LibBytes.BytesStorage storage casted)
    {
        /// @solidity memory-safe-assembly
        assembly {
            casted.slot := $.slot
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     DECIMAL OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the base 10 decimal representation of `value`.
    function toString(uint256 value) internal pure returns (string memory result) {
        return _decimal(value, false);
    }

    /// @dev Returns the base 10 decimal representation of `value`.
    function toString(int256 value) internal pure returns (string memory result) {
        if (value >= 0) return _decimal(uint256(value), false);
        // The magnitude of the most negative value does not fit `int256`.
        return _decimal(value == type(int256).min ? uint256(1) << 255 : uint256(-value), true);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   HEXADECIMAL OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the hexadecimal representation of `value`,
    /// left-padded to an input length of `byteCount` bytes.
    /// The output is prefixed with "0x" encoded using 2 hexadecimal digits per byte,
    /// giving a total length of `byteCount * 2 + 2` bytes.
    /// Reverts if `byteCount` is too small for the output to contain all the digits.
    function toHexString(uint256 value, uint256 byteCount)
        internal
        pure
        returns (string memory result)
    {
        _checkHexLength(value, byteCount);
        return _toHexString(value, byteCount);
    }

    /// @dev Returns the hexadecimal representation of `value`,
    /// left-padded to an input length of `byteCount` bytes.
    /// The output is not prefixed with "0x" and is encoded using 2 hexadecimal digits per byte,
    /// giving a total length of `byteCount * 2` bytes.
    /// Reverts if `byteCount` is too small for the output to contain all the digits.
    function toHexStringNoPrefix(uint256 value, uint256 byteCount)
        internal
        pure
        returns (string memory result)
    {
        _checkHexLength(value, byteCount);
        return _toHexStringNoPrefix(value, byteCount);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output is prefixed with "0x" and encoded using 2 hexadecimal digits per byte.
    /// As address are 20 bytes long, the output will left-padded to have
    /// a length of `20 * 2 + 2` bytes.
    function toHexString(uint256 value) internal pure returns (string memory result) {
        return _toHexString(value);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output is prefixed with "0x".
    /// The output excludes leading "0" from the `toHexString` output.
    /// `0x00: "0x0", 0x01: "0x1", 0x12: "0x12", 0x123: "0x123"`.
    function toMinimalHexString(uint256 value) internal pure returns (string memory result) {
        return _toMinimalHexString(value);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output excludes leading "0" from the `toHexStringNoPrefix` output.
    /// `0x00: "0", 0x01: "1", 0x12: "12", 0x123: "123"`.
    function toMinimalHexStringNoPrefix(uint256 value)
        internal
        pure
        returns (string memory result)
    {
        return _toMinimalHexStringNoPrefix(value);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output is encoded using 2 hexadecimal digits per byte.
    /// As address are 20 bytes long, the output will left-padded to have
    /// a length of `20 * 2` bytes.
    function toHexStringNoPrefix(uint256 value) internal pure returns (string memory result) {
        return _toHexStringNoPrefix(value);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output is prefixed with "0x", encoded using 2 hexadecimal digits per byte,
    /// and the alphabets are capitalized conditionally according to
    /// https://eips.ethereum.org/EIPS/eip-55
    function toHexStringChecksummed(address value) internal pure returns (string memory result) {
        // The top sixteen bytes make one word of characters; the low four make eight more,
        // kept in the top of another word.
        uint256 raw = uint160(value);
        uint256 head = uint256(_hexWord(raw >> 32));
        uint256 tail = uint256(_hexWord((raw & 0xffffffff) << 96)) >> 192 << 192;
        // A character is uppercased when it is a letter and its nibble of the hash of the
        // lowercase digits is at least eight: nibble by nibble, the hash's top sixteen bytes
        // line up with the head and the next four with the tail.
        uint256 hash = uint256(keccak256(abi.encodePacked(bytes32(head), bytes8(bytes32(tail)))));
        head = _checksumCase(head, _nibbles(hash >> 128));
        tail = _checksumCase(tail, _nibbles(hash & type(uint128).max));
        // `0x` and the forty characters in two whole words, cut to their 42 bytes.
        bytes memory out = abi.encodePacked(
            bytes32((0x3078 << 240) | (head >> 16)), bytes32((head << 240) | (tail >> 16))
        );
        _setLength(out, 42);
        return string(out);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output is prefixed with "0x" and encoded using 2 hexadecimal digits per byte.
    function toHexString(address value) internal pure returns (string memory result) {
        return _toHexString(uint160(value), 20);
    }

    /// @dev Returns the hexadecimal representation of `value`.
    /// The output is encoded using 2 hexadecimal digits per byte.
    function toHexStringNoPrefix(address value) internal pure returns (string memory result) {
        return _toHexStringNoPrefix(uint160(value), 20);
    }

    /// @dev Returns the hex encoded string from the raw bytes.
    /// The output is encoded using 2 hexadecimal digits per byte.
    function toHexString(bytes memory raw) internal pure returns (string memory result) {
        return _hexEncodePrefixed(raw);
    }

    /// @dev Returns the hex encoded string from the raw bytes.
    /// The output is encoded using 2 hexadecimal digits per byte.
    function toHexStringNoPrefix(bytes memory raw) internal pure returns (string memory result) {
        return _hexEncode(raw);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   RUNE STRING OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the number of UTF characters in the string.
    function runeCount(string memory s) internal pure returns (uint256 result) {
        return _runeCount(s);
    }

    /// @dev Returns if this string is a 7-bit ASCII string.
    /// (i.e. all characters codes are in [0..127])
    function is7BitASCII(string memory s) internal pure returns (bool result) {
        // A word at a time: any byte with its top bit set fails the whole word.
        bytes memory b = bytes(s);
        uint256 n = b.length;
        uint256 i;
        while (i + 32 <= n) {
            if (uint256(_readBytes32(b, i)) & _HIGH_BITS != 0) return false;
            i += 32;
        }
        if (i < n) return uint256(_readBytesN(b, i, n - i)) & _HIGH_BITS == 0;
        return true;
    }

    /// @dev Returns if this string is a 7-bit ASCII string,
    /// AND all characters are in the `allowed` lookup.
    /// Note: If `s` is empty, returns true regardless of `allowed`.
    function is7BitASCII(string memory s, uint128 allowed) internal pure returns (bool result) {
        // With every 7-bit byte allowed, only the high bits matter.
        if (allowed == type(uint128).max) return is7BitASCII(s);
        return _allowedBytes(bytes(s), allowed);
    }

    /// @dev Converts the bytes in the 7-bit ASCII string `s` to
    /// an allowed lookup for use in `is7BitASCII(s, allowed)`.
    /// To save runtime gas, you can cache the result in an immutable variable.
    function to7BitASCIIAllowedLookup(string memory s) internal pure returns (uint128 result) {
        bytes memory b = bytes(s);
        if (b.length == 0) return 0;
        uint256 lookup;
        for (uint256 i; i < b.length; ++i) {
            lookup |= uint256(1) << uint8(b[i]);
        }
        if (lookup > type(uint128).max) revert StringNot7BitASCII();
        return uint128(lookup);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   BYTE STRING OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // For performance and bytecode compactness, byte string operations are restricted
    // to 7-bit ASCII strings. All offsets are byte offsets, not UTF character offsets.
    // Usage of byte string operations on charsets with runes spanning two or more bytes
    // can lead to undefined behavior.

    /// @dev Returns `subject` all occurrences of `needle` replaced with `replacement`.
    function replace(string memory subject, string memory needle, string memory replacement)
        internal
        pure
        returns (string memory)
    {
        return string(LibBytes.replace(bytes(subject), bytes(needle), bytes(replacement)));
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right, starting from `from`.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function indexOf(string memory subject, string memory needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return LibBytes.indexOf(bytes(subject), bytes(needle), from);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from left to right.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function indexOf(string memory subject, string memory needle) internal pure returns (uint256) {
        return LibBytes.indexOf(bytes(subject), bytes(needle), 0);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from right to left, starting from `from`.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function lastIndexOf(string memory subject, string memory needle, uint256 from)
        internal
        pure
        returns (uint256)
    {
        return LibBytes.lastIndexOf(bytes(subject), bytes(needle), from);
    }

    /// @dev Returns the byte index of the first location of `needle` in `subject`,
    /// needleing from right to left.
    /// Returns `NOT_FOUND` (i.e. `type(uint256).max`) if the `needle` is not found.
    function lastIndexOf(string memory subject, string memory needle)
        internal
        pure
        returns (uint256)
    {
        return LibBytes.lastIndexOf(bytes(subject), bytes(needle), type(uint256).max);
    }

    /// @dev Returns true if `needle` is found in `subject`, false otherwise.
    function contains(string memory subject, string memory needle) internal pure returns (bool) {
        return LibBytes.contains(bytes(subject), bytes(needle));
    }

    /// @dev Returns whether `subject` starts with `needle`.
    function startsWith(string memory subject, string memory needle) internal pure returns (bool) {
        return LibBytes.startsWith(bytes(subject), bytes(needle));
    }

    /// @dev Returns whether `subject` ends with `needle`.
    function endsWith(string memory subject, string memory needle) internal pure returns (bool) {
        return LibBytes.endsWith(bytes(subject), bytes(needle));
    }

    /// @dev Returns `subject` repeated `times`.
    function repeat(string memory subject, uint256 times) internal pure returns (string memory) {
        return string(LibBytes.repeat(bytes(subject), times));
    }

    /// @dev Returns a copy of `subject` sliced from `start` to `end` (exclusive).
    /// `start` and `end` are byte offsets.
    function slice(string memory subject, uint256 start, uint256 end)
        internal
        pure
        returns (string memory)
    {
        return string(LibBytes.slice(bytes(subject), start, end));
    }

    /// @dev Returns a copy of `subject` sliced from `start` to the end of the string.
    /// `start` is a byte offset.
    function slice(string memory subject, uint256 start) internal pure returns (string memory) {
        return string(LibBytes.slice(bytes(subject), start));
    }

    /// @dev Returns all the indices of `needle` in `subject`.
    /// The indices are byte offsets.
    function indicesOf(string memory subject, string memory needle)
        internal
        pure
        returns (uint256[] memory)
    {
        return LibBytes.indicesOf(bytes(subject), bytes(needle));
    }

    /// @dev Returns an arrays of strings based on the `delimiter` inside of the `subject` string.
    function split(string memory subject, string memory delimiter)
        internal
        pure
        returns (string[] memory)
    {
        return _toStrings(LibBytes.split(bytes(subject), bytes(delimiter)));
    }

    /// @dev Returns a concatenated string of `a` and `b`.
    /// Cheaper than `string.concat()` and does not de-align the free memory pointer.
    /// @custom:solar-inline always
    function concat(string memory a, string memory b) internal pure returns (string memory) {
        return string(LibBytes.concat(bytes(a), bytes(b)));
    }

    /// @dev Returns a copy of the string in either lowercase or UPPERCASE.
    /// WARNING! This function is only compatible with 7-bit ASCII strings.
    function toCase(string memory subject, bool toUpper)
        internal
        pure
        returns (string memory result)
    {
        bytes memory b = bytes(subject);
        uint256 n = b.length;
        if (n == 0) return result;
        // Either direction is the same single bit flip, applied a word at a
        // time. Flipping that bit in every byte first maps uppercase letters
        // onto the lowercase range, so both directions test one range. A
        // shorter string is one zero-padded word.
        uint256 flip = toUpper ? 0 : SPREAD_20;
        if (n < 32) {
            uint256 word = uint256(bytes32(b));
            bytes memory short = abi.encodePacked(bytes32(word ^ _caseFlips(word, flip)));
            _truncate(short, n);
            return string(short);
        }
        bytes memory out = new bytes(n);
        uint256 i;
        for (; i + 32 <= n; i += 32) {
            uint256 word = uint256(_readBytes32(b, i));
            _writeBytes32(out, i, bytes32(word ^ _caseFlips(word, flip)));
        }
        // The last word ends at the end of the string, repeating bytes already
        // converted with the same result.
        if (i < n) {
            uint256 word = uint256(_readBytes32(b, n - 32));
            _writeBytes32(out, n - 32, bytes32(word ^ _caseFlips(word, flip)));
        }
        _zeroPad(out);
        return string(out);
    }

    /// @dev Returns a string from a small bytes32 string.
    /// `s` must be null-terminated, or behavior will be undefined.
    function fromSmallString(bytes32 s) internal pure returns (string memory result) {
        // A null in the first eight bytes is found by testing them in turn,
        // which costs less than spreading and counting its marks. After eight
        // tests, spreading the marks still costs less than scanning to the
        // null a byte at a time, so no length pays more than a scan.
        if (s[0] == 0) return "";
        bytes32 word;
        uint256 length;
        if (s[1] == 0) {
            (word, length) = (s & bytes32(bytes1(0xff)), 1);
        } else if (s[2] == 0) {
            (word, length) = (s & bytes32(bytes2(0xffff)), 2);
        } else if (s[3] == 0) {
            (word, length) = (s & bytes32(bytes3(0xffffff)), 3);
        } else if (s[4] == 0) {
            (word, length) = (s & bytes32(bytes4(0xffffffff)), 4);
        } else if (s[5] == 0) {
            (word, length) = (s & bytes32(bytes5(0xffffffffff)), 5);
        } else if (s[6] == 0) {
            (word, length) = (s & bytes32(bytes6(0xffffffffffff)), 6);
        } else if (s[7] == 0) {
            (word, length) = (s & bytes32(bytes7(0xffffffffffffff)), 7);
        } else {
            uint256 tail = _nullTail(s);
            (word, length) = (s & bytes32(_smallStringMask(tail)), _smallStringLength(tail));
        }
        // The word is written whole, with the bytes from the null on cleared,
        // and the string then shortened to them.
        bytes memory out = abi.encodePacked(word);
        _truncate(out, length);
        return string(out);
    }

    /// @dev Returns the small string, with all bytes after the first null byte zeroized.
    function normalizeSmallString(bytes32 s) internal pure returns (bytes32 result) {
        // A null in the first seven bytes is found by testing them in turn,
        // which costs less than clearing from it with word operations; after
        // seven tests the word path costs less than a byte scan to the null.
        if (s[0] == 0) return 0;
        if (s[1] == 0) return s & bytes32(bytes1(0xff));
        if (s[2] == 0) return s & bytes32(bytes2(0xffff));
        if (s[3] == 0) return s & bytes32(bytes3(0xffffff));
        if (s[4] == 0) return s & bytes32(bytes4(0xffffffff));
        if (s[5] == 0) return s & bytes32(bytes5(0xffffffffff));
        if (s[6] == 0) return s & bytes32(bytes6(0xffffffffffff));
        // Otherwise each byte from the first zero byte on is cleared, spelled
        // out here so that the word path pays for no helper calls where the
        // helpers are shared.
        uint256 x = uint256(s);
        uint256 tail = ~(x | ((x & LANES_7F) + LANES_7F) | LANES_7F);
        tail |= tail >> 8;
        tail |= tail >> 16;
        tail |= tail >> 32;
        tail |= tail >> 64;
        tail |= tail >> 128;
        return s & bytes32(~((tail - (tail >> 7)) | tail));
    }

    /// @dev Returns the string as a normalized null-terminated small string.
    function toSmallString(string memory s) internal pure returns (bytes32 result) {
        bytes memory b = bytes(s);
        if (b.length > 32) revert TooBigForSmallString();
        return bytes32(b);
    }

    /// @dev Returns a lowercased copy of the string.
    /// WARNING! This function is only compatible with 7-bit ASCII strings.
    function lower(string memory subject) internal pure returns (string memory result) {
        return toCase(subject, false);
    }

    /// @dev Returns an UPPERCASED copy of the string.
    /// WARNING! This function is only compatible with 7-bit ASCII strings.
    function upper(string memory subject) internal pure returns (string memory result) {
        return toCase(subject, true);
    }

    /// @dev Escapes the string to be used within HTML tags.
    function escapeHTML(string memory s) internal pure returns (string memory result) {
        return _escapeHTML(s);
    }

    /// @dev Escapes the string to be used within double-quotes in a JSON.
    /// If `addDoubleQuotes` is true, the result will be enclosed in double-quotes.
    function escapeJSON(string memory s, bool addDoubleQuotes)
        internal
        pure
        returns (string memory result)
    {
        return _escapeJSON(s, addDoubleQuotes);
    }

    /// @dev Escapes the string to be used within double-quotes in a JSON.
    function escapeJSON(string memory s) internal pure returns (string memory result) {
        return _escapeJSON(s);
    }

    /// @dev Encodes `s` so that it can be safely used in a URI,
    /// just like `encodeURIComponent` in JavaScript.
    /// See: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
    /// See: https://datatracker.ietf.org/doc/html/rfc2396
    /// See: https://datatracker.ietf.org/doc/html/rfc3986
    function encodeURIComponent(string memory s) internal pure returns (string memory result) {
        return _encodeURIComponent(s);
    }

    /// @dev Returns whether `a` equals `b`.
    function eq(string memory a, string memory b) internal pure returns (bool result) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    /// @dev Returns whether `a` equals `b`, where `b` is a null-terminated small string.
    function eqs(string memory a, bytes32 b) internal pure returns (bool result) {
        bytes memory s = bytes(a);
        uint256 tail = _nullTail(b);
        // `b`'s null marks must start exactly where `a` ends.
        if (s.length > 32 || tail != _HIGH_BITS >> (s.length * 8)) return false;
        // The conversion pads `a` with zeros after its bytes, and the mask
        // clears `b` from its first null byte on.
        return bytes32(s) == b & bytes32(_smallStringMask(tail));
    }

    /// @dev Returns 0 if `a == b`, -1 if `a < b`, +1 if `a > b`.
    /// If `a` == b[:a.length]`, and `a.length < b.length`, returns -1.
    function cmp(string memory a, string memory b) internal pure returns (int256) {
        return LibBytes.cmp(bytes(a), bytes(b));
    }

    /// @dev Packs a single string with its length into a single word.
    /// Returns `bytes32(0)` if the length is zero or greater than 31.
    function packOne(string memory a) internal pure returns (bytes32 result) {
        return _packOne(a);
    }

    /// @dev Unpacks a string packed using {packOne}.
    /// Returns the empty string if `packed` is `bytes32(0)`.
    /// If `packed` is not an output of {packOne}, the output behavior is undefined.
    function unpackOne(bytes32 packed) internal pure returns (string memory result) {
        return _unpackOne(packed);
    }

    /// @dev Packs two strings with their lengths into a single word.
    /// Returns `bytes32(0)` if combined length is zero or greater than 30.
    function packTwo(string memory a, string memory b) internal pure returns (bytes32 result) {
        return _packTwo(a, b);
    }

    /// @dev Unpacks strings packed using {packTwo}.
    /// Returns the empty strings if `packed` is `bytes32(0)`.
    /// If `packed` is not an output of {packTwo}, the output behavior is undefined.
    function unpackTwo(bytes32 packed)
        internal
        pure
        returns (string memory resultA, string memory resultB)
    {
        return _unpackTwo(packed);
    }

    /// @dev Directly returns `a` without copying.
    function directReturn(string memory a) internal pure {
        _directReturn(a);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The thirty-two hex characters of the sixteen bytes in `x`, which
    /// must be below `2 ** 128`.
    function _hexWord(uint256 x) private pure returns (bytes32) {
        // Spread the thirty-two nibbles one to a byte, halving the packing
        // each step: eight bytes, four, two, one, then one nibble.
        x = (x | (x << 64)) & MASK_64;
        x = (x | (x << 32)) & MASK_32;
        x = (x | (x << 16)) & MASK_16;
        x = (x | (x << 8)) & MASK_8;
        x = (x | (x << 4)) & MASK_4;
        // Adding six carries every nibble above nine into the next bit, which
        // marks the ones that become letters rather than digits; `0x2a` more
        // makes the digits `0` to `9`.
        x += SPREAD_6;
        uint256 letters = (x >> 4) & SPREAD_1;
        return bytes32(x + SPREAD_2A + letters * 39);
    }

    /// @dev Spreads the thirty-two nibbles of the low sixteen bytes of `x` one to a byte,
    /// the highest nibble first, as `_hexWord` does before it turns them into digits. Kept
    /// apart from it so that the hex formatters' loops keep their inlined body.
    function _nibbles(uint256 x) private pure returns (uint256) {
        x = (x | (x << 64)) & MASK_64;
        x = (x | (x << 32)) & MASK_32;
        x = (x | (x << 16)) & MASK_16;
        x = (x | (x << 8)) & MASK_8;
        return (x | (x << 4)) & MASK_4;
    }

    /// @dev Whether every byte of `b` has its bit set in `allowed`.
    function _allowedBytes(bytes memory b, uint256 allowed) private pure returns (bool) {
        for (uint256 i; i < b.length; ++i) {
            if (((allowed >> uint8(b[i])) & 1) == 0) return false;
        }
        return true;
    }

    /// @dev `0x20` in each byte of `word` that is a lowercase letter once
    /// `flip` is applied. A byte's low seven bits plus `0x80 - x` reach its
    /// high bit exactly when they are at least `x`, and never carry into the
    /// next byte; bytes of `0x80` and above are no letters.
    function _caseFlips(uint256 word, uint256 flip) private pure returns (uint256) {
        uint256 low = (word ^ flip) & LANES_7F;
        // `a` through `z` are 0x61 through 0x7a.
        uint256 letters = (low + SPREAD_1F) ^ (low + SPREAD_5);
        return (letters & ~word & _HIGH_BITS) >> 2;
    }

    /// @dev Uppercases every letter of the hex `chars` whose lane of `nibbles` is at least
    /// eight. Adding 0x1f sets the top bit of a letter's lane, 0x61 to 0x66, and of no digit's
    /// or empty lane; the nibble's bit three shifted up is the other condition, and taking
    /// 0x20 off a marked lane is the case change.
    function _checksumCase(uint256 chars, uint256 nibbles) private pure returns (uint256) {
        uint256 letters = (chars + SPREAD_1F) & _HIGH_BITS;
        uint256 marked = letters & ((nibbles << 4) & _HIGH_BITS);
        return chars - (marked >> 2);
    }

    /// @dev Returns the length of a small string up to its first null byte,
    /// from the string's `_nullTail` marks.
    function _smallStringLength(uint256 tail) private pure returns (uint256) {
        // One mark for each byte from the first zero byte on; the bytes before
        // it are the string. Multiplying the marks, one per byte, by a one in
        // every byte sums them into the top byte, modulo `2**256` on purpose:
        // no byte of the product exceeds 32, so no sum carries into another.
        return 32 - (_rawMul(tail >> 7, LANES_01) >> 248);
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

    /// @dev `value` in decimal after a `-` when `negative`. The digits come eight
    /// at a time from the low end, each group spread one digit to a byte by
    /// `_decimalGroup` and shifted into the top of a word, four groups to a word.
    /// The top group loses its leading zeros, and the output is three words,
    /// written whole and cut to the digits, with the full words shifted into
    /// place after the sign and the top word's digits.
    /// @custom:solar-inline always
    function _decimal(uint256 value, bool negative) private pure returns (string memory) {
        // One digit, after the sign, is written directly.
        if (value < 10) {
            if (negative) return _shortString((0x2d30 + value) << 240, 2);
            return _shortString((0x30 + value) << 248, 1);
        }
        uint256 top;
        // The full words, the more significant one first.
        uint256 high;
        uint256 low;
        uint256 full;
        // The groups the top word still has room for.
        uint256 slots = 4;
        uint256 last;
        do {
            if (slots == 0) {
                (low, high, top, slots) = (high, top, 0, 4);
                full += 32;
            }
            last = value % 1e8;
            value /= 1e8;
            top = (top >> 64) | ((_decimalGroup(last) | (SPREAD_ASCII_0 >> 192)) << 192);
            --slots;
        } while (value != 0);
        // The top group's leading zeros, and the bits of the top word without
        // digits: its empty groups and those zeros.
        uint256 zeros;
        if (last < 1e4) {
            zeros = 4;
            last *= 1e4;
        }
        if (last < 1e6) {
            zeros += 2;
            last *= 100;
        }
        if (last < 1e7) ++zeros;
        top <<= zeros << 3;
        uint256 empty = (slots << 6) | (zeros << 3);
        bytes memory out;
        if (negative) {
            if (empty == 0) {
                // A full top word, of a magnitude below `2**255` with at most one
                // full word after it, leaves the sign a word of its own.
                out = abi.encodePacked(
                    bytes32((0x2d << 248) | (top >> 8)),
                    bytes32((top << 248) | (high >> 8)),
                    bytes32(high << 248)
                );
                _setLength(out, 33 + full);
                return string(out);
            }
            top = (0x2d << 248) | (top >> 8);
            empty -= 8;
        }
        uint256 used = 256 - empty;
        out = abi.encodePacked(
            bytes32(top | (high >> used)),
            bytes32((high << empty) | (low >> used)),
            bytes32(low << empty)
        );
        _setLength(out, (used >> 3) + full);
        return string(out);
    }

    /// @dev The eight decimal digits of `x`, which must be below `10**8`, one to a
    /// byte in the low eight bytes, the most significant first: two halves, then
    /// quarters, then single digits, each split by a multiply by the divisor's
    /// reciprocal, which is exact for its lane's range and stays inside the lane.
    /// @custom:solar-inline always
    function _decimalGroup(uint256 x) private pure returns (uint256 y) {
        y = ((x / 1e4) << 32) | (x % 1e4);
        // `ceil(2**20 / 100)` and `ceil(2**10 / 10)`; `2**16 - 100` and `2**8 - 10`
        // move each quotient up beside its remainder.
        y += _rawMul((_rawMul(y, 10486) >> 20) & 0x7f0000007f, 0xff9c);
        y += _rawMul((_rawMul(y, 103) >> 10) & 0xf000f000f000f, 246);
    }

    /// @dev `s` with every character JSON requires escaped, without quotes.
    function _escapeJSON(string memory s) private pure returns (string memory) {
        return _escapeJSON(s, false);
    }

    /// @dev `s` with the quote, the backslash and the control characters
    /// escaped, as the short forms where JSON has them and `\u00XX` elsewhere,
    /// enclosed in double quotes when `addDoubleQuotes`. The input is read and
    /// written a word at a time, with the bytes to escape marked in one step;
    /// each run of marked bytes is then written over the word, an escape after
    /// another, and the rest of the word after the run. The output has room for
    /// six characters per input byte, two quotes and a word of slack, so every
    /// piece can be a whole word whose bytes past the piece the next piece, or
    /// the final zeros, overwrite.
    function _escapeJSON(string memory s, bool addDoubleQuotes)
        private
        pure
        returns (string memory)
    {
        bytes memory input = bytes(s);
        uint256 n = input.length;
        bytes memory out = new bytes(n * 6 + 34);
        // The characters the escapes add to the bytes they replace, and the
        // opening quote: the word at `i` goes to `i + extra`.
        uint256 extra;
        if (addDoubleQuotes) {
            out[0] = '"';
            extra = 1;
        }
        for (uint256 i; i < n; i += 32) {
            // The zero padding past the end reads as control bytes.
            uint256 w = _wordAt(input, i);
            uint256 marks = _jsonSpecials(w) & ~(type(uint256).max >> ((n - i) << 3));
            uint256 o = i + extra;
            _writeBytes32(out, o, bytes32(w));
            while (marks != 0) {
                // Past the bytes before the next one to escape, already
                // written, then each one of the run it starts, and the rest of
                // the word after the run.
                uint256 k = _firstMark(marks);
                o += k;
                w <<= k << 3;
                marks <<= k << 3;
                do {
                    (bytes32 escape, uint256 size) = _jsonEscape(w >> 248);
                    _writeBytes32(out, o, escape);
                    o += size;
                    extra += size - 1;
                    w <<= 8;
                    marks <<= 8;
                } while (marks >> 255 != 0);
                _writeBytes32(out, o, bytes32(w));
            }
        }
        uint256 end = n + extra;
        if (addDoubleQuotes) out[end++] = '"';
        _truncate(out, end);
        return string(out);
    }

    /// @dev The JSON escape of the byte `c`, which is `"`, `\` or below 0x20,
    /// left-aligned, and its length.
    /// @custom:solar-inline always
    function _jsonEscape(uint256 c) private pure returns (bytes32, uint256) {
        // `\"`, `\\`, `\b`, `\t`, `\n`, `\f` and `\r`, by the byte's low five bits.
        if ((_JSON_SHORT_ESCAPED >> c) & 1 != 0) {
            return (bytes32((0x5c00 | uint256(uint8(_JSON_SHORT_ESCAPES[c & 31]))) << 240), 2);
        }
        // `\u00` and two lowercase hexadecimal digits, the first `0` or `1`.
        return (
            bytes32(
                (0x5c7530300000 | ((0x30 + (c >> 4)) << 8) | uint256(uint8(_DIGITS[c & 15]))) << 208
            ),
            6
        );
    }

    /// @dev `s` with the characters HTML gives meaning to replaced by their
    /// entities: `&quot;`, `&amp;`, `&#39;`, `&lt;` and `&gt;`. Read a word at a
    /// time as `_escapeJSON` reads its input, with room for six characters per
    /// input byte and a word of slack.
    function _escapeHTML(string memory s) private pure returns (string memory) {
        bytes memory input = bytes(s);
        uint256 n = input.length;
        bytes memory out = new bytes(n * 6 + 32);
        // The characters the entities add to the bytes they replace: the word
        // at `i` goes to `i + extra`.
        uint256 extra;
        for (uint256 i; i < n; i += 32) {
            // No zero byte is one to replace, so the padding past the end
            // needs no mask.
            uint256 w = _wordAt(input, i);
            uint256 marks = _htmlSpecials(w);
            uint256 o = i + extra;
            _writeBytes32(out, o, bytes32(w));
            while (marks != 0) {
                uint256 k = _firstMark(marks);
                o += k;
                w <<= k << 3;
                marks <<= k << 3;
                do {
                    (bytes32 entity, uint256 size) = _htmlEntity(w >> 248);
                    _writeBytes32(out, o, entity);
                    o += size;
                    extra += size - 1;
                    w <<= 8;
                    marks <<= 8;
                } while (marks >> 255 != 0);
                _writeBytes32(out, o, bytes32(w));
            }
        }
        _truncate(out, n + extra);
        return string(out);
    }

    /// @dev The HTML entity of the byte `c`, which is one `escapeHTML` replaces,
    /// left-aligned, and its length: the byte's low five bits pick the entity's
    /// length and offset in the string of all five.
    /// @custom:solar-inline always
    function _htmlEntity(uint256 c) private pure returns (bytes32, uint256) {
        uint256 t = uint8(_HTML_ENTITY_SPANS[c & 31]);
        return (_HTML_ENTITIES << ((t & 31) << 3), t >> 5);
    }

    /// @dev The bytes of `b` from `offset`, which must be before its end, up to a word,
    /// left-aligned and zero past the end. Untagged, unlike `_readBytesN`, as is
    /// `_firstMark`: a build for gas still inlines both, and a build for size keeps
    /// one copy of each instead of one per escaping loop, whose repeats its
    /// outliner would share with the other functions' copies.
    function _wordAt(bytes memory b, uint256 offset) private pure returns (uint256) {
        return uint256(_readBytesN(b, offset, b.length - offset));
    }

    /// @dev The index, from the top, of the first byte of `marks` with its top
    /// bit set. `marks` has only top bits set, and at least one: spread down to
    /// every later byte, the marks leave unmarked exactly the bytes before the
    /// first, which a multiplication by a one in every byte counts into the top
    /// byte, as in `_smallStringLength`.
    function _firstMark(uint256 marks) private pure returns (uint256) {
        marks |= marks >> 8;
        marks |= marks >> 16;
        marks |= marks >> 32;
        marks |= marks >> 64;
        marks |= marks >> 128;
        return _rawMul((~marks & _HIGH_BITS) >> 7, LANES_01) >> 248;
    }

    /// @dev `s` as a URI component, like JavaScript's `encodeURIComponent`:
    /// every byte other than the letters, the digits and `-_.!~*'()` becomes
    /// `%` and two uppercase hexadecimal digits. Read a word at a time as
    /// `_escapeJSON` reads its input, with room for three characters per input
    /// byte and a word of slack.
    function _encodeURIComponent(string memory s) private pure returns (string memory) {
        bytes memory input = bytes(s);
        uint256 n = input.length;
        bytes memory out = new bytes(n * 3 + 32);
        // Two characters for each byte encoded so far: the word at `i` goes to
        // `i + extra`.
        uint256 extra;
        for (uint256 i; i < n; i += 32) {
            // The zero padding past the end reads as bytes to encode.
            uint256 w = _wordAt(input, i);
            uint256 marks = _uriEscaped(w) & ~(type(uint256).max >> ((n - i) << 3));
            uint256 o = i + extra;
            _writeBytes32(out, o, bytes32(w));
            while (marks != 0) {
                uint256 k = _firstMark(marks);
                o += k;
                w <<= k << 3;
                marks <<= k << 3;
                do {
                    uint256 c = w >> 248;
                    _writeBytes32(
                        out,
                        o,
                        bytes32(
                            (0x250000
                                    | (uint256(uint8(_UPPER_HEX[c >> 4])) << 8)
                                    | uint256(uint8(_UPPER_HEX[c & 15]))) << 232
                        )
                    );
                    o += 3;
                    extra += 2;
                    w <<= 8;
                    marks <<= 8;
                } while (marks >> 255 != 0);
                _writeBytes32(out, o, bytes32(w));
            }
        }
        _truncate(out, n + extra);
        return string(out);
    }

    /// @dev `0x80` in each byte of `w` that `encodeURIComponent` encodes, and
    /// zero in every other byte: the bytes with the top bit set, and the ones
    /// outside the letters, the digits and `-_.!~*'()`. Without the case bit the
    /// letters are one range, `'()*` and `-.` are ranges too, and `_` and `~`
    /// are tested with bit three flipped, so that no two tests share a
    /// constant.
    function _uriEscaped(uint256 w) private pure returns (uint256) {
        uint256 low = w & LANES_7F;
        uint256 flipped = low ^ (0x08 * LANES_01);
        uint256 kept = _inRange(low & (0xdf * LANES_01), 0x41, 0x5a) | _inRange(low, 0x30, 0x39)
            | _inRange(low, 0x27, 0x2a) | _inRange(low, 0x2d, 0x2e) | _inRange(low, 0x21, 0x21)
            | _inRange(flipped, 0x57, 0x57) | _inRange(flipped, 0x76, 0x76);
        return (~kept | w) & _HIGH_BITS;
    }

    /// @dev The top bit of each byte of `low`, whose bytes are below 0x80, that is
    /// at least `a` and at most `b`, with other bits set below it: adding
    /// `0x80 - a` reaches a byte's top bit exactly when it is at least `a`, adding
    /// `0x7f - b` exactly when it is above `b`, and neither carries into the
    /// next byte.
    /// @custom:solar-inline always
    function _inRange(uint256 low, uint256 a, uint256 b) private pure returns (uint256) {
        return (low + (0x80 - a) * LANES_01) & ~(low + (0x7f - b) * LANES_01);
    }

    /// @dev `0x80` in each byte of `z` that is zero, and zero in every other
    /// byte: the low seven bits of a byte plus `0x7f` carry into its top bit
    /// unless they are all clear, and never into the next byte.
    /// @custom:solar-inline always
    function _zeroBytes(uint256 z) private pure returns (uint256) {
        return ~(((z & LANES_7F) + LANES_7F) | z | LANES_7F);
    }

    /// @dev Nonzero when a byte of `w` is one `escapeHTML` replaces. `&` and
    /// `'` differ in the low bit, `<` and `>` in the next one.
    /// @custom:solar-inline always
    function _htmlSpecials(uint256 w) private pure returns (uint256) {
        return _zeroBytes(w ^ (0x22 * LANES_01)) | _zeroBytes((w | LANES_01) ^ (0x27 * LANES_01))
            | _zeroBytes((w | (0x02 * LANES_01)) ^ (0x3e * LANES_01));
    }

    /// @dev Nonzero when a byte of `w` is one `escapeJSON` escapes: `"`, `\`,
    /// or below 0x20, which neither has its top bit set nor reaches it by
    /// adding 0x60 to its low seven bits.
    /// @custom:solar-inline always
    function _jsonSpecials(uint256 w) private pure returns (uint256) {
        return _zeroBytes(w ^ (0x22 * LANES_01)) | _zeroBytes(w ^ (0x5c * LANES_01))
            | (~(((w & LANES_7F) + 0x60 * LANES_01) | w) & _HIGH_BITS);
    }

    /// @dev The number of UTF-8 runes in `subject`. Each rune is stepped over by
    /// the length its lead byte declares from the byte's top six bits: one below
    /// 0x80, two up to 0xdf (a stray continuation byte included), then three,
    /// four, five and six. Malformed text is counted by the same steps.
    function _runeCount(string memory subject) private pure returns (uint256 count) {
        bytes memory s = bytes(subject);
        // One nibble per value of the top six bits, at four times that value.
        uint256 lengths = 0x6544333322222222222222222222222211111111111111111111111111111111;
        for (uint256 i; i < s.length; ++count) {
            // A word of bytes below 0x80 is 32 runes of one byte each.
            while (s.length - i >= 32 && uint256(_readBytes32(s, i)) & _HIGH_BITS == 0) {
                count += 32;
                i += 32;
            }
            if (i == s.length) break;
            i += (lengths >> (uint8(s[i]) & 0xfc)) & 15;
        }
    }

    /// @dev The low `byteCount` bytes of `value` as lowercase hexadecimal, two
    /// digits per byte, without a prefix. `value` must fit in them, which
    /// `_checkHexLength` checks for a caller's `byteCount`.
    function _toHexStringNoPrefix(uint256 value, uint256 byteCount)
        private
        pure
        returns (string memory)
    {
        if (byteCount < 33) return _hexString(value, 2 * byteCount, false);
        bytes memory out = new bytes(byteCount * 2);
        _hexInto(out, 0, value, byteCount);
        _zeroPad(out);
        return string(out);
    }

    /// @dev `_toHexStringNoPrefix(value, byteCount)` after `0x`.
    function _toHexString(uint256 value, uint256 byteCount) private pure returns (string memory) {
        if (byteCount < 33) return _hexString(value, 2 * byteCount, true);
        bytes memory out = new bytes(byteCount * 2 + 2);
        (out[0], out[1]) = ("0", "x");
        _hexInto(out, 2, value, byteCount);
        _zeroPad(out);
        return string(out);
    }

    /// @dev `value` as lowercase hexadecimal in its fewest whole bytes, at
    /// least one, without a prefix.
    function _toHexStringNoPrefix(uint256 value) private pure returns (string memory) {
        return _toHexStringNoPrefix(value, _byteLength(value));
    }

    /// @dev `_toHexStringNoPrefix(value)` after `0x`.
    function _toHexString(uint256 value) private pure returns (string memory) {
        return _toHexString(value, _byteLength(value));
    }

    /// @dev The fewest whole bytes that hold `value`, at least one.
    function _byteLength(uint256 value) private pure returns (uint256) {
        return (_nibbleLength(value) + 1) >> 1;
    }

    /// @dev The fewest hexadecimal digits that spell `value`, at least one,
    /// found by halving the remaining width.
    function _nibbleLength(uint256 value) private pure returns (uint256 n) {
        n = 1;
        if (value >> 128 != 0) {
            value >>= 128;
            n += 32;
        }
        if (value >> 64 != 0) {
            value >>= 64;
            n += 16;
        }
        if (value >> 32 != 0) {
            value >>= 32;
            n += 8;
        }
        if (value >> 16 != 0) {
            value >>= 16;
            n += 4;
        }
        if (value >> 8 != 0) {
            value >>= 8;
            n += 2;
        }
        if (value >> 4 != 0) ++n;
    }

    /// @dev Reverts with `HexLengthInsufficient()` when `value` does not fit in
    /// its low `byteCount` bytes. The functions taking a caller's `byteCount`
    /// check it before they allocate the digits, which a failing call does
    /// not need; a length found from `value` always fits.
    function _checkHexLength(uint256 value, uint256 byteCount) private pure {
        if (byteCount < 32 && value >> (8 * byteCount) != 0) revert HexLengthInsufficient();
    }

    /// @dev Writes `byteCount` bytes of `value`, more than a word's 32, into `out` at
    /// `offset` as `2 * byteCount` lowercase hexadecimal digits, ending at `out`'s end:
    /// `0` characters for the bytes above the word, a word of them at a time, then the
    /// word's 64 digits, which overwrite the last word of `0`s where they overlap.
    function _hexInto(bytes memory out, uint256 offset, uint256 value, uint256 byteCount)
        private
        pure
    {
        uint256 digits = offset + 2 * byteCount - 64;
        for (uint256 o = offset; o < digits; o += 32) {
            _writeBytes32(out, o, bytes32(SPREAD_ASCII_0));
        }
        _writeBytes32(out, digits, _hexWord(value >> 128));
        _writeBytes32(out, digits + 32, _hexWord(value & type(uint128).max));
    }

    /// @dev Minimal lowercase hexadecimal digits without a prefix.
    function _toMinimalHexStringNoPrefix(uint256 value) private pure returns (string memory) {
        return _hexString(value, _nibbleLength(value), false);
    }

    /// @dev Minimal lowercase hexadecimal digits after `0x`.
    function _toMinimalHexString(uint256 value) private pure returns (string memory) {
        return _hexString(value, _nibbleLength(value), true);
    }

    /// @dev The last `n` of the 64 lowercase hexadecimal digits of `value`, after
    /// `0x` when `prefixed`, where the prefix and the digits beyond the 32 of the
    /// low 16 bytes take at most a word: the head word holds them, and the low
    /// digits follow, spilling into a second word when the head leaves too
    /// little room. `value` must fit in the `n` digits.
    function _hexString(uint256 value, uint256 n, bool prefixed)
        private
        pure
        returns (string memory)
    {
        uint256 p = prefixed ? 2 : 0;
        uint256 head = prefixed ? 0x3078 << 240 : 0;
        if (n + p < 33) {
            // `value` is below `2**128`, and all its digits fit the head word.
            return
                _shortString(head | ((uint256(_hexWord(value)) << (256 - 8 * n)) >> (8 * p)), n + p);
        }
        // The low 16 bytes' digits and the high bytes' ones, left-aligned.
        uint256 lo = uint256(_hexWord(value & type(uint128).max));
        uint256 high;
        uint256 a = p;
        if (n > 32) {
            a += n - 32;
            high = uint256(_hexWord(value >> 128)) << (512 - 8 * n);
        } else {
            lo <<= 256 - 8 * n;
        }
        head |= high >> (8 * p);
        bytes memory out;
        if (a < 33) {
            out = abi.encodePacked(bytes32(head | (lo >> (8 * a))), bytes32(lo << (256 - 8 * a)));
        } else {
            // The prefix and 31 or 32 high digits overflow the head word into a
            // second one, before the low digits.
            a -= 32;
            out = abi.encodePacked(
                bytes32(head),
                bytes32((high << (256 - 8 * p)) | (lo >> (8 * a))),
                bytes32(lo << (256 - 8 * a))
            );
        }
        _setLength(out, n + p);
        return string(out);
    }

    /// @dev The leading `n` bytes of `word`, whose other bytes are zero, as a
    /// string: the word written whole, then the length cut to them.
    /// @custom:solar-inline always
    function _shortString(uint256 word, uint256 n) private pure returns (string memory) {
        bytes memory out = abi.encodePacked(bytes32(word));
        _setLength(out, n);
        return string(out);
    }

    /// @dev The digits of `data`, without a prefix.
    function _hexEncode(bytes memory data) private pure returns (string memory) {
        bytes memory out = new bytes(data.length * 2);
        _hexEncodeInto(out, 0, data);
        _zeroPad(out);
        return string(out);
    }

    /// @dev The digits of `data` after `0x`.
    function _hexEncodePrefixed(bytes memory data) private pure returns (string memory) {
        bytes memory out = new bytes(data.length * 2 + 2);
        (out[0], out[1]) = ("0", "x");
        _hexEncodeInto(out, 2, data);
        _zeroPad(out);
        return string(out);
    }

    /// @dev Writes the digits of `data` into `out` from `start`. Sixteen bytes
    /// make one word of digits; a remainder is one more block pulled back to
    /// end where the input ends, and an input below sixteen bytes goes a byte
    /// at a time.
    function _hexEncodeInto(bytes memory out, uint256 start, bytes memory data) private pure {
        uint256 n = data.length;
        uint256 i;
        uint256 o = start;
        while (i + 16 <= n) {
            _writeBytes32(out, o, _hexWord(uint128(_readBytes16(data, i))));
            i += 16;
            o += 32;
        }
        if (i == n) return;
        if (n >= 16) {
            uint256 last = n - 16;
            _writeBytes32(out, start + last * 2, _hexWord(uint128(_readBytes16(data, last))));
            return;
        }
        for (; i < n; ++i) {
            uint256 x = uint8(data[i]);
            out[o] = _DIGITS[x >> 4];
            out[o + 1] = _DIGITS[x & 15];
            o += 2;
        }
    }

    /// @dev Packs a nonempty string of at most 31 bytes into one word. The
    /// first byte is its length and the remaining bytes are its contents.
    function _packOne(string memory value) private pure returns (bytes32 result) {
        bytes memory input = bytes(value);
        if (input.length == 0 || input.length > 31) return 0;
        // The length byte, then the contents in the rest of the word.
        result = bytes32(input.length << 248) | (_readBytesN(input, 0, input.length) >> 8);
    }

    /// @dev Reconstructs a string produced by `_packOne`.
    function _unpackOne(bytes32 packed) private pure returns (string memory result) {
        uint256 n = uint8(packed[0]);
        if (n > 31) n = 31;
        // The contents after the length byte, cut to `n` bytes, in one fresh word.
        bytes memory out = abi.encodePacked((packed << 8) & ~bytes32(type(uint256).max >> (n << 3)));
        _setLength(out, n);
        return string(out);
    }

    /// @dev Packs two strings whose combined length is 1..30 bytes into one
    /// word. Each string is preceded by one length byte.
    function _packTwo(string memory a, string memory b) private pure returns (bytes32 result) {
        bytes memory x = bytes(a);
        bytes memory y = bytes(b);
        uint256 total = x.length + y.length;
        if (total == 0 || total > 30) return 0;
        // Each length byte, then its string's contents.
        result = bytes32(x.length << 248) | (_readBytesN(x, 0, x.length) >> 8)
            | bytes32(y.length << ((30 - x.length) * 8))
            | (_readBytesN(y, 0, y.length) >> ((x.length + 2) * 8));
    }

    /// @dev Reconstructs two strings produced by `_packTwo`.
    function _unpackTwo(bytes32 packed)
        private
        pure
        returns (string memory resultA, string memory resultB)
    {
        uint256 aLength = uint8(packed[0]);
        if (aLength > 30) aLength = 30;
        // Each string's contents, cut to its length, in one fresh word.
        bytes memory a =
            abi.encodePacked((packed << 8) & ~bytes32(type(uint256).max >> (aLength << 3)));
        _setLength(a, aLength);
        uint256 bLength = uint8(packed[aLength + 1]);
        if (bLength > 30 - aLength) bLength = 30 - aLength;
        bytes memory b = abi.encodePacked(
            (packed << ((aLength + 2) * 8)) & ~bytes32(type(uint256).max >> (bLength << 3))
        );
        _setLength(b, bLength);
        return (string(a), string(b));
    }

    /// @dev `x * y` modulo `2**256`.
    /// @custom:solar-trusted
    function _rawMul(uint256 x, uint256 y) private pure returns (uint256 z) {
        unchecked {
            z = x * y;
        }
    }

    /// @dev Shrinks `b` to its first `n` bytes in place and clears the rest of
    /// its last word, so the bytes past the new end read as zero padding.
    /// Solidity cannot spell a shorter length for an existing buffer.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _truncate(bytes memory b, uint256 n) private pure {
        if (n > b.length) n = new uint256[](0)[0];
        /// @solidity memory-safe-assembly
        assembly {
            mstore(b, n)
            mstore(add(add(b, 0x20), n), 0)
        }
    }

    /// @dev Shrinks `b` to its first `n` bytes in place. The caller has cleared the
    /// bytes past `n` in its last word, so they read as zero padding.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _setLength(bytes memory b, uint256 n) private pure {
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

    /// @dev Ends the call, returning `s` ABI-encoded as the single result of a
    /// function that returns `string`. A `return` statement leaves only the
    /// function it is in.
    /// @custom:solar-trusted
    function _directReturn(string memory s) private pure {
        bytes memory data = abi.encode(s);
        /// @solidity memory-safe-assembly
        assembly {
            return(add(data, 0x20), mload(data))
        }
    }

    /// @dev The 16 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes16(bytes memory b, uint256 offset) private pure returns (bytes16 result) {
        for (uint256 k; k < 16; ++k) {
            result |= bytes16(b[offset + k]) >> (8 * k);
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

    /// @dev `a` as strings: the same words, each a pointer to bytes, which
    /// Solidity cannot convert in place.
    /// @custom:solar-trusted
    function _toStrings(bytes[] memory a) private pure returns (string[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := a
        }
    }
}
