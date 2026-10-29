// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for comparing SemVers.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SemVerLib.sol)
/// @dev The checked port reads each version from the top of a word that it shifts left as it
/// goes, so the bytes past the 32 read as zero, as upstream's `byte` reads them. It orders
/// numbers without computing them: the digits of a number, at most 32, are the digits of a
/// base-256 number, one to a byte, which orders as the decimal number does, leading zeros
/// included. An identifier that is not numeric orders as its bytes left-aligned in a word,
/// which is what upstream copies through scratch memory, and a word-at-a-time test tells
/// whether an identifier is numeric. It needs no trusted helper.
/// @custom:solar-safe memory arithmetic
library SemVerLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         COMPARISON                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns -1 if `a < b`, 0 if `a == b`, 1 if `a > b`.
    /// For efficiency, this is a forgiving, non-reverting parser:
    /// - Early returns if a strict order can be determined.
    /// - Skips the first byte if it is `v` (case insensitive).
    /// - If a strict order cannot be determined, returns 0.
    /// To convert a regular string to a small string (bytes32), use `LibString.toSmallString`.
    function cmp(bytes32 a, bytes32 b) internal pure returns (int256 result) {
        // The unread rest of each version, its next byte on top.
        uint256 s = uint256(a);
        uint256 t = uint256(b);
        if ((s >> 248) | 32 == 118) s <<= 8; // `v`, `V`.
        if ((t >> 248) | 32 == 118) t <<= 8; // `v`, `V`.
        uint256 x;
        uint256 y;
        (x, s) = _number(s);
        (y, t) = _number(t);
        // The `.`-separated numbers that follow, while equal, a missing one counting as zero.
        while (x == y) {
            bool u = s >> 248 == 46; // `.`
            bool v = t >> 248 == 46; // `.`
            if (!(u || v)) break;
            x = 0;
            y = 0;
            if (u) (x, s) = _number(s << 8);
            if (v) (y, t) = _number(t << 8);
        }
        if (x != y) return x < y ? -1 : int256(1);
        // A pre-release precedes its release.
        bool more = s >> 248 == 45; // `-`
        if (more != (t >> 248 == 45)) return more ? -1 : int256(1);
        // The `.`-separated pre-release identifiers, while both have another.
        while (more) {
            bool p;
            bool q;
            (p, x, s) = _identifier(s << 8);
            (q, y, t) = _identifier(t << 8);
            // A numeric identifier precedes one that is not.
            if (p != q) return p ? int256(1) : -1;
            if (x != y) return x < y ? -1 : int256(1);
            more = s >> 248 == 46; // `.`
            if (more != (t >> 248 == 46)) return more ? int256(1) : -1;
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The low four bits of every byte.
    uint256 private constant _LOW_NIBBLES =
        0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;

    /// @dev The low seven bits of every byte.
    uint256 private constant _LOW_BITS =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    /// @dev The top bit of every byte.
    uint256 private constant _HIGH_BITS =
        0x8080808080808080808080808080808080808080808080808080808080808080;

    /// @dev The number that the digits at the top of `w` spell in base 256, which orders as
    /// their decimal number does, and `w` after them.
    /// @custom:solar-inline always
    function _number(uint256 w) private pure returns (uint256 r, uint256 rest) {
        while (true) {
            uint256 digit = (w >> 248) ^ 48;
            if (digit > 9) break;
            r = (r << 8) | digit;
            w <<= 8;
        }
        rest = w;
    }

    /// @dev Parses the pre-release identifier at the top of `w`, which ends at a `\x00`, `.`
    /// or `+`. Returns whether it has a byte that is not a digit; if it has, its bytes
    /// left-aligned in a word, else the number its digits spell in base 256; and `w` after it.
    /// @custom:solar-inline always
    function _identifier(uint256 w)
        private
        pure
        returns (bool hasNonDigit, uint256 r, uint256 rest)
    {
        uint256 bits;
        rest = w;
        // Up to a `\x00`, `.` or `+`.
        while ((1 << (rest >> 248)) & 0x480000000001 == 0) {
            rest <<= 8;
            bits += 8;
        }
        uint256 keep = ~(type(uint256).max >> bits);
        r = w & keep;
        // The top bit of each byte of `r` that is a digit: at least `0` and at most `9`,
        // each byte apart, as no carry leaves a byte.
        uint256 low = r & _LOW_BITS;
        uint256 digits = (low + 0x5050505050505050505050505050505050505050505050505050505050505050)
            & ~(low + 0x4646464646464646464646464646464646464646464646464646464646464646) & ~r
            & _HIGH_BITS;
        hasNonDigit = digits != keep & _HIGH_BITS;
        if (!hasNonDigit) r = (r >> (256 - bits)) & _LOW_NIBBLES;
    }
}
