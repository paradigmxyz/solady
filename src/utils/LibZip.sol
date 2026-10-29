// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for compressing and decompressing bytes.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibZip.sol)
/// @author Calldata compression by clabby (https://github.com/clabby/op-kompressor)
/// @author FastLZ by ariya (https://github.com/ariya/FastLZ)
///
/// @dev Note:
/// The accompanying solady.js library includes implementations of
/// FastLZ and calldata operations for convenience.
///
/// The checked port runs upstream's algorithms a word at a time. Each function reads its input, for
/// `cdFallback` the calldata, from a copy with a zero word after it, which keeps the words read
/// near its end in bounds, and writes whole words into an output buffer with room to spare, the
/// bytes of a word past its step replaced by the next step's word; the trusted `_truncate` then
/// sets the output's length. `cdCompress` and `cdFallback` keep the copy in the output's buffer,
/// after the room for the output. FastLZ keeps upstream's 8192-entry hash table, packing each
/// offset into 8, 16, or 32 bits according to the input length, measures matches a word at a time,
/// and copies a repeat shorter than a match as a word of whole repeats. The decompressors grow
/// their output as it fills. `cdDecompress` reads the byte after its input with the trusted
/// `_byteAfter`, as upstream reads it for the length of a run whose `0x00` ends the input, and
/// `cdFallback` ends the call with the trusted `_return` and `_returnCall`. Deliberate differences,
/// on input the compressors never write: a `0xff` run longer
/// than 32 bytes goes on with zeros where upstream leaves the memory there as it was, and
/// `flzDecompress` reads zeros past the end of its input where upstream reads the memory after it,
/// and reverts with `Panic(0x11)` for a match that starts before its output, where upstream reads
/// the memory before it.
/// @custom:solar-safe memory arithmetic
library LibZip {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     FAST LZ OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // LZ77 implementation based on FastLZ.
    // Equivalent to level 1 compression and decompression at the following commit:
    // https://github.com/ariya/FastLZ/commit/344eb4025f9ae866ebf7a2ec48850f7113a97a42
    // Decompression is backwards compatible.

    /// @dev Returns the compressed `data`.
    function flzCompress(bytes memory data) internal pure returns (bytes memory result) {
        uint256 n = data.length;
        // Literal runs take one control byte per 32 bytes, and a match fewer bytes than it
        // covers, so the output is at most this long; the last write may reach a word past it.
        result = new bytes(n + (n + 31) / 32 + 32);
        // The output offset, and the offset of the first input byte not yet written.
        uint256 op;
        uint256 a;
        {
            // `data`, and a zero word after it, which the reads near its end reach.
            bytes memory x = bytes.concat(data, bytes32(0));
            if (n > 15) {
                // Every recorded offset is below n. Keep all 8192 buckets, using only the
                // bits needed for this input; large inputs retain upstream's 32-bit offsets.
                // The low byte holds log2(entry bits), and the upper bytes hold their mask.
                uint256 format = n <= 0x100 ? 0xff03 : n <= 0x10000 ? 0xffff04 : 0xffffffff05;
                uint256[] memory htab = new uint256[](uint256(32) << (format & 7));
                uint256 ipLimit = n - 13;
                for (uint256 ip = 2; ip < ipLimit;) {
                    uint256 r;
                    uint256 l;
                    (ip, r, l) = _find(x, htab, ip, ipLimit, format);
                    if (ip >= ipLimit) break;
                    --ip;
                    if (ip > a) op = _literals(result, op, x, a, ip - a);
                    op = _match(result, op, l, ip - r);
                    // Hash the two offsets after the match, from one word.
                    ip += l;
                    uint256 w = uint256(_readBytes32(x, ip));
                    _swapHash(htab, _hash(w >> 232), ip, format);
                    _swapHash(htab, _hash((w >> 224) & 0xffffff), ip + 1, format);
                    a = ip += 2;
                }
            }
            op = _literals(result, op, x, a, n - a);
        }
        _writeBytes32(result, op, 0);
        _truncate(result, op);
    }

    /// @dev Returns the decompressed `data`.
    function flzDecompress(bytes memory data) internal pure returns (bytes memory result) {
        // `data`, and a zero word after it, which the last literal run's word reaches.
        bytes memory x = bytes.concat(data, bytes32(0));
        // The output, in a buffer that doubles when it fills.
        result = new bytes((data.length << 1) + 320);
        uint256 o;
        uint256 i;
        while (true) {
            // Each step starts at most a word before the end; a long match needs more room.
            // Both tests take one branch, as the loop's only exit.
            uint256 end = result.length - 32;
            for (; (i < x.length - 32 ? 1 : 0) & (o <= end ? 1 : 0) != 0;) {
                uint256 w = uint256(_readBytes32(x, i));
                uint256 c = w >> 248;
                if (c < 32) {
                    // A literal run of `c + 1` bytes, written with the rest of their word. All
                    // but a 32nd are in the token's word.
                    _writeBytes32(result, o, c < 31 ? bytes32(w << 8) : _readBytes32(x, i + 1));
                    o += c + 1;
                    i += c + 2;
                    continue;
                }
                // A match of length `l`, repeating the `s` bytes before it.
                uint256 l;
                uint256 s = (c & 0x1f) << 8;
                if (c < 0xe0) {
                    // A match of at most 8 bytes, written as one word: the bytes it repeats,
                    // or a word of whole repeats of them when they reach the match.
                    l = (c >> 5) + 2;
                    s += ((w >> 240) & 0xff) + 1;
                    bytes32 v = _readBytes32(result, o - s);
                    if (l > s) v = _repeated(v, s);
                    _writeBytes32(result, o, v);
                    o += l;
                    i += 2;
                    continue;
                }
                // A length field of 7 takes a byte of its own.
                l = ((w >> 240) & 0xff) + 9;
                s += ((w >> 232) & 0xff) + 1;
                uint256 from = o - s;
                if (l <= 32 && l <= s) {
                    // One word, whose first `l` bytes are already written.
                    _writeBytes32(result, o, _readBytes32(result, from));
                } else {
                    // A longer match needs room for its words.
                    if (o + 264 > end) break;
                    if (s < 32) {
                        _repeat(result, o, from, s, l);
                    } else {
                        for (uint256 j; j < l; j += 32) {
                            _writeBytes32(result, o + j, _readBytes32(result, from + j));
                        }
                    }
                }
                o += l;
                i += 3;
            }
            // The last step may end past `end`, and the word after the output must fit.
            if (i >= x.length - 32 && o <= end) break;
            result = bytes.concat(result, new bytes(result.length));
        }
        _writeBytes32(result, o, 0);
        _truncate(result, o);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CALLDATA OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Calldata compression and decompression using selective run length encoding:
    // - Sequences of 0x00 (up to 128 consecutive).
    // - Sequences of 0xff (up to 32 consecutive).
    //
    // A run length encoded block consists of two bytes:
    // (0) 0x00
    // (1) A control byte with the following bit layout:
    //     - [7]     `0: 0x00, 1: 0xff`.
    //     - [0..6]  `runLength - 1`.
    //
    // The first 4 bytes are bitwise negated so that the compressed calldata
    // can be dispatched into the `fallback` and `receive` functions.

    /// @dev Returns the compressed `data`.
    function cdCompress(bytes memory data) internal pure returns (bytes memory result) {
        uint256 n = data.length;
        // The output, which a byte takes at most two bytes of, with room for a word past it,
        // then `data` and a zero word, in one buffer.
        result = bytes.concat(new bytes((n << 1) + 32), data, bytes32(0));
        uint256 o;
        uint256 end = result.length - 32;
        for (uint256 i = end - n; i < end;) {
            uint256 w = uint256(_readBytes32(result, i));
            uint256 r;
            if (w >> 248 == 0) {
                // A run of up to 128 zeros: `0x00` and its length minus one.
                while (true) {
                    uint256 z = _leadingClearBytes(_nonzeroBytes(w));
                    r += z;
                    if (z != 32 || r >= 128 || i + r >= end) break;
                    w = uint256(_readBytes32(result, i + r));
                }
                if (r > 128) r = 128;
                if (r > end - i) r = end - i;
                // The length minus one, as the run holds at least the byte at `i`.
                _writeBytes32(result, o, bytes32(((r + 0xff) & 0xff) << 240));
                o += 2;
            } else if (w >> 248 == 0xff) {
                // A run of up to 32 `0xff` bytes: `0x00` and `0x80` plus its length minus
                // one. The zero word after `data` ends it there.
                r = _leadingClearBytes(_nonzeroBytes(~w));
                _writeBytes32(result, o, bytes32((0x7f + r) << 240));
                o += 2;
            } else {
                // Literal bytes up to the next `0x00` or `0xff`, at most a word of them: often
                // one, as calldata has many small numbers.
                r = (((w >> 240) + 1) & 0xff) < 2 ? 1 : _leadingClearBytes(_specials(w));
                _writeBytes32(result, o, bytes32(w));
                o += r;
            }
            i += r;
        }
        // Bitwise negate the first 4 bytes, then clear what the last step wrote past the end.
        _writeBytes4(result, 0, _readBytes4(result, 0) ^ _NEGATED_PREFIX);
        _writeBytes32(result, o, 0);
        _truncate(result, o);
    }

    /// @dev Returns the decompressed `data`.
    function cdDecompress(bytes memory data) internal pure returns (bytes memory result) {
        if (data.length != 0) {
            result = _cdDecompress(bytes.concat(data, bytes32(0)), _byteAfter(data));
        }
    }

    /// @dev To be called in the `fallback` function.
    /// ```
    ///     fallback() external payable { LibZip.cdFallback(); }
    ///     receive() external payable {} // Silence compiler warning to add a `receive` function.
    /// ```
    /// For efficiency, this function will directly return the results, terminating the context.
    /// If called internally, it must be called at the end of the function.
    function cdFallback() internal {
        uint256 n = msg.data.length;
        bytes memory data;
        if (n == 0) _return(data);
        // The output, with room for a step and a word to spare, then the calldata and a zero
        // word, in one buffer. Each step writes a whole word, whose bytes past the step the
        // next step replaces. Should the output not fit, which takes a ratio above 16, it
        // starts over with room for 64 bytes per byte of calldata, which always fits.
        uint256 cap = n << 4;
        uint256 o;
        while (true) {
            uint256 b = cap + 160;
            data = new bytes(b + n + 32);
            _copyCalldata(data, b, msg.data, n);
            // Negate the first 4 bytes, and the bytes after a shorter calldata up to the one
            // after its last byte when that is `0xff`, as upstream reads them: a negated `0xff`
            // is the `0x00` of a run whose length upstream reads there; any other step that
            // reaches the byte after the calldata is a literal run, which a zero there ends.
            uint256 head = uint256(_readBytes32(data, b));
            uint256 z = (head << ((n - 1) << 3)) >> 248 == 0xff ? 1 : 0;
            head ^= uint256(_NEGATED_PREFIX) & ~(type(uint256).max >> ((n + z) << 3));
            _writeBytes32(data, b, bytes32(head));
            o = 0;
            uint256 i = b;
            uint256 end = b + n;
            // Both tests take one branch, as the loop's only exit.
            for (; (i < end ? 1 : 0) & (o <= cap ? 1 : 0) != 0;) {
                bytes32 w = _readBytes32(data, i);
                if (w[0] == 0) {
                    uint256 d = uint8(w[1]);
                    // A run of `0xff` bytes writes 32 of them at most, as upstream does. A
                    // run of zeros clears what the last step wrote past the end; the buffer
                    // holds zeros after that.
                    _writeBytes32(data, o, d > 0x7f ? bytes32(type(uint256).max) : bytes32(0));
                    o += (d & 0x7f) + 1;
                    i += 2;
                    // A literal run after the run, as calldata usually has, is read from the
                    // same word. The room for a step covers both.
                    if (w[2] == 0 || i >= end) continue;
                    w <<= 16;
                }
                // Literal bytes up to the next zero or the end of the word.
                uint256 r;
                do {
                    ++r;
                } while (r < 32 && w[r] != 0);
                _writeBytes32(data, o, w);
                o += r;
                i += r;
            }
            if (i >= end) break;
            cap = n << 6;
        }
        // The bytes past `o` are not cleared: `data` is only the call's input.
        _truncate(data, o);
        (bool success,) = address(this).delegatecall(data);
        _returnCall(success);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The low seven bits of every byte.
    uint256 private constant _LOW_BITS =
        0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;

    /// @dev The first four bytes of a word set, which negate the prefix of the calldata
    /// formats.
    bytes32 private constant _NEGATED_PREFIX =
        0xffffffff00000000000000000000000000000000000000000000000000000000;

    /// @dev FastLZ's 13-bit hash of the three bytes `seq`, read with the first in the lowest
    /// byte.
    /// @custom:solar-inline always
    function _hash(uint256 seq) private pure returns (uint256) {
        uint256 v = (seq >> 16) | (seq & 0xff00) | ((seq & 0xff) << 16);
        return ((v * 2654435769) >> 19) & 0x1fff;
    }

    /// @dev Writes `l` bytes that repeat the `s` bytes of `out` from `from`, fewer than `l`
    /// and 32, at `o`: a word of whole repeats at every multiple of the repeat in it. The bytes
    /// past them in the last word are left for the next step to replace.
    /// @custom:solar-inline always
    function _repeat(bytes memory out, uint256 o, uint256 from, uint256 s, uint256 l) private pure {
        uint256 shift = 256 - (s << 3);
        uint256 p = (uint256(_readBytes32(out, from)) >> shift) << shift;
        for (uint256 k = s; k < 32; k <<= 1) {
            p |= p >> (k << 3);
        }
        uint256 step = 32 - (32 % s);
        for (uint256 j; j < l; j += step) {
            _writeBytes32(out, o + j, bytes32(p));
        }
    }

    /// @dev The word of whole repeats of the first `s` bytes of `v`, fewer than 32, at every
    /// multiple of `s` in it.
    function _repeated(bytes32 v, uint256 s) private pure returns (bytes32) {
        uint256 shift = 256 - (s << 3);
        uint256 p = (uint256(v) >> shift) << shift;
        for (uint256 k = s; k < 32; k <<= 1) {
            p |= p >> (k << 3);
        }
        return bytes32(p);
    }

    /// @dev Hashes the three bytes at each offset from `ip` into `htab` until one matches the
    /// last bytes that hashed alike within 8192 bytes back, or `ipLimit` is hashed. Returns the
    /// offset after the match's first byte, or `ipLimit`; the offset of the bytes it matches;
    /// and the match's length field, which `_cmp` counts up to `ipLimit + 9`.
    function _find(
        bytes memory x,
        uint256[] memory htab,
        uint256 ip,
        uint256 ipLimit,
        uint256 format
    ) private pure returns (uint256, uint256 r, uint256 l) {
        uint256 first = uint256(_readBytes32(x, 0)) >> 232;
        while (true) {
            uint256 w = uint256(_readBytes32(x, ip));
            r = _swapHash(htab, _hash(w >> 232), ip, format);
            if (ip >= ipLimit) return (ip, r, 0);
            ++ip;
            // Offset zero can only match the first prefix; skip its word load otherwise.
            if (r == 0 && w >> 232 != first) continue;
            if (ip <= r + 0x2000) {
                uint256 diff = w ^ uint256(_readBytes32(x, r));
                if (diff >> 232 == 0) {
                    // The 29 bytes after the three that match are in the words already read;
                    // most matches end there.
                    diff <<= 24;
                    if (diff >> 248 != 0) l = 1;
                    else if (diff >> 240 != 0) l = 2;
                    else if (diff != 0) l = _leadingZeroBytes(diff) + 1;
                    else l = 30;
                    uint256 max = ipLimit + 7 - ip;
                    if (l > max) l = max;
                    else if (l == 30) l = 29 + _cmp(x, r + 32, ip + 31, ipLimit + 9);
                    return (ip, r, l);
                }
            }
        }
    }

    /// @dev Stores the offset `v` for the hash `h` in `htab` and returns the offset it held.
    /// @custom:solar-inline always
    function _swapHash(uint256[] memory htab, uint256 h, uint256 v, uint256 format)
        private
        pure
        returns (uint256 r)
    {
        uint256 position = h << (format & 7);
        uint256 offsetMask = format >> 8;
        uint256 i = position >> 8;
        uint256 shift = position & 255;
        uint256 w = htab[i];
        r = (w >> shift) & offsetMask;
        htab[i] = w ^ (((r ^ v) & offsetMask) << shift);
    }

    /// @dev The length of the match at `q` with the bytes at `p`, up to `e`, counted as
    /// FastLZ's `flz_cmp` does: one past the first byte that differs. `x` holds a word past
    /// `e`.
    function _cmp(bytes memory x, uint256 p, uint256 q, uint256 e)
        private
        pure
        returns (uint256 l)
    {
        uint256 n = e - q;
        while (true) {
            uint256 diff = uint256(_readBytes32(x, p + l) ^ _readBytes32(x, q + l));
            if (diff != 0) {
                l += _leadingZeroBytes(diff) + 1;
                break;
            }
            l += 32;
            if (l >= n) break;
        }
        if (l > n) l = n;
    }

    /// @dev Writes the `count` bytes of `x` from `start` to `out` at `op` as literal runs of
    /// at most 32 bytes, each after a control byte holding its length minus one, and returns
    /// the offset after them. Each run is written with the rest of its word, which later
    /// writes replace.
    function _literals(bytes memory out, uint256 op, bytes memory x, uint256 start, uint256 count)
        private
        pure
        returns (uint256)
    {
        for (; count >= 32; count -= 32) {
            out[op] = 0x1f;
            _writeBytes32(out, op + 1, _readBytes32(x, start));
            op += 33;
            start += 32;
        }
        if (count != 0) {
            // The control byte and the run, at most 31 bytes, in one word.
            _writeBytes32(
                out, op, bytes32(((count - 1) << 248) | (uint256(_readBytes32(x, start)) >> 8))
            );
            op += count + 1;
        }
        return op;
    }

    /// @dev Writes a match of length field `l` at distance `d` to `out` at `op`, and returns
    /// the offset after it. Each token is written with the rest of its word, which later writes
    /// replace.
    /// @custom:solar-inline always
    function _match(bytes memory out, uint256 op, uint256 l, uint256 d)
        private
        pure
        returns (uint256)
    {
        uint256 hi = (224 + ((d - 1) >> 8)) << 248;
        uint256 lo = (d - 1) & 0xff;
        for (; l >= 263; l -= 262) {
            _writeBytes32(out, op, bytes32(hi | (253 << 240) | (lo << 232)));
            op += 3;
        }
        if (l >= 7) {
            _writeBytes32(out, op, bytes32(hi | ((l - 7) << 240) | (lo << 232)));
            return op + 3;
        }
        _writeBytes32(out, op, bytes32((((l << 5) + ((d - 1) >> 8)) << 248) | (lo << 240)));
        return op + 2;
    }

    /// @dev Decompresses `x` without the zero word at its end. `next` is the byte that upstream
    /// reads after the input, as the length of a run whose `0x00` is the input's last byte.
    function _cdDecompress(bytes memory x, uint256 next)
        private
        pure
        returns (bytes memory result)
    {
        uint256 n = x.length - 32;
        // Negate the first 4 bytes, and with them the bytes after a shorter input, as upstream
        // reads them. The byte after the input is the length of a run whose `0x00` ends the
        // input; any other step that reaches it is a literal run, which a zero there ends.
        _writeBytes4(x, 0, _readBytes4(x, 0) ^ _NEGATED_PREFIX);
        x[n] = x[n - 1] == 0 ? bytes1(uint8(next)) ^ x[n] : bytes1(0);
        // The output, in a buffer with room for a step and a word to spare, that doubles when
        // it fills. Each step writes a whole word, whose bytes past the step the next step
        // replaces. A step takes at most 158 bytes: a run of 128 and a literal run of 30.
        result = new bytes((n << 2) + 192);
        uint256 o;
        uint256 i;
        while (true) {
            // Both tests take one branch, as the loop's only exit.
            for (uint256 end = result.length - 192; (i < n ? 1 : 0) & (o <= end ? 1 : 0) != 0;) {
                bytes32 w = _readBytes32(x, i);
                if (w[0] == 0) {
                    uint256 d = uint8(w[1]);
                    // A run of `0xff` bytes writes 32 of them at most, as upstream does. A
                    // run of zeros clears what the last step wrote past the end; the buffer
                    // holds zeros after that.
                    _writeBytes32(result, o, d > 0x7f ? bytes32(type(uint256).max) : bytes32(0));
                    o += (d & 0x7f) + 1;
                    i += 2;
                    // A literal run after the run, as calldata usually has, is read from the
                    // same word. The room for a step covers both.
                    if (w[2] == 0 || i >= n) continue;
                    w <<= 16;
                }
                // Literal bytes up to the next zero or the end of the word.
                uint256 r = _leadingClearBytes(_zeroBytes(uint256(w)));
                _writeBytes32(result, o, w);
                o += r;
                i += r;
            }
            if (i >= n) break;
            result = bytes.concat(result, new bytes(result.length));
        }
        _writeBytes32(result, o, 0);
        _truncate(result, o);
    }

    /// @dev `0x80` in each byte of `x` that is zero, zero in every other byte.
    /// @custom:solar-inline always
    function _zeroBytes(uint256 x) private pure returns (uint256) {
        return ~((((x & _LOW_BITS) + _LOW_BITS) | x) | _LOW_BITS);
    }

    /// @dev `0x80` in each byte of `x` that is not zero, zero in every other byte.
    /// @custom:solar-inline always
    function _nonzeroBytes(uint256 x) private pure returns (uint256) {
        return (((x & _LOW_BITS) + _LOW_BITS) | x) & ~_LOW_BITS;
    }

    /// @dev `0x80` in each byte of `x` that is `0x00` or `0xff`, zero in every other byte.
    /// @custom:solar-inline always
    function _specials(uint256 x) private pure returns (uint256) {
        return ~(((((x & _LOW_BITS) + _LOW_BITS) | x) & (((~x & _LOW_BITS) + _LOW_BITS) | ~x))
                | _LOW_BITS);
    }

    /// @dev The number of leading zero bytes of the nonzero `x`.
    function _leadingZeroBytes(uint256 x) private pure returns (uint256) {
        uint256 r = x > type(uint128).max ? 128 : 0;
        r |= (x >> r) > type(uint64).max ? 64 : 0;
        r |= (x >> r) > type(uint32).max ? 32 : 0;
        r |= (x >> r) > type(uint16).max ? 16 : 0;
        r |= (x >> r) > type(uint8).max ? 8 : 0;
        return 31 - (r >> 3);
    }

    /// @dev The number of leading bytes of `flags` before the first one with its top bit set,
    /// or 32, for `flags` with no other bits set. The two top halves of a set bit's index come
    /// from comparisons, and the rest from a perfect hash of the eight flags of that quarter,
    /// gathered into one byte by a multiplication that cannot overflow.
    function _leadingClearBytes(uint256 flags) private pure returns (uint256) {
        uint256 r = flags > 0x8421084210842108cc6318c6db6d54be ? 128 : 0;
        r |= (flags >> r) > type(uint64).max ? 64 : 0;
        uint256 b = ((((flags >> r) & type(uint64).max) * 0x02040810204081) >> 56) & 0xff;
        uint256 t = uint8(
            bytes32(
                0xc0c8c8d0c8e8d0d8c8e8e0e8d0d8e0f0c8d0e8d0e0e0d8f0d0d0e0d8f8f8f8f8
            )[(0x8421084210842108cc6318c6db6d54be >> b) & 0x1f]
        );
        return ((t ^ r) >> 3) + (flags == 0 ? 1 : 0);
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (k << 3);
        }
    }

    /// @dev Writes `value` into `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytes32(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 32; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev The 4 bytes of `b` at `offset`, followed by zeros.
    /// @custom:solar-inline always
    function _readBytes4(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 4; ++k) {
            result |= bytes32(b[offset + k]) >> (k << 3);
        }
    }

    /// @dev Writes the first 4 bytes of `value` into `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytes4(bytes memory b, uint256 offset, bytes32 value) private pure {
        for (uint256 k; k < 4; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Copies the first `n` bytes of `src` to `dst` at `dstOffset`.
    /// @custom:solar-inline always
    function _copyCalldata(bytes memory dst, uint256 dstOffset, bytes calldata src, uint256 n)
        private
        pure
    {
        for (uint256 k; k < n; ++k) {
            dst[dstOffset + k] = src[k];
        }
    }

    /// @dev Shrinks `b` to its first `n` bytes in place. The callers clear the rest of the last
    /// word of a buffer they return, so it reads as zero padding. Solidity cannot spell a
    /// shorter length for an existing buffer.
    /// @custom:solar-trusted
    function _truncate(bytes memory b, uint256 n) private pure {
        if (n > b.length) n = _outOfBounds();
        /// @solidity memory-safe-assembly
        assembly {
            mstore(b, n)
        }
    }

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the portable
    /// spelling of a failed range check.
    function _outOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }

    /// @dev The byte in memory just past the end of `b`, which upstream reads as the length
    /// of a run whose `0x00` is the last byte of its input. Solidity reads no byte past an
    /// array's length.
    /// @custom:solar-trusted
    function _byteAfter(bytes memory b) private pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := byte(0, mload(add(add(b, 0x20), mload(b))))
        }
    }

    /// @dev Ends the call, returning `data`. Solidity cannot end a call from a library
    /// function without assembly.
    /// @custom:solar-trusted
    function _return(bytes memory data) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            return(add(data, 0x20), mload(data))
        }
    }

    /// @dev Ends the call with the return data of the last call: returns it if `success`, and
    /// reverts with it otherwise. Solidity cannot end a call from a library function without
    /// assembly.
    /// @custom:solar-trusted
    function _returnCall(bool success) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            returndatacopy(m, 0x00, returndatasize())
            if iszero(success) { revert(m, returndatasize()) }
            return(m, returndatasize())
        }
    }
}
