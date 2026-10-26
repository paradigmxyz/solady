// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// This file is auto-generated.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                          STRUCTS                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// @dev A pseudorandom number state in memory.
struct PRNG {
    uint256 state;
}

/// @dev A lazy Fisher-Yates shuffler for a range `[0..n)` in storage.
struct LazyShuffler {
    // Bits Layout:
    // - [0..31]    `numShuffled`
    // - [32..223]  Reserved.
    // - [224..255] `length`
    uint256 _state;
    mapping(uint256 => uint256) _buckets;
}

using LibPRNG for PRNG global;
using LibPRNG for LazyShuffler global;

/// @notice Library for generating pseudorandom numbers.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/g/LibPRNG.sol)
/// @author LazyShuffler based on NextShuffler by aschlosberg (divergencearran)
/// (https://github.com/divergencetech/ethier/blob/main/contracts/random/NextShuffler.sol)
/// @dev The checked port draws the same numbers and makes the same swaps as the
/// assembly. The normal sample's lane sum multiplies past the word on purpose, so
/// it goes through the raw `_mul`. A lazy shuffler keeps its packed state in its
/// struct and its packed permutation in a Solidity mapping. This layout is for
/// new deployments and differs from upstream. Signed and address arrays are shuffled
/// directly, preserving their aliases without reference casts or extra arrays. A
/// shuffle keeps the state in a local and stores it when it ends, where the
/// assembly stores it after every draw: they differ only for an array that
/// overlaps the generator's memory. A full shuffle takes both draws of a hash in
/// one pass and tests its bound once per pass, so for an even length it also makes
/// the last pass's swap of the first element with itself, which the assembly
/// skips. A lazy shuffler's `next` reads each bucket word once and writes the words
/// both entries end with, once when they share a bucket, where the assembly reads a
/// bucket again for each entry it writes: the storage ends the same. One deliberate
/// difference, as later upstream releases have it: `grow` reverts with
/// `InvalidNewLazyShufflerLength()` for a length of `2**32 - 1` or more, which the
/// assembly stores without its high bits, and for growing past 65535 entries from fewer,
/// after which the assembly reads the 16-bit entries as 32-bit ones.
/// @custom:solar-safe memory arithmetic
library LibPRNG {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The initial length must be greater than zero and less than `2**32 - 1`.
    error InvalidInitialLazyShufflerLength();

    /// @dev The new length must not be less than the current length.
    /// It must also be less than `2**32 - 1`.
    error InvalidNewLazyShufflerLength();

    /// @dev The lazy shuffler has not been initialized.
    error LazyShufflerNotInitialized();

    /// @dev Cannot double initialize the lazy shuffler.
    error LazyShufflerAlreadyInitialized();

    /// @dev The lazy shuffle has finished.
    error LazyShuffleFinished();

    /// @dev The queried index is out of bounds.
    error LazyShufflerGetOutOfBounds();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The scalar of ETH and most ERC20s.
    uint256 internal constant WAD = 1e18;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OPERATIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Seeds the `prng` with `state`.
    function seed(PRNG memory prng, uint256 state) internal pure {
        prng.state = state;
    }

    /// @dev Returns the next pseudorandom uint256.
    /// All bits of the returned uint256 pass the NIST Statistical Test Suite.
    function next(PRNG memory prng) internal pure returns (uint256 result) {
        // We simply use `keccak256` for a great balance between
        // runtime gas costs, bytecode size, and statistical properties.
        result = uint256(keccak256(abi.encode(prng.state)));
        prng.state = result;
    }

    /// @dev Returns a pseudorandom uint256, uniformly distributed
    /// between 0 (inclusive) and `upper` (exclusive).
    /// If your modulus is big, this method is recommended
    /// for uniform sampling to avoid modulo bias.
    /// For uniform sampling across all uint256 values,
    /// or for small enough moduli such that the bias is negligible,
    /// use {next} instead.
    function uniform(PRNG memory prng, uint256 upper) internal pure returns (uint256 result) {
        // `2**256 % upper`: draws below it would bias the remainder.
        uint256 threshold = upper == 0 ? 0 : (type(uint256).max - upper + 1) % upper;
        do {
            result = next(prng);
        } while (result < threshold);
        result = upper == 0 ? 0 : result % upper;
    }

    /// @dev Returns a sample from the standard normal distribution denominated in `WAD`.
    function standardNormalWad(PRNG memory prng) internal pure returns (int256 result) {
        // Technically, this is the Irwin-Hall distribution with 20 samples.
        // The chance of drawing a sample outside 10 σ from the standard normal distribution
        // is ≈ 0.000000000000000000000015, which is insignificant for most practical purposes.
        // Passes the Kolmogorov-Smirnov test for 200k samples.
        uint256 r0 = next(prng);
        uint256 n = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43; // Prime.
        uint256 a = 0x100000000000000000000000000000051; // Prime and a primitive root of `n`.
        uint256 m = 0x1fffffffffffffff1fffffffffffffff1fffffffffffffff1fffffffffffffff;
        uint256 r1 = mulmod(r0, a, n);
        uint256 r2 = mulmod(r1, a, n);
        uint256 r3 = mulmod(r2, a, n);
        uint256 sum = _laneSum((m & r0) + (m & r1)) + _laneSum((m & r2) + (m & r3))
            + _laneSum(m & mulmod(r3, a, n));
        // The product stays below `2**161`, so the logical shift is the assembly's arithmetic one.
        result = int256((26614938895861601847173011183 * sum) >> 96) - 7745966692414833770;
    }

    /// @dev Returns a sample from the unit exponential distribution denominated in `WAD`.
    function exponentialWad(PRNG memory prng) internal pure returns (uint256 result) {
        // Passes the Kolmogorov-Smirnov test for 200k samples.
        uint256 r = next(prng);
        uint256 p = r << 129;
        uint256 w = r << 1;
        if (w <= p) {
            uint256 n = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43; // Prime.
            uint256 a = 0x100000000000000000000000000000051; // Prime and a primitive root of `n`.
            uint128 k; // The number of whole units drawn, added as `WAD`s at the end.
            while (true) {
                r = mulmod(r, a, n);
                uint256 q = r << 129;
                if (q >= w) {
                    r = mulmod(r, a, n);
                    ++k;
                    p = r << 129;
                    q = p;
                }
                w = r << 1;
                if (w >= q) break;
            }
            result = uint256(k) * 1000000000000000000;
        }
        result += p / (uint256(170141183460469231732) << 129);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*             MEMORY ARRAY SHUFFLING OPERATIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Shuffles the array in-place with Fisher-Yates shuffle.
    function shuffle(PRNG memory prng, uint256[] memory a) internal pure {
        uint256 n = a.length;
        if (n == 0) return;
        // The state stays in a local until the shuffle ends.
        uint256 r = prng.state;
        while (n > 1) {
            r = uint256(keccak256(abi.encode(r)));
            // Note that there will be a very tiny modulo bias
            // if the length of the array is not a power of 2.
            // For all practical purposes, it is negligible
            // and will not be a fairness or security concern.
            uint256 j = (r >> 128) % n;
            (a[n - 1], a[j]) = (a[j], a[n - 1]);
            j = ((r << 128) >> 128) % (n - 1);
            (a[n - 2], a[j]) = (a[j], a[n - 2]);
            n -= 2;
        }
        // An odd length draws once more, for a last element that stays in place.
        if (n == 1) r = uint256(keccak256(abi.encode(r)));
        prng.state = r;
    }

    /// @dev Shuffles the array in-place with Fisher-Yates shuffle.
    function shuffle(PRNG memory prng, int256[] memory a) internal pure {
        uint256 n = a.length;
        uint256 r = prng.state;
        while (n > 1) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = (r >> 128) % n;
            (a[n - 1], a[j]) = (a[j], a[n - 1]);
            j = uint128(r) % (n - 1);
            (a[n - 2], a[j]) = (a[j], a[n - 2]);
            n -= 2;
        }
        if (n == 1) r = uint256(keccak256(abi.encode(r)));
        prng.state = r;
    }

    /// @dev Shuffles the array in-place with Fisher-Yates shuffle.
    function shuffle(PRNG memory prng, address[] memory a) internal pure {
        uint256 n = a.length;
        uint256 r = prng.state;
        while (n > 1) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = (r >> 128) % n;
            (a[n - 1], a[j]) = (a[j], a[n - 1]);
            j = uint128(r) % (n - 1);
            (a[n - 2], a[j]) = (a[j], a[n - 2]);
            n -= 2;
        }
        if (n == 1) r = uint256(keccak256(abi.encode(r)));
        prng.state = r;
    }

    /// @dev Partially shuffles the array in-place with Fisher-Yates shuffle.
    /// The first `k` elements will be uniformly sampled without replacement.
    function shuffle(PRNG memory prng, uint256[] memory a, uint256 k) internal pure {
        uint256 n = a.length;
        if (k > n) k = n;
        if (k == 0) return;
        // The state stays in a local until the shuffle ends.
        uint256 r = prng.state;
        uint256 b;
        // `m` counts the elements from `b` on, which the draws choose from; two or more of the
        // first `k` remain while it exceeds `n - k + 1`.
        uint256 m = n;
        for (uint256 last = n - k + 1; m > last; m -= 2) {
            r = uint256(keccak256(abi.encode(r)));
            // Note that there will be a very tiny modulo bias
            // if the length of the array is not a power of 2.
            // For all practical purposes, it is negligible
            // and will not be a fairness or security concern.
            uint256 j = b + (r >> 128) % m;
            (a[b], a[j]) = (a[j], a[b]);
            j = b + 1 + ((r << 128) >> 128) % (m - 1);
            (a[b + 1], a[j]) = (a[j], a[b + 1]);
            b += 2;
        }
        // An odd `k` draws once more, for its last element.
        if (b < k) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = b + (r >> 128) % m;
            (a[b], a[j]) = (a[j], a[b]);
        }
        prng.state = r;
    }

    /// @dev Partially shuffles the array in-place with Fisher-Yates shuffle.
    /// The first `k` elements will be uniformly sampled without replacement.
    function shuffle(PRNG memory prng, int256[] memory a, uint256 k) internal pure {
        uint256 n = a.length;
        if (k > n) k = n;
        if (k == 0) return;
        uint256 r = prng.state;
        uint256 b;
        uint256 m = n;
        for (uint256 last = n - k + 1; m > last; m -= 2) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = b + (r >> 128) % m;
            (a[b], a[j]) = (a[j], a[b]);
            j = b + 1 + uint128(r) % (m - 1);
            (a[b + 1], a[j]) = (a[j], a[b + 1]);
            b += 2;
        }
        if (b < k) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = b + (r >> 128) % m;
            (a[b], a[j]) = (a[j], a[b]);
        }
        prng.state = r;
    }

    /// @dev Partially shuffles the array in-place with Fisher-Yates shuffle.
    /// The first `k` elements will be uniformly sampled without replacement.
    function shuffle(PRNG memory prng, address[] memory a, uint256 k) internal pure {
        uint256 n = a.length;
        if (k > n) k = n;
        if (k == 0) return;
        uint256 r = prng.state;
        uint256 b;
        uint256 m = n;
        for (uint256 last = n - k + 1; m > last; m -= 2) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = b + (r >> 128) % m;
            (a[b], a[j]) = (a[j], a[b]);
            j = b + 1 + uint128(r) % (m - 1);
            (a[b + 1], a[j]) = (a[j], a[b + 1]);
            b += 2;
        }
        if (b < k) {
            r = uint256(keccak256(abi.encode(r)));
            uint256 j = b + (r >> 128) % m;
            (a[b], a[j]) = (a[j], a[b]);
        }
        prng.state = r;
    }

    /// @dev Shuffles the bytes in-place with Fisher-Yates shuffle.
    function shuffle(PRNG memory prng, bytes memory a) internal pure {
        uint256 n = a.length;
        if (n == 0) return;
        // The state stays in a local until the shuffle ends.
        uint256 r = prng.state;
        while (n > 1) {
            r = uint256(keccak256(abi.encode(r)));
            // Note that there will be a very tiny modulo bias
            // if the length of the array is not a power of 2.
            // For all practical purposes, it is negligible
            // and will not be a fairness or security concern.
            uint256 o = (r >> 128) % n;
            (a[n - 1], a[o]) = (a[o], a[n - 1]);
            o = ((r << 128) >> 128) % (n - 1);
            (a[n - 2], a[o]) = (a[o], a[n - 2]);
            n -= 2;
        }
        // An odd length draws once more, for a last element that stays in place.
        if (n == 1) r = uint256(keccak256(abi.encode(r)));
        prng.state = r;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*       STORAGE-BASED RANGE LAZY SHUFFLING OPERATIONS        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Initializes the state for lazy-shuffling the range `[0..n)`.
    /// Reverts if `n == 0 || n >= 2**32 - 1`.
    /// Reverts if `$` has already been initialized.
    /// If you need to reduce the length after initialization, just use a fresh new `$`.
    function initialize(LazyShuffler storage $, uint256 n) internal {
        if (n == 0 || n > 0xfffffffe) revert InvalidInitialLazyShufflerLength();
        if ($._state != 0) revert LazyShufflerAlreadyInitialized();
        $._state = n << 224;
    }

    /// @dev Increases the length of `$`.
    /// Reverts if `$` has not been initialized.
    /// Reverts if `n` is less than the current length, or if `n >= 2**32 - 1`.
    /// Reverts if `n` crosses the entry width boundary at a length of 65535.
    function grow(LazyShuffler storage $, uint256 n) internal {
        uint256 state = $._state; // The packed value at `$`.
        if (state == 0) revert LazyShufflerNotInitialized();
        uint256 o = state >> 224; // The old length.
        uint256 limit = o > 0xfffe ? 0xfffffffe : 0xfffe;
        if (n < o || n > limit) revert InvalidNewLazyShufflerLength();
        $._state = (n << 224) | ((state << 32) >> 32);
    }

    /// @dev Restarts the shuffler by setting `numShuffled` to zero,
    /// such that all elements can be drawn again.
    /// Restarting does NOT clear the internal permutation, nor changes the length.
    /// Even with the same sequence of randomness, reshuffling can yield different results.
    function restart(LazyShuffler storage $) internal {
        uint256 state = $._state;
        if (state == 0) revert LazyShufflerNotInitialized();
        $._state = (state >> 32) << 32;
    }

    /// @dev Returns the number of elements that have been shuffled.
    function numShuffled(LazyShuffler storage $) internal view returns (uint256 result) {
        result = $._state & 0xffffffff;
    }

    /// @dev Returns the length of `$`.
    /// Returns zero if `$` is not initialized, else a non-zero value less than `2**32 - 1`.
    function length(LazyShuffler storage $) internal view returns (uint256 result) {
        result = $._state >> 224;
    }

    /// @dev Returns if `$` has been initialized.
    function initialized(LazyShuffler storage $) internal view returns (bool result) {
        result = $._state != 0;
    }

    /// @dev Returns if there are any more elements left to shuffle.
    /// Reverts if `$` is not initialized.
    function finished(LazyShuffler storage $) internal view returns (bool result) {
        uint256 state = $._state; // The packed value at `$`.
        if (state == 0) revert LazyShufflerNotInitialized();
        result = state >> 224 == state & 0xffffffff;
    }

    /// @dev Returns the current value stored at `index`, accounting for all historical shuffling.
    /// Reverts if `index` is greater than or equal to the `length` of `$`.
    function get(LazyShuffler storage $, uint256 index) internal view returns (uint256 result) {
        uint256 state = $._state; // The packed value at `$`.
        uint256 n = state >> 224; // Length of `$`.
        if (index >= n) revert LazyShufflerGetOutOfBounds();
        uint256 w = n > 0xfffe ? 1 : 0; // Whether entries are 32 bits wide.
        uint256 s = index >> (4 - w); // Bucket index.
        uint256 o = (index & (15 >> w)) << (4 + w); // Bucket slot offset (bits).
        result = ($._buckets[s] >> o) & (0xffffffff >> ((w ^ 1) << 4));
        result = result == 0 ? index : result - 1;
    }

    /// @dev Does a single Fisher-Yates shuffle step, increments the `numShuffled` in `$`,
    /// and returns the next value in the shuffled range.
    /// `randomness` can be taken from a good-enough source, or a higher quality source like VRF.
    /// Reverts if there are no more values to shuffle, which includes the case if `$` is not initialized.
    function next(LazyShuffler storage $, uint256 randomness) internal returns (uint256 chosen) {
        uint256 state = $._state; // The packed value at `$`.
        uint256 shuffled = state & 0xffffffff; // Number of elements shuffled.
        uint256 index;
        // The blocks keep the legacy pipeline's stack within reach.
        {
            uint256 n = state >> 224; // Length of `$`.
            uint256 remainder = n - shuffled; // Number of elements left to shuffle.
            if (remainder == 0) revert LazyShuffleFinished();
            // (Re)hash the randomness so that we don't
            // need to expect guarantees on its distribution.
            index = uint256(keccak256(abi.encode(randomness, shuffled))) % remainder + shuffled;
        }
        uint256 m; // Value mask.
        uint256 sI; // Bucket slot of `index`.
        uint256 oI; // Its offset (bits).
        uint256 sS; // Bucket slot of `shuffled`.
        uint256 oS; // Its offset (bits).
        {
            uint256 w = state >> 224 > 0xfffe ? 1 : 0; // Whether entries are 32 bits wide.
            m = 0xffffffff >> ((w ^ 1) << 4);
            sI = index >> (4 - w);
            oI = (index & (15 >> w)) << (4 + w);
            sS = shuffled >> (4 - w);
            oS = (shuffled & (15 >> w)) << (4 + w);
        }
        uint256 vI = $._buckets[sI];
        chosen = (vI >> oI) & m;
        chosen = chosen == 0 ? index : chosen - 1;
        // Record the value at `shuffled` at `index`, then `chosen` at `shuffled`, reading and
        // writing each bucket word once.
        if (sS == sI) {
            uint256 value = (vI >> oS) & m;
            value = value == 0 ? shuffled : value - 1; // The value at `shuffled`.
            vI ^= (((vI >> oI) & m) ^ (index == value ? 0 : value + 1)) << oI;
            vI ^= (((vI >> oS) & m) ^ (shuffled == chosen ? 0 : chosen + 1)) << oS;
            $._buckets[sI] = vI;
        } else {
            uint256 vS = $._buckets[sS];
            uint256 value = (vS >> oS) & m;
            $._buckets[sS] = vS ^ ((value ^ (shuffled == chosen ? 0 : chosen + 1)) << oS);
            value = value == 0 ? shuffled : value - 1; // The value at `shuffled`.
            $._buckets[sI] = vI ^ ((((vI >> oI) & m) ^ (index == value ? 0 : value + 1)) << oI);
        }
        $._state = state + 1; // Increment the `numShuffled` by 1, and store it.
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The sum of the four 64-bit lanes of `x`, which the multiplication gathers in its
    /// top lane: the bits it carries past the word are dropped, as the assembly drops them.
    function _laneSum(uint256 x) private pure returns (uint256) {
        return _mul(0x1000000000000000100000000000000010000000000000001, x) >> 192;
    }

    /// @dev Unchecked arithmetic for multiplying two numbers.
    /// @custom:solar-trusted
    function _mul(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a * b;
        }
    }
}
