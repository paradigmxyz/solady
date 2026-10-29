// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for burning gas without reverting.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/GasBurnerLib.sol)
///
/// @dev Intended for Contract Secured Revenue (CSR).
///
/// Recommendation: for the amount of gas to burn,
/// pass in an admin-controlled dynamic value instead of a hardcoded one.
/// This is so that you can adjust your contract as needed depending on market conditions,
/// and to give you and your users a leeway in case the L2 chain change the rules.
///
/// The checked port runs the assembly's loops, with the same hashes, calls and logs, on a buffer
/// each function allocates once, where the assembly uses scratch and free memory. Solidity hashes
/// a computed word only after copying it into new memory, so `burnPure` hashes the leading 16
/// bytes of a buffer whose first word the trusted `_firstWord` lets it overwrite with each hash.
/// `burnView` sends the ecrecover precompile the same 129 bytes through the trusted
/// `_staticCallInto`, which copies the answer over the hash, as the assembly does; the last
/// byte, which the precompile ignores, is zero where the assembly sends the byte of memory at
/// `0x80`. `burn` copies the running code into a zeroed buffer with the trusted `_codeCopyInto`
/// and logs it with the trusted `_log0`, so bytes it never writes log as zero where the assembly
/// logs what memory held. A burn costs what its hashes, calls and logs cost, plus the compiler's
/// loop overhead. A final check that the assembly fails with `invalid()` reverts with no data,
/// as `invalid()` does, without spending the gas left.
/// @custom:solar-safe memory arithmetic
library GasBurnerLib {
    /// @dev Burns approximately `x` amount of gas.
    function burnPure(uint256 x) internal pure {
        uint256 n = x > 120 ? x / 91 : 0;
        // The hash of the word's leading 16 bytes replaces the word, as at `0x10`.
        bytes memory buffer = new bytes(0x10);
        bytes32[1] memory word = _firstWord(buffer);
        word[0] = bytes32(x | 1);
        // We use keccak256 instead of blake2f precompile for better widespread compatibility.
        for (uint256 i; i < n; ++i) {
            word[0] = keccak256(buffer); // Yes.
        }
        if (word[0] == 0) revert();
    }

    /// @dev Burns approximately `x` amount of gas.
    function burnView(uint256 x) internal view {
        uint256 n = x > 3500 ? x / 3200 : 0;
        // The hash, `v`, `r`, `s`, and a byte that the precompile ignores.
        bytes memory payload = abi.encodePacked(
            keccak256(
                abi.encode(
                    uint256(uint160(address(this))) ^ uint256(uint160(tx.origin)) ^ block.timestamp
                )
            ),
            uint256(27),
            uint256(45),
            uint256(10),
            bytes1(0)
        );
        // An answer overwrites the hash, as it overwrites `0x00`.
        for (uint256 i; i < n; ++i) {
            _staticCallInto(address(1), gasleft(), payload);
        }
        // The word at `0x10` is the hash's last 16 bytes and the leading 16 of `v`, which are zero.
        if (uint128(uint256(_firstWord(payload)[0])) == 0) revert();
    }

    /// @dev Burns approximately `x` amount of gas.
    function burn(uint256 x) internal {
        uint256 n = x > 18000 ? x / 17700 : 0;
        // The 2302 bytes the assembly uses from the free memory pointer, rounded up to words.
        bytes32[] memory m = new bytes32[](72);
        m[0] = bytes32(
            uint256(uint160(address(this))) ^ uint256(uint160(tx.origin)) ^ block.timestamp
        );
        _codeCopyInto(m, 0x20, uint256(keccak256(abi.encode(m[0]))) & 0xff, 2080);
        for (uint256 i;; ++i) {
            bytes32 h = keccak256(abi.encodePacked(m[0], bytes1(m[1])));
            m[0] = h;
            _codeCopyInto(m, uint256(h) & 0x7ff, uint256(h) & 0xff, 0xff);
            m[64] = ~h;
            if (i == n) {
                n = (x % 17700) >> 3;
                n = n > 0x30 ? n - 0x30 : 0;
                _storeWordAt(m, n, h);
                _log0(m, n + 0x20);
                break;
            }
            _log0(m, 2080);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Writes `value` into the bytes of `m`'s words at byte `offset`, across two words
    /// when `offset` is not a multiple of 32.
    /// @custom:solar-inline always
    function _storeWordAt(bytes32[] memory m, uint256 offset, bytes32 value) private pure {
        uint256 w = offset >> 5;
        uint256 shift = (offset & 31) << 3;
        if (shift == 0) {
            m[w] = value;
            return;
        }
        bytes32 low = bytes32(type(uint256).max >> shift);
        m[w] = (m[w] & ~low) | (value >> shift);
        m[w + 1] = (m[w + 1] & low) | (value << (256 - shift));
    }

    /// @dev The first word of `b`'s bytes, which `b` must have, as a one-word array to write
    /// it through. Solidity writes a word into `bytes` only a byte at a time.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _firstWord(bytes memory b) private pure returns (bytes32[1] memory result) {
        if (b.length == 0) revert();
        /// @solidity memory-safe-assembly
        assembly {
            result := add(b, 0x20)
        }
    }

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and copies at most the
    /// first word of the answer over `payload`'s first word, which `payload` must have.
    /// Solidity's `staticcall` copies the whole answer into new memory instead.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _staticCallInto(address target, uint256 gasLimit, bytes memory payload)
        private
        view
        returns (bool success)
    {
        if (payload.length < 0x20) revert();
        /// @solidity memory-safe-assembly
        assembly {
            let data := add(payload, 0x20)
            success := staticcall(gasLimit, target, data, mload(payload), data, 0x20)
        }
    }

    /// @dev Copies `count` bytes of the running code from `start`, zeros past its end, into
    /// `m`'s words at byte `offset`. Solidity cannot copy the running code.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _codeCopyInto(bytes32[] memory m, uint256 offset, uint256 start, uint256 count)
        private
        pure
    {
        uint256 size = m.length << 5;
        if (offset > size || count > size - offset) revert();
        /// @solidity memory-safe-assembly
        assembly {
            codecopy(add(add(m, 0x20), offset), start, count)
        }
    }

    /// @dev Logs the first `length` bytes of `m`'s words with no topics. Solidity logs event
    /// data in whole words.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _log0(bytes32[] memory m, uint256 length) private {
        if (length > m.length << 5) revert();
        /// @solidity memory-safe-assembly
        assembly {
            log0(add(m, 0x20), length)
        }
    }
}
