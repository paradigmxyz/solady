// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for reading contract metadata robustly.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/MetadataReaderLib.sol)
///
/// The checked port makes each query with the trusted `_staticCallWord`, which passes the
/// same gas stipend and copies only the first word of the returndata, as the assembly does.
/// The checks of the `abi.decode` and the scan for the null byte, a word at a time, are
/// Solidity. The trusted `_returnDataWord` and `_returnDataCopy` copy the length word and the
/// string's bytes these checks decide on, or the bytes up to the null byte, as the assembly
/// does, since Solidity only gives a call's whole returndata.
/// @custom:solar-safe memory arithmetic
library MetadataReaderLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Default gas stipend for contract reads. High enough for most practical use cases
    /// (able to SLOAD about 1000 bytes of data), but low enough to prevent griefing.
    uint256 internal constant GAS_STIPEND_NO_GRIEF = 100000;

    /// @dev Default string byte length limit.
    uint256 internal constant STRING_LIMIT_DEFAULT = 1000;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                METADATA READING OPERATIONS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Best-effort string reading operations.
    // Should NOT revert as long as sufficient gas is provided.
    //
    // Performs the following in order:
    // 1. Returns the empty string for the following cases:
    //     - Reverts.
    //     - No returndata (e.g. function returns nothing, EOA).
    //     - Returns empty string.
    // 2. Attempts to `abi.decode` the returndata into a string.
    // 3. With any remaining gas, scans the returndata from start to end for the
    //    null byte '\0', to interpret the returndata as a null-terminated string.

    /// @dev Equivalent to `readString(abi.encodeWithSignature("name()"))`.
    function readName(address target) internal view returns (string memory) {
        return _string(target, _ptr(0x06fdde03), STRING_LIMIT_DEFAULT, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Equivalent to `readString(abi.encodeWithSignature("name()"), limit)`.
    function readName(address target, uint256 limit) internal view returns (string memory) {
        return _string(target, _ptr(0x06fdde03), limit, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Equivalent to `readString(abi.encodeWithSignature("name()"), limit, gasStipend)`.
    function readName(address target, uint256 limit, uint256 gasStipend)
        internal
        view
        returns (string memory)
    {
        return _string(target, _ptr(0x06fdde03), limit, gasStipend);
    }

    /// @dev Equivalent to `readString(abi.encodeWithSignature("symbol()"))`.
    function readSymbol(address target) internal view returns (string memory) {
        return _string(target, _ptr(0x95d89b41), STRING_LIMIT_DEFAULT, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Equivalent to `readString(abi.encodeWithSignature("symbol()"), limit)`.
    function readSymbol(address target, uint256 limit) internal view returns (string memory) {
        return _string(target, _ptr(0x95d89b41), limit, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Equivalent to `readString(abi.encodeWithSignature("symbol()"), limit, gasStipend)`.
    function readSymbol(address target, uint256 limit, uint256 gasStipend)
        internal
        view
        returns (string memory)
    {
        return _string(target, _ptr(0x95d89b41), limit, gasStipend);
    }

    /// @dev Performs a best-effort string query on `target` with `data` as the calldata.
    /// The string will be truncated to `STRING_LIMIT_DEFAULT` (1000) bytes.
    function readString(address target, bytes memory data) internal view returns (string memory) {
        return _string(target, _ptr(data), STRING_LIMIT_DEFAULT, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Performs a best-effort string query on `target` with `data` as the calldata.
    /// The string will be truncated to `limit` bytes.
    function readString(address target, bytes memory data, uint256 limit)
        internal
        view
        returns (string memory)
    {
        return _string(target, _ptr(data), limit, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Performs a best-effort string query on `target` with `data` as the calldata.
    /// The string will be truncated to `limit` bytes.
    function readString(address target, bytes memory data, uint256 limit, uint256 gasStipend)
        internal
        view
        returns (string memory)
    {
        return _string(target, _ptr(data), limit, gasStipend);
    }

    // Best-effort unsigned integer reading operations.
    // Should NOT revert as long as sufficient gas is provided.
    //
    // Performs the following in order:
    // 1. Attempts to `abi.decode` the result into a uint256
    //    (equivalent across all Solidity uint types, downcast as needed).
    // 2. Returns zero for the following cases:
    //     - Reverts.
    //     - No returndata (e.g. function returns nothing, EOA).
    //     - Returns zero.
    //     - `abi.decode` failure.

    /// @dev Equivalent to `uint8(readUint(abi.encodeWithSignature("decimals()")))`.
    function readDecimals(address target) internal view returns (uint8) {
        return uint8(_uint(target, _ptr(0x313ce567), GAS_STIPEND_NO_GRIEF));
    }

    /// @dev Equivalent to `uint8(readUint(abi.encodeWithSignature("decimals()"), gasStipend))`.
    function readDecimals(address target, uint256 gasStipend) internal view returns (uint8) {
        return uint8(_uint(target, _ptr(0x313ce567), gasStipend));
    }

    /// @dev Performs a best-effort uint query on `target` with `data` as the calldata.
    function readUint(address target, bytes memory data) internal view returns (uint256) {
        return _uint(target, _ptr(data), GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Performs a best-effort uint query on `target` with `data` as the calldata.
    function readUint(address target, bytes memory data, uint256 gasStipend)
        internal
        view
        returns (uint256)
    {
        return _uint(target, _ptr(data), gasStipend);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Attempts to read and return a string at `target`.
    function _string(address target, bytes memory ptr, uint256 limit, uint256 gasStipend)
        private
        view
        returns (string memory result)
    {
        (bool success, uint256 size, bytes32 word) = _staticCallWord(target, gasStipend, ptr);
        if (!success) return result;
        // Attempt to `abi.decode` if the returndatasize is greater or equal to 64.
        if (size >= 0x40) {
            uint256 o = uint256(word); // The string's offset in the returndata.
            // If the string's offset is within bounds.
            if (o <= size - 0x20) {
                uint256 l = uint256(_returnDataWord(o)); // The string's length.
                // If the full string's end is within bounds.
                // Note: If the full string doesn't fit, the `abi.decode` must be aborted
                // for compliance purposes, regardless if the truncated string can fit.
                if (l <= size - (o + 0x20)) {
                    // Truncate if needed.
                    return string(_returnDataCopy(o + 0x20, l < limit ? l : limit));
                }
            }
        }
        // Try interpreting as a null-terminated string.
        uint256 n = size < limit ? size : limit; // Truncate if needed.
        uint256 i = _firstZeroByte(word); // Scan for '\0'.
        if (i > n) i = n;
        if (i == 0) return result;
        // If the first word has no '\0', scan on in a copy of the bytes, a word at a time.
        if (i == 0x20 && n > 0x20) {
            bytes memory s = _returnDataCopy(0, n);
            uint256 z;
            do {
                uint256 m = n - i < 0x20 ? n - i : 0x20;
                // The word's bytes past `m` are zero, so `z <= m`.
                z = _firstZeroByte(_gather(s, i, m));
                i += z;
            } while (z == 0x20 && i < n);
            if (i == n) return string(s);
        }
        result = string(_returnDataCopy(0, i));
    }

    /// @dev Attempts to read and return a uint at `target`.
    function _uint(address target, bytes memory ptr, uint256 gasStipend)
        private
        view
        returns (uint256 result)
    {
        (bool success, uint256 size, bytes32 word) = _staticCallWord(target, gasStipend, ptr);
        // At least 32 bytes returned.
        if (success && size > 0x1f) result = uint256(word);
    }

    /// @dev Casts the function selector `s` into a pointer.
    /// The port returns the calldata, the 4-byte selector.
    function _ptr(uint256 s) private pure returns (bytes memory result) {
        result = abi.encodeWithSelector(bytes4(uint32(s)));
    }

    /// @dev Casts the `data` into a pointer.
    /// The port passes the calldata on as it is.
    function _ptr(bytes memory data) private pure returns (bytes memory result) {
        result = data;
    }

    /// @dev The index of the first zero byte of `w`, or 32 if it has none.
    function _firstZeroByte(bytes32 w) private pure returns (uint256 i) {
        uint256 x = uint256(w);
        if (x >> 248 == 0) return 0;
        uint256 m = 0x7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f;
        // The top bit of each byte of `x | ((x & m) + m)` is set where `x`'s byte is not
        // zero, and `(x & m) + m` carries into no other byte.
        uint256 t = ~(x | ((x & m) + m)) & ~m;
        if (t == 0) return 32;
        // Count the bytes before the first set top bit.
        if (t >> 128 == 0) (i, t) = (16, t << 128);
        if (t >> 192 == 0) (i, t) = (i + 8, t << 64);
        if (t >> 224 == 0) (i, t) = (i + 4, t << 32);
        if (t >> 240 == 0) (i, t) = (i + 2, t << 16);
        if (t >> 248 == 0) ++i;
    }

    /// @dev The `count` bytes of `b` from `offset`, for `count` at most 32, left-aligned in a
    /// word whose other bytes are zero.
    /// @custom:solar-inline always
    function _gather(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes32 w)
    {
        for (uint256 k; k < count; ++k) {
            w |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and returns the first word
    /// of the returndata, right padded with zeros, which is all of it that is copied.
    /// `totalSize` is how many bytes there were. Solidity copies a call's whole returndata.
    /// @custom:solar-trusted
    function _staticCallWord(address target, uint256 gasLimit, bytes memory payload)
        private
        view
        returns (bool success, uint256 totalSize, bytes32 word)
    {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0)
            success := staticcall(gasLimit, target, add(payload, 0x20), mload(payload), 0x00, 0x20)
            totalSize := returndatasize()
            word := mload(0x00)
        }
    }

    /// @dev The word of the last call's returndata at `start`. Solidity only gives a call's
    /// whole returndata. The caller calls nothing in between, and checks that the word lies
    /// inside the returndata.
    /// @custom:solar-trusted
    function _returnDataWord(uint256 start) private pure returns (bytes32 word) {
        /// @solidity memory-safe-assembly
        assembly {
            returndatacopy(0x00, start, 0x20)
            word := mload(0x00)
        }
    }

    /// @dev The `count` bytes of the last call's returndata from `start`, as a new buffer
    /// right padded with zeros. Solidity only gives a call's whole returndata. The caller
    /// calls nothing in between, and checks that the bytes lie inside the returndata.
    /// @custom:solar-trusted
    function _returnDataCopy(uint256 start, uint256 count)
        private
        pure
        returns (bytes memory output)
    {
        /// @solidity memory-safe-assembly
        assembly {
            output := mload(0x40)
            mstore(output, count)
            let o := add(output, 0x20)
            returndatacopy(o, start, count)
            mstore(add(o, count), 0) // Zeroize the slot after the bytes.
            mstore(0x40, add(o, and(add(count, 0x1f), not(0x1f)))) // Allocate the memory.
        }
    }
}
