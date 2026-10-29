// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

/// @notice Library for handling ERC7579 mode and execution data.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/LibERC7579.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/main/contracts/account/utils/draft-ERC7579Utils.sol)
///
/// The checked port reads `executionData` through calldata slices, so every offset and length
/// it follows is checked against the bytes it lies in. The checked decoders keep the assembly's
/// bounds checks, stated against the slice: a batch, a call or `opData` that does not fit
/// `executionData` reverts with `DecodingError()`. Solidity cannot view bytes as an array or
/// tell where an array starts, so the trusted `_toBytes32Array` views the first words of a slice
/// as a `bytes32[]` once they are checked to lie in it, and the trusted `_offset` gives the
/// calldata offset `getExecution` reads from. `reencodeBatch` writes its result with
/// `abi.encodePacked` and drops the zeros it does not need with the trusted `_truncate`.
/// Deliberate differences, on data the checked decoders reject: the `Unchecked` decoders,
/// `getExecution` and `reencodeBatch` read through Solidity's bounds checks, so a field past the
/// end of `executionData` (of calldata, for `getExecution`) reverts where the assembly reads on
/// or runs out of gas; `getExecution` returns `target` cleaned to 160 bits; a pointer count too
/// large to address reverts with `DecodingError()` where the assembly runs out of gas; and
/// `executionData` that ends within the first word of calldata, which only a slice of
/// `msg.data` can, is checked against its own length where the assembly's bound wraps around.
/// @custom:solar-safe memory arithmetic
library LibERC7579 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Cannot decode `executionData`.
    error DecodingError();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev A single execution.
    bytes1 internal constant CALLTYPE_SINGLE = 0x00;

    /// @dev A batch of executions.
    bytes1 internal constant CALLTYPE_BATCH = 0x01;

    /// @dev A single `staticcall` execution.
    bytes1 internal constant CALLTYPE_STATICCALL = 0xfe;

    /// @dev A `delegatecall` execution.
    bytes1 internal constant CALLTYPE_DELEGATECALL = 0xff;

    /// @dev Default execution type that reverts on failure.
    bytes1 internal constant EXECTYPE_DEFAULT = 0x00;

    /// @dev Execution type that does not revert on failure.
    bytes1 internal constant EXECTYPE_TRY = 0x01;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      MODE OPERATIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes the fields into a mode.
    function encodeMode(bytes1 callType, bytes1 execType, bytes4 selector, bytes22 payload)
        internal
        pure
        returns (bytes32 result)
    {
        // Bytes 0 and 1 are the types, bytes 2 to 5 stay zero, then the selector and payload.
        result = bytes32(callType) | (bytes32(execType) >> 8) | (bytes32(selector) >> 48)
            | (bytes32(payload) >> 80);
    }

    /// @dev Returns the call type of the mode.
    function getCallType(bytes32 mode) internal pure returns (bytes1) {
        return bytes1(mode);
    }

    /// @dev Returns the call type of the mode.
    function getExecType(bytes32 mode) internal pure returns (bytes1) {
        return mode[1];
    }

    /// @dev Returns the selector of the mode.
    function getSelector(bytes32 mode) internal pure returns (bytes4) {
        return bytes4(bytes32(uint256(mode) << 48));
    }

    /// @dev Returns the payload stored in the mode.
    function getPayload(bytes32 mode) internal pure returns (bytes22) {
        return bytes22(bytes32(uint256(mode) << 80));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 EXECUTION DATA OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes a single call execution.
    /// Reverts if `executionData` is not correctly encoded.
    function decodeSingle(bytes calldata executionData)
        internal
        pure
        returns (address target, uint256 value, bytes calldata data)
    {
        // `abi.encodePacked(target, value, data)`.
        if (executionData.length < 0x34) revert DecodingError();
        target = address(bytes20(executionData));
        value = _load(executionData, 0x14);
        data = executionData[0x34:];
    }

    /// @dev Decodes a single call execution without bounds checks.
    function decodeSingleUnchecked(bytes calldata executionData)
        internal
        pure
        returns (address target, uint256 value, bytes calldata data)
    {
        target = address(bytes20(executionData[:0x14]));
        value = _load(executionData, 0x14);
        data = executionData[0x34:];
    }

    /// @dev Decodes a single delegate execution.
    /// Reverts if `executionData` is not correctly encoded.
    function decodeDelegate(bytes calldata executionData)
        internal
        pure
        returns (address target, bytes calldata data)
    {
        // `abi.encodePacked(target, data)`.
        if (executionData.length < 0x14) revert DecodingError();
        target = address(bytes20(executionData));
        data = executionData[0x14:];
    }

    /// @dev Decodes a single delegate execution without bounds checks.
    function decodeDelegateUnchecked(bytes calldata executionData)
        internal
        pure
        returns (address target, bytes calldata data)
    {
        target = address(bytes20(executionData[:0x14]));
        data = executionData[0x14:];
    }

    /// @dev Decodes a batch.
    /// Reverts if `executionData` is not correctly encoded.
    function decodeBatch(bytes calldata executionData)
        internal
        pure
        returns (bytes32[] calldata pointers)
    {
        // The offset of the calls, their count, and a pointer word per call. Every offset and
        // length read must be below `2**64`, so no sum below can wrap.
        uint256 end = executionData.length;
        uint256 base;
        {
            if (end < 0x20) revert DecodingError();
            uint256 u = _load(executionData, 0);
            if (u >> 64 != 0 || u + 0x20 > end) revert DecodingError();
            base = u + 0x20;
            bytes calldata words = executionData[base:];
            uint256 n = _load(executionData, u);
            if (n > words.length >> 5) revert DecodingError();
            pointers = _toBytes32Array(words, n);
        }
        // Each call's three head words, and its `data` with its length word, from `base`.
        for (uint256 i; i < pointers.length; ++i) {
            uint256 c = uint256(pointers[i]);
            if (c >> 64 != 0) revert DecodingError();
            c += base;
            if (c + 0x60 > end) revert DecodingError();
            uint256 o = _load(executionData, c + 0x40);
            if (o >> 64 != 0) revert DecodingError();
            o += c;
            if (o + 0x20 > end) revert DecodingError();
            uint256 n = _load(executionData, o);
            if (n >> 64 != 0 || o + 0x20 + n > end) revert DecodingError();
        }
    }

    /// @dev Decodes a batch without bounds checks.
    /// This function can be used in `execute`, if the validation phase has already
    /// decoded the `executionData` with checks via `decodeBatch`.
    function decodeBatchUnchecked(bytes calldata executionData)
        internal
        pure
        returns (bytes32[] calldata pointers)
    {
        uint256 u = _load(executionData, 0);
        pointers = _toBytes32Array(executionData[u + 0x20:], _load(executionData, u));
    }

    /// @dev Decodes a batch and optional `opData`.
    /// Reverts if `executionData` is not correctly encoded.
    function decodeBatchAndOpData(bytes calldata executionData)
        internal
        pure
        returns (bytes32[] calldata pointers, bytes calldata opData)
    {
        opData = emptyCalldataBytes();
        pointers = decodeBatch(executionData);
        if (hasOpData(executionData)) {
            // The offset of `opData`, its length word and its bytes.
            uint256 end = executionData.length;
            uint256 p = _load(executionData, 0x20);
            if (p >> 64 != 0 || p + 0x20 > end) revert DecodingError();
            uint256 n = _load(executionData, p);
            if (n >> 64 != 0 || p + 0x20 + n > end) revert DecodingError();
            opData = executionData[p + 0x20:p + 0x20 + n];
        }
    }

    /// @dev Decodes a batch without bounds checks.
    /// This function can be used in `execute`, if the validation phase has already
    /// decoded the `executionData` with checks via `decodeBatchAndOpData`.
    function decodeBatchAndOpDataUnchecked(bytes calldata executionData)
        internal
        pure
        returns (bytes32[] calldata pointers, bytes calldata opData)
    {
        opData = emptyCalldataBytes();
        pointers = decodeBatchUnchecked(executionData);
        if (hasOpData(executionData)) {
            uint256 p = _load(executionData, 0x20);
            opData = executionData[p + 0x20:p + 0x20 + _load(executionData, p)];
        }
    }

    /// @dev Returns whether the `executionData` has optional `opData`.
    function hasOpData(bytes calldata executionData) internal pure returns (bool result) {
        return executionData.length >= 0x40 && _load(executionData, 0) >= 0x40;
    }

    /// @dev Returns the `i`th execution at `pointers`, without bounds checks.
    /// The bounds check is excluded as this function is intended to be called in a bounded loop.
    function getExecution(bytes32[] calldata pointers, uint256 i)
        internal
        pure
        returns (address target, uint256 value, bytes calldata data)
    {
        // The calls lie after `pointers`, at the offsets its words give from its start.
        bytes calldata a = msg.data[_offset(pointers):];
        uint256 c = _load(a, i * 0x20);
        target = address(uint160(_load(a, c)));
        value = _load(a, c + 0x20);
        uint256 o = c + _load(a, c + 0x40);
        data = a[o + 0x20:o + 0x20 + _load(a, o)];
    }

    /// @dev Reencodes `executionData` such that it has `opData` added to it.
    /// Like `abi.encode(abi.decode(executionData, (Call[])), opData)`.
    /// Useful for forwarding `executionData` with extra `opData`.
    /// This function does not perform any check on the validity of `executionData`.
    function reencodeBatch(bytes calldata executionData, bytes memory opData)
        internal
        pure
        returns (bytes memory result)
    {
        // The bytes from the offset of the calls on, then `opData` padded to whole words. Two
        // words of zeros keep the result zero right padded once it is cut to that length.
        bytes calldata calls = executionData[_load(executionData, 0):];
        result = abi.encodePacked(
            uint256(0x40), 0x40 + calls.length, calls, opData.length, opData, bytes32(0), bytes32(0)
        );
        _truncate(result, _reencodedLength(calls.length, opData.length));
    }

    /// @dev `abi.encodeWithSignature("execute(bytes32,bytes)", mode, reencodeBatch(executionData, opData))`.
    function reencodeBatchAsExecuteCalldata(
        bytes32 mode,
        bytes calldata executionData,
        bytes memory opData
    ) internal pure returns (bytes memory result) {
        // `reencodeBatch`, written after `execute(bytes32,bytes)`'s head and its length.
        bytes calldata calls = executionData[_load(executionData, 0):];
        uint256 n = _reencodedLength(calls.length, opData.length);
        result = abi.encodePacked(
            bytes4(0xe9ae5c53),
            mode,
            uint256(0x40),
            n,
            uint256(0x40),
            0x40 + calls.length,
            calls,
            opData.length,
            opData,
            bytes32(0),
            bytes32(0)
        );
        _truncate(result, 0x64 + n);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          HELPERS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Helper function to return empty calldata bytes.
    function emptyCalldataBytes() internal pure returns (bytes calldata result) {
        return msg.data[:0];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The word at `offset` in `b`.
    /// @custom:solar-inline always
    function _load(bytes calldata b, uint256 offset) private pure returns (uint256) {
        return uint256(bytes32(b[offset:offset + 0x20]));
    }

    /// @dev The length of `reencodeBatch`'s result for calls of `callsLength` bytes and
    /// `opData` of `opDataLength` bytes: two offsets, the calls, then `opData` with its length
    /// word, padded to whole words.
    function _reencodedLength(uint256 callsLength, uint256 opDataLength)
        private
        pure
        returns (uint256)
    {
        return 0x60 + callsLength + (opDataLength + 0x1f) / 0x20 * 0x20;
    }

    /// @dev Views the first `n` words of `b` as an array, once they are checked to lie in it.
    /// Solidity cannot convert calldata bytes to an array.
    /// @custom:solar-trusted
    function _toBytes32Array(bytes calldata b, uint256 n)
        private
        pure
        returns (bytes32[] calldata a)
    {
        if (n > b.length >> 5) n = new uint256[](0)[0];
        /// @solidity memory-safe-assembly
        assembly {
            a.offset := b.offset
            a.length := n
        }
    }

    /// @dev The calldata offset at which `a` starts. Solidity cannot read where a calldata
    /// array lies.
    /// @custom:solar-trusted
    function _offset(bytes32[] calldata a) private pure returns (uint256 o) {
        /// @solidity memory-safe-assembly
        assembly {
            o := a.offset
        }
    }

    /// @dev Shrinks `b` to its first `n` bytes in place. Solidity cannot spell a shorter length
    /// for an existing buffer.
    /// @custom:solar-trusted
    function _truncate(bytes memory b, uint256 n) private pure {
        if (n > b.length) n = new uint256[](0)[0];
        /// @solidity memory-safe-assembly
        assembly {
            mstore(b, n)
        }
    }
}
