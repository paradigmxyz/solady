// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import {Receiver} from "./Receiver.sol";

/// @notice Minimal batch executor mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC7821.sol)
///
/// @dev This contract can be inherited to create fully-fledged smart accounts.
/// If you merely want to combine approve-swap transactions into a single transaction
/// using [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702), you will need to implement basic
/// [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) `isValidSignature` functionality to
/// validate signatures with `ecrecover` against the EOA address. This is necessary because some
/// signature checks skip `ecrecover` if the signer has code. For a basic EOA batch executor,
/// please refer to [BEBE](https://github.com/vectorized/bebe), which inherits from this class.
///
/// The checked port reads `executionData` through calldata slices, so every offset and length
/// it follows is checked against the bytes it lies in, and makes each call with Solidity's
/// `call`, bubbling a revert up with the trusted `_erc7821RevertReturndata`. Solidity cannot
/// view bytes as an array, so the trusted `_erc7821Calls` views the offset words of the calls as
/// a `Call[]` once they are checked to lie in `executionData`. `_get` reads `calls[i]` with
/// Solidity's calldata access, which follows the same offsets and checks they stay in calldata,
/// and reads `to` as the whole word it is stored as at the offset the trusted `_erc7821Offset`
/// gives. Deliberate differences, on data no encoder produces: calls or batches that do not fit
/// `executionData` (or calldata, for `_get`), or an index past `calls`, revert where the
/// assembly reads on, and a batch whose length wraps the end of `executionData` around reverts
/// with `BatchOfBatchesDecodingError()` where the assembly's sum wraps and executes it.
/// @custom:solar-safe memory arithmetic
contract ERC7821 is Receiver {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Call struct for the `execute` function.
    struct Call {
        address to; // Replaced as `address(this)` if `address(0)`. Renamed to `to` for Ithaca Porto.
        uint256 value; // Amount of native currency (i.e. Ether) to send.
        bytes data; // Calldata to send with the call.
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The execution mode is not supported.
    error UnsupportedExecutionMode();

    /// @dev Cannot decode `executionData` as a batch of batches `abi.encode(bytes[])`.
    error BatchOfBatchesDecodingError();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EXECUTION OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Executes the calls in `executionData`.
    /// Reverts and bubbles up error if any call fails.
    ///
    /// `executionData` encoding (single batch):
    /// - If `opData` is empty, `executionData` is simply `abi.encode(calls)`.
    /// - Else, `executionData` is `abi.encode(calls, opData)`.
    ///   See: https://eips.ethereum.org/EIPS/eip-7579
    ///
    /// `executionData` encoding (batch of batches):
    /// - `executionData` is `abi.encode(bytes[])`, where each element in `bytes[]`
    ///   is an `executionData` for a single batch.
    ///
    /// Supported modes:
    /// - `0x01000000000000000000...`: Single batch. Does not support optional `opData`.
    /// - `0x01000000000078210001...`: Single batch. Supports optional `opData`.
    /// - `0x01000000000078210002...`: Batch of batches.
    ///
    /// For the "batch of batches" mode, each batch will be recursively passed into
    /// `execute` internally with mode `0x01000000000078210001...`.
    /// Useful for passing in batches signed by different signers.
    ///
    /// Authorization checks:
    /// - If `opData` is empty, the implementation SHOULD require that
    ///   `msg.sender == address(this)`.
    /// - If `opData` is not empty, the implementation SHOULD use the signature
    ///   encoded in `opData` to determine if the caller can perform the execution.
    /// - If `msg.sender` is an authorized entry point, then `execute` MAY accept
    ///   calls from the entry point, and MAY use `opData` for specialized logic.
    ///
    /// `opData` may be used to store additional data for authentication,
    /// paymaster data, gas limits, etc.
    function execute(bytes32 mode, bytes calldata executionData) public payable virtual {
        uint256 id = _executionModeId(mode);
        if (id == 3) return _executeBatchOfBatches(mode, executionData);
        if (id == 0) revert UnsupportedExecutionMode();
        // The calls are at the offset in the first word of `executionData`.
        uint256 u = _erc7821Load(executionData, 0);
        Call[] calldata calls =
            _erc7821Calls(executionData[u + 0x20:], _erc7821Load(executionData, u));
        bytes calldata opData = msg.data[:0];
        // If the offset of `executionData` allows for `opData`, and the mode supports it.
        if (id == 2 && u >= 0x40) {
            uint256 p = _erc7821Load(executionData, 0x20);
            opData = executionData[p + 0x20:p + 0x20 + _erc7821Load(executionData, p)];
        }
        // Bounds checking for `executionData` is skipped here for efficiency.
        // This is safe if it is only used as an argument to `execute` externally.
        // If `executionData` used as an argument to other functions externally,
        // please perform the bounds checks via `LibERC7579.decodeBatchAndOpData`
        /// or `abi.decode` in the other functions for safety.
        _execute(mode, executionData, calls, opData);
    }

    /// @dev Provided for execution mode support detection.
    function supportsExecutionMode(bytes32 mode) public view virtual returns (bool result) {
        return _executionModeId(mode) != 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev 0: invalid mode, 1: no `opData` support, 2: with `opData` support, 3: batch of batches.
    function _executionModeId(bytes32 mode) internal view virtual returns (uint256 id) {
        // Only supports atomic batched executions.
        // For the encoding scheme, see: https://eips.ethereum.org/EIPS/eip-7579
        // Bytes Layout:
        // - [0]      ( 1 byte )  `0x01` for batch call.
        // - [1]      ( 1 byte )  `0x00` for revert on any failure.
        // - [2..5]   ( 4 bytes)  Reserved by ERC7579 for future standardization.
        // - [6..9]   ( 4 bytes)  `0x00000000` or `0x78210001` or `0x78210002`.
        // - [10..31] (22 bytes)  Unused. Free for use.
        uint256 m = (uint256(mode) >> (22 * 8)) & 0xffff00000000ffffffff;
        if (m == 0x01000000000000000000) return 1;
        if (m == 0x01000000000078210001) return 2;
        if (m == 0x01000000000078210002) return 3;
    }

    /// @dev For execution of a batch of batches.
    function _executeBatchOfBatches(bytes32 mode, bytes calldata executionData) internal virtual {
        // Replace with `0x0100________78210001...` while preserving optional and reserved fields.
        mode ^= bytes32(uint256(3 << (22 * 8))); // `2 XOR 3 = 1`.
        // Do the bounds check on `executionData` treating it as `abi.encode(bytes[])`:
        // the offset of `batches`, their count and an offset word per batch.
        // Every offset read must be below `2**64`, so no sum below can wrap.
        uint256 end = executionData.length;
        if (end < 0x20) revert BatchOfBatchesDecodingError();
        uint256 j = _erc7821Load(executionData, 0);
        if (j >> 64 != 0 || j + 0x20 > end) revert BatchOfBatchesDecodingError();
        uint256 o = j + 0x20; // Offset of `batches[0]`.
        uint256 n = _erc7821Load(executionData, j); // `batches.length`.
        if (n > (end - o) >> 5) revert BatchOfBatchesDecodingError();
        for (uint256 i; i != n; ++i) {
            // Validate that `batches[i]` is not out-of-bounds.
            uint256 t = _erc7821Load(executionData, o + (i << 5));
            if (t >> 64 != 0 || o + t + 0x20 > end) revert BatchOfBatchesDecodingError();
            t += o;
            uint256 length = _erc7821Load(executionData, t);
            if (length > end - t - 0x20) revert BatchOfBatchesDecodingError();
            execute(mode, executionData[t + 0x20:t + 0x20 + length]);
        }
    }

    /// @dev Executes the calls.
    /// Reverts and bubbles up error if any call fails.
    /// The `mode` and `executionData` are passed along in case there's a need to use them.
    function _execute(
        bytes32 mode,
        bytes calldata executionData,
        Call[] calldata calls,
        bytes calldata opData
    ) internal virtual {
        // Silence compiler warning on unused variables.
        mode = mode;
        executionData = executionData;
        // Very basic auth to only allow this contract to be called by itself.
        // Override this function to perform more complex auth with `opData`.
        if (opData.length == uint256(0)) {
            require(msg.sender == address(this));
            // Remember to return `_execute(calls, extraData)` when you override this function.
            return _execute(calls, bytes32(0));
        }
        revert(); // In your override, replace this with logic to operate on `opData`.
    }

    /// @dev Executes the calls.
    /// Reverts and bubbles up error if any call fails.
    /// `extraData` can be any supplementary data (e.g. a memory pointer, some hash).
    function _execute(Call[] calldata calls, bytes32 extraData) internal virtual {
        for (uint256 i; i < calls.length; ++i) {
            (address to, uint256 value, bytes calldata data) = _get(calls, i);
            _execute(to, value, data, extraData);
        }
    }

    /// @dev Executes the call.
    /// Reverts and bubbles up error if any call fails.
    /// `extraData` can be any supplementary data (e.g. a memory pointer, some hash).
    function _execute(address to, uint256 value, bytes calldata data, bytes32 extraData)
        internal
        virtual
    {
        extraData = extraData; // Silence unused variable compiler warning.
        (bool success,) = to.call{value: value}(data);
        // Bubble up the revert if the call reverts.
        if (!success) _erc7821RevertReturndata();
    }

    /// @dev Convenience function for getting `calls[i]`, without bounds checks.
    function _get(Call[] calldata calls, uint256 i)
        internal
        view
        virtual
        returns (address to, uint256 value, bytes calldata data)
    {
        // Solidity's own access to `calls[i]` follows the offsets as the assembly does, and
        // checks that `calls[i]` and its `data` lie in calldata.
        Call calldata c = calls[i];
        // Replaces `to` with `address(this)` if `address(0)` is provided.
        to = address(uint160(_erc7821Load(msg.data, _erc7821Offset(c))));
        if (to == address(0)) to = address(this);
        value = c.value;
        data = c.data;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The word at `offset` in `b`.
    /// @custom:solar-inline always
    function _erc7821Load(bytes calldata b, uint256 offset) private pure returns (uint256) {
        return uint256(bytes32(b[offset:offset + 0x20]));
    }

    /// @dev Views the first `n` words of `words` as the offset words of a `Call[]`, once they are
    /// checked to lie in it. Solidity cannot convert calldata bytes to an array.
    /// @custom:solar-trusted
    function _erc7821Calls(bytes calldata words, uint256 n)
        private
        pure
        returns (Call[] calldata calls)
    {
        if (n > words.length >> 5) n = _erc7821OutOfBounds();
        /// @solidity memory-safe-assembly
        assembly {
            calls.offset := words.offset
            calls.length := n
        }
    }

    /// @dev The calldata offset at which `c` starts, where its `to` word lies. Solidity cannot
    /// read where a calldata struct lies, nor read an address word without checking it is clean.
    /// @custom:solar-trusted
    function _erc7821Offset(Call calldata c) private pure returns (uint256 o) {
        /// @solidity memory-safe-assembly
        assembly {
            o := c
        }
    }

    /// @dev Reverts with the last call's return data, which Solidity holds only as a copy.
    /// @custom:solar-trusted
    function _erc7821RevertReturndata() private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            returndatacopy(m, 0x00, returndatasize())
            revert(m, returndatasize())
        }
    }

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the
    /// portable spelling of a failed range check.
    function _erc7821OutOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }
}
