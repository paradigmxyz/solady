// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for making calls.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibCall.sol)
/// @author Modified from ExcessivelySafeCall (https://github.com/nomad-xyz/ExcessivelySafeCall)
///
/// @dev Note:
/// - The arguments of the functions may differ from the libraries.
///   Please read the functions carefully before use.
///
/// The checked port's contract calls copy the whole response, as `address.call` does, bubble
/// a revert with the trusted `_revertRaw`, and reject an empty response from an account
/// without code. The try calls copy at most `maxCopy` bytes of the response with the trusted
/// `_callBounded`, into a buffer allocated once its size is known, so a callee cannot make
/// the caller copy more than it asked for.
/// @custom:solar-safe memory arithmetic
library LibCall {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The target of the call is not a contract.
    error TargetIsNotContract();

    /// @dev The data is too short to contain a function selector.
    error DataTooShort();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONTRACT CALL OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // These functions will revert if called on a non-contract
    // (i.e. address without code).
    // They will bubble up the revert if the call fails.

    /// @dev Makes a call to `target`, with `data` and `value`.
    function callContract(address target, uint256 value, bytes memory data)
        internal
        returns (bytes memory result)
    {
        bool success;
        (success, result) = target.call{value: value}(data);
        _check(target, success, result);
    }

    /// @dev Makes a call to `target`, with `data`.
    function callContract(address target, bytes memory data)
        internal
        returns (bytes memory result)
    {
        bool success;
        (success, result) = target.call(data);
        _check(target, success, result);
    }

    /// @dev Makes a static call to `target`, with `data`.
    function staticCallContract(address target, bytes memory data)
        internal
        view
        returns (bytes memory result)
    {
        bool success;
        (success, result) = target.staticcall(data);
        _check(target, success, result);
    }

    /// @dev Makes a delegate call to `target`, with `data`.
    function delegateCallContract(address target, bytes memory data)
        internal
        returns (bytes memory result)
    {
        bool success;
        (success, result) = target.delegatecall(data);
        _check(target, success, result);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    TRY CALL OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // These functions enable gas limited calls to be performed,
    // with a cap on the number of return data bytes to be copied.
    // The can be used to ensure that the calling contract will not
    // run out-of-gas.

    /// @dev Makes a call to `target`, with `data` and `value`.
    /// The call is given a gas limit of `gasStipend`,
    /// and up to `maxCopy` bytes of return data can be copied.
    function tryCall(
        address target,
        uint256 value,
        uint256 gasStipend,
        uint16 maxCopy,
        bytes memory data
    ) internal returns (bool success, bool exceededMaxCopy, bytes memory result) {
        uint256 total;
        (success, result, total) = _callBounded(target, value, gasStipend, data, maxCopy);
        exceededMaxCopy = total > maxCopy;
    }

    /// @dev Makes a call to `target`, with `data`.
    /// The call is given a gas limit of `gasStipend`,
    /// and up to `maxCopy` bytes of return data can be copied.
    function tryStaticCall(address target, uint256 gasStipend, uint16 maxCopy, bytes memory data)
        internal
        view
        returns (bool success, bool exceededMaxCopy, bytes memory result)
    {
        uint256 total;
        (success, result, total) = _staticCallBounded(target, gasStipend, data, maxCopy);
        exceededMaxCopy = total > maxCopy;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      OTHER OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Bubbles up the revert.
    function bubbleUpRevert(bytes memory revertReturnData) internal pure {
        _revertRaw(revertReturnData);
    }

    /// @dev In-place replaces the function selector of encoded contract call data.
    function setSelector(bytes4 newSelector, bytes memory data) internal pure {
        if (data.length < 4) revert DataTooShort();
        _writeBytes4(data, 0, newSelector);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Bubbles a failed call's revert, and rejects an empty response from
    /// an account without code, which a call to it succeeds with.
    function _check(address target, bool success, bytes memory result) private view {
        if (!success) _revertRaw(result);
        if (result.length == 0 && target.code.length == 0) revert TargetIsNotContract();
    }

    /// @dev Writes `value` into `b` at `offset`.
    /// @custom:solar-inline always
    function _writeBytes4(bytes memory b, uint256 offset, bytes4 value) private pure {
        for (uint256 k; k < 4; ++k) {
            b[offset + k] = value[k];
        }
    }

    /// @dev Calls `target` with `payload`, `value` wei and `gasLimit` gas, and
    /// copies at most `maxCopy` bytes of the response into a new buffer sized to
    /// what it holds, allocated after the call. `totalSize` is how many bytes
    /// there were.
    /// @custom:solar-trusted
    function _callBounded(
        address target,
        uint256 value,
        uint256 gasLimit,
        bytes memory payload,
        uint256 maxCopy
    ) private returns (bool success, bytes memory output, uint256 totalSize) {
        /// @solidity memory-safe-assembly
        assembly {
            success := call(gasLimit, target, value, add(payload, 0x20), mload(payload), 0x00, 0x00)
            totalSize := returndatasize()
            let copied := totalSize
            if gt(copied, maxCopy) { copied := maxCopy }
            output := mload(0x40)
            mstore(output, copied)
            returndatacopy(add(output, 0x20), 0x00, copied)
            mstore(0x40, and(add(add(output, 0x3f), copied), not(0x1f)))
        }
    }

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and copies
    /// at most `maxCopy` bytes of the response into a new buffer, as
    /// `callBounded` does.
    /// @custom:solar-trusted
    function _staticCallBounded(
        address target,
        uint256 gasLimit,
        bytes memory payload,
        uint256 maxCopy
    ) private view returns (bool success, bytes memory output, uint256 totalSize) {
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(gasLimit, target, add(payload, 0x20), mload(payload), 0x00, 0x00)
            totalSize := returndatasize()
            let copied := totalSize
            if gt(copied, maxCopy) { copied := maxCopy }
            output := mload(0x40)
            mstore(output, copied)
            returndatacopy(add(output, 0x20), 0x00, copied)
            mstore(0x40, and(add(add(output, 0x3f), copied), not(0x1f)))
        }
    }

    /// @dev Reverts the current call with exactly `data`.
    /// @custom:solar-trusted
    function _revertRaw(bytes memory data) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(data, 0x20), mload(data))
        }
    }
}
