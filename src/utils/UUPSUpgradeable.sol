// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {CallContextChecker} from "./CallContextChecker.sol";

/// @notice UUPS proxy mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/UUPSUpgradeable.sol)
/// @author Modified from OpenZeppelin
/// (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/utils/UUPSUpgradeable.sol)
///
/// @dev Note:
/// - This implementation is intended to be used with ERC1967 proxies.
/// See: `LibClone.deployERC1967` and related functions.
/// - This implementation is NOT compatible with legacy OpenZeppelin proxies
/// which do not store the implementation at `_ERC1967_IMPLEMENTATION_SLOT`.
///
/// The checked port checks `proxiableUUID` with a trusted static call that reads at most one
/// word of the answer, through the scratch space, as the assembly reads it, stores the
/// implementation with a trusted helper, since Solidity cannot name the ERC-1967 slot, and
/// makes the delegatecall with a trusted call that copies none of the answer, bubbling a
/// revert's data with a trusted helper, as the assembly does; the event is an ordinary emit.
/// The helpers' names carry a `_uupsUpgradeable` prefix, so that a contract can inherit this
/// alongside other ports.
/// @custom:solar-safe memory arithmetic
abstract contract UUPSUpgradeable is CallContextChecker {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The upgrade failed.
    error UpgradeFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when the proxy's implementation is upgraded.
    event Upgraded(address indexed implementation);

    /// @dev `keccak256(bytes("Upgraded(address)"))`.
    uint256 private constant _UPGRADED_EVENT_SIGNATURE =
        0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ERC-1967 storage slot for the implementation in the proxy.
    /// `uint256(keccak256("eip1967.proxy.implementation")) - 1`.
    bytes32 internal constant _ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      UUPS OPERATIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Please override this function to check if `msg.sender` is authorized
    /// to upgrade the proxy to `newImplementation`, reverting if not.
    /// ```
    ///     function _authorizeUpgrade(address) internal override onlyOwner {}
    /// ```
    function _authorizeUpgrade(address newImplementation) internal virtual;

    /// @dev Returns the storage slot used by the implementation,
    /// as specified in [ERC1822](https://eips.ethereum.org/EIPS/eip-1822).
    ///
    /// Note: The `notDelegated` modifier prevents accidental upgrades to
    /// an implementation that is a proxy contract.
    function proxiableUUID() public view virtual notDelegated returns (bytes32) {
        // This function must always return `_ERC1967_IMPLEMENTATION_SLOT` to comply with ERC1967.
        return _ERC1967_IMPLEMENTATION_SLOT;
    }

    /// @dev Upgrades the proxy's implementation to `newImplementation`.
    /// Emits a {Upgraded} event.
    ///
    /// Note: Passing in empty `data` skips the delegatecall to `newImplementation`.
    function upgradeToAndCall(address newImplementation, bytes calldata data)
        public
        payable
        virtual
        onlyProxy
    {
        _authorizeUpgrade(newImplementation);
        // Check if `newImplementation` implements `proxiableUUID` correctly.
        // A failed call or an answer shorter than a word never matches the slot.
        (bool success, uint256 answerSize, bytes32 answer) = _uupsUpgradeableStaticCallWord(
            newImplementation,
            abi.encodeWithSelector(0x52d1902d) // `proxiableUUID()`.
        );
        if (!success || answerSize < 0x20 || answer != _ERC1967_IMPLEMENTATION_SLOT) {
            revert UpgradeFailed();
        }
        // Emit the {Upgraded} event.
        emit Upgraded(newImplementation);
        // Updates the implementation.
        _uupsUpgradeableSstore(
            uint256(_ERC1967_IMPLEMENTATION_SLOT), uint256(uint160(newImplementation))
        );

        // Perform a delegatecall to `newImplementation` if `data` is non-empty.
        if (data.length != 0) {
            // Forwards the `data` to `newImplementation` via delegatecall.
            // Bubble up the revert if the call reverts.
            if (!_uupsUpgradeableDelegateCall(newImplementation, data)) {
                _uupsUpgradeableRevertReturndata();
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Stores `value` in storage slot `slot`. Solidity cannot name a slot it did not
    /// allocate.
    /// @custom:solar-trusted
    function _uupsUpgradeableSstore(uint256 slot, uint256 value) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, value)
        }
    }

    /// @dev Static-calls `target` with `payload` and all the gas left, and returns the size and
    /// the first word of the answer, read through the scratch space; past the size, the word
    /// holds what the scratch space held.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _uupsUpgradeableStaticCallWord(address target, bytes memory payload)
        private
        view
        returns (bool success, uint256 totalSize, bytes32 first)
    {
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(gas(), target, add(payload, 0x20), mload(payload), 0x00, 0x20)
            totalSize := returndatasize()
            first := mload(0x00)
        }
    }

    /// @dev Delegate-calls `target` with `payload` and all the gas left, and copies none of
    /// the answer. Solidity's calls copy the whole answer.
    /// @custom:solar-trusted
    function _uupsUpgradeableDelegateCall(address target, bytes memory payload)
        private
        returns (bool success)
    {
        /// @solidity memory-safe-assembly
        assembly {
            success := delegatecall(
                gas(),
                target,
                add(payload, 0x20),
                mload(payload),
                codesize(),
                0x00
            )
        }
    }

    /// @dev Reverts the current call with the return data of the last call, which Solidity
    /// cannot read without copying it on success too.
    /// @custom:solar-trusted
    function _uupsUpgradeableRevertReturndata() private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            returndatacopy(m, 0x00, returndatasize())
            revert(m, returndatasize())
        }
    }
}
