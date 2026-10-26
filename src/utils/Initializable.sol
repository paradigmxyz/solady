// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Initializable mixin for the upgradeable contracts.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/Initializable.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/proxy/utils/Initializable.sol)
/// @dev This port keeps the packed word, the initializing bit below the initialized version,
/// with the same checks and {Initialized} events. It uses a Solidity mapping keyed by
/// `_initializableSlot()` rather than writing that slot directly. This layout is for new
/// deployments and is not compatible with an existing upstream deployment. The
/// `initializer` guard checks the word it read before it stores the new one, where upstream
/// stores first; a failed check reverts the store either way.
/// @custom:solar-safe memory arithmetic
abstract contract Initializable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The contract is already initialized.
    error InvalidInitialization();

    /// @dev The contract is not initializing.
    error NotInitializing();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Triggered when the contract has been initialized.
    event Initialized(uint64 version);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The default initializer namespace is given by:
    /// `bytes32(~uint256(uint32(bytes4(keccak256("_INITIALIZABLE_SLOT")))))`.
    ///
    /// Bits Layout:
    /// - [0]     `initializing`
    /// - [1..64] `initializedVersion`
    bytes32 private constant _INITIALIZABLE_SLOT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffbf601132;

    mapping(bytes32 => uint256) private _initializableStates;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor() {
        // Construction time check to ensure that `_initializableSlot()` is not
        // overridden to zero. Will be optimized away if there is no revert.
        require(_initializableSlot() != bytes32(0));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OPERATIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Override to return a non-zero custom storage slot if required.
    /// In this port the returned value selects a mapping key, not a physical storage slot.
    function _initializableSlot() internal pure virtual returns (bytes32) {
        return _INITIALIZABLE_SLOT;
    }

    /// @dev Guards an initializer function so that it can be invoked at most once.
    ///
    /// You can guard a function with `onlyInitializing` such that it can be called
    /// through a function guarded with `initializer`.
    ///
    /// This is similar to `reinitializer(1)`, except that in the context of a constructor,
    /// an `initializer` guarded function can be invoked multiple times.
    /// This can be useful during testing and is not expected to be used in production.
    ///
    /// Emits an {Initialized} event.
    modifier initializer() virtual {
        bytes32 s = _initializableSlot();
        uint256 i = _initializableSload(s);
        // If `!(initializing == 0 && initializedVersion == 0)`.
        if (i != 0) {
            // If `!(address(this).code.length == 0 && initializedVersion == 1)`.
            if (address(this).code.length != 0 || i >> 1 != 1) revert InvalidInitialization();
        }
        // Set `initializing` to 1, `initializedVersion` to 1.
        _initializableSstore(s, 3);
        // Skip initializing if `initializing == 1`.
        if (i & 1 != 0) s = bytes32(0);
        _;
        if (s != bytes32(0)) {
            // Set `initializing` to 0, `initializedVersion` to 1.
            _initializableSstore(s, 2);
            // Emit the {Initialized} event.
            emit Initialized(1);
        }
    }

    /// @dev Guards a reinitializer function so that it can be invoked at most once.
    ///
    /// You can guard a function with `onlyInitializing` such that it can be called
    /// through a function guarded with `reinitializer`.
    ///
    /// Emits an {Initialized} event.
    modifier reinitializer(uint64 version) virtual {
        bytes32 s = _initializableSlot();
        // Shift left by 1 to make space for the initializing bit.
        uint256 shifted = uint256(version) << 1;
        uint256 i = _initializableSload(s);
        // If `initializing == 1 || initializedVersion >= version`.
        if (i & 1 != 0 || i >= shifted) revert InvalidInitialization();
        // Set `initializing` to 1, `initializedVersion` to `version`.
        _initializableSstore(s, shifted | 1);
        _;
        // Set `initializing` to 0, `initializedVersion` to `version`.
        _initializableSstore(s, shifted);
        // Emit the {Initialized} event.
        emit Initialized(version);
    }

    /// @dev Guards a function such that it can only be called in the scope
    /// of a function guarded with `initializer` or `reinitializer`.
    modifier onlyInitializing() virtual {
        _checkInitializing();
        _;
    }

    /// @dev Reverts if the contract is not initializing.
    function _checkInitializing() internal view virtual {
        if (_initializableSload(_initializableSlot()) & 1 == 0) revert NotInitializing();
    }

    /// @dev Locks any future initializations by setting the initialized version to `2**64 - 1`.
    ///
    /// Calling this in the constructor will prevent the contract from being initialized
    /// or reinitialized. It is recommended to use this to lock implementation contracts
    /// that are designed to be called through proxies.
    ///
    /// Emits an {Initialized} event the first time it is successfully called.
    function _disableInitializers() internal virtual {
        bytes32 s = _initializableSlot();
        uint256 i = _initializableSload(s);
        if (i & 1 != 0) revert InvalidInitialization();
        if (i >> 1 != type(uint64).max) {
            // Set `initializing` to 0, `initializedVersion` to `2**64 - 1`.
            _initializableSstore(s, uint256(type(uint64).max) << 1);
            // Emit the {Initialized} event.
            emit Initialized(type(uint64).max);
        }
    }

    /// @dev Returns the highest version that has been initialized.
    function _getInitializedVersion() internal view virtual returns (uint64 version) {
        version = uint64(_initializableSload(_initializableSlot()) >> 1);
    }

    /// @dev Returns whether the contract is currently initializing.
    function _isInitializing() internal view virtual returns (bool result) {
        result = _initializableSload(_initializableSlot()) & 1 != 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The packed state for the initializer namespace `slot`.
    function _initializableSload(bytes32 slot) private view returns (uint256 value) {
        value = _initializableStates[slot];
    }

    /// @dev Stores `value` for the initializer namespace `slot`.
    function _initializableSstore(bytes32 slot, uint256 value) private {
        _initializableStates[slot] = value;
    }
}
