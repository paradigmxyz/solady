// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Timed multiroles authorization mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/auth/TimedRoles.sol)
///
/// @dev Note:
/// This implementation is agnostic to the Ownable that the contract inherits from.
/// It performs a self-staticcall to the `owner()` function to determine the owner.
/// This is useful for situations where the contract inherits from
/// OpenZeppelin's Ownable, such as in LayerZero's OApp contracts.
///
/// This implementation performs a self-staticcall to `MAX_TIMED_ROLE()` to determine
/// the maximum timed role that can be set/unset. If the inheriting contract does not
/// have `MAX_TIMED_ROLE()`, then any timed role can be set/unset.
///
/// This implementation allows for any uint256 role,
/// it does NOT take in a bitmask of roles.
/// This is to accommodate teams that are allergic to bitwise flags.
///
/// By default, the `owner()` is the only account that is authorized to set timed roles.
/// This behavior can be changed via overrides.
///
/// This implementation is compatible with any Ownable.
/// This implementation is NOT compatible with OwnableRoles.
///
/// As timed roles can turn active or inactive anytime, enumeration is omitted here.
/// Querying the number of active timed roles will cost `O(n)` instead of `O(1)`.
///
/// Names are deliberately prefixed with "Timed", so that this contract
/// can be used in conjunction with EnumerableRoles without collisions.
///
/// The safe port stores active time ranges in a Solidity mapping without inline assembly.
/// This storage layout is for new deployments, not upgrades from the original layout.
/// The self-staticcalls to `owner()` and `MAX_TIMED_ROLE()` are plain
/// low-level calls whose first returned word is compared, the timed roles in
/// `encodedTimeRoles` are read a word at a time, and the event and errors are ordinary
/// emits and reverts. The private helpers carry the contract's name, as upstream's do,
/// so that it still combines with Ownable and EnumerableRoles.
/// @custom:solar-safe
abstract contract TimedRoles {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The active time range of the timed role has been set.
    event TimedRoleSet(
        address indexed holder, uint256 indexed timedRole, uint40 start, uint40 expires
    );

    /// @dev `keccak256(bytes("TimedRoleSet(address,uint256,uint40,uint40)"))`.
    uint256 private constant _TIMED_ROLE_SET_EVENT_SIGNATURE =
        0xf7b5bcd44281f9bd7dfe7227dbb5c96dafa8587339fe558592433e9d02ade7d7;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Cannot set the timed role of the zero address.
    error TimedRoleHolderIsZeroAddress();

    /// @dev The timed role has exceeded the maximum timed role.
    error InvalidTimedRole();

    /// @dev Unauthorized to perform the action.
    error TimedRolesUnauthorized();

    /// @dev The `expires` cannot be less than the `start`.
    error InvalidTimedRoleRange();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The active time range for each holder and timed role, in Solidity-managed storage.
    /// Bits Layout:
    /// - [0..39]    `expires`.
    /// - [216..255] `start`.
    mapping(address => mapping(uint256 => uint256)) private _timedRolesRanges;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  PUBLIC UPDATE FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sets the active time range of `timedRole` of `holder` to [`start`, `expires`].
    /// The `timedRole` is active when `start <= block.timestamp && block.timestamp <= expires`.
    function setTimedRole(address holder, uint256 timedRole, uint40 start, uint40 expires)
        public
        payable
        virtual
    {
        _authorizeSetTimedRole(holder, timedRole, start, expires);
        _setTimedRole(holder, timedRole, start, expires);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   PUBLIC READ FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether the `timedRole` is active for `holder` and the active time range.
    function timedRoleActive(address holder, uint256 timedRole)
        public
        view
        virtual
        returns (bool isActive, uint40 start, uint40 expires)
    {
        uint256 p = _timedRolesRanges[holder][timedRole];
        start = uint40(p >> 216);
        expires = uint40(p);
        // Active unless before the start or after the expiry, tested without branches.
        isActive = (block.timestamp < start ? 1 : 0) | (block.timestamp > expires ? 1 : 0) == 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Set the timed role for holder directly without authorization guard.
    function _setTimedRole(address holder, uint256 timedRole, uint40 start, uint40 expires)
        internal
        virtual
    {
        _validateTimedRole(timedRole);
        if (holder == address(0)) revert TimedRoleHolderIsZeroAddress();
        // Validate the range.
        if (expires < start) revert InvalidTimedRoleRange();
        // Store the range.
        _timedRolesRanges[holder][timedRole] = uint256(start) << 216 | uint256(expires);
        // Emit the {TimedRoleSet} event.
        emit TimedRoleSet(holder, timedRole, start, expires);
    }

    /// @dev Requires the timedRole is not greater than `MAX_TIMED_ROLE()`.
    /// If `MAX_TIMED_ROLE()` is not implemented, this is an no-op.
    function _validateTimedRole(uint256 timedRole) internal view virtual {
        (bool success, bytes memory answer) =
            address(this).staticcall(abi.encodeWithSelector(0x32bc6439)); // `MAX_TIMED_ROLE()`.
        if (success && answer.length >= 0x20) {
            if (timedRole > uint256(_timedRolesReadBytes32(answer, 0))) revert InvalidTimedRole();
        }
    }

    /// @dev Checks that the caller is authorized to set the timed role.
    function _authorizeSetTimedRole(address holder, uint256 timedRole, uint40 start, uint40 expires)
        internal
        virtual
    {
        if (!_timedRolesSenderIsContractOwner()) _revertTimedRolesUnauthorized();
        // Silence compiler warning on unused variables.
        (holder, timedRole, start, expires) = (holder, timedRole, start, expires);
    }

    /// @dev Returns if `holder` has any roles in `encodedTimeRoles`.
    /// `encodedTimeRoles` is `abi.encode(SAMPLE_TIMED_ROLE_0, SAMPLE_TIMED_ROLE_1, ...)`.
    function _hasAnyTimedRoles(address holder, bytes memory encodedTimeRoles)
        internal
        view
        virtual
        returns (bool result)
    {
        // Each whole word is a timed role; the bytes past the last whole word are ignored.
        uint256 n = encodedTimeRoles.length >> 5;
        for (uint256 i; i < n; ++i) {
            uint256 timedRole = uint256(_timedRolesReadBytes32(encodedTimeRoles, i << 5));
            uint256 p = _timedRolesRanges[holder][timedRole];
            // Active unless before the start or after the expiry, tested without branches.
            uint256 inactive =
                (block.timestamp < p >> 216 ? 1 : 0) | (block.timestamp > uint40(p) ? 1 : 0);
            if (inactive == 0) return true;
        }
    }

    /// @dev Reverts if `msg.sender` does not have `timedRole`.
    function _checkTimedRole(uint256 timedRole) internal view virtual {
        (bool isActive,,) = timedRoleActive(msg.sender, timedRole);
        if (!isActive) _revertTimedRolesUnauthorized();
    }

    /// @dev Reverts if `msg.sender` does not have any timed role in `encodedTimedRoles`.
    function _checkTimedRoles(bytes memory encodedTimedRoles) internal view virtual {
        if (!_hasAnyTimedRoles(msg.sender, encodedTimedRoles)) _revertTimedRolesUnauthorized();
    }

    /// @dev Reverts if `msg.sender` is not the contract owner and does not have `timedRole`.
    function _checkOwnerOrTimedRole(uint256 timedRole) internal view virtual {
        if (!_timedRolesSenderIsContractOwner()) _checkTimedRole(timedRole);
    }

    /// @dev Reverts if `msg.sender` is not the contract owner and
    /// does not have any timed role in `encodedTimedRoles`.
    function _checkOwnerOrTimedRoles(bytes memory encodedTimedRoles) internal view virtual {
        if (!_timedRolesSenderIsContractOwner()) _checkTimedRoles(encodedTimedRoles);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         MODIFIERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Marks a function as only callable by an account with `timedRole`.
    modifier onlyTimedRole(uint256 timedRole) virtual {
        _checkTimedRole(timedRole);
        _;
    }

    /// @dev Marks a function as only callable by an account with any role in `encodedTimedRoles`.
    /// `encodedTimedRoles` is `abi.encode(SAMPLE_TIMED_ROLE_0, SAMPLE_TIMED_ROLE_1, ...)`.
    modifier onlyTimedRoles(bytes memory encodedTimedRoles) virtual {
        _checkTimedRoles(encodedTimedRoles);
        _;
    }

    /// @dev Marks a function as only callable by the owner or by an account with `timedRole`.
    modifier onlyOwnerOrTimedRole(uint256 timedRole) virtual {
        _checkOwnerOrTimedRole(timedRole);
        _;
    }

    /// @dev Marks a function as only callable by the owner or
    /// by an account with any role in `encodedTimedRoles`.
    /// Checks for ownership first, then checks for roles.
    /// `encodedTimedRoles` is `abi.encode(SAMPLE_TIMED_ROLE_0, SAMPLE_TIMED_ROLE_1, ...)`.
    modifier onlyOwnerOrTimedRoles(bytes memory encodedTimedRoles) virtual {
        _checkOwnerOrTimedRoles(encodedTimedRoles);
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns if the `msg.sender` is equal to `owner()` on this contract.
    /// If the contract does not have `owner()` implemented, returns false.
    function _timedRolesSenderIsContractOwner() private view returns (bool result) {
        (bool success, bytes memory answer) =
            address(this).staticcall(abi.encodeWithSelector(0x8da5cb5b)); // `owner()`.
        result = success && answer.length >= 0x20
            && uint256(_timedRolesReadBytes32(answer, 0)) == uint256(uint160(msg.sender));
    }

    /// @dev Reverts with `TimedRolesUnauthorized()`.
    /// @custom:solar-terminates
    function _revertTimedRolesUnauthorized() private pure {
        revert TimedRolesUnauthorized();
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline
    function _timedRolesReadBytes32(bytes memory b, uint256 offset)
        private
        pure
        returns (bytes32 result)
    {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }
}
