// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Enumerable multiroles authorization mixin.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/auth/EnumerableRoles.sol)
///
/// @dev Note:
/// This implementation is agnostic to the Ownable that the contract inherits from.
/// It performs a self-staticcall to the `owner()` function to determine the owner.
/// This is useful for situations where the contract inherits from
/// OpenZeppelin's Ownable, such as in LayerZero's OApp contracts.
///
/// This implementation performs a self-staticcall to `MAX_ROLE()` to determine
/// the maximum role that can be set/unset. If the inheriting contract does not
/// have `MAX_ROLE()`, then any role can be set/unset.
///
/// This implementation allows for any uint256 role,
/// it does NOT take in a bitmask of roles.
/// This is to accommodate teams that are allergic to bitwise flags.
///
/// By default, the `owner()` is the only account that is authorized to set roles.
/// This behavior can be changed via overrides.
///
/// This implementation is compatible with any Ownable.
/// This implementation is NOT compatible with OwnableRoles.
///
/// The safe port stores holders and their positions in Solidity arrays and mappings.
/// This storage layout is for new deployments, not upgrades from the original layout.
/// Removing a holder moves the last holder into its position. The self-staticcalls to
/// `owner()` and `MAX_ROLE()` are plain low-level calls whose first returned word is
/// compared, the roles in `encodedRoles` are read a word at a time, and the event and
/// errors are ordinary emits and reverts. The private helpers carry the contract's
/// name, as upstream's do, so that it still combines with Ownable and TimedRoles.
/// @custom:solar-safe
abstract contract EnumerableRoles {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The status of `role` for `holder` has been set to `active`.
    event RoleSet(address indexed holder, uint256 indexed role, bool indexed active);

    /// @dev `keccak256(bytes("RoleSet(address,uint256,bool)"))`.
    uint256 private constant _ROLE_SET_EVENT_SIGNATURE =
        0xaddc47d7e02c95c00ec667676636d772a589ffbf0663cfd7cd4dd3d4758201b8;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The index is out of bounds of the role holders array.
    error RoleHoldersIndexOutOfBounds();

    /// @dev Cannot set the role of the zero address.
    error RoleHolderIsZeroAddress();

    /// @dev The role has exceeded the maximum role.
    error InvalidRole();

    /// @dev Unauthorized to perform the action.
    error EnumerableRolesUnauthorized();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Holders in enumeration order and their one-based positions.
    struct EnumerableRoleData {
        address[] holders;
        mapping(address => uint256) positions;
    }

    mapping(uint256 => EnumerableRoleData) private _enumerableRolesData;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  PUBLIC UPDATE FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sets the status of `role` of `holder` to `active`.
    function setRole(address holder, uint256 role, bool active) public payable virtual {
        _authorizeSetRole(holder, role, active);
        _setRole(holder, role, active);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   PUBLIC READ FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns if `holder` has active `role`.
    function hasRole(address holder, uint256 role) public view virtual returns (bool result) {
        result = _enumerableRolesData[role].positions[holder] != 0;
    }

    /// @dev Returns an array of the holders of `role`.
    function roleHolders(uint256 role) public view virtual returns (address[] memory result) {
        result = _enumerableRolesData[role].holders;
    }

    /// @dev Returns the total number of holders of `role`.
    function roleHolderCount(uint256 role) public view virtual returns (uint256 result) {
        result = _enumerableRolesData[role].holders.length;
    }

    /// @dev Returns the holder of `role` at the index `i`.
    function roleHolderAt(uint256 role, uint256 i) public view virtual returns (address result) {
        address[] storage holders = _enumerableRolesData[role].holders;
        if (i >= holders.length) revert RoleHoldersIndexOutOfBounds();
        result = holders[i];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Set the role for holder directly without authorization guard.
    function _setRole(address holder, uint256 role, bool active) internal virtual {
        _validateRole(role);
        if (holder == address(0)) revert RoleHolderIsZeroAddress();
        EnumerableRoleData storage data = _enumerableRolesData[role];
        uint256 position = data.positions[holder];
        if (!active) {
            if (position != 0) {
                uint256 last = data.holders.length - 1;
                uint256 index = position - 1;
                if (index != last) {
                    // Move the last holder into the removed holder's place.
                    address lastHolder = data.holders[last];
                    data.holders[index] = lastHolder;
                    data.positions[lastHolder] = position;
                }
                data.holders.pop();
                delete data.positions[holder];
            }
        } else if (position == 0) {
            data.holders.push(holder);
            data.positions[holder] = data.holders.length;
        }
        emit RoleSet(holder, role, active);
    }

    /// @dev Requires the role is not greater than `MAX_ROLE()`.
    /// If `MAX_ROLE()` is not implemented, this is an no-op.
    function _validateRole(uint256 role) internal view virtual {
        (bool success, bytes memory answer) =
            address(this).staticcall(abi.encodeWithSelector(0xd24f19d5)); // `MAX_ROLE()`.
        if (success && answer.length >= 0x20) {
            if (role > uint256(_enumerableRolesReadBytes32(answer, 0))) revert InvalidRole();
        }
    }

    /// @dev Checks that the caller is authorized to set the role.
    function _authorizeSetRole(address holder, uint256 role, bool active) internal virtual {
        if (!_enumerableRolesSenderIsContractOwner()) _revertEnumerableRolesUnauthorized();
        // Silence compiler warning on unused variables.
        (holder, role, active) = (holder, role, active);
    }

    /// @dev Returns if `holder` has any roles in `encodedRoles`.
    /// `encodedRoles` is `abi.encode(SAMPLE_ROLE_0, SAMPLE_ROLE_1, ...)`.
    function _hasAnyRoles(address holder, bytes memory encodedRoles)
        internal
        view
        virtual
        returns (bool result)
    {
        // Each whole word is a role; the bytes past the last whole word are ignored.
        uint256 n = encodedRoles.length >> 5;
        for (uint256 i; i < n; ++i) {
            uint256 role = uint256(_enumerableRolesReadBytes32(encodedRoles, i << 5));
            if (_enumerableRolesData[role].positions[holder] != 0) {
                return true;
            }
        }
    }

    /// @dev Reverts if `msg.sender` does not have `role`.
    function _checkRole(uint256 role) internal view virtual {
        if (!hasRole(msg.sender, role)) _revertEnumerableRolesUnauthorized();
    }

    /// @dev Reverts if `msg.sender` does not have any role in `encodedRoles`.
    function _checkRoles(bytes memory encodedRoles) internal view virtual {
        if (!_hasAnyRoles(msg.sender, encodedRoles)) _revertEnumerableRolesUnauthorized();
    }

    /// @dev Reverts if `msg.sender` is not the contract owner and does not have `role`.
    function _checkOwnerOrRole(uint256 role) internal view virtual {
        if (!_enumerableRolesSenderIsContractOwner()) _checkRole(role);
    }

    /// @dev Reverts if `msg.sender` is not the contract owner and
    /// does not have any role in `encodedRoles`.
    function _checkOwnerOrRoles(bytes memory encodedRoles) internal view virtual {
        if (!_enumerableRolesSenderIsContractOwner()) _checkRoles(encodedRoles);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         MODIFIERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Marks a function as only callable by an account with `role`.
    modifier onlyRole(uint256 role) virtual {
        _checkRole(role);
        _;
    }

    /// @dev Marks a function as only callable by an account with any role in `encodedRoles`.
    /// `encodedRoles` is `abi.encode(SAMPLE_ROLE_0, SAMPLE_ROLE_1, ...)`.
    modifier onlyRoles(bytes memory encodedRoles) virtual {
        _checkRoles(encodedRoles);
        _;
    }

    /// @dev Marks a function as only callable by the owner or by an account with `role`.
    modifier onlyOwnerOrRole(uint256 role) virtual {
        _checkOwnerOrRole(role);
        _;
    }

    /// @dev Marks a function as only callable by the owner or
    /// by an account with any role in `encodedRoles`.
    /// Checks for ownership first, then checks for roles.
    /// `encodedRoles` is `abi.encode(SAMPLE_ROLE_0, SAMPLE_ROLE_1, ...)`.
    modifier onlyOwnerOrRoles(bytes memory encodedRoles) virtual {
        _checkOwnerOrRoles(encodedRoles);
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns if the `msg.sender` is equal to `owner()` on this contract.
    /// If the contract does not have `owner()` implemented, returns false.
    function _enumerableRolesSenderIsContractOwner() private view returns (bool result) {
        (bool success, bytes memory answer) =
            address(this).staticcall(abi.encodeWithSelector(0x8da5cb5b)); // `owner()`.
        result = success && answer.length >= 0x20
            && uint256(_enumerableRolesReadBytes32(answer, 0)) == uint256(uint160(msg.sender));
    }

    /// @dev Reverts with `EnumerableRolesUnauthorized()`.
    function _revertEnumerableRolesUnauthorized() private pure {
        revert EnumerableRolesUnauthorized();
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _enumerableRolesReadBytes32(bytes memory b, uint256 offset)
        private
        pure
        returns (bytes32 result)
    {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }
}
