// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Simple ERC721 implementation with storage hitchhiking.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/tokens/ERC721.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC721.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/token/ERC721/ERC721.sol)
///
/// @dev Note:
/// - The ERC721 standard allows for self-approvals.
///   For performance, this implementation WILL NOT revert for such actions.
///   Please add any checks with overrides if desired.
/// - For performance, methods are made payable where permitted by the ERC721 standard.
/// - The `safeTransfer` functions use the identity precompile (0x4)
///   to copy memory internally.
///
/// If you are overriding:
/// - NEVER violate the ERC721 invariant:
///   the balance of an owner MUST always be equal to their number of ownership slots.
///   The transfer functions do not have an underflow guard for user token balances.
/// - Make sure all variables written to storage are properly cleaned
///   (e.g. the bool value for `isApprovedForAll` MUST be either 1 or 0 under the hood).
/// - Check that the overridden function is actually used in the function you want to
///   change the behavior of. Much of the code has been manually inlined for performance.
///
/// The checked port keeps upstream's storage slots, read and written through two
/// trusted helpers, and derives them in Solidity: the slot hashes are
/// `abi.encodePacked` words, and the ownership slot adds twice the id with
/// wrap-around, through a trusted `_erc721Add`, as the assembly does. Every check keeps
/// its order and custom error, the events are ordinary emits, and the receiver
/// check is a plain call whose revert data the trusted `_erc721RevertWith` bubbles up.
/// A sender's balance is decremented with checked arithmetic, which only an
/// override that breaks the balance invariant above can make revert.
/// @custom:solar-safe memory arithmetic
abstract contract ERC721 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev An account can hold up to 4294967295 tokens.
    uint256 internal constant _MAX_ACCOUNT_BALANCE = 0xffffffff;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Only the token owner or an approved account can manage the token.
    error NotOwnerNorApproved();

    /// @dev The token does not exist.
    error TokenDoesNotExist();

    /// @dev The token already exists.
    error TokenAlreadyExists();

    /// @dev Cannot query the balance for the zero address.
    error BalanceQueryForZeroAddress();

    /// @dev Cannot mint or transfer to the zero address.
    error TransferToZeroAddress();

    /// @dev The token must be owned by `from`.
    error TransferFromIncorrectOwner();

    /// @dev The recipient's balance has overflowed.
    error AccountBalanceOverflow();

    /// @dev Cannot safely transfer to a contract that does not implement
    /// the ERC721Receiver interface.
    error TransferToNonERC721ReceiverImplementer();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when token `id` is transferred from `from` to `to`.
    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    /// @dev Emitted when `owner` enables `account` to manage the `id` token.
    event Approval(address indexed owner, address indexed account, uint256 indexed id);

    /// @dev Emitted when `owner` enables or disables `operator` to manage all of their tokens.
    event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ownership data slot of `id` is given by:
    /// ```
    ///     mstore(0x00, id)
    ///     mstore(0x1c, _ERC721_MASTER_SLOT_SEED)
    ///     let ownershipSlot := add(id, add(id, keccak256(0x00, 0x20)))
    /// ```
    /// Bits Layout:
    /// - [0..159]   `addr`
    /// - [160..255] `extraData`
    ///
    /// The approved address slot is given by: `add(1, ownershipSlot)`.
    ///
    /// See: https://notes.ethereum.org/%40vbuterin/verkle_tree_eip
    ///
    /// The balance slot of `owner` is given by:
    /// ```
    ///     mstore(0x1c, _ERC721_MASTER_SLOT_SEED)
    ///     mstore(0x00, owner)
    ///     let balanceSlot := keccak256(0x0c, 0x1c)
    /// ```
    /// Bits Layout:
    /// - [0..31]   `balance`
    /// - [32..255] `aux`
    ///
    /// The `operator` approval slot of `owner` is given by:
    /// ```
    ///     mstore(0x1c, or(_ERC721_MASTER_SLOT_SEED, operator))
    ///     mstore(0x00, owner)
    ///     let operatorApprovalSlot := keccak256(0x0c, 0x30)
    /// ```
    uint256 private constant _ERC721_MASTER_SLOT_SEED = 0x7d8825530a5a2e7a << 192;

    /// @dev Pre-shifted and pre-masked constant.
    uint256 private constant _ERC721_MASTER_SLOT_SEED_MASKED = 0x0a5a2e7a00000000;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ERC721 METADATA                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the token collection name.
    function name() public view virtual returns (string memory);

    /// @dev Returns the token collection symbol.
    function symbol() public view virtual returns (string memory);

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    function tokenURI(uint256 id) public view virtual returns (string memory);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERC721                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the owner of token `id`.
    ///
    /// Requirements:
    /// - Token `id` must exist.
    function ownerOf(uint256 id) public view virtual returns (address result) {
        result = _ownerOf(id);
        if (result == address(0)) revert TokenDoesNotExist();
    }

    /// @dev Returns the number of tokens owned by `owner`.
    ///
    /// Requirements:
    /// - `owner` must not be the zero address.
    function balanceOf(address owner) public view virtual returns (uint256 result) {
        // Revert if the `owner` is the zero address.
        if (owner == address(0)) revert BalanceQueryForZeroAddress();
        result = _erc721Sload(_erc721BalanceSlot(owner)) & _MAX_ACCOUNT_BALANCE;
    }

    /// @dev Returns the account approved to manage token `id`.
    ///
    /// Requirements:
    /// - Token `id` must exist.
    function getApproved(uint256 id) public view virtual returns (address result) {
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        if (uint160(_erc721Sload(ownershipSlot)) == 0) revert TokenDoesNotExist();
        result = address(uint160(_erc721Sload(_erc721Add(ownershipSlot, 1))));
    }

    /// @dev Sets `account` as the approved account to manage token `id`.
    ///
    /// Requirements:
    /// - Token `id` must exist.
    /// - The caller must be the owner of the token,
    ///   or an approved operator for the token owner.
    ///
    /// Emits an {Approval} event.
    function approve(address account, uint256 id) public payable virtual {
        _approve(msg.sender, account, id);
    }

    /// @dev Returns whether `operator` is approved to manage the tokens of `owner`.
    function isApprovedForAll(address owner, address operator)
        public
        view
        virtual
        returns (bool result)
    {
        result = _erc721Sload(_erc721OperatorApprovalSlot(owner, operator)) != 0;
    }

    /// @dev Sets whether `operator` is approved to manage the tokens of the caller.
    ///
    /// Emits an {ApprovalForAll} event.
    function setApprovalForAll(address operator, bool isApproved) public virtual {
        // Update the `isApproved` for (`msg.sender`, `operator`).
        _erc721Sstore(_erc721OperatorApprovalSlot(msg.sender, operator), isApproved ? 1 : 0);
        emit ApprovalForAll(msg.sender, operator, isApproved);
    }

    /// @dev Transfers token `id` from `from` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must exist.
    /// - `from` must be the owner of the token.
    /// - `to` cannot be the zero address.
    /// - The caller must be the owner of the token, or be approved to manage the token.
    ///
    /// Emits a {Transfer} event.
    function transferFrom(address from, address to, uint256 id) public payable virtual {
        _beforeTokenTransfer(from, to, id);
        _erc721Move(msg.sender, from, to, id);
        _afterTokenTransfer(from, to, id);
    }

    /// @dev Equivalent to `safeTransferFrom(from, to, id, "")`.
    function safeTransferFrom(address from, address to, uint256 id) public payable virtual {
        transferFrom(from, to, id);
        if (_hasCode(to)) _checkOnERC721Received(from, to, id, "");
    }

    /// @dev Transfers token `id` from `from` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must exist.
    /// - `from` must be the owner of the token.
    /// - `to` cannot be the zero address.
    /// - The caller must be the owner of the token, or be approved to manage the token.
    /// - If `to` refers to a smart contract, it must implement
    ///   {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
    ///
    /// Emits a {Transfer} event.
    function safeTransferFrom(address from, address to, uint256 id, bytes calldata data)
        public
        payable
        virtual
    {
        transferFrom(from, to, id);
        if (_hasCode(to)) _checkOnERC721Received(from, to, id, data);
    }

    /// @dev Returns true if this contract implements the interface defined by `interfaceId`.
    /// See: https://eips.ethereum.org/EIPS/eip-165
    /// This function call must use less than 30000 gas.
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool result) {
        // ERC165: 0x01ffc9a7, ERC721: 0x80ac58cd, ERC721Metadata: 0x5b5e139f.
        result = interfaceId == 0x01ffc9a7 || interfaceId == 0x80ac58cd || interfaceId == 0x5b5e139f;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL QUERY FUNCTIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns if token `id` exists.
    function _exists(uint256 id) internal view virtual returns (bool result) {
        result = uint160(_erc721Sload(_erc721OwnershipSlot(id))) != 0;
    }

    /// @dev Returns the owner of token `id`.
    /// Returns the zero address instead of reverting if the token does not exist.
    function _ownerOf(uint256 id) internal view virtual returns (address result) {
        result = address(uint160(_erc721Sload(_erc721OwnershipSlot(id))));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*            INTERNAL DATA HITCHHIKING FUNCTIONS             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // For performance, no events are emitted for the hitchhiking setters.
    // Please emit your own events if required.

    /// @dev Returns the auxiliary data for `owner`.
    /// Minting, transferring, burning the tokens of `owner` will not change the auxiliary data.
    /// Auxiliary data can be set for any address, even if it does not have any tokens.
    function _getAux(address owner) internal view virtual returns (uint224 result) {
        result = uint224(_erc721Sload(_erc721BalanceSlot(owner)) >> 32);
    }

    /// @dev Set the auxiliary data for `owner` to `value`.
    /// Minting, transferring, burning the tokens of `owner` will not change the auxiliary data.
    /// Auxiliary data can be set for any address, even if it does not have any tokens.
    function _setAux(address owner, uint224 value) internal virtual {
        uint256 balanceSlot = _erc721BalanceSlot(owner);
        uint256 packed = _erc721Sload(balanceSlot);
        _erc721Sstore(balanceSlot, (packed & _MAX_ACCOUNT_BALANCE) | (uint256(value) << 32));
    }

    /// @dev Returns the extra data for token `id`.
    /// Minting, transferring, burning a token will not change the extra data.
    /// The extra data can be set on a non-existent token.
    function _getExtraData(uint256 id) internal view virtual returns (uint96 result) {
        result = uint96(_erc721Sload(_erc721OwnershipSlot(id)) >> 160);
    }

    /// @dev Sets the extra data for token `id` to `value`.
    /// Minting, transferring, burning a token will not change the extra data.
    /// The extra data can be set on a non-existent token.
    function _setExtraData(uint256 id, uint96 value) internal virtual {
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        uint256 packed = _erc721Sload(ownershipSlot);
        _erc721Sstore(ownershipSlot, uint256(uint160(packed)) | (uint256(value) << 160));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL MINT FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mints token `id` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must not exist.
    /// - `to` cannot be the zero address.
    ///
    /// Emits a {Transfer} event.
    function _mint(address to, uint256 id) internal virtual {
        _beforeTokenTransfer(address(0), to, id);
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        uint256 ownershipPacked = _erc721Sload(ownershipSlot);
        // Revert if the token already exists.
        if (uint160(ownershipPacked) != 0) revert TokenAlreadyExists();
        // Update with the owner.
        _erc721Sstore(ownershipSlot, ownershipPacked | uint256(uint160(to)));
        // Increment the balance of the owner.
        _erc721IncrementBalance(to);
        emit Transfer(address(0), to, id);
        _afterTokenTransfer(address(0), to, id);
    }

    /// @dev Mints token `id` to `to`, and updates the extra data for token `id` to `value`.
    /// Does NOT check if token `id` already exists (assumes `id` is auto-incrementing).
    ///
    /// Requirements:
    ///
    /// - `to` cannot be the zero address.
    ///
    /// Emits a {Transfer} event.
    function _mintAndSetExtraDataUnchecked(address to, uint256 id, uint96 value) internal virtual {
        _beforeTokenTransfer(address(0), to, id);
        // Update with the owner and extra data.
        _erc721Sstore(_erc721OwnershipSlot(id), (uint256(value) << 160) | uint256(uint160(to)));
        // Increment the balance of the owner.
        _erc721IncrementBalance(to);
        emit Transfer(address(0), to, id);
        _afterTokenTransfer(address(0), to, id);
    }

    /// @dev Equivalent to `_safeMint(to, id, "")`.
    function _safeMint(address to, uint256 id) internal virtual {
        _safeMint(to, id, "");
    }

    /// @dev Mints token `id` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must not exist.
    /// - `to` cannot be the zero address.
    /// - If `to` refers to a smart contract, it must implement
    ///   {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
    ///
    /// Emits a {Transfer} event.
    function _safeMint(address to, uint256 id, bytes memory data) internal virtual {
        _mint(to, id);
        if (_hasCode(to)) _checkOnERC721Received(address(0), to, id, data);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL BURN FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `_burn(address(0), id)`.
    function _burn(uint256 id) internal virtual {
        _burn(address(0), id);
    }

    /// @dev Destroys token `id`, using `by`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must exist.
    /// - If `by` is not the zero address,
    ///   it must be the owner of the token, or be approved to manage the token.
    ///
    /// Emits a {Transfer} event.
    function _burn(address by, uint256 id) internal virtual {
        address owner = ownerOf(id);
        _beforeTokenTransfer(owner, address(0), id);
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        uint256 ownershipPacked = _erc721Sload(ownershipSlot);
        // Reload the owner in case it is changed in `_beforeTokenTransfer`.
        owner = address(uint160(ownershipPacked));
        // Revert if the token does not exist.
        if (owner == address(0)) revert TokenDoesNotExist();
        // Load and check the token approval.
        uint256 approvedSlot = _erc721Add(ownershipSlot, 1);
        uint256 approvedAddress = _erc721Sload(approvedSlot);
        // If `by` is not the zero address, do the authorization check.
        // Revert if the `by` is not the owner, nor approved.
        if (by != address(0) && by != owner && uint256(uint160(by)) != approvedAddress) {
            if (_erc721Sload(_erc721OperatorApprovalSlot(owner, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        // Delete the approved address if any.
        if (approvedAddress != 0) _erc721Sstore(approvedSlot, 0);
        // Clear the owner.
        _erc721Sstore(ownershipSlot, ownershipPacked ^ uint256(uint160(owner)));
        // Decrement the balance of `owner`.
        uint256 balanceSlot = _erc721BalanceSlot(owner);
        _erc721Sstore(balanceSlot, _erc721Sload(balanceSlot) - 1);
        emit Transfer(owner, address(0), id);
        _afterTokenTransfer(owner, address(0), id);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                INTERNAL APPROVAL FUNCTIONS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether `account` is the owner of token `id`, or is approved to manage it.
    ///
    /// Requirements:
    /// - Token `id` must exist.
    function _isApprovedOrOwner(address account, uint256 id)
        internal
        view
        virtual
        returns (bool result)
    {
        result = true;
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        address owner = address(uint160(_erc721Sload(ownershipSlot)));
        // Revert if the token does not exist.
        if (owner == address(0)) revert TokenDoesNotExist();
        // Check if `account` is the `owner`.
        if (account != owner) {
            // Check if `account` is approved to manage the token.
            if (_erc721Sload(_erc721OperatorApprovalSlot(owner, account)) == 0) {
                result = uint256(uint160(account)) == _erc721Sload(_erc721Add(ownershipSlot, 1));
            }
        }
    }

    /// @dev Returns the account approved to manage token `id`.
    /// Returns the zero address instead of reverting if the token does not exist.
    function _getApproved(uint256 id) internal view virtual returns (address result) {
        result = address(uint160(_erc721Sload(_erc721Add(_erc721OwnershipSlot(id), 1))));
    }

    /// @dev Equivalent to `_approve(address(0), account, id)`.
    function _approve(address account, uint256 id) internal virtual {
        _approve(address(0), account, id);
    }

    /// @dev Sets `account` as the approved account to manage token `id`, using `by`.
    ///
    /// Requirements:
    /// - Token `id` must exist.
    /// - If `by` is not the zero address, `by` must be the owner
    ///   or an approved operator for the token owner.
    ///
    /// Emits a {Approval} event.
    function _approve(address by, address account, uint256 id) internal virtual {
        // Load the owner of the token.
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        address owner = address(uint160(_erc721Sload(ownershipSlot)));
        // Revert if the token does not exist.
        if (owner == address(0)) revert TokenDoesNotExist();
        // If `by` is not the zero address, do the authorization check.
        // Revert if `by` is not the owner, nor approved.
        if (by != address(0) && by != owner) {
            if (_erc721Sload(_erc721OperatorApprovalSlot(owner, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        // Sets `account` as the approved account to manage `id`.
        _erc721Sstore(_erc721Add(ownershipSlot, 1), uint256(uint160(account)));
        emit Approval(owner, account, id);
    }

    /// @dev Approve or remove the `operator` as an operator for `by`,
    /// without authorization checks.
    ///
    /// Emits an {ApprovalForAll} event.
    function _setApprovalForAll(address by, address operator, bool isApproved) internal virtual {
        // Update the `isApproved` for (`by`, `operator`).
        _erc721Sstore(_erc721OperatorApprovalSlot(by, operator), isApproved ? 1 : 0);
        emit ApprovalForAll(by, operator, isApproved);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                INTERNAL TRANSFER FUNCTIONS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `_transfer(address(0), from, to, id)`.
    function _transfer(address from, address to, uint256 id) internal virtual {
        _transfer(address(0), from, to, id);
    }

    /// @dev Transfers token `id` from `from` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must exist.
    /// - `from` must be the owner of the token.
    /// - `to` cannot be the zero address.
    /// - If `by` is not the zero address,
    ///   it must be the owner of the token, or be approved to manage the token.
    ///
    /// Emits a {Transfer} event.
    function _transfer(address by, address from, address to, uint256 id) internal virtual {
        _beforeTokenTransfer(from, to, id);
        _erc721Move(by, from, to, id);
        _afterTokenTransfer(from, to, id);
    }

    /// @dev Equivalent to `_safeTransfer(from, to, id, "")`.
    function _safeTransfer(address from, address to, uint256 id) internal virtual {
        _safeTransfer(from, to, id, "");
    }

    /// @dev Transfers token `id` from `from` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must exist.
    /// - `from` must be the owner of the token.
    /// - `to` cannot be the zero address.
    /// - The caller must be the owner of the token, or be approved to manage the token.
    /// - If `to` refers to a smart contract, it must implement
    ///   {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
    ///
    /// Emits a {Transfer} event.
    function _safeTransfer(address from, address to, uint256 id, bytes memory data)
        internal
        virtual
    {
        _transfer(address(0), from, to, id);
        if (_hasCode(to)) _checkOnERC721Received(from, to, id, data);
    }

    /// @dev Equivalent to `_safeTransfer(by, from, to, id, "")`.
    function _safeTransfer(address by, address from, address to, uint256 id) internal virtual {
        _safeTransfer(by, from, to, id, "");
    }

    /// @dev Transfers token `id` from `from` to `to`.
    ///
    /// Requirements:
    ///
    /// - Token `id` must exist.
    /// - `from` must be the owner of the token.
    /// - `to` cannot be the zero address.
    /// - If `by` is not the zero address,
    ///   it must be the owner of the token, or be approved to manage the token.
    /// - If `to` refers to a smart contract, it must implement
    ///   {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
    ///
    /// Emits a {Transfer} event.
    function _safeTransfer(address by, address from, address to, uint256 id, bytes memory data)
        internal
        virtual
    {
        _transfer(by, from, to, id);
        if (_hasCode(to)) _checkOnERC721Received(from, to, id, data);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    HOOKS FOR OVERRIDING                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Hook that is called before any token transfers, including minting and burning.
    function _beforeTokenTransfer(address from, address to, uint256 id) internal virtual {}

    /// @dev Hook that is called after any token transfers, including minting and burning.
    function _afterTokenTransfer(address from, address to, uint256 id) internal virtual {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns if `a` has bytecode of non-zero length.
    function _hasCode(address a) private view returns (bool result) {
        result = a.code.length != 0;
    }

    /// @dev Perform a call to invoke {IERC721Receiver-onERC721Received} on `to`.
    /// Reverts if the target does not support the function correctly.
    function _checkOnERC721Received(address from, address to, uint256 id, bytes memory data)
        private
    {
        // The `operator` is always `msg.sender`.
        (bool success, bytes memory answer) =
            to.call(abi.encodeWithSelector(0x150b7a02, msg.sender, from, id, data));
        // Bubble up the revert if the call reverts.
        if (!success && answer.length != 0) _erc721RevertWith(answer);
        // Load the returndata and compare it.
        if (answer.length < 0x20 || abi.decode(answer, (bytes32)) != bytes32(bytes4(0x150b7a02))) {
            revert TransferToNonERC721ReceiverImplementer();
        }
    }

    /// @dev Moves token `id` from `from` to `to`, as `by` if it is not the zero address,
    /// between the transfer hooks of `transferFrom` and `_transfer`.
    function _erc721Move(address by, address from, address to, uint256 id) private {
        // Load the ownership data.
        uint256 ownershipSlot = _erc721OwnershipSlot(id);
        uint256 ownershipPacked = _erc721Sload(ownershipSlot);
        address owner = address(uint160(ownershipPacked));
        // Revert if the token does not exist, or if `from` is not the owner.
        if (owner == address(0)) revert TokenDoesNotExist();
        if (owner != from) revert TransferFromIncorrectOwner();
        // Load, check, and update the token approval.
        uint256 approvedSlot = _erc721Add(ownershipSlot, 1);
        uint256 approvedAddress = _erc721Sload(approvedSlot);
        // If `by` is not the zero address, do the authorization check.
        // Revert if the `by` is not the owner, nor approved.
        if (by != address(0) && by != from && uint256(uint160(by)) != approvedAddress) {
            if (_erc721Sload(_erc721OperatorApprovalSlot(from, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        // Delete the approved address if any.
        if (approvedAddress != 0) _erc721Sstore(approvedSlot, 0);
        // Update with the new owner.
        _erc721Sstore(
            ownershipSlot, ownershipPacked ^ uint256(uint160(from)) ^ uint256(uint160(to))
        );
        // Decrement the balance of `from`.
        uint256 fromBalanceSlot = _erc721BalanceSlot(from);
        _erc721Sstore(fromBalanceSlot, _erc721Sload(fromBalanceSlot) - 1);
        // Increment the balance of `to`.
        _erc721IncrementBalance(to);
        emit Transfer(from, to, id);
    }

    /// @dev Adds one token to the balance of `to`.
    /// Reverts if `to` is the zero address, or if the account balance overflows.
    function _erc721IncrementBalance(address to) private {
        uint256 balanceSlot = _erc721BalanceSlot(to);
        uint256 balanceSlotPacked = _erc721Sload(balanceSlot);
        if (to == address(0)) revert TransferToZeroAddress();
        if (balanceSlotPacked & _MAX_ACCOUNT_BALANCE == _MAX_ACCOUNT_BALANCE) {
            revert AccountBalanceOverflow();
        }
        // The balance bits are below their maximum, so the increment stays in them.
        _erc721Sstore(balanceSlot, _erc721Add(balanceSlotPacked, 1));
    }

    /// @dev The ownership data slot of `id`: the hash of `id` with its last four bytes
    /// replaced by the seed's first four, plus twice `id`, wrapping.
    /// @custom:solar-inline always
    function _erc721OwnershipSlot(uint256 id) private pure returns (uint256) {
        bytes32 h = keccak256(abi.encode((id >> 32 << 32) | (_ERC721_MASTER_SLOT_SEED >> 224)));
        return _erc721Add(uint256(h), id << 1);
    }

    /// @dev The balance slot of `owner`.
    /// @custom:solar-inline always
    function _erc721BalanceSlot(address owner) private pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(owner, uint64(_ERC721_MASTER_SLOT_SEED_MASKED))));
    }

    /// @dev The `operator` approval slot of `owner`.
    /// @custom:solar-inline always
    function _erc721OperatorApprovalSlot(address owner, address operator)
        private
        pure
        returns (uint256)
    {
        return uint256(
            keccak256(abi.encodePacked(owner, uint64(_ERC721_MASTER_SLOT_SEED_MASKED), operator))
        );
    }

    /// @dev Returns the word in storage slot `slot`.
    /// @custom:solar-trusted
    function _erc721Sload(uint256 slot) private view returns (uint256 value) {
        /// @solidity memory-safe-assembly
        assembly {
            value := sload(slot)
        }
    }

    /// @dev Stores `value` in storage slot `slot`.
    /// @custom:solar-trusted
    function _erc721Sstore(uint256 slot, uint256 value) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, value)
        }
    }

    /// @dev `a + b` modulo `2**256`.
    /// @custom:solar-trusted
    function _erc721Add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev Reverts with `revertData`.
    /// @custom:solar-trusted
    function _erc721RevertWith(bytes memory revertData) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(revertData, 0x20), mload(revertData))
        }
    }
}
