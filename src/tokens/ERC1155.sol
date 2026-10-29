// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Simple ERC1155 implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/tokens/ERC1155.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC1155.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/token/ERC1155/ERC1155.sol)
///
/// @dev Note:
/// - The ERC1155 standard allows for self-approvals.
///   For performance, this implementation WILL NOT revert for such actions.
///   Please add any checks with overrides if desired.
/// - The transfer functions use the identity precompile (0x4)
///   to copy memory internally.
///
/// If you are overriding:
/// - Make sure all variables written to storage are properly cleaned
//    (e.g. the bool value for `isApprovedForAll` MUST be either 1 or 0 under the hood).
/// - Check that the overridden function is actually used in the function you want to
///   change the behavior of. Much of the code has been manually inlined for performance.
///
/// The checked port keeps upstream's storage slots, read and written through two
/// trusted helpers, and derives them in Solidity as `abi.encode` and
/// `abi.encodePacked` hashes. Every check keeps its order and custom error, batches
/// update balances from the last pair to the first, the events are ordinary emits,
/// and the receiver checks are plain calls whose revert data the trusted
/// `_erc1155RevertWith` bubbles up. A credit adds with wrap-around through a trusted
/// `_erc1155Add` and reverts if it wrapped, as the assembly does.
/// @custom:solar-safe memory arithmetic
abstract contract ERC1155 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The lengths of the input arrays are not the same.
    error ArrayLengthsMismatch();

    /// @dev Cannot mint or transfer to the zero address.
    error TransferToZeroAddress();

    /// @dev The recipient's balance has overflowed.
    error AccountBalanceOverflow();

    /// @dev Insufficient balance.
    error InsufficientBalance();

    /// @dev Only the token owner or an approved account can manage the tokens.
    error NotOwnerNorApproved();

    /// @dev Cannot safely transfer to a contract that does not implement
    /// the ERC1155Receiver interface.
    error TransferToNonERC1155ReceiverImplementer();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when `amount` of token `id` is transferred
    /// from `from` to `to` by `operator`.
    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 amount
    );

    /// @dev Emitted when `amounts` of token `ids` are transferred
    /// from `from` to `to` by `operator`.
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] amounts
    );

    /// @dev Emitted when `owner` enables or disables `operator` to manage all of their tokens.
    event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved);

    /// @dev Emitted when the Uniform Resource Identifier (URI) for token `id`
    /// is updated to `value`. This event is not used in the base contract.
    /// You may need to emit this event depending on your URI logic.
    ///
    /// See: https://eips.ethereum.org/EIPS/eip-1155#metadata
    event URI(string value, uint256 indexed id);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The `ownerSlotSeed` of a given owner is given by.
    /// ```
    ///     let ownerSlotSeed := or(_ERC1155_MASTER_SLOT_SEED, shl(96, owner))
    /// ```
    ///
    /// The balance slot of `owner` is given by.
    /// ```
    ///     mstore(0x20, ownerSlotSeed)
    ///     mstore(0x00, id)
    ///     let balanceSlot := keccak256(0x00, 0x40)
    /// ```
    ///
    /// The operator approval slot of `owner` is given by.
    /// ```
    ///     mstore(0x20, ownerSlotSeed)
    ///     mstore(0x00, operator)
    ///     let operatorApprovalSlot := keccak256(0x0c, 0x34)
    /// ```
    uint256 private constant _ERC1155_MASTER_SLOT_SEED = 0x9a31110384e0b0c9;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ERC1155 METADATA                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the URI for token `id`.
    ///
    /// You can either return the same templated URI for all token IDs,
    /// (e.g. "https://example.com/api/{id}.json"),
    /// or return a unique URI for each `id`.
    ///
    /// See: https://eips.ethereum.org/EIPS/eip-1155#metadata
    function uri(uint256 id) public view virtual returns (string memory);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERC1155                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the amount of `id` owned by `owner`.
    function balanceOf(address owner, uint256 id) public view virtual returns (uint256 result) {
        result = _erc1155Sload(_erc1155BalanceSlot(owner, id));
    }

    /// @dev Returns whether `operator` is approved to manage the tokens of `owner`.
    function isApprovedForAll(address owner, address operator)
        public
        view
        virtual
        returns (bool result)
    {
        result = _erc1155Sload(_erc1155OperatorApprovalSlot(owner, operator)) != 0;
    }

    /// @dev Sets whether `operator` is approved to manage the tokens of the caller.
    ///
    /// Emits a {ApprovalForAll} event.
    function setApprovalForAll(address operator, bool isApproved) public virtual {
        // Update the `isApproved` for (`msg.sender`, `operator`).
        _erc1155Sstore(_erc1155OperatorApprovalSlot(msg.sender, operator), isApproved ? 1 : 0);
        emit ApprovalForAll(msg.sender, operator, isApproved);
    }

    /// @dev Transfers `amount` of `id` from `from` to `to`.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
    /// - `from` must have at least `amount` of `id`.
    /// - If the caller is not `from`,
    ///   it must be approved to manage the tokens of `from`.
    /// - If `to` refers to a smart contract, it must implement
    ///   {ERC1155-onERC1155Received}, which is called upon a batch transfer.
    ///
    /// Emits a {TransferSingle} event.
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) public virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(from, to, _single(id), _single(amount), data);
        }
        // Revert if `to` is the zero address.
        if (to == address(0)) revert TransferToZeroAddress();
        // If the caller is not `from`, do the authorization check.
        if (msg.sender != from) {
            if (_erc1155Sload(_erc1155OperatorApprovalSlot(from, msg.sender)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        _erc1155Debit(from, id, amount);
        _erc1155Credit(to, id, amount);
        emit TransferSingle(msg.sender, from, to, id, amount);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(from, to, _single(id), _single(amount), data);
        }
        // Do the {onERC1155Received} check if `to` is a smart contract.
        if (_hasCode(to)) _checkOnERC1155Received(from, to, id, amount, data);
    }

    /// @dev Transfers `amounts` of `ids` from `from` to `to`.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
    /// - `from` must have at least `amount` of `id`.
    /// - `ids` and `amounts` must have the same length.
    /// - If the caller is not `from`,
    ///   it must be approved to manage the tokens of `from`.
    /// - If `to` refers to a smart contract, it must implement
    ///   {ERC1155-onERC1155BatchReceived}, which is called upon a batch transfer.
    ///
    /// Emits a {TransferBatch} event.
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) public virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(from, to, ids, amounts, data);
        }
        if (ids.length != amounts.length) revert ArrayLengthsMismatch();
        // Revert if `to` is the zero address.
        if (to == address(0)) revert TransferToZeroAddress();
        // If the caller is not `from`, do the authorization check.
        if (msg.sender != from) {
            if (_erc1155Sload(_erc1155OperatorApprovalSlot(from, msg.sender)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        // Loop through all the `ids` and update the balances.
        for (uint256 i = ids.length; i != 0;) {
            --i;
            uint256 amount = amounts[i];
            _erc1155Debit(from, ids[i], amount);
            _erc1155Credit(to, ids[i], amount);
        }
        emit TransferBatch(msg.sender, from, to, ids, amounts);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransferCalldata(from, to, ids, amounts, data);
        }
        // Do the {onERC1155BatchReceived} check if `to` is a smart contract.
        if (_hasCode(to)) _checkOnERC1155BatchReceived(from, to, ids, amounts, data);
    }

    /// @dev Returns the amounts of `ids` for `owners.
    ///
    /// Requirements:
    /// - `owners` and `ids` must have the same length.
    function balanceOfBatch(address[] calldata owners, uint256[] calldata ids)
        public
        view
        virtual
        returns (uint256[] memory balances)
    {
        if (ids.length != owners.length) revert ArrayLengthsMismatch();
        balances = new uint256[](ids.length);
        // Loop through all the `ids` and load the balances.
        for (uint256 i; i < ids.length; ++i) {
            balances[i] = _erc1155Sload(_erc1155BalanceSlot(owners[i], ids[i]));
        }
    }

    /// @dev Returns true if this contract implements the interface defined by `interfaceId`.
    /// See: https://eips.ethereum.org/EIPS/eip-165
    /// This function call must use less than 30000 gas.
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool result) {
        // ERC165: 0x01ffc9a7, ERC1155: 0xd9b67a26, ERC1155MetadataURI: 0x0e89341c.
        result = interfaceId == 0x01ffc9a7 || interfaceId == 0xd9b67a26 || interfaceId == 0x0e89341c;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL MINT FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mints `amount` of `id` to `to`.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
    /// - If `to` refers to a smart contract, it must implement
    ///   {ERC1155-onERC1155Received}, which is called upon a batch transfer.
    ///
    /// Emits a {TransferSingle} event.
    function _mint(address to, uint256 id, uint256 amount, bytes memory data) internal virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(address(0), to, _single(id), _single(amount), data);
        }
        // Revert if `to` is the zero address.
        if (to == address(0)) revert TransferToZeroAddress();
        _erc1155Credit(to, id, amount);
        emit TransferSingle(msg.sender, address(0), to, id, amount);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(address(0), to, _single(id), _single(amount), data);
        }
        if (_hasCode(to)) _checkOnERC1155Received(address(0), to, id, amount, data);
    }

    /// @dev Mints `amounts` of `ids` to `to`.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
    /// - `ids` and `amounts` must have the same length.
    /// - If `to` refers to a smart contract, it must implement
    ///   {ERC1155-onERC1155BatchReceived}, which is called upon a batch transfer.
    ///
    /// Emits a {TransferBatch} event.
    function _batchMint(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(address(0), to, ids, amounts, data);
        }
        if (ids.length != amounts.length) revert ArrayLengthsMismatch();
        // Revert if `to` is the zero address.
        if (to == address(0)) revert TransferToZeroAddress();
        // Loop through all the `ids` and update the balances.
        for (uint256 i = ids.length; i != 0;) {
            --i;
            _erc1155Credit(to, ids[i], amounts[i]);
        }
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(address(0), to, ids, amounts, data);
        }
        if (_hasCode(to)) _checkOnERC1155BatchReceived(address(0), to, ids, amounts, data);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL BURN FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `_burn(address(0), from, id, amount)`.
    function _burn(address from, uint256 id, uint256 amount) internal virtual {
        _burn(address(0), from, id, amount);
    }

    /// @dev Destroys `amount` of `id` from `from`.
    ///
    /// Requirements:
    /// - `from` must have at least `amount` of `id`.
    /// - If `by` is not the zero address, it must be either `from`,
    ///   or approved to manage the tokens of `from`.
    ///
    /// Emits a {TransferSingle} event.
    function _burn(address by, address from, uint256 id, uint256 amount) internal virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(from, address(0), _single(id), _single(amount), "");
        }
        // If `by` is not the zero address, and not equal to `from`,
        // check if it is approved to manage all the tokens of `from`.
        if (by != address(0) && by != from) {
            if (_erc1155Sload(_erc1155OperatorApprovalSlot(from, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        _erc1155Debit(from, id, amount);
        emit TransferSingle(msg.sender, from, address(0), id, amount);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(from, address(0), _single(id), _single(amount), "");
        }
    }

    /// @dev Equivalent to `_batchBurn(address(0), from, ids, amounts)`.
    function _batchBurn(address from, uint256[] memory ids, uint256[] memory amounts)
        internal
        virtual
    {
        _batchBurn(address(0), from, ids, amounts);
    }

    /// @dev Destroys `amounts` of `ids` from `from`.
    ///
    /// Requirements:
    /// - `ids` and `amounts` must have the same length.
    /// - `from` must have at least `amounts` of `ids`.
    /// - If `by` is not the zero address, it must be either `from`,
    ///   or approved to manage the tokens of `from`.
    ///
    /// Emits a {TransferBatch} event.
    function _batchBurn(address by, address from, uint256[] memory ids, uint256[] memory amounts)
        internal
        virtual
    {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(from, address(0), ids, amounts, "");
        }
        if (ids.length != amounts.length) revert ArrayLengthsMismatch();
        // If `by` is not the zero address, and not equal to `from`,
        // check if it is approved to manage all the tokens of `from`.
        if (by != address(0) && by != from) {
            if (_erc1155Sload(_erc1155OperatorApprovalSlot(from, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        // Loop through all the `ids` and update the balances.
        for (uint256 i = ids.length; i != 0;) {
            --i;
            _erc1155Debit(from, ids[i], amounts[i]);
        }
        emit TransferBatch(msg.sender, from, address(0), ids, amounts);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(from, address(0), ids, amounts, "");
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                INTERNAL APPROVAL FUNCTIONS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Approve or remove the `operator` as an operator for `by`,
    /// without authorization checks.
    ///
    /// Emits a {ApprovalForAll} event.
    function _setApprovalForAll(address by, address operator, bool isApproved) internal virtual {
        // Update the `isApproved` for (`by`, `operator`).
        _erc1155Sstore(_erc1155OperatorApprovalSlot(by, operator), isApproved ? 1 : 0);
        emit ApprovalForAll(by, operator, isApproved);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                INTERNAL TRANSFER FUNCTIONS                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `_safeTransfer(address(0), from, to, id, amount, data)`.
    function _safeTransfer(address from, address to, uint256 id, uint256 amount, bytes memory data)
        internal
        virtual
    {
        _safeTransfer(address(0), from, to, id, amount, data);
    }

    /// @dev Transfers `amount` of `id` from `from` to `to`.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
    /// - `from` must have at least `amount` of `id`.
    /// - If `by` is not the zero address, it must be either `from`,
    ///   or approved to manage the tokens of `from`.
    /// - If `to` refers to a smart contract, it must implement
    ///   {ERC1155-onERC1155Received}, which is called upon a batch transfer.
    ///
    /// Emits a {TransferSingle} event.
    function _safeTransfer(
        address by,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(from, to, _single(id), _single(amount), data);
        }
        // Revert if `to` is the zero address.
        if (to == address(0)) revert TransferToZeroAddress();
        // If `by` is not the zero address, and not equal to `from`,
        // check if it is approved to manage all the tokens of `from`.
        if (by != address(0) && by != from) {
            if (_erc1155Sload(_erc1155OperatorApprovalSlot(from, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        _erc1155Debit(from, id, amount);
        _erc1155Credit(to, id, amount);
        emit TransferSingle(msg.sender, from, to, id, amount);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(from, to, _single(id), _single(amount), data);
        }
        if (_hasCode(to)) _checkOnERC1155Received(from, to, id, amount, data);
    }

    /// @dev Equivalent to `_safeBatchTransfer(address(0), from, to, ids, amounts, data)`.
    function _safeBatchTransfer(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        _safeBatchTransfer(address(0), from, to, ids, amounts, data);
    }

    /// @dev Transfers `amounts` of `ids` from `from` to `to`.
    ///
    /// Requirements:
    /// - `to` cannot be the zero address.
    /// - `ids` and `amounts` must have the same length.
    /// - `from` must have at least `amounts` of `ids`.
    /// - If `by` is not the zero address, it must be either `from`,
    ///   or approved to manage the tokens of `from`.
    /// - If `to` refers to a smart contract, it must implement
    ///   {ERC1155-onERC1155BatchReceived}, which is called upon a batch transfer.
    ///
    /// Emits a {TransferBatch} event.
    function _safeBatchTransfer(
        address by,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        if (_useBeforeTokenTransfer()) {
            _beforeTokenTransfer(from, to, ids, amounts, data);
        }
        if (ids.length != amounts.length) revert ArrayLengthsMismatch();
        // Revert if `to` is the zero address.
        if (to == address(0)) revert TransferToZeroAddress();
        // If `by` is not the zero address, and not equal to `from`,
        // check if it is approved to manage all the tokens of `from`.
        if (by != address(0) && by != from) {
            if (_erc1155Sload(_erc1155OperatorApprovalSlot(from, by)) == 0) {
                revert NotOwnerNorApproved();
            }
        }
        // Loop through all the `ids` and update the balances.
        for (uint256 i = ids.length; i != 0;) {
            --i;
            uint256 amount = amounts[i];
            _erc1155Debit(from, ids[i], amount);
            _erc1155Credit(to, ids[i], amount);
        }
        emit TransferBatch(msg.sender, from, to, ids, amounts);
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(from, to, ids, amounts, data);
        }
        if (_hasCode(to)) _checkOnERC1155BatchReceived(from, to, ids, amounts, data);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    HOOKS FOR OVERRIDING                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Override this function to return true if `_beforeTokenTransfer` is used.
    /// This is to help the compiler avoid producing dead bytecode.
    function _useBeforeTokenTransfer() internal view virtual returns (bool) {
        return false;
    }

    /// @dev Hook that is called before any token transfer.
    /// This includes minting and burning, as well as batched variants.
    ///
    /// The same hook is called on both single and batched variants.
    /// For single transfers, the length of the `id` and `amount` arrays are 1.
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {}

    /// @dev Override this function to return true if `_afterTokenTransfer` is used.
    /// This is to help the compiler avoid producing dead bytecode.
    function _useAfterTokenTransfer() internal view virtual returns (bool) {
        return false;
    }

    /// @dev Hook that is called after any token transfer.
    /// This includes minting and burning, as well as batched variants.
    ///
    /// The same hook is called on both single and batched variants.
    /// For single transfers, the length of the `id` and `amount` arrays are 1.
    function _afterTokenTransfer(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Helper for calling the `_afterTokenTransfer` hook.
    /// This is to help the compiler avoid producing dead bytecode.
    function _afterTokenTransferCalldata(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) private {
        if (_useAfterTokenTransfer()) {
            _afterTokenTransfer(from, to, ids, amounts, data);
        }
    }

    /// @dev Returns if `a` has bytecode of non-zero length.
    function _hasCode(address a) private view returns (bool result) {
        result = a.code.length != 0;
    }

    /// @dev Perform a call to invoke {IERC1155Receiver-onERC1155Received} on `to`.
    /// Reverts if the target does not support the function correctly.
    function _checkOnERC1155Received(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) private {
        // `onERC1155Received(address,address,uint256,uint256,bytes)`.
        (bool success, bytes memory answer) =
            to.call(abi.encodeWithSelector(0xf23a6e61, msg.sender, from, id, amount, data));
        _erc1155CheckAnswer(success, answer, 0xf23a6e61);
    }

    /// @dev Perform a call to invoke {IERC1155Receiver-onERC1155BatchReceived} on `to`.
    /// Reverts if the target does not support the function correctly.
    function _checkOnERC1155BatchReceived(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) private {
        // `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
        (bool success, bytes memory answer) =
            to.call(abi.encodeWithSelector(0xbc197c81, msg.sender, from, ids, amounts, data));
        _erc1155CheckAnswer(success, answer, 0xbc197c81);
    }

    /// @dev Returns `x` in an array with a single element.
    function _single(uint256 x) private pure returns (uint256[] memory result) {
        result = new uint256[](1);
        result[0] = x;
    }

    /// @dev Reverts unless a receiver's call answered with its `selector`, bubbling up the
    /// revert data of a call that reverted with some.
    function _erc1155CheckAnswer(bool success, bytes memory answer, bytes4 selector) private pure {
        // Bubble up the revert if the call reverts.
        if (!success && answer.length != 0) _erc1155RevertWith(answer);
        // Load the returndata and compare it with the function selector.
        if (answer.length < 0x20 || abi.decode(answer, (bytes32)) != bytes32(selector)) {
            revert TransferToNonERC1155ReceiverImplementer();
        }
    }

    /// @dev Subtracts `amount` of `id` from the balance of `from`.
    function _erc1155Debit(address from, uint256 id, uint256 amount) private {
        uint256 fromBalanceSlot = _erc1155BalanceSlot(from, id);
        uint256 fromBalance = _erc1155Sload(fromBalanceSlot);
        if (amount > fromBalance) revert InsufficientBalance();
        _erc1155Sstore(fromBalanceSlot, fromBalance - amount);
    }

    /// @dev Adds `amount` of `id` to the balance of `to`.
    function _erc1155Credit(address to, uint256 id, uint256 amount) private {
        uint256 toBalanceSlot = _erc1155BalanceSlot(to, id);
        uint256 toBalanceBefore = _erc1155Sload(toBalanceSlot);
        uint256 toBalanceAfter = _erc1155Add(toBalanceBefore, amount);
        if (toBalanceAfter < toBalanceBefore) revert AccountBalanceOverflow();
        _erc1155Sstore(toBalanceSlot, toBalanceAfter);
    }

    /// @dev The balance slot of `owner` for `id`.
    /// @custom:solar-inline always
    function _erc1155BalanceSlot(address owner, uint256 id) private pure returns (uint256) {
        return uint256(keccak256(abi.encode(id, _erc1155OwnerSlotSeed(owner))));
    }

    /// @dev The `operator` approval slot of `owner`.
    /// @custom:solar-inline always
    function _erc1155OperatorApprovalSlot(address owner, address operator)
        private
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encodePacked(operator, _erc1155OwnerSlotSeed(owner))));
    }

    /// @dev The `ownerSlotSeed` of `owner`.
    function _erc1155OwnerSlotSeed(address owner) private pure returns (uint256) {
        return (uint256(uint160(owner)) << 96) | _ERC1155_MASTER_SLOT_SEED;
    }

    /// @dev Returns the word in storage slot `slot`.
    /// @custom:solar-trusted
    function _erc1155Sload(uint256 slot) private view returns (uint256 value) {
        /// @solidity memory-safe-assembly
        assembly {
            value := sload(slot)
        }
    }

    /// @dev Stores `value` in storage slot `slot`.
    /// @custom:solar-trusted
    function _erc1155Sstore(uint256 slot, uint256 value) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, value)
        }
    }

    /// @dev `a + b` modulo `2**256`.
    /// @custom:solar-trusted
    function _erc1155Add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev Reverts with `revertData`.
    /// @custom:solar-trusted
    function _erc1155RevertWith(bytes memory revertData) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(revertData, 0x20), mload(revertData))
        }
    }
}
