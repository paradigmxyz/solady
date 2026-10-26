// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Simple EIP-6909 implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/tokens/ERC6909.sol)
///
/// @dev Note:
/// The ERC6909 standard allows minting and transferring to and from the zero address,
/// minting and transferring zero tokens, as well as self-approvals.
/// For performance, this implementation WILL NOT revert for such actions.
/// Please add any checks with overrides if desired.
///
/// If you are overriding:
/// - Make sure all variables written to storage are properly cleaned
//    (e.g. the bool value for `isOperator` MUST be either 1 or 0 under the hood).
/// - Check that the overridden function is actually used in the function you want to
///   change the behavior of. Much of the code has been manually inlined for performance.
///
/// This port uses Solidity mappings and is intended for new deployments, not upgrades
/// from upstream's storage layout. Every check keeps its order and custom error, and
/// the events are ordinary emits. A credit adds with wrap-around through `_erc6909Add`
/// and reverts if it wrapped, as the assembly does.
/// @custom:solar-safe memory arithmetic
abstract contract ERC6909 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Insufficient balance.
    error InsufficientBalance();

    /// @dev Insufficient permission to perform the action.
    error InsufficientPermission();

    /// @dev The balance has overflowed.
    error BalanceOverflow();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Emitted when `by` transfers `amount` of token `id` from `from` to `to`.
    event Transfer(
        address by, address indexed from, address indexed to, uint256 indexed id, uint256 amount
    );

    /// @dev Emitted when `owner` enables or disables `operator` to manage all of their tokens.
    event OperatorSet(address indexed owner, address indexed operator, bool approved);

    /// @dev Emitted when `owner` approves `spender` to use `amount` of `id` token.
    event Approval(
        address indexed owner, address indexed spender, uint256 indexed id, uint256 amount
    );

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    mapping(address => mapping(uint256 => uint256)) private _erc6909Balances;
    mapping(address => mapping(address => mapping(uint256 => uint256))) private _erc6909Allowances;
    mapping(address => mapping(address => bool)) private _erc6909Operators;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ERC6909 METADATA                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the name for token `id`.
    function name(uint256 id) public view virtual returns (string memory);

    /// @dev Returns the symbol for token `id`.
    function symbol(uint256 id) public view virtual returns (string memory);

    /// @dev Returns the number of decimals for token `id`.
    /// Returns 18 by default.
    /// Please override this function if you need to return a custom value.
    function decimals(uint256 id) public view virtual returns (uint8) {
        id = id; // Silence compiler warning.
        return 18;
    }

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    function tokenURI(uint256 id) public view virtual returns (string memory);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERC6909                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the amount of token `id` owned by `owner`.
    function balanceOf(address owner, uint256 id) public view virtual returns (uint256 amount) {
        amount = _erc6909Balances[owner][id];
    }

    /// @dev Returns the amount of token `id` that `spender` can spend on behalf of `owner`.
    function allowance(address owner, address spender, uint256 id)
        public
        view
        virtual
        returns (uint256 amount)
    {
        amount = _erc6909Allowances[owner][spender][id];
    }

    /// @dev Checks if a `spender` is approved by `owner` to manage all of their tokens.
    function isOperator(address owner, address spender) public view virtual returns (bool status) {
        status = _erc6909Operators[owner][spender];
    }

    /// @dev Transfers `amount` of token `id` from the caller to `to`.
    ///
    /// Requirements:
    /// - caller must at least have `amount`.
    ///
    /// Emits a {Transfer} event.
    function transfer(address to, uint256 id, uint256 amount)
        public
        payable
        virtual
        returns (bool)
    {
        _beforeTokenTransfer(msg.sender, to, id, amount);
        _erc6909Debit(msg.sender, id, amount);
        _erc6909Credit(to, id, amount);
        emit Transfer(msg.sender, msg.sender, to, id, amount);
        _afterTokenTransfer(msg.sender, to, id, amount);
        return true;
    }

    /// @dev Transfers `amount` of token `id` from `from` to `to`.
    ///
    /// Note:
    /// - Allowance is NOT deducted if it is `type(uint256).max`.
    /// - Allowance is NOT deducted if `from` is an operator.
    /// - For efficiency, allowance is deducted even if `from` is the caller.
    ///
    /// Requirements:
    /// - `from` must at least have `amount` of token `id`.
    /// -  The caller must have at least `amount` of allowance to transfer the
    ///    tokens of `from` or approved as an operator.
    ///
    /// Emits a {Transfer} event.
    function transferFrom(address from, address to, uint256 id, uint256 amount)
        public
        payable
        virtual
        returns (bool)
    {
        _beforeTokenTransfer(from, to, id, amount);
        // Check if the caller is an operator.
        if (!_erc6909Operators[from][msg.sender]) {
            _erc6909SpendAllowance(from, msg.sender, id, amount);
        }
        _erc6909Debit(from, id, amount);
        _erc6909Credit(to, id, amount);
        emit Transfer(msg.sender, from, to, id, amount);
        _afterTokenTransfer(from, to, id, amount);
        return true;
    }

    /// @dev Sets `amount` as the allowance of `spender` for the caller for token `id`.
    ///
    /// Emits a {Approval} event.
    function approve(address spender, uint256 id, uint256 amount)
        public
        payable
        virtual
        returns (bool)
    {
        _erc6909Allowances[msg.sender][spender][id] = amount;
        emit Approval(msg.sender, spender, id, amount);
        return true;
    }

    ///  @dev Sets whether `operator` is approved to manage the tokens of the caller.
    ///
    /// Emits {OperatorSet} event.
    function setOperator(address operator, bool approved) public payable virtual returns (bool) {
        _erc6909Operators[msg.sender][operator] = approved;
        emit OperatorSet(msg.sender, operator, approved);
        return true;
    }

    /// @dev Returns true if this contract implements the interface defined by `interfaceId`.
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool result) {
        // ERC165: 0x01ffc9a7, ERC6909: 0x0f632fb3.
        result = interfaceId == 0x01ffc9a7 || interfaceId == 0x0f632fb3;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Mints `amount` of token `id` to `to`.
    ///
    /// Emits a {Transfer} event.
    function _mint(address to, uint256 id, uint256 amount) internal virtual {
        _beforeTokenTransfer(address(0), to, id, amount);
        _erc6909Credit(to, id, amount);
        emit Transfer(msg.sender, address(0), to, id, amount);
        _afterTokenTransfer(address(0), to, id, amount);
    }

    /// @dev Burns `amount` token `id` from `from`.
    ///
    /// Emits a {Transfer} event.
    function _burn(address from, uint256 id, uint256 amount) internal virtual {
        _beforeTokenTransfer(from, address(0), id, amount);
        _erc6909Debit(from, id, amount);
        emit Transfer(msg.sender, from, address(0), id, amount);
        _afterTokenTransfer(from, address(0), id, amount);
    }

    /// @dev Transfers `amount` of token `id` from `from` to `to`.
    ///
    /// Note:
    /// - Allowance is NOT deducted if it is `type(uint256).max`.
    /// - Allowance is NOT deducted if `from` is an operator.
    /// - For efficiency, allowance is deducted even if `from` is `by`.
    ///
    /// Requirements:
    /// - `from` must at least have `amount` of token `id`.
    /// - If `by` is not the zero address,
    ///   it must have at least `amount` of allowance to transfer the
    ///   tokens of `from` or approved as an operator.
    ///
    /// Emits a {Transfer} event.
    function _transfer(address by, address from, address to, uint256 id, uint256 amount)
        internal
        virtual
    {
        _beforeTokenTransfer(from, to, id, amount);
        // If `by` is not the zero address, check if it is an operator.
        if (by != address(0)) {
            if (!_erc6909Operators[from][by]) {
                _erc6909SpendAllowance(from, by, id, amount);
            }
        }
        _erc6909Debit(from, id, amount);
        _erc6909Credit(to, id, amount);
        emit Transfer(by, from, to, id, amount);
        _afterTokenTransfer(from, to, id, amount);
    }

    /// @dev Sets `amount` as the allowance of `spender` for `owner` for token `id`.
    ///
    /// Emits a {Approval} event.
    function _approve(address owner, address spender, uint256 id, uint256 amount) internal virtual {
        _erc6909Allowances[owner][spender][id] = amount;
        emit Approval(owner, spender, id, amount);
    }

    ///  @dev Sets whether `operator` is approved to manage the tokens of `owner`.
    ///
    /// Emits {OperatorSet} event.
    function _setOperator(address owner, address operator, bool approved) internal virtual {
        _erc6909Operators[owner][operator] = approved;
        emit OperatorSet(owner, operator, approved);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HOOKS TO OVERRIDE                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Hook that is called before any transfer of tokens.
    /// This includes minting and burning.
    function _beforeTokenTransfer(address from, address to, uint256 id, uint256 amount)
        internal
        virtual {}

    /// @dev Hook that is called after any transfer of tokens.
    /// This includes minting and burning.
    function _afterTokenTransfer(address from, address to, uint256 id, uint256 amount)
        internal
        virtual {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deducts `amount` from the allowance of `spender` for the `id` tokens of `owner`,
    /// unless the allowance is the maximum uint256 value.
    function _erc6909SpendAllowance(address owner, address spender, uint256 id, uint256 amount)
        private
    {
        uint256 allowance_ = _erc6909Allowances[owner][spender][id];
        // If the allowance is not the maximum uint256 value.
        if (allowance_ != type(uint256).max) {
            // Revert if the amount to be transferred exceeds the allowance.
            if (amount > allowance_) revert InsufficientPermission();
            // Subtract and store the updated allowance.
            _erc6909Allowances[owner][spender][id] = allowance_ - amount;
        }
    }

    /// @dev Subtracts `amount` of `id` from the balance of `from`.
    function _erc6909Debit(address from, uint256 id, uint256 amount) private {
        uint256 fromBalance = _erc6909Balances[from][id];
        // Revert if insufficient balance.
        if (amount > fromBalance) revert InsufficientBalance();
        _erc6909Balances[from][id] = fromBalance - amount;
    }

    /// @dev Adds `amount` of `id` to the balance of `to`.
    function _erc6909Credit(address to, uint256 id, uint256 amount) private {
        uint256 toBalanceBefore = _erc6909Balances[to][id];
        uint256 toBalanceAfter = _erc6909Add(toBalanceBefore, amount);
        // Revert if the balance overflows.
        if (toBalanceAfter < toBalanceBefore) revert BalanceOverflow();
        _erc6909Balances[to][id] = toBalanceAfter;
    }

    /// @dev `a + b` modulo `2**256`.
    /// @custom:solar-trusted
    function _erc6909Add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }
}
