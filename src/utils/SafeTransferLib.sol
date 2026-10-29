// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Safe ETH and ERC20 transfer library that gracefully handles missing return values.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SafeTransferLib.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SafeTransferLib.sol)
/// @author Permit2 operations from (https://github.com/Uniswap/permit2/blob/main/src/libraries/Permit2Lib.sol)
///
/// @dev Note:
/// - For ETH transfers, please use `forceSafeTransferETH` for DoS protection.
///
/// The checked port reads a token's answer with the trusted `_callBounded`, at most one word of
/// it, so a token cannot make the caller copy more. A transfer or approval succeeds when the
/// call does and the token answers `true`, or answers nothing and has code, as upstream decides
/// it. A forced transfer deploys a contract that self-destructs to its recipient, as the
/// assembly does, and Permit2 is called with exactly the ABI-encoded arguments. Three
/// deliberate differences, none reachable while gas lasts and the tokens behave: a forced
/// transfer or ETH vault whose creation fails, which only running out of gas does, reverts with
/// `ETHTransferFailed()` instead of `codesize` bytes of memory; `safeMoveETH` raises
/// `Panic(0x01)` where the assembly runs `INVALID` if its balance grew; and a DAI-style permit
/// sends the nonce zero where the assembly sends its buffer's old word if the token's `nonces`
/// call fails.
/// @custom:solar-safe memory arithmetic
library SafeTransferLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ETH transfer has failed.
    error ETHTransferFailed();

    /// @dev The ERC20 `transferFrom` has failed.
    error TransferFromFailed();

    /// @dev The ERC20 `transfer` has failed.
    error TransferFailed();

    /// @dev The ERC20 `approve` has failed.
    error ApproveFailed();

    /// @dev The ERC20 `totalSupply` query has failed.
    error TotalSupplyQueryFailed();

    /// @dev The Permit2 operation has failed.
    error Permit2Failed();

    /// @dev The Permit2 amount must be less than `2**160 - 1`.
    error Permit2AmountOverflow();

    /// @dev The Permit2 approve operation has failed.
    error Permit2ApproveFailed();

    /// @dev The Permit2 lockdown operation has failed.
    error Permit2LockdownFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Suggested gas stipend for contract receiving ETH that disallows any storage writes.
    uint256 internal constant GAS_STIPEND_NO_STORAGE_WRITES = 2300;

    /// @dev Suggested gas stipend for contract receiving ETH to perform a few
    /// storage reads and writes, but low enough to prevent griefing.
    uint256 internal constant GAS_STIPEND_NO_GRIEF = 100000;

    /// @dev The unique EIP-712 domain separator for the DAI token contract.
    bytes32 internal constant DAI_DOMAIN_SEPARATOR =
        0xdbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7;

    /// @dev The address for the WETH9 contract on Ethereum mainnet.
    address internal constant WETH9 = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    /// @dev The canonical Permit2 address.
    /// [Github](https://github.com/Uniswap/permit2)
    /// [Etherscan](https://etherscan.io/address/0x000000000022D473030F116dDEE9F6B43aC78BA3)
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    /// @dev The canonical address of the `SELFDESTRUCT` ETH mover.
    /// See: https://gist.github.com/Vectorized/1cb8ad4cf393b1378e08f23f79bd99fa
    /// [Etherscan](https://etherscan.io/address/0x00000000000073c48c8055bD43D1A53799176f0D)
    address internal constant ETH_MOVER = 0x00000000000073c48c8055bD43D1A53799176f0D;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       ETH OPERATIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // If the ETH transfer MUST succeed with a reasonable gas budget, use the force variants.
    //
    // The regular variants:
    // - Forwards all remaining gas to the target.
    // - Reverts if the target reverts.
    // - Reverts if the current contract has insufficient balance.
    //
    // The force variants:
    // - Forwards with an optional gas stipend
    //   (defaults to `GAS_STIPEND_NO_GRIEF`, which is sufficient for most cases).
    // - If the target reverts, or if the gas stipend is exhausted,
    //   creates a temporary contract to force send the ETH via `SELFDESTRUCT`.
    //   Future compatible with `SENDALL`: https://eips.ethereum.org/EIPS/eip-4758.
    // - Reverts if the current contract has insufficient balance.
    //
    // The try variants:
    // - Forwards with a mandatory gas stipend.
    // - Instead of reverting, returns whether the transfer succeeded.

    /// @dev Sends `amount` (in wei) ETH to `to`.
    function safeTransferETH(address to, uint256 amount) internal {
        if (!_sendETH(to, amount, gasleft())) revert ETHTransferFailed();
    }

    /// @dev Sends all the ETH in the current contract to `to`.
    function safeTransferAllETH(address to) internal {
        if (!_sendETH(to, address(this).balance, gasleft())) revert ETHTransferFailed();
    }

    /// @dev Force sends `amount` (in wei) ETH to `to`, with a `gasStipend`.
    function forceSafeTransferETH(address to, uint256 amount, uint256 gasStipend) internal {
        if (address(this).balance < amount) revert ETHTransferFailed();
        if (!_sendETH(to, amount, gasStipend)) _forceSendETH(to, amount);
    }

    /// @dev Force sends all the ETH in the current contract to `to`, with a `gasStipend`.
    function forceSafeTransferAllETH(address to, uint256 gasStipend) internal {
        if (!_sendETH(to, address(this).balance, gasStipend)) {
            _forceSendETH(to, address(this).balance);
        }
    }

    /// @dev Force sends `amount` (in wei) ETH to `to`, with `GAS_STIPEND_NO_GRIEF`.
    function forceSafeTransferETH(address to, uint256 amount) internal {
        forceSafeTransferETH(to, amount, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Force sends all the ETH in the current contract to `to`, with `GAS_STIPEND_NO_GRIEF`.
    function forceSafeTransferAllETH(address to) internal {
        forceSafeTransferAllETH(to, GAS_STIPEND_NO_GRIEF);
    }

    /// @dev Sends `amount` (in wei) ETH to `to`, with a `gasStipend`.
    function trySafeTransferETH(address to, uint256 amount, uint256 gasStipend)
        internal
        returns (bool success)
    {
        return _sendETH(to, amount, gasStipend);
    }

    /// @dev Sends all the ETH in the current contract to `to`, with a `gasStipend`.
    function trySafeTransferAllETH(address to, uint256 gasStipend) internal returns (bool success) {
        return _sendETH(to, address(this).balance, gasStipend);
    }

    /// @dev Force transfers ETH to `to`, without triggering the fallback (if any).
    /// This method attempts to use a separate contract to send via `SELFDESTRUCT`,
    /// and upon failure, deploys a minimal vault to accrue the ETH.
    function safeMoveETH(address to, uint256 amount) internal returns (address vault) {
        if (to == address(this)) return address(0);
        uint256 selfBalanceBefore = address(this).balance;
        if (selfBalanceBefore < amount || to == ETH_MOVER) revert ETHTransferFailed();
        if (ETH_MOVER.code.length != 0) {
            // The mover self-destructs to the word it is called with. The
            // transfer is judged by the balance it adds, in case `SELFDESTRUCT`
            // no longer sends.
            uint256 balanceBefore = to.balance;
            _callBounded(ETH_MOVER, amount, gasleft(), abi.encode(to), 0);
            if (to.balance >= amount + balanceBefore) return address(0);
            assert(address(this).balance <= selfBalanceBefore);
        }
        // A vault that pays out all it holds to `to` when `to` calls it, and
        // answers anyone else with one word. The ETH is sent to its CREATE2
        // address first; if nothing answered there, it is deployed after.
        bytes memory initcode = abi.encodePacked(
            hex"6035600b3d3960353df3fe73",
            to,
            hex"33146025575b600160005260206000f35b3d3d3d3d47335af1601a5760003dfd"
        );
        vault = _createPredict2(address(this), 0, keccak256(initcode));
        (,, uint256 answered) = _callBounded(vault, amount, gasleft(), "", 0);
        if (answered == 0) {
            (bool created,) = _createTryDeploy2(initcode, 0, 0);
            if (!created) revert ETHTransferFailed();
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      ERC20 OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to`.
    /// Reverts upon failure.
    ///
    /// The `from` account must have at least `amount` approved for
    /// the current contract to manage.
    function safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        if (!trySafeTransferFrom(token, from, to, amount)) revert TransferFromFailed();
    }

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to`.
    ///
    /// The `from` account must have at least `amount` approved for the current contract to manage.
    function trySafeTransferFrom(address token, address from, address to, uint256 amount)
        internal
        returns (bool success)
    {
        return _accepted(token, abi.encodeWithSelector(0x23b872dd, from, to, amount));
    }

    /// @dev Sends all of ERC20 `token` from `from` to `to`.
    /// Reverts upon failure.
    ///
    /// The `from` account must have their entire balance approved for the current contract to manage.
    function safeTransferAllFrom(address token, address from, address to)
        internal
        returns (uint256 amount)
    {
        bool implemented;
        (implemented, amount) = checkBalanceOf(token, from);
        if (!implemented) revert TransferFromFailed();
        safeTransferFrom(token, from, to, amount);
    }

    /// @dev Sends `amount` of ERC20 `token` from the current contract to `to`.
    /// Reverts upon failure.
    function safeTransfer(address token, address to, uint256 amount) internal {
        if (!_accepted(token, abi.encodeWithSelector(0xa9059cbb, to, amount))) {
            revert TransferFailed();
        }
    }

    /// @dev Sends all of ERC20 `token` from the current contract to `to`.
    /// Reverts upon failure.
    function safeTransferAll(address token, address to) internal returns (uint256 amount) {
        bool implemented;
        (implemented, amount) = checkBalanceOf(token, address(this));
        if (!implemented) revert TransferFailed();
        safeTransfer(token, to, amount);
    }

    /// @dev Sets `amount` of ERC20 `token` for `to` to manage on behalf of the current contract.
    /// Reverts upon failure.
    function safeApprove(address token, address to, uint256 amount) internal {
        if (!_accepted(token, abi.encodeWithSelector(0x095ea7b3, to, amount))) {
            revert ApproveFailed();
        }
    }

    /// @dev Sets `amount` of ERC20 `token` for `to` to manage on behalf of the current contract.
    /// If the initial attempt to approve fails, attempts to reset the approved amount to zero,
    /// then retries the approval again (some tokens, e.g. USDT, requires this).
    /// Reverts upon failure.
    function safeApproveWithRetry(address token, address to, uint256 amount) internal {
        if (_accepted(token, abi.encodeWithSelector(0x095ea7b3, to, amount))) return;
        // The reset's answer is ignored, as upstream ignores it.
        _callBounded(token, 0, gasleft(), abi.encodeWithSelector(0x095ea7b3, to, 0), 0);
        if (!_accepted(token, abi.encodeWithSelector(0x095ea7b3, to, amount))) {
            revert ApproveFailed();
        }
    }

    /// @dev Returns the amount of ERC20 `token` owned by `account`.
    /// Returns zero if the `token` does not exist.
    function balanceOf(address token, address account) internal view returns (uint256 amount) {
        (, amount) = checkBalanceOf(token, account);
    }

    /// @dev Performs a `token.balanceOf(account)` check.
    /// `implemented` denotes whether the `token` does not implement `balanceOf`.
    /// `amount` is zero if the `token` does not implement `balanceOf`.
    /// `implemented` denotes whether the `token` implements `balanceOf`.
    function checkBalanceOf(address token, address account)
        internal
        view
        returns (bool implemented, uint256 amount)
    {
        (implemented, amount) = _word(token, abi.encodeWithSelector(0x70a08231, account));
    }

    /// @dev Returns the total supply of the `token`.
    /// Reverts if the token does not exist or does not implement `totalSupply()`.
    function totalSupply(address token) internal view returns (uint256 result) {
        bool implemented;
        (implemented, result) = _word(token, abi.encodeWithSelector(0x18160ddd));
        if (!implemented) revert TotalSupplyQueryFailed();
    }

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to`.
    /// If the initial attempt fails, try to use Permit2 to transfer the token.
    /// Reverts upon failure.
    ///
    /// The `from` account must have at least `amount` approved for the current contract to manage.
    function safeTransferFrom2(address token, address from, address to, uint256 amount) internal {
        if (!trySafeTransferFrom(token, from, to, amount)) {
            permit2TransferFrom(token, from, to, amount);
        }
    }

    /// @dev Sends `amount` of ERC20 `token` from `from` to `to` via Permit2.
    /// Reverts upon failure.
    function permit2TransferFrom(address token, address from, address to, uint256 amount) internal {
        bool exists = block.chainid == 1 || PERMIT2.code.length != 0;
        bool tokenHasCode = token.code.length != 0;
        // `transferFrom(address,address,uint160,address)`, with the whole
        // amount word, which Permit2 rejects past 160 bits.
        (bool success,,) = _callBounded(
            PERMIT2, 0, gasleft(), abi.encodeWithSelector(0x36c78516, from, to, amount, token), 0
        );
        if (!(success && tokenHasCode && exists)) {
            if (amount >> 160 != 0) revert Permit2AmountOverflow();
            revert TransferFromFailed();
        }
    }

    /// @dev Permit a user to spend a given amount of
    /// another user's tokens via native EIP-2612 permit if possible, falling
    /// back to Permit2 if native permit fails or is not implemented on the token.
    function permit2(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        if (!_permit(token, owner, spender, amount, deadline, v, r, s)) {
            simplePermit2(token, owner, spender, amount, deadline, v, r, s);
        }
    }

    /// @dev Simple permit on the Permit2 contract.
    function simplePermit2(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        if (amount >> 160 != 0) revert Permit2AmountOverflow();
        uint256 nonce = _permit2Nonce(owner, token, spender);
        bytes memory signature = abi.encodePacked(r, s, v);
        if (
            !_permitSingle(owner, token, amount, nonce, spender, deadline, signature)
                || token.code.length == 0
        ) revert Permit2Failed();
    }

    /// @dev Approves `spender` to spend `amount` of `token` for `address(this)`.
    function permit2Approve(address token, address spender, uint160 amount, uint48 expiration)
        internal
    {
        // `approve(address,address,uint160,uint48)`.
        (bool success,,) = _callBounded(
            PERMIT2,
            0,
            gasleft(),
            abi.encodeWithSelector(0x87517c45, token, spender, amount, expiration),
            0
        );
        if (!success) revert Permit2ApproveFailed();
    }

    /// @dev Revokes an approval for `token` and `spender` for `address(this)`.
    function permit2Lockdown(address token, address spender) internal {
        // `lockdown((address,address)[])` with the one pair.
        (bool success,,) = _callBounded(
            PERMIT2,
            0,
            gasleft(),
            abi.encodeWithSelector(0xcc53287f, uint256(0x20), uint256(1), token, spender),
            0
        );
        if (!success) revert Permit2LockdownFailed();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Tries `token`'s own permit: DAI's when its domain separator is
    /// DAI's, EIP-2612's otherwise. WETH9 has none, and neither has a token
    /// whose `DOMAIN_SEPARATOR()` does not answer one nonzero word within
    /// 5,000 gas, which limits what a token without it can burn.
    function _permit(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) private returns (bool success) {
        if (token == WETH9) return false;
        (bool answered, bytes memory answer, uint256 total) =
            _staticCallBounded(token, 5000, abi.encodeWithSelector(0x3644e515), 32);
        if (!answered || total != 32 || _readBytes32(answer, 0) == 0) return false;
        if (_readBytes32(answer, 0) == DAI_DOMAIN_SEPARATOR) {
            return _daiPermit(token, owner, spender, amount != 0, deadline, v, r, s);
        }
        // `IERC20Permit.permit`.
        (success,,) = _callBounded(
            token,
            0,
            gasleft(),
            abi.encodeWithSelector(0xd505accf, owner, spender, amount, deadline, v, r, s),
            0
        );
    }

    /// @dev The nonce Permit2 holds for `owner`'s allowance of `token` to
    /// `spender`: `allowance(address,address,address)` answers the amount, the
    /// expiration and the nonce.
    function _permit2Nonce(address owner, address token, address spender)
        private
        view
        returns (uint256)
    {
        (bool success, bytes memory answer, uint256 total) = _staticCallBounded(
            PERMIT2, gasleft(), abi.encodeWithSelector(0x927da105, owner, token, spender), 96
        );
        if (!success || total < 96) revert Permit2Failed();
        return uint256(_readBytes32(answer, 64));
    }

    /// @dev `Permit2.permit` (PermitSingle variant): the details, with
    /// `expiration = type(uint48).max`, the spender, the deadline, and the
    /// signature `r ++ s ++ v`.
    function _permitSingle(
        address owner,
        address token,
        uint256 amount,
        uint256 nonce,
        address spender,
        uint256 deadline,
        bytes memory signature
    ) private returns (bool success) {
        (success,,) = _callBounded(
            PERMIT2,
            0,
            gasleft(),
            abi.encodeWithSelector(
                0x2b67b570,
                owner,
                token,
                amount,
                uint256(type(uint48).max),
                nonce,
                spender,
                deadline,
                signature
            ),
            0
        );
    }

    /// @dev DAI's permit, which allows all or nothing, with the nonce its
    /// `nonces(address)` answers. The call is encoded in two parts, which keeps
    /// the arguments few enough for solc's legacy pipeline.
    function _daiPermit(
        address token,
        address owner,
        address spender,
        bool allowAny,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) private returns (bool success) {
        (bool known, uint256 nonce) = _word(token, abi.encodeWithSelector(0x7ecebe00, owner));
        // `IDAIPermit.permit`.
        (success,,) = _callBounded(
            token,
            0,
            gasleft(),
            abi.encodePacked(
                abi.encodeWithSelector(0x8fcbaf0c, owner, spender, nonce, deadline),
                abi.encode(known && allowAny, v, r, s)
            ),
            0
        );
    }

    /// @dev Deploys a contract that self-destructs at once, sending the
    /// `amount` wei it is created with to `to` without calling it.
    function _forceSendETH(address to, uint256 amount) private {
        // PUSH20 to, SELFDESTRUCT
        (bool created,) = _createTryDeploy(abi.encodePacked(hex"73", to, hex"ff"), amount);
        if (!created) revert ETHTransferFailed();
    }

    /// @dev Sends `amount` wei to `to` with `gasLimit` gas and no calldata,
    /// copying none of the answer.
    function _sendETH(address to, uint256 amount, uint256 gasLimit) private returns (bool success) {
        (success,,) = _callBounded(to, amount, gasLimit, "", 0);
    }

    /// @dev Whether `token` accepted the call `payload`: the call succeeded and
    /// the token answered `true`, or answered nothing and has code.
    function _accepted(address token, bytes memory payload) private returns (bool) {
        (bool success, bytes memory answer, uint256 total) =
            _callBounded(token, 0, gasleft(), payload, 32);
        if (!success) return false;
        if (total == 0) return token.code.length != 0;
        return answer.length == 32 && uint256(_readBytes32(answer, 0)) == 1;
    }

    /// @dev The first word `token` answers the static call `payload` with, and
    /// whether the call succeeded with a word at least.
    function _word(address token, bytes memory payload)
        private
        view
        returns (bool answered, uint256 word)
    {
        (bool success, bytes memory answer,) = _staticCallBounded(token, gasleft(), payload, 32);
        if (!success || answer.length < 32) return (false, 0);
        return (true, uint256(_readBytes32(answer, 0)));
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
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

    /// @dev The address `deploy2` gives `deployer` for `salt` and initcode
    /// hashing to `initcodeHash`. Computes only; deploys nothing.
    function _createPredict2(address deployer, bytes32 salt, bytes32 initcodeHash)
        private
        pure
        returns (address)
    {
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initcodeHash)))
            )
        );
    }

    /// @dev Like `deploy`, but a creation that returns no address is `false`
    /// and the zero address, not a revert.
    /// @custom:solar-trusted
    function _createTryDeploy(bytes memory initcode, uint256 value)
        private
        returns (bool success, address deployed)
    {
        /// @solidity memory-safe-assembly
        assembly {
            deployed := create(value, add(initcode, 0x20), mload(initcode))
        }
        success = deployed != address(0);
    }

    /// @dev Like `deploy2`, but a creation that returns no address is `false`
    /// and the zero address, not a revert.
    /// @custom:solar-trusted
    function _createTryDeploy2(bytes memory initcode, bytes32 salt, uint256 value)
        private
        returns (bool success, address deployed)
    {
        /// @solidity memory-safe-assembly
        assembly {
            deployed := create2(value, add(initcode, 0x20), mload(initcode), salt)
        }
        success = deployed != address(0);
    }
}
