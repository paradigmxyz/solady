// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import {Receiver} from "./Receiver.sol";
import {LibZip} from "../utils/LibZip.sol";
import {Ownable} from "../auth/Ownable.sol";
import {UUPSUpgradeable} from "../utils/UUPSUpgradeable.sol";
import {SignatureCheckerLib, ERC1271} from "../accounts/ERC1271.sol";

/// @notice Simple ERC4337 account implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC4337.sol)
/// @author Infinitism (https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/samples/SimpleAccount.sol)
///
/// @dev Recommended usage:
/// 1. Deploy the ERC4337 as an implementation contract, and verify it on Etherscan.
/// 2. Create a factory that uses `LibClone.deployERC1967` or
///    `LibClone.deployDeterministicERC1967` to clone the implementation.
///    See: `ERC4337Factory.sol`.
///
/// Note:
/// ERC4337 is a very complicated standard with many potential gotchas.
/// Also, it is subject to change and has not been finalized
/// (so accounts are encouraged to be upgradeable).
/// Usually, ERC4337 account implementations are developed by companies with ample funds
/// for security reviews. This implementation is intended to serve as a base reference
/// for smart account developers working in such companies. If you are using this
/// implementation, please do get one or more security reviews before deployment.
///
/// The checked port makes the calls with Solidity's calls, or with trusted calls that copy no
/// more of the answer than the assembly reads, and bubbles a revert with trusted helpers. It
/// reads and writes the raw storage slots with trusted helpers, since Solidity cannot name
/// them. `executeBatch` reads the calls as the assembly does, following their offsets with
/// wrap-around additions and without the checks of Solidity's accessors, which would reject
/// dirty addresses and offsets past the calldata; trusted helpers read the array's calldata
/// offset and make each call's data a slice wherever it lies, which Solidity cannot. Reads past
/// the calldata give zeros, as `CALLDATALOAD` does; call data that runs past it is copied with
/// the zeros, and a length no gas could copy halts with a trusted `invalid()`, as the copy would
/// run out of gas. The helpers' names carry an `_erc4337` prefix, so that a contract can inherit
/// this alongside other ports.
/// @custom:solar-safe memory arithmetic
abstract contract ERC4337 is Ownable, UUPSUpgradeable, Receiver, ERC1271 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The packed ERC4337 user operation (userOp) struct.
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode; // Factory address and `factoryData` (or empty).
        bytes callData;
        bytes32 accountGasLimits; // `verificationGas` (16 bytes) and `callGas` (16 bytes).
        uint256 preVerificationGas;
        bytes32 gasFees; // `maxPriorityFee` (16 bytes) and `maxFeePerGas` (16 bytes).
        bytes paymasterAndData; // Paymaster fields (or empty).
        bytes signature;
    }

    /// @dev Call struct for the `executeBatch` function.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys this ERC4337 account implementation and disables initialization (see below).
    constructor() payable {
        _disableERC4337ImplementationInitializer();
    }

    /// @dev Automatically initializes the owner for the implementation. This blocks someone
    /// from initializing the implementation and doing a delegatecall to SELFDESTRUCT.
    /// Proxies to the implementation will still be able to initialize as per normal.
    function _disableERC4337ImplementationInitializer() internal virtual {
        // Note that `Ownable._guardInitializeOwner` has been and must be overridden
        // to return true, to block double-initialization. We'll initialize to `address(1)`,
        // so that it's easier to verify that the implementation has been initialized.
        _initializeOwner(address(1));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        INITIALIZER                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Initializes the account with the owner. Can only be called once.
    function initialize(address newOwner) public payable virtual {
        _initializeOwner(newOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        ENTRY POINT                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the canonical ERC4337 EntryPoint contract (0.7).
    /// Override this function to return a different EntryPoint.
    function entryPoint() public view virtual returns (address) {
        return 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   VALIDATION OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Validates the signature and nonce.
    /// The EntryPoint will make the call to the recipient only if
    /// this validation call returns successfully.
    ///
    /// Signature failure should be reported by returning 1 (see: `_validateSignature`).
    /// This allows making a "simulation call" without a valid signature.
    /// Other failures (e.g. nonce mismatch, or invalid signature format)
    /// should still revert to signal failure.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        payable
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
    }

    /// @dev Validate `userOp.signature` for the `userOpHash`.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        virtual
        returns (uint256 validationData)
    {
        bool success = SignatureCheckerLib.isValidSignatureNowCalldata(
            owner(), SignatureCheckerLib.toEthSignedMessageHash(userOpHash), userOp.signature
        );
        // Returns 0 if the recovered address matches the owner.
        // Else returns 1, which is equivalent to:
        // `(success ? 0 : 1) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48))`
        // where `validUntil` is 0 (indefinite) and `validAfter` is 0.
        validationData = success ? 0 : 1;
    }

    /// @dev Override to validate the nonce of the userOp.
    /// This method may validate the nonce requirement of this account.
    /// e.g.
    /// To limit the nonce to use sequenced userOps only (no "out of order" userOps):
    ///      `require(nonce < type(uint64).max)`
    /// For a hypothetical account that *requires* the nonce to be out-of-order:
    ///      `require(nonce & type(uint64).max == 0)`
    ///
    /// The actual nonce uniqueness is managed by the EntryPoint, and thus no other
    /// action is needed by the account itself.
    function _validateNonce(uint256 nonce) internal virtual {
        nonce = nonce; // Silence unused variable warning.
    }

    /// @dev Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    /// Subclass MAY override this modifier for better funds management.
    /// (e.g. send to the EntryPoint more than the minimum required, so that in future transactions
    /// it will not be required to send again)
    ///
    /// `missingAccountFunds` is the minimum value this modifier should send the EntryPoint,
    /// which MAY be zero, in case there is enough deposit, or the userOp has a paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;
        if (missingAccountFunds != 0) {
            // Ignore failure (it's EntryPoint's job to verify, not the account's).
            _erc4337Call(msg.sender, missingAccountFunds);
        }
    }

    /// @dev Requires that the caller is the EntryPoint.
    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) revert Unauthorized();
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EXECUTION OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Execute a call from this account.
    function execute(address target, uint256 value, bytes calldata data)
        public
        payable
        virtual
        onlyEntryPointOrOwner
        returns (bytes memory result)
    {
        bool success;
        (success, result) = target.call{value: value}(data);
        // Bubble up the revert if the call reverts.
        if (!success) _erc4337RevertRaw(result);
    }

    /// @dev Execute a sequence of calls from this account.
    /// @custom:solar-inline always
    function executeBatch(Call[] calldata calls)
        public
        payable
        virtual
        onlyEntryPointOrOwner
        returns (bytes[] memory results)
    {
        // Each call is `(target, value, data)` at the offset its head word gives from `calls`,
        // read as the assembly reads it, following the offsets unchecked.
        uint256 offset = _erc4337CalldataOffset(calls);
        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            uint256 e = _erc4337Add(offset, uint256(_erc4337CalldataWord(offset + (i << 5))));
            uint256 o = _erc4337Add(e, uint256(_erc4337CalldataWord(_erc4337Add(e, 0x40))));
            uint256 length = uint256(_erc4337CalldataWord(o));
            // A length no gas could copy halts, as the copy would.
            if (length >> 63 != 0) _erc4337Invalid();
            (bool success, bytes memory result) = address(uint160(uint256(_erc4337CalldataWord(e))))
            .call{value: uint256(_erc4337CalldataWord(_erc4337Add(e, 0x20)))}(
                _erc4337CalldataSlice(_erc4337Add(o, 0x20), length)
            );
            // Bubble up the revert if the call reverts.
            if (!success) _erc4337RevertRaw(result);
            results[i] = result; // Append the returndata into `results`.
        }
    }

    /// @dev Execute a delegatecall with `delegate` on this account.
    function delegateExecute(address delegate, bytes calldata data)
        public
        payable
        virtual
        onlyEntryPointOrOwner
        delegateExecuteGuard
        returns (bytes memory result)
    {
        bool success;
        // Forwards the `data` to `delegate` via delegatecall.
        (success, result) = delegate.delegatecall(data);
        // Bubble up the revert if the call reverts.
        if (!success) _erc4337RevertRaw(result);
    }

    /// @dev Ensures that the owner and implementation slots' values aren't changed.
    /// You can override this modifier to ensure the sanctity of other storage slots too.
    modifier delegateExecuteGuard() virtual {
        bytes32 ownerSlotValue;
        bytes32 implementationSlotValue;
        implementationSlotValue = bytes32(_erc4337Sload(uint256(_ERC1967_IMPLEMENTATION_SLOT)));
        ownerSlotValue = bytes32(_erc4337Sload(uint256(_OWNER_SLOT)));
        _;
        bool kept = implementationSlotValue
            == bytes32(_erc4337Sload(uint256(_ERC1967_IMPLEMENTATION_SLOT)));
        kept = kept && ownerSlotValue == bytes32(_erc4337Sload(uint256(_OWNER_SLOT)));
        if (!kept) revert();
    }

    /// @dev Requires that the caller is the EntryPoint, the owner, or the account itself.
    modifier onlyEntryPointOrOwner() virtual {
        if (msg.sender != entryPoint()) _checkOwner();
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 DIRECT STORAGE OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the raw storage value at `storageSlot`.
    function storageLoad(bytes32 storageSlot) public view virtual returns (bytes32 result) {
        result = bytes32(_erc4337Sload(uint256(storageSlot)));
    }

    /// @dev Writes the raw storage value at `storageSlot`.
    function storageStore(bytes32 storageSlot, bytes32 storageValue)
        public
        payable
        virtual
        onlyEntryPointOrOwner
        storageStoreGuard(storageSlot)
    {
        _erc4337Sstore(uint256(storageSlot), uint256(storageValue));
    }

    /// @dev Ensures that the `storageSlot` is prohibited for direct storage writes.
    /// You can override this modifier to ensure the sanctity of other storage slots too.
    modifier storageStoreGuard(bytes32 storageSlot) virtual {
        if (storageSlot == _OWNER_SLOT || storageSlot == _ERC1967_IMPLEMENTATION_SLOT) revert();
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     DEPOSIT OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the account's balance on the EntryPoint.
    function getDeposit() public view virtual returns (uint256 result) {
        address ep = entryPoint();
        // `balanceOf(address)`, with the `account` argument.
        (bool success, uint256 answerSize, bytes32 answer) =
            _erc4337StaticCallWord(ep, abi.encodeWithSelector(0x70a08231, address(this)));
        // Returns 0 if the EntryPoint does not exist.
        // At least 32 bytes returned.
        if (success && answerSize > 0x1f) result = uint256(answer);
    }

    /// @dev Deposit more funds for this account in the EntryPoint.
    function addDeposit() public payable virtual {
        address ep = entryPoint();
        // The EntryPoint has balance accounting logic in the `receive()` function, as defined in ERC-4337.
        if (!_erc4337Call(ep, msg.value) || ep.code.length == 0) revert(); // For gas estimation.
    }

    /// @dev Withdraw ETH from the account's deposit on the EntryPoint.
    function withdrawDepositTo(address to, uint256 amount) public payable virtual onlyOwner {
        address ep = entryPoint();
        // `withdrawTo(address,uint256)`, with the `to` and `amount` arguments.
        bool success = _erc4337CallPayload(ep, abi.encodeWithSelector(0x205c2878, to, amount));
        if (!success || ep.code.length == 0) _erc4337RevertReturndata();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OVERRIDES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Requires that the caller is the owner or the account itself.
    /// This override affects the `onlyOwner` modifier.
    /// @custom:solar-inline always
    function _checkOwner() internal view virtual override(Ownable) {
        if (msg.sender != owner()) if (msg.sender != address(this)) revert Unauthorized();
    }

    /// @dev To prevent double-initialization (reuses the owner storage slot for efficiency).
    function _guardInitializeOwner() internal pure virtual override(Ownable) returns (bool) {
        return true;
    }

    /// @dev Uses the `owner` as the ERC1271 signer.
    function _erc1271Signer() internal view virtual override(ERC1271) returns (address) {
        return owner();
    }

    /// @dev Allow the entry point to skip the ERC7739 nested typed data workflow.
    /// This is safe as the entry point already includes the smart account in the user op digest.
    function _erc1271CallerIsSafe() internal view virtual override(ERC1271) returns (bool) {
        return msg.sender == entryPoint() || ERC1271._erc1271CallerIsSafe();
    }

    /// @dev To ensure that only the owner or the account itself can upgrade the implementation.
    function _authorizeUpgrade(address) internal virtual override(UUPSUpgradeable) onlyOwner {}

    /// @dev If you don't need to use `LibZip.cdFallback`, override this function to return false.
    function _useLibZipCdFallback() internal view virtual returns (bool) {
        return true;
    }

    /// @dev Handle token callbacks. If no token callback is triggered,
    /// use `LibZip.cdFallback` for generalized calldata decompression.
    fallback() external payable virtual override(Receiver) receiverFallback {
        if (_useLibZipCdFallback()) {
            // Reverts with out-of-gas by recursing infinitely if the first 4 bytes
            // of the decompressed `msg.data` doesn't match any function selector.
            LibZip.cdFallback();
        } else {
            revert FnSelectorNotRecognized();
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The word of calldata at `offset`, zero-padded past the end of the calldata, as
    /// `CALLDATALOAD` reads it.
    /// @custom:solar-inline always
    function _erc4337CalldataWord(uint256 offset) private pure returns (bytes32) {
        return bytes32(_erc4337CalldataSlice(offset, 0x20));
    }

    /// @dev `a + b` modulo `2**256`, as the assembly adds calldata offsets. Solidity's
    /// addition reverts where this wraps around.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc4337Add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev The word in storage slot `slot`. Solidity cannot name a slot it did not allocate.
    /// @custom:solar-trusted
    function _erc4337Sload(uint256 slot) private view returns (uint256 value) {
        /// @solidity memory-safe-assembly
        assembly {
            value := sload(slot)
        }
    }

    /// @dev Stores `value` in storage slot `slot`.
    /// @custom:solar-trusted
    function _erc4337Sstore(uint256 slot, uint256 value) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, value)
        }
    }

    /// @dev The calldata offset of `calls`. Solidity cannot read a calldata array's offset.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc4337CalldataOffset(Call[] calldata calls) private pure returns (uint256 offset) {
        /// @solidity memory-safe-assembly
        assembly {
            offset := calls.offset
        }
    }

    /// @dev The calldata slice of `length` bytes at `offset`, which may lie past the end of
    /// the calldata, where reads give zeros. Solidity slices only within `msg.data`.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc4337CalldataSlice(uint256 offset, uint256 length)
        private
        pure
        returns (bytes calldata s)
    {
        /// @solidity memory-safe-assembly
        assembly {
            s.offset := offset
            s.length := length
        }
    }

    /// @dev Calls `target` with `value` wei, no data and all the gas left, and copies none of
    /// the answer. Solidity's calls copy the whole answer.
    /// @custom:solar-trusted
    function _erc4337Call(address target, uint256 value) private returns (bool success) {
        /// @solidity memory-safe-assembly
        assembly {
            success := call(gas(), target, value, codesize(), 0x00, codesize(), 0x00)
        }
    }

    /// @dev Calls `target` with `payload` and all the gas left, and copies none of the answer.
    /// Solidity's calls copy the whole answer.
    /// @custom:solar-trusted
    function _erc4337CallPayload(address target, bytes memory payload)
        private
        returns (bool success)
    {
        /// @solidity memory-safe-assembly
        assembly {
            success := call(gas(), target, 0, add(payload, 0x20), mload(payload), codesize(), 0x00)
        }
    }

    /// @dev Static-calls `target` with `payload` and all the gas left, and returns the size and
    /// the first word of the answer, read through the scratch space; past the size, the word
    /// holds what the scratch space held.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc4337StaticCallWord(address target, bytes memory payload)
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

    /// @dev Reverts the current call with exactly `data`.
    /// @custom:solar-trusted
    function _erc4337RevertRaw(bytes memory data) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(data, 0x20), mload(data))
        }
    }

    /// @dev Halts with the designated invalid instruction, which consumes all the gas left, as
    /// running out of gas does. Solidity cannot spell it: its failures revert.
    /// @custom:solar-trusted
    function _erc4337Invalid() private pure {
        /// @solidity memory-safe-assembly
        assembly {
            invalid()
        }
    }

    /// @dev Reverts the current call with the return data of the last call, which Solidity
    /// cannot read without copying it on success too.
    /// @custom:solar-trusted
    function _erc4337RevertReturndata() private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            returndatacopy(m, 0x00, returndatasize())
            revert(m, returndatasize())
        }
    }
}
