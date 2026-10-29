// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import {Receiver} from "./Receiver.sol";
import {ERC1271} from "./ERC1271.sol";
import {LibZip} from "../utils/LibZip.sol";
import {UUPSUpgradeable} from "../utils/UUPSUpgradeable.sol";

/// @notice Simple ERC6551 account implementation.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC6551.sol)
/// @author ERC6551 team (https://github.com/erc6551/reference/blob/main/src/examples/upgradeable/ERC6551AccountUpgradeable.sol)
///
/// @dev Recommended usage (regular):
/// 1. Deploy the ERC6551 as an implementation contract, and verify it on Etherscan.
/// 2. Use the canonical ERC6551Registry to deploy a clone to the ERC6551 implementation.
///    The UUPSUpgradeable functions will be disabled.
///
/// Recommended usage (upgradeable):
/// 1. Deploy the ERC6551 as an implementation contract, and verify it on Etherscan.
/// 2. Deploy the ERC6551Proxy pointing to the implementation.
///    This relay proxy is required, but Etherscan verification of it is optional.
/// 3. Use the canonical ERC6551Registry to deploy a clone to the ERC6551Proxy.
///    If you want to reveal the "Read as Proxy" and "Write as Proxy" tabs on Etherscan,
///    send 0 ETH to the clone to initialize its ERC1967 implementation slot,
///    the click on "Is this a proxy?" on the clone's page on Etherscan.
///
/// Note:
/// - This implementation does NOT include ERC4337 functionality.
///   This is intentional, because the canonical ERC4337 entry point may still change and we
///   don't want to encourage upgradeability by default for ERC6551 accounts just to handle this.
///   We may include ERC4337 functionality once ERC4337 has been finalized.
///   Recent updates to the account abstraction validation scope rules
///   [ERC7562](https://eips.ethereum.org/EIPS/eip-7562) has made ERC6551 compatible with ERC4337.
///   For an opinionated implementation, see https://github.com/tokenbound/contracts.
///   If you want to add it yourself, you'll just need to add in the
///   user operation validation functionality (and use ERC6551's execution functionality).
/// - Please refer to the official [ERC6551](https://github.com/erc6551/reference) reference
///   for latest updates on the ERC6551 standard, as well as canonical registry information.
///
/// The checked port reads the account's footer, the chain ID, token contract and token ID words
/// at the end of its code, with the trusted `_erc6551CodeCopyInto`, which copies the bytes into a
/// buffer it checks they fit, and the implementation word with the trusted `_erc6551CodeWord`,
/// both with zeros past the end of the code as the assembly reads them. It asks token contracts
/// with trusted static calls that copy at most the words the assembly reads of an answer:
/// `_erc6551StaticCallWord` through the scratch space, `_erc6551StaticCallInto` into a buffer.
/// Calls are Solidity's `call`, with a revert bubbled up by the trusted `_erc6551RevertRaw`.
/// `executeBatch` reads the calls as the assembly does, following their offsets with
/// wrap-around additions, reading `target` as the word it is stored as, and reading past the
/// calldata as zeros, where Solidity's accessors would check the calls lie in calldata: trusted
/// helpers read the array's calldata offset and make each call's data a slice wherever it lies,
/// which Solidity cannot, and a data length no gas could copy halts with a trusted `invalid()`,
/// as the copy would run out of gas. Trusted helpers also read and write the state slot, which
/// Solidity cannot name, and answer a token callback with `msg.sig` as the call's whole return
/// data, which a fallback cannot return in Solidity.
/// @custom:solar-safe memory arithmetic
abstract contract ERC6551 is UUPSUpgradeable, Receiver, ERC1271 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Call struct for the `executeBatch` function.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The caller is not authorized to call the function.
    error Unauthorized();

    /// @dev The operation is not supported.
    error OperationNotSupported();

    /// @dev Self ownership detected.
    error SelfOwnDetected();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The ERC6551 state slot is given by:
    /// `bytes32(~uint256(uint32(bytes4(keccak256("_ERC6551_STATE_SLOT_NOT")))))`.
    /// It is intentionally chosen to be a high value
    /// to avoid collision with lower slots.
    /// The choice of manual storage layout is to enable compatibility
    /// with both regular and upgradeable contracts.
    uint256 internal constant _ERC6551_STATE_SLOT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffb919c7a5;

    /// @dev Caches the chain ID in the deployed bytecode,
    /// so that in the rare case of a hard fork, `owner` will still work.
    uint256 private immutable _cachedChainId = block.chainid;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              TOKEN-BOUND OWNERSHIP OPERATIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the token-bound information.
    function token()
        public
        view
        virtual
        returns (uint256 chainId, address tokenContract, uint256 tokenId)
    {
        uint256 tokenContractWord;
        (chainId, tokenContractWord, tokenId) = _erc6551Footer();
        tokenContract = address(uint160(tokenContractWord)); // Upper 96 bits will be clean.
    }

    /// @dev Returns the owner of the contract.
    /// @custom:solar-inline always
    function owner() public view virtual returns (address result) {
        uint256 cachedChainId = _cachedChainId;
        (uint256 chainId, uint256 tokenContract, uint256 tokenId) = _erc6551Footer();
        if (chainId == cachedChainId) {
            // Returns `address(0)` on failure or if contract does not exist.
            (bool answered, uint256 word) = _erc6551OwnerOf(tokenContract, tokenId);
            if (answered) result = address(uint160(word));
        }
    }

    /// @dev Returns if `signer` is an authorized signer.
    /// `extraData` can be anything (e.g. an address, a pointer to a struct / string in memory).
    /// @custom:solar-inline always
    function _isValidSigner(address signer, bytes32 extraData, bytes calldata context)
        internal
        view
        virtual
        returns (bool)
    {
        extraData = extraData; // Silence unused variable warning.
        context = context; // Silence unused variable warning.
        return signer == owner();
    }

    /// @dev Returns if `signer` is an authorized signer, with an optional `context`.
    /// MUST return the bytes4 magic value `0x523e3260` if the given signer is valid.
    /// By default, the holder of the non-fungible token the account is bound to
    /// MUST be considered a valid signer.
    function isValidSigner(address signer, bytes calldata context)
        public
        view
        virtual
        returns (bytes4 result)
    {
        bool isValid = _isValidSigner(signer, bytes32(0), context);
        // `isValid ? bytes4(keccak256("isValidSigner(address,bytes)")) : 0x00000000`.
        // We use `0x00000000` for invalid, in convention with the reference implementation.
        result = bytes4(uint32(isValid ? 0x523e3260 : 0));
    }

    /// @dev Returns empty calldata bytes.
    function _emptyContext() internal pure returns (bytes calldata context) {
        context = msg.data[:0];
    }

    /// @dev Requires that the caller is a valid signer (i.e. the owner).
    modifier onlyValidSigner() virtual {
        if (!_isValidSigner(msg.sender, bytes32(0), _emptyContext())) revert Unauthorized();
        _;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      STATE OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the current value of the state.
    function state() public view virtual returns (bytes32 result) {
        result = bytes32(_erc6551Sload(_ERC6551_STATE_SLOT));
    }

    /// @dev Mutates the state. This function is required to be called in every
    /// public / external function that may modify storage or emit events.
    /// @custom:solar-inline always
    function _updateState() internal virtual {
        uint256 s = _ERC6551_STATE_SLOT;
        _erc6551Sstore(s, uint256(keccak256(abi.encode(_erc6551Sload(s), msg.data))));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EXECUTION OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Execute a call from this account.
    /// Reverts and bubbles up error if operation fails.
    /// Returns the result of the operation.
    ///
    /// Accounts MUST accept the following operation parameter values:
    /// - 0 = CALL
    /// - 1 = DELEGATECALL
    /// - 2 = CREATE
    /// - 3 = CREATE2
    ///
    /// Accounts MAY support additional operations or restrict a signer's
    /// ability to execute certain operations.
    function execute(address target, uint256 value, bytes calldata data, uint8 operation)
        public
        payable
        virtual
        onlyValidSigner
        returns (bytes memory result)
    {
        if (operation != 0) revert OperationNotSupported();
        result = _erc6551Call(target, value, data);
        _updateState();
    }

    /// @dev Execute a sequence of calls from this account.
    /// Reverts and bubbles up error if an operation fails.
    /// Returns the results of the operations.
    ///
    /// This is a batch variant of `execute` and is not required for `IERC6551Executable`.
    function executeBatch(Call[] calldata calls, uint8 operation)
        public
        payable
        virtual
        onlyValidSigner
        returns (bytes[] memory results)
    {
        if (operation != 0) revert OperationNotSupported();
        // Each call is `(target, value, data)` at the offset its head word gives from `calls`,
        // read as the assembly reads it, following the offsets unchecked.
        uint256 offset = _erc6551CalldataOffset(calls);
        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            uint256 e = _erc6551Add(offset, uint256(_erc6551CalldataWord(offset + (i << 5))));
            uint256 o = _erc6551Add(e, uint256(_erc6551CalldataWord(_erc6551Add(e, 0x40))));
            uint256 length = uint256(_erc6551CalldataWord(o));
            // A length no gas could copy halts, as the copy would.
            if (length >> 63 != 0) _erc6551Invalid();
            results[i] = _erc6551Call(
                address(uint160(uint256(_erc6551CalldataWord(e)))),
                uint256(_erc6551CalldataWord(_erc6551Add(e, 0x20))),
                _erc6551CalldataSlice(_erc6551Add(o, 0x20), length)
            );
        }
        _updateState();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERC165                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns true if this contract implements the interface defined by `interfaceId`.
    /// See: https://eips.ethereum.org/EIPS/eip-165
    /// This function call must use less than 30000 gas.
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool result) {
        uint256 s = uint32(interfaceId);
        // ERC165: 0x01ffc9a7, ERC6551: 0x6faff5f1, ERC6551Executable: 0x51945447.
        result = s == 0x01ffc9a7 || s == 0x6faff5f1 || s == 0x51945447;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL HELPERS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether there is an ownership cycle.
    /// @custom:solar-inline always
    function _hasOwnershipCycle() internal view virtual returns (bool result) {
        uint256 cachedChainId = _cachedChainId;
        (uint256 chainId, uint256 tokenContract, uint256 tokenId) = _erc6551Footer();
        bytes memory tokenCall = abi.encodeWithSelector(0xfc0c546a);
        bytes memory tokenAnswer = new bytes(0x60);
        while (true) {
            // `chainId == cachedChainId ? tokenContract.ownerOf(tokenId) : address(0)`, where
            // the call is made either way.
            (bool answered, uint256 currentOwner) = _erc6551OwnerOf(tokenContract, tokenId);
            if (!answered || chainId != cachedChainId) currentOwner = 0;
            if (currentOwner == uint256(uint160(address(this)))) return true;
            // `(chainId, tokenContract, tokenId) = currentOwner.token()`.
            (bool success, uint256 answerSize) =
                _erc6551StaticCallInto(address(uint160(currentOwner)), tokenCall, tokenAnswer);
            if (!success || answerSize < 0x60) return false;
            (chainId, tokenContract, tokenId) = abi.decode(tokenAnswer, (uint256, uint256, uint256));
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OVERRIDES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev To ensure that only the owner or the account itself can upgrade the implementation.
    /// If you don't need upgradeability, override this function to return false for extra safety.
    function _authorizeUpgrade(address)
        internal
        virtual
        override(UUPSUpgradeable)
        onlyValidSigner
        onlyViaERC6551Proxy
    {
        _updateState();
    }

    /// @dev Guards `_authorizeUpgrade` such that it must be used via an ERC6551Proxy.
    modifier onlyViaERC6551Proxy() virtual {
        address selfImplementation = _selfImplementation();
        // Revert if the implementation is the same as the self implementation.
        if (address(bytes20(_erc6551CodeWord(0x0a))) == selfImplementation) {
            revert UnauthorizedCallContext();
        }
        _;
    }

    /// @dev Uses the `owner` as the ERC1271 signer.
    function _erc1271Signer() internal view virtual override(ERC1271) returns (address) {
        return owner();
    }

    /// @dev For handling token callbacks.
    /// Safe-transferred ERC721 tokens will trigger an ownership cycle check.
    modifier receiverFallback() override(Receiver) {
        uint256 s = uint256(bytes32(msg.sig)) >> 224;
        // 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
        if (s == 0x150b7a02) {
            if (!_hasOwnershipCycle()) _erc6551ReturnWord(bytes32(msg.sig)); // Return `msg.sig`.
            revert SelfOwnDetected();
        }
        // 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
        // 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
        if (s == 0xf23a6e61 || s == 0xbc197c81) {
            _erc6551ReturnWord(bytes32(msg.sig)); // Return `msg.sig`.
        }
        _;
    }

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

    /// @dev The chain ID, token contract and token ID words at the end of the account's code.
    function _erc6551Footer()
        private
        view
        returns (uint256 chainId, uint256 tokenContract, uint256 tokenId)
    {
        bytes memory footer = new bytes(0x60);
        _erc6551CodeCopyInto(footer, 0, address(this), 0x4d, 0x60);
        return abi.decode(footer, (uint256, uint256, uint256));
    }

    /// @dev Calls `target` with `data` and `value`, and returns its return data.
    /// Reverts and bubbles up error if the call fails.
    /// @custom:solar-inline always
    function _erc6551Call(address target, uint256 value, bytes calldata data)
        private
        returns (bytes memory result)
    {
        bool success;
        (success, result) = target.call{value: value}(data);
        if (!success) _erc6551RevertRaw(result);
    }

    /// @dev `tokenContract.ownerOf(tokenId)`: whether the call succeeded with a word at least,
    /// and its first word.
    function _erc6551OwnerOf(uint256 tokenContract, uint256 tokenId)
        private
        view
        returns (bool answered, uint256 word)
    {
        // `ownerOf(uint256)`.
        (bool success, uint256 answerSize, bytes32 first) = _erc6551StaticCallWord(
            address(uint160(tokenContract)), abi.encodeWithSelector(0x6352211e, tokenId)
        );
        if (success && answerSize > 0x1f) return (true, uint256(first));
    }

    /// @dev The word of calldata at `offset`, zero-padded past the end of the calldata, as
    /// `CALLDATALOAD` reads it.
    /// @custom:solar-inline always
    function _erc6551CalldataWord(uint256 offset) private pure returns (bytes32) {
        return bytes32(_erc6551CalldataSlice(offset, 0x20));
    }

    /// @dev `a + b` modulo `2**256`, as the assembly adds calldata offsets. Solidity's
    /// addition reverts where this wraps around.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc6551Add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev The word in storage slot `slot`. Solidity cannot name a slot it did not allocate.
    /// @custom:solar-trusted
    function _erc6551Sload(uint256 slot) private view returns (uint256 value) {
        /// @solidity memory-safe-assembly
        assembly {
            value := sload(slot)
        }
    }

    /// @dev Stores `value` in storage slot `slot`.
    /// @custom:solar-trusted
    function _erc6551Sstore(uint256 slot, uint256 value) private {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, value)
        }
    }

    /// @dev Copies `count` bytes of `target`'s code from `start` into `dst` at `dstOffset`, with
    /// zeros for the bytes past the end of the code. Solidity can only copy a whole account's code.
    /// @custom:solar-trusted
    function _erc6551CodeCopyInto(
        bytes memory dst,
        uint256 dstOffset,
        address target,
        uint256 start,
        uint256 count
    ) private view {
        if (count > dst.length || dstOffset > dst.length - count) {
            count = _erc6551OutOfBounds();
        }
        /// @solidity memory-safe-assembly
        assembly {
            extcodecopy(target, add(add(dst, 0x20), dstOffset), start, count)
        }
    }

    /// @dev The 32 bytes of the account's code from `start`, with zeros past the end of the code,
    /// read through the scratch space. Solidity can only copy a whole account's code.
    /// @custom:solar-trusted
    function _erc6551CodeWord(uint256 start) private view returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            extcodecopy(address(), 0x00, start, 0x20)
            result := mload(0x00)
        }
    }

    /// @dev Static-calls `target` with `payload` and all the gas left, and copies at most
    /// `out.length` bytes of the answer into `out`. `totalSize` is how many bytes there were.
    /// @custom:solar-trusted
    function _erc6551StaticCallInto(address target, bytes memory payload, bytes memory out)
        private
        view
        returns (bool success, uint256 totalSize)
    {
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(
                gas(),
                target,
                add(payload, 0x20),
                mload(payload),
                add(out, 0x20),
                mload(out)
            )
            totalSize := returndatasize()
        }
    }

    /// @dev Static-calls `target` with `payload` and all the gas left, and returns the size and
    /// the first word of the answer, read through the scratch space; past the size, the word
    /// holds what the scratch space held.
    /// @custom:solar-trusted
    function _erc6551StaticCallWord(address target, bytes memory payload)
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

    /// @dev The calldata offset of `calls`. Solidity cannot read a calldata array's offset.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc6551CalldataOffset(Call[] calldata calls) private pure returns (uint256 offset) {
        /// @solidity memory-safe-assembly
        assembly {
            offset := calls.offset
        }
    }

    /// @dev The calldata slice of `length` bytes at `offset`, which may lie past the end of
    /// the calldata, where reads give zeros. Solidity slices only within `msg.data`.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc6551CalldataSlice(uint256 offset, uint256 length)
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

    /// @dev Reverts the current call with exactly `data`.
    /// @custom:solar-trusted
    function _erc6551RevertRaw(bytes memory data) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(data, 0x20), mload(data))
        }
    }

    /// @dev Ends the call, returning `word` as its whole return data. Solidity returns data only
    /// from a function that declares it.
    /// @custom:solar-trusted
    function _erc6551ReturnWord(bytes32 word) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, word)
            return(0x00, 0x20)
        }
    }

    /// @dev Halts with the designated invalid instruction, which consumes all the gas left, as
    /// running out of gas does. Solidity cannot spell it: its failures revert.
    /// @custom:solar-trusted
    function _erc6551Invalid() private pure {
        /// @solidity memory-safe-assembly
        assembly {
            invalid()
        }
    }

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the
    /// portable spelling of a failed range check.
    function _erc6551OutOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }
}
