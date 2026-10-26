// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {ERC20} from "./ERC20.sol";

/// @notice ERC20 with votes based on ERC5805 and ERC6372.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/tokens/ERC20Votes.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC20Votes.sol)
///
/// @dev This assembly-free port uses Solidity mappings for delegates and checkpoints.
/// It is intended for new deployments and is not storage-compatible with upstream.
/// Checkpoint words still pack the key, a 48-bit length (the first checkpoint's is current),
/// and a value of up to 160 bits that is not this contract's address. Other values use a
/// separate entry at the complemented checkpoint index. Delegates and total supply have
/// disjoint namespaces. The pushes and lookups keep the checks, custom errors and search
/// probes, the events are ordinary emits, and the signer is recovered by a plain
/// low-level call to the precompile, read as the assembly reads it. Where the assembly runs
/// out of gas or hits `invalid()`, on a block number from `2 ** 48` and on a checkpoint key
/// that goes back or a length past 48 bits, this port reverts with the same empty data. The
/// private helpers carry the contract's name, so that it still combines with other mixins.
/// @custom:solar-safe memory arithmetic
abstract contract ERC20Votes is ERC20 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The timepoint is in the future.
    error ERC5805FutureLookup();

    /// @dev The ERC5805 signature to set a delegate has expired.
    error ERC5805DelegateSignatureExpired();

    /// @dev The ERC5805 signature to set a delegate is invalid.
    error ERC5805DelegateInvalidSignature();

    /// @dev Out-of-bounds access for the checkpoints.
    error ERC5805CheckpointIndexOutOfBounds();

    /// @dev Arithmetic overflow when pushing a new checkpoint.
    error ERC5805CheckpointValueOverflow();

    /// @dev Arithmetic underflow when pushing a new checkpoint.
    error ERC5805CheckpointValueUnderflow();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The delegate of `delegator` is changed from `from` to `to`.
    event DelegateChanged(address indexed delegator, address indexed from, address indexed to);

    /// @dev The votes balance of `delegate` is changed from `oldValue` to `newValue`.
    event DelegateVotesChanged(address indexed delegate, uint256 oldValue, uint256 newValue);

    /// @dev `keccak256(bytes("DelegateChanged(address,address,address)"))`.
    uint256 private constant _DELEGATE_CHANGED_EVENT_SIGNATURE =
        0x3134e8a2e6d97e929a7e54011ea5485d7d196dd5f0ba4d4ef95803e8e3fc257f;

    /// @dev `keccak256(bytes("DelegateVotesChanged(address,uint256,uint256)"))`.
    uint256 private constant _DELEGATE_VOTES_CHANGED_EVENT_SIGNATURE =
        0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    bytes32 private constant _DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev `keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)")`.
    bytes32 private constant _ERC5805_DELEGATION_TYPEHASH =
        0xe48329057bfd03d55e49b547132e39cffd9c1820ad7b9d4c5307691425d15adf;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    mapping(address => uint256) private _erc20VotesDelegates;
    mapping(uint256 => mapping(uint256 => uint256)) private _erc20VotesCheckpoints;

    // Outside the address domain, including the zero address.
    uint256 private constant _ERC20_VOTES_TOTAL = 1 << 160;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERC6372                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the clock mode.
    function CLOCK_MODE() public view virtual returns (string memory) {
        return "mode=blocknumber&from=default";
    }

    /// @dev Returns the current clock.
    function clock() public view virtual returns (uint48 result) {
        // Revert with no data, as the assembly's out-of-gas revert, if `block.number >= 2 ** 48`.
        if (block.number >> 48 != 0) revert();
        result = uint48(block.number);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERC5805                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the latest amount of voting units for `account`.
    function getVotes(address account) public view virtual returns (uint256) {
        return _checkpointLatest(_erc20VotesCheckpoints[uint160(account)]);
    }

    /// @dev Returns the latest amount of voting units `account` has before or during `timepoint`.
    function getPastVotes(address account, uint256 timepoint)
        public
        view
        virtual
        returns (uint256)
    {
        if (timepoint >= clock()) _revertERC5805FutureLookup();
        return _checkpointUpperLookupRecent(_erc20VotesCheckpoints[uint160(account)], timepoint);
    }

    /// @dev Returns the current voting delegate of `delegator`.
    function delegates(address delegator) public view virtual returns (address result) {
        result = address(uint160(_erc20VotesDelegates[delegator]));
    }

    /// @dev Set the voting delegate of the caller to `delegatee`.
    function delegate(address delegatee) public virtual {
        _delegate(msg.sender, delegatee);
    }

    /// @dev Sets the voting delegate of the signature signer to `delegatee`.
    function delegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        address signer;
        bytes32 nameHash = _constantNameHash();
        //  We simply calculate it on-the-fly to allow for cases where the `name` may change.
        if (nameHash == bytes32(0)) nameHash = keccak256(bytes(name()));
        bytes32 versionHash = _versionHash();
        if (block.timestamp > expiry) revert ERC5805DelegateSignatureExpired();
        bytes32 digest;
        {
            // Prepare the struct hash.
            bytes32 structHash =
                keccak256(abi.encode(_ERC5805_DELEGATION_TYPEHASH, delegatee, nonce, expiry));
            // Prepare the domain separator.
            bytes32 domainSeparator = keccak256(
                abi.encode(_DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(this))
            );
            digest = keccak256(abi.encodePacked(hex"1901", domainSeparator, structHash));
        }
        bool failed;
        (signer, failed) = _erc20VotesRecover(digest, v, r, s);
        if (nonces(signer) != nonce || failed) revert ERC5805DelegateInvalidSignature();
        _incrementNonce(signer);
        _delegate(signer, delegatee);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              OTHER VOTE PUBLIC VIEW FUNCTIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the number of checkpoints for `account`.
    function checkpointCount(address account) public view virtual returns (uint256 result) {
        result = uint48(_erc20VotesCheckpoints[uint160(account)][0] >> 48);
    }

    /// @dev Returns the voting checkpoint for `account` at index `i`.
    function checkpointAt(address account, uint256 i)
        public
        view
        virtual
        returns (uint48 checkpointClock, uint256 checkpointValue)
    {
        mapping(uint256 => uint256) storage checkpoints = _erc20VotesCheckpoints[uint160(account)];
        uint256 lengthSlotPacked = checkpoints[0];
        if (i >= uint48(lengthSlotPacked >> 48)) revert ERC5805CheckpointIndexOutOfBounds();
        uint256 checkpointPacked = i == 0 ? lengthSlotPacked : checkpoints[i];
        checkpointClock = uint48(checkpointPacked);
        checkpointValue = _erc20VotesCheckpointValue(checkpoints, i, checkpointPacked);
    }

    /// @dev Returns the latest amount of total voting units.
    function getVotesTotalSupply() public view virtual returns (uint256) {
        return _checkpointLatest(_erc20VotesCheckpoints[_ERC20_VOTES_TOTAL]);
    }

    /// @dev Returns the latest amount of total voting units before or during `timepoint`.
    function getPastVotesTotalSupply(uint256 timepoint) public view virtual returns (uint256) {
        if (timepoint >= clock()) _revertERC5805FutureLookup();
        return _checkpointUpperLookupRecent(_erc20VotesCheckpoints[_ERC20_VOTES_TOTAL], timepoint);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the amount of voting units `delegator` has control over.
    /// Override if you need a different formula.
    function _getVotingUnits(address delegator) internal view virtual returns (uint256) {
        return balanceOf(delegator);
    }

    /// @dev ERC20 after token transfer internal hook.
    function _afterTokenTransfer(address from, address to, uint256 amount)
        internal
        virtual
        override
    {
        _transferVotingUnits(from, to, amount);
    }

    /// @dev Used in `_afterTokenTransfer(address from, address to, uint256 amount)`.
    function _transferVotingUnits(address from, address to, uint256 amount) internal virtual {
        if (from == address(0)) {
            _checkpointPushDiff(_erc20VotesCheckpoints[_ERC20_VOTES_TOTAL], clock(), amount, true);
        }
        if (to == address(0)) {
            _checkpointPushDiff(_erc20VotesCheckpoints[_ERC20_VOTES_TOTAL], clock(), amount, false);
        }
        _moveDelegateVotes(delegates(from), delegates(to), amount);
    }

    /// @dev Transfer `amount` of delegated votes from `from` to `to`.
    /// Emits a {DelegateVotesChanged} event for each change of delegated votes.
    function _moveDelegateVotes(address from, address to, uint256 amount) internal virtual {
        if (amount == uint256(0)) return;
        (uint256 fromCleaned, uint256 toCleaned) = (uint256(uint160(from)), uint256(uint160(to)));
        if (fromCleaned == toCleaned) return;
        if (fromCleaned != 0) {
            (uint256 oldValue, uint256 newValue) =
                _checkpointPushDiff(_erc20VotesCheckpoints[uint160(from)], clock(), amount, false);
            // Emit the {DelegateVotesChanged} event.
            emit DelegateVotesChanged(from, oldValue, newValue);
        }
        if (toCleaned != 0) {
            (uint256 oldValue, uint256 newValue) =
                _checkpointPushDiff(_erc20VotesCheckpoints[uint160(to)], clock(), amount, true);
            // Emit the {DelegateVotesChanged} event.
            emit DelegateVotesChanged(to, oldValue, newValue);
        }
    }

    /// @dev Delegates all of `account`'s voting units to `delegatee`.
    /// Emits the {DelegateChanged} and {DelegateVotesChanged} events.
    function _delegate(address account, address delegatee) internal virtual {
        address from = address(uint160(_erc20VotesDelegates[account]));
        _erc20VotesDelegates[account] = uint160(delegatee);
        // Emit the {DelegateChanged} event.
        emit DelegateChanged(account, from, delegatee);
        _moveDelegateVotes(from, delegatee, _getVotingUnits(account));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Pushes a checkpoint.
    function _checkpointPushDiff(
        mapping(uint256 => uint256) storage checkpoints,
        uint256 key,
        uint256 amount,
        bool isAdd
    ) private returns (uint256 oldValue, uint256 newValue) {
        uint256 lengthSlotPacked = checkpoints[0];
        uint256 n = uint48(lengthSlotPacked >> 48);
        if (n == 0) {
            if (!isAdd && amount != 0) revert ERC5805CheckpointValueUnderflow();
            newValue = amount;
            _erc20VotesStoreCheckpoint(checkpoints, 0, key | 1 << 48, newValue);
            return (oldValue, newValue);
        }
        uint256 index = n - 1;
        uint256 lastPacked = index == 0 ? lengthSlotPacked : checkpoints[index];
        oldValue = _erc20VotesCheckpointValue(checkpoints, index, lastPacked);
        if (!isAdd) {
            if (amount > oldValue) revert ERC5805CheckpointValueUnderflow();
            newValue = oldValue - amount;
        } else {
            if (amount > type(uint256).max - oldValue) revert ERC5805CheckpointValueOverflow();
            newValue = oldValue + amount;
        }
        uint256 lastKey = uint48(lastPacked);
        if (lastKey != key) {
            n = n + 1;
            ++index;
            checkpoints[0] = lengthSlotPacked + (1 << 48);
        }
        // Revert with no data, as the assembly's `invalid()`, if the key goes back or the
        // length overflows.
        if (lastKey > key || n >> 48 != 0) revert();
        _erc20VotesStoreCheckpoint(checkpoints, index, key | n << 48, newValue);
    }

    /// @dev Returns the latest value in the checkpoints.
    function _checkpointLatest(mapping(uint256 => uint256) storage checkpoints)
        private
        view
        returns (uint256 result)
    {
        uint256 first = checkpoints[0];
        uint256 n = uint48(first >> 48);
        if (n != 0) {
            result =
                _erc20VotesCheckpointValue(checkpoints, n - 1, n == 1 ? first : checkpoints[n - 1]);
        }
    }

    /// @dev Returns checkpoint value with the largest key that is less than or equal to `key`.
    function _checkpointUpperLookupRecent(
        mapping(uint256 => uint256) storage checkpoints,
        uint256 key
    ) private view returns (uint256 result) {
        uint256 l; // Low.
        uint256 h = uint48(checkpoints[0] >> 48); // High.
        // Start the binary search nearer to the right to optimize for recent checkpoints.
        if (h >= 6) {
            // The assembly's first guess: `16 << 4k` for the `k` from 0 to 3 that suits `h`.
            uint256 m = h > 0xffffff ? 0x10000 : h > 0xffff ? 0x1000 : h > 0xff ? 0x100 : 0x10;
            m = (m + h / m) >> 1;
            m = (m + h / m) >> 1;
            m = (m + h / m) >> 1;
            m = (m + h / m) >> 1;
            m = (m + h / m) >> 1;
            m = h - ((m + h / m) >> 1); // Approx `h - sqrt(h)`.
            if (key >= uint48(checkpoints[m])) l = m + 1;
            else h = m;
        }
        // Binary search.
        while (l < h) {
            uint256 m = (l + h) >> 1; // Won't overflow in practice.
            if (key >= uint48(checkpoints[m])) l = m + 1;
            else h = m;
        }
        if (h != 0) {
            result = _erc20VotesCheckpointValue(checkpoints, h - 1, checkpoints[h - 1]);
        }
    }

    /// @dev Reverts with `ERC5805FutureLookup()`.
    /// @custom:solar-terminates
    function _revertERC5805FutureLookup() private pure {
        revert ERC5805FutureLookup();
    }

    /// @dev The signer of `digest` by the ecrecover precompile, and whether it gave no answer.
    function _erc20VotesRecover(bytes32 digest, uint8 v, bytes32 r, bytes32 s)
        private
        view
        returns (address signer, bool failed)
    {
        (bool success, bytes memory recovered) = address(1).staticcall(abi.encode(digest, v, r, s));
        // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise. Without an
        // answer, the signer is the word the assembly reads instead: its call's input from
        // byte 1, or the digest if the call itself failed.
        failed = recovered.length == 0;
        uint256 signerWord = uint256(digest);
        // The precompile returns exactly one ABI word on success.
        if (!failed) signerWord = abi.decode(recovered, (uint256));
        else if (success) signerWord <<= 8;
        signer = address(uint160(signerWord));
    }

    /// @dev The value of the checkpoint at `index`, whose word is `packed`: its top
    /// 160 bits, unless they are this contract's address, which stands for the value kept
    /// whole at the complemented index.
    /// @custom:solar-inline
    function _erc20VotesCheckpointValue(
        mapping(uint256 => uint256) storage checkpoints,
        uint256 index,
        uint256 packed
    ) private view returns (uint256 value) {
        value = packed >> 96;
        if (value == uint160(address(this))) value = checkpoints[~index];
    }

    /// @dev Stores the checkpoint `keyAndLength` with `value` at `index`: the value in
    /// the top 160 bits if it fits there and is not this contract's address, else the address
    /// there and the value at the complemented index.
    function _erc20VotesStoreCheckpoint(
        mapping(uint256 => uint256) storage checkpoints,
        uint256 index,
        uint256 keyAndLength,
        uint256 value
    ) private {
        if (value == uint160(address(this)) || value >> 160 != 0) {
            checkpoints[index] = keyAndLength | uint256(uint160(address(this))) << 96;
            checkpoints[~index] = value;
        } else {
            checkpoints[index] = keyAndLength | value << 96;
        }
    }
}
