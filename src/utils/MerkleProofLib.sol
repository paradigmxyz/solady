// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Gas optimized verification of proof of inclusion for a leaf in a Merkle tree.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/MerkleProofLib.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/MerkleProofLib.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/MerkleProof.sol)
/// @dev The checked port folds a proof one sibling at a time, hashing the smaller word of each
/// pair first, as the assembly orders the two words in scratch space. A multiproof rebuilds
/// the root through a queue that starts with the leaves and grows by one hash per flag; each
/// hash takes its second input from the queue or from the proof, as its flag says. The
/// assembly reads its queue and its proof without bounds, and its final check that every
/// proof element was used turns any read past either into `false`. The port returns `false`
/// as soon as a read would pass the written queue or the proof, which gives the same result
/// without reading memory nothing wrote. The queue is a new array, where the assembly uses
/// free memory without reserving it. A calldata flag is read as a word, so any nonzero word
/// counts as true, as in the assembly: Solidity reads a calldata `bool` only after checking
/// it, so the trusted `_flagWords` views the flags as words. `emptyProof`, `emptyLeaves` and
/// `emptyFlags` stay trusted assembly, since no Solidity expression is an empty calldata
/// array.
/// @custom:solar-safe memory arithmetic
library MerkleProofLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*            MERKLE PROOF VERIFICATION OPERATIONS            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether `leaf` exists in the Merkle tree with `root`, given `proof`.
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool isValid)
    {
        for (uint256 i; i < proof.length; ++i) {
            bytes32 a = leaf;
            bytes32 b = proof[i];
            if (a > b) (a, b) = (b, a);
            leaf = keccak256(abi.encode(a, b));
        }
        return leaf == root;
    }

    /// @dev Returns whether `leaf` exists in the Merkle tree with `root`, given `proof`.
    function verifyCalldata(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal
        pure
        returns (bool isValid)
    {
        for (uint256 i; i < proof.length; ++i) {
            bytes32 a = leaf;
            bytes32 b = proof[i];
            if (a > b) (a, b) = (b, a);
            leaf = keccak256(abi.encode(a, b));
        }
        return leaf == root;
    }

    /// @dev Returns whether all `leaves` exist in the Merkle tree with `root`,
    /// given `proof` and `flags`.
    ///
    /// Note:
    /// - Breaking the invariant `flags.length == (leaves.length - 1) + proof.length`
    ///   will always return false.
    /// - The sum of the lengths of `proof` and `leaves` must never overflow.
    /// - Any non-zero word in the `flags` array is treated as true.
    /// - The memory offset of `proof` must be non-zero
    ///   (i.e. `proof` is not pointing to the scratch space).
    function verifyMultiProof(
        bytes32[] memory proof,
        bytes32 root,
        bytes32[] memory leaves,
        bool[] memory flags
    ) internal pure returns (bool isValid) {
        if (leaves.length + proof.length != flags.length + 1) return false;
        if (flags.length == 0) return (proof.length == 1 ? proof[0] : leaves[0]) == root;
        bytes32[] memory hashes = new bytes32[](leaves.length + flags.length);
        for (uint256 i; i < leaves.length; ++i) {
            hashes[i] = leaves[i];
        }
        (bool complete, bytes32 computed) = _rebuild(hashes, leaves.length, proof, flags);
        return complete && computed == root;
    }

    /// @dev Returns whether all `leaves` exist in the Merkle tree with `root`,
    /// given `proof` and `flags`.
    ///
    /// Note:
    /// - Breaking the invariant `flags.length == (leaves.length - 1) + proof.length`
    ///   will always return false.
    /// - Any non-zero word in the `flags` array is treated as true.
    /// - The calldata offset of `proof` must be non-zero
    ///   (i.e. `proof` is from a regular Solidity function with a 4-byte selector).
    function verifyMultiProofCalldata(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32[] calldata leaves,
        bool[] calldata flags
    ) internal pure returns (bool isValid) {
        if (leaves.length + proof.length != flags.length + 1) return false;
        if (flags.length == 0) return (proof.length == 1 ? proof[0] : leaves[0]) == root;
        bytes32[] memory hashes = new bytes32[](leaves.length + flags.length);
        for (uint256 i; i < leaves.length; ++i) {
            hashes[i] = leaves[i];
        }
        (bool complete, bytes32 computed) =
            _rebuildCalldata(hashes, leaves.length, proof, _flagWords(flags));
        return complete && computed == root;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EMPTY CALLDATA HELPERS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an empty calldata bytes32 array.
    /// Solidity cannot spell a calldata array of its own, so this keeps the
    /// upstream assembly.
    /// @custom:solar-trusted
    function emptyProof() internal pure returns (bytes32[] calldata proof) {
        /// @solidity memory-safe-assembly
        assembly {
            proof.length := 0
        }
    }

    /// @dev Returns an empty calldata bytes32 array.
    /// @custom:solar-trusted
    function emptyLeaves() internal pure returns (bytes32[] calldata leaves) {
        /// @solidity memory-safe-assembly
        assembly {
            leaves.length := 0
        }
    }

    /// @dev Returns an empty calldata bool array.
    /// @custom:solar-trusted
    function emptyFlags() internal pure returns (bool[] calldata flags) {
        /// @solidity memory-safe-assembly
        assembly {
            flags.length := 0
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Runs the queue whose first `back` entries `hashes` holds, one hash
    /// per flag, and returns the last hash and whether every read stayed in the
    /// written queue and the proof, and every proof element was used. `hashes`
    /// has room for every hash the flags make, so `back` never reaches its
    /// length; testing that first bounds every queue index the step reads.
    /// @custom:solar-inline always
    function _rebuild(
        bytes32[] memory hashes,
        uint256 back,
        bytes32[] memory proof,
        bool[] memory flags
    ) private pure returns (bool complete, bytes32 computed) {
        uint256 front;
        uint256 used;
        for (uint256 i; i < flags.length; ++i) {
            // Each index is checked before it steps, so the step cannot wrap.
            if (back >= hashes.length || front >= back) return (false, 0);
            bytes32 a = hashes[front];
            ++front;
            bytes32 b;
            if (flags[i]) {
                if (front >= back) return (false, 0);
                b = hashes[front];
                ++front;
            } else {
                if (used >= proof.length) return (false, 0);
                b = proof[used];
                ++used;
            }
            if (a > b) (a, b) = (b, a);
            hashes[back] = keccak256(abi.encode(a, b));
            ++back;
        }
        return (used == proof.length, hashes[back - 1]);
    }

    /// @dev `_rebuild` for a proof and flags in calldata.
    /// @custom:solar-inline always
    function _rebuildCalldata(
        bytes32[] memory hashes,
        uint256 back,
        bytes32[] calldata proof,
        uint256[] calldata flags
    ) private pure returns (bool complete, bytes32 computed) {
        uint256 front;
        uint256 used;
        for (uint256 i; i < flags.length; ++i) {
            // Each index is checked before it steps, so the step cannot wrap.
            if (back >= hashes.length || front >= back) return (false, 0);
            bytes32 a = hashes[front];
            ++front;
            bytes32 b;
            if (flags[i] != 0) {
                if (front >= back) return (false, 0);
                b = hashes[front];
                ++front;
            } else {
                if (used >= proof.length) return (false, 0);
                b = proof[used];
                ++used;
            }
            if (a > b) (a, b) = (b, a);
            hashes[back] = keccak256(abi.encode(a, b));
            ++back;
        }
        return (used == proof.length, hashes[back - 1]);
    }

    /// @dev `flags` viewed as words, so a flag word other than zero or one counts as true,
    /// as in the assembly. Solidity reads a calldata `bool` only after checking it is clean.
    /// @custom:solar-trusted
    function _flagWords(bool[] calldata flags) private pure returns (uint256[] calldata words) {
        /// @solidity memory-safe-assembly
        assembly {
            words.offset := flags.offset
            words.length := flags.length
        }
    }
}
