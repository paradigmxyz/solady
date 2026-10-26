// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/SoladyTest.sol";
import {MerkleTreeLib} from "../src/utils/MerkleTreeLib.sol";
import {MerkleProofLib} from "../src/utils/MerkleProofLib.sol";
import {LibSort} from "../src/utils/LibSort.sol";
import {LibPRNG} from "../src/utils/LibPRNG.sol";
import {EfficientHashLib} from "../src/utils/EfficientHashLib.sol";

contract MerkleTreeLibTest is SoladyTest {
    using MerkleTreeLib for bytes32[];
    using LibPRNG for *;

    function testBuildCompleteMerkleTree(bytes32[] memory leaves, bytes32 r) public {
        _maybeBrutalizeMemory(r);
        if (leaves.length <= 1) {
            leaves = new bytes32[](1);
            leaves[0] = r;
        }
        bytes32[] memory t = MerkleTreeLib.build(leaves);
        assertEq(t.length, leaves.length * 2 - 1);
        if (leaves.length == 1) {
            assertEq(t[0], r);
        } else {
            assertNotEq(t[0], 0);
        }
        assertEq(t.root(), t[0]);
        assertEq(leaves.length, t.numLeaves());
        assertEq(t.length, t.numLeaves() + t.numInternalNodes());
        _checkMemory(t);
        if (leaves.length >= 1) {
            uint256 i = _randomUniform() % leaves.length;
            assertEq(t.leaf(i), leaves[i]);
        }
    }

    function testPad(bytes32[] memory leaves, bytes32 defaultFill, uint256 r) public {
        _maybeBrutalizeMemory(r);
        if (leaves.length == 0) return;
        assertEq(MerkleTreeLib.pad(leaves, defaultFill), _padOriginal(leaves, defaultFill));
        _checkMemory();
    }

    function _padOriginal(bytes32[] memory leaves, bytes32 defaultFill)
        internal
        pure
        returns (bytes32[] memory result)
    {
        unchecked {
            uint256 p = 1;
            while (p < leaves.length) p = p << 1;
            result = new bytes32[](p);
            for (uint256 i; i < p; ++i) {
                if (i < leaves.length) {
                    result[i] = leaves[i];
                } else {
                    result[i] = defaultFill;
                }
            }
        }
    }

    function _maybeBrutalizeMemory(uint256 r) internal view {
        _maybeBrutalizeMemory(bytes32(r));
    }

    function _maybeBrutalizeMemory(bytes32 r) internal view {
        uint256 h = uint256(EfficientHashLib.hash(r, "hehe"));
        if (h & 0xf0 == 0) _misalignFreeMemoryPointer();
        if (h & 0x0f == 0) _brutalizeMemory();
    }

    function testBuildAndGetLeaf(bytes32[] memory leaves, uint256 leafIndex) public {
        if (leaves.length == 0) return;

        if (leafIndex < leaves.length) {
            assertEq(this.buildAndGetLeaf(leaves, leafIndex), leaves[leafIndex]);
        } else {
            vm.expectRevert(MerkleTreeLib.MerkleTreeOutOfBoundsAccess.selector);
            this.buildAndGetLeaf(leaves, leafIndex);
        }
    }

    function buildAndGetLeaf(bytes32[] memory leaves, uint256 leafIndex)
        public
        pure
        returns (bytes32)
    {
        return MerkleTreeLib.build(leaves).leaf(leafIndex);
    }

    function _maybePad(bytes32[] memory leaves) internal returns (bytes32[] memory) {
        if (_randomChance(2)) {
            if (_randomChance(2)) {
                return leaves.pad();
            }
            return leaves.pad(bytes32(_random()));
        }
        return leaves;
    }

    function testBuildAndGetLeafProof(bytes32[] memory leaves, uint256 leafIndex) public {
        if (leaves.length == 0) return _testBuildAndGetRoot(leaves);
        leaves = _maybePad(leaves);
        bytes32[] memory t = MerkleTreeLib.build(leaves);
        if (leafIndex < leaves.length) {
            bytes32[] memory proof = this.buildAndGetLeafProof(leaves, leafIndex);
            assertTrue(MerkleProofLib.verify(proof, t.root(), leaves[leafIndex]));
        } else {
            vm.expectRevert(MerkleTreeLib.MerkleTreeOutOfBoundsAccess.selector);
            this.buildAndGetLeafProof(leaves, leafIndex);
        }
    }

    function buildAndGetLeafProof(bytes32[] memory leaves, uint256 leafIndex)
        public
        pure
        returns (bytes32[] memory proof)
    {
        bytes32[] memory t = MerkleTreeLib.build(leaves);
        proof = t.leafProof(leafIndex);
        _checkMemory();
    }

    function testBuildAndGetNodeProof(bytes32[] memory leaves, uint256 nodeIndex) public {
        if (leaves.length == 0) return _testBuildAndGetRoot(leaves);
        bytes32[] memory t = MerkleTreeLib.build(leaves);
        if (nodeIndex < t.length) {
            bytes32[] memory proof = this.buildAndGetNodeProof(leaves, nodeIndex);
            assertTrue(MerkleProofLib.verify(proof, t.root(), t[nodeIndex]));
        } else {
            vm.expectRevert(MerkleTreeLib.MerkleTreeOutOfBoundsAccess.selector);
            this.buildAndGetNodeProof(leaves, nodeIndex);
        }
    }

    function buildAndGetNodeProof(bytes32[] memory leaves, uint256 nodeIndex)
        public
        pure
        returns (bytes32[] memory proof)
    {
        bytes32[] memory t = MerkleTreeLib.build(leaves);
        proof = t.nodeProof(nodeIndex);
        _checkMemory();
    }

    function _testBuildAndGetRoot(bytes32[] memory leaves) internal {
        vm.expectRevert(MerkleTreeLib.MerkleTreeLeavesEmpty.selector);
        this.buildAndGetRoot(leaves);
    }

    function buildAndGetRoot(bytes32[] memory leaves) public pure returns (bytes32) {
        return MerkleTreeLib.build(leaves).root();
    }

    function testGetRootFromEmptyTree() public {
        vm.expectRevert(MerkleTreeLib.MerkleTreeOutOfBoundsAccess.selector);
        this.getRootFromEmptyTree();
    }

    function getRootFromEmptyTree() public pure returns (bytes32) {
        return (new bytes32[](0)).root();
    }

    struct TestMultiProofTemps {
        bytes32[] leaves;
        uint256[] leafIndices;
        bytes32[] gathered;
        bytes32[] tree;
        bytes32[] proof;
        bool[] flags;
    }

    function testBuildAndGetLeafsMultiProof(bytes32 r) public {
        _maybeBrutalizeMemory(r);
        TestMultiProofTemps memory t;
        t.leaves = new bytes32[](_bound(_random(), 1, 128));
        for (uint256 i; i < t.leaves.length; ++i) {
            t.leaves[i] = bytes32(_random());
        }
        t.leaves = _maybePad(t.leaves);
        t.leafIndices = _generateUniqueLeafIndices(t.leaves);
        t.tree = MerkleTreeLib.build(t.leaves);
        (t.proof, t.flags) = t.tree.multiProofForLeaves(t.leafIndices);
        t.gathered = t.tree.gatherLeaves(t.leafIndices);
        assertTrue(MerkleProofLib.verifyMultiProof(t.proof, t.tree.root(), t.gathered, t.flags));
    }

    function _generateUniqueLeafIndices(bytes32[] memory leaves)
        internal
        returns (uint256[] memory indices)
    {
        indices = new uint256[](leaves.length);
        for (uint256 i; i < leaves.length; ++i) {
            indices[i] = i;
        }
        LibPRNG.PRNG memory prng;
        prng.seed(_randomUniform());
        prng.shuffle(indices);
        uint256 n = _bound(_random(), 1, indices.length);
        /// @solidity memory-safe-assembly
        assembly {
            mstore(indices, n)
        }
        LibSort.sort(indices);
    }

    function testMultiProofRevertsForEmptyLeafs() public {
        vm.expectRevert(MerkleTreeLib.MerkleTreeInvalidLeafIndices.selector);
        this.multiProofRevertsForEmptyLeafs();
    }

    function multiProofRevertsForEmptyLeafs() public pure {
        (new bytes32[](1)).multiProofForLeaves(new uint256[](0));
    }

    function testMultiProofMatchesQueue(uint256 n, uint256 selected) public {
        n = 1 + n % 32;
        selected = (selected & ((uint256(1) << n) - 1)) | 1;
        bytes32[] memory leaves = new bytes32[](n);
        uint256 count;
        for (uint256 i; i < n; ++i) {
            leaves[i] = keccak256(abi.encode(i));
            if ((selected >> i) & 1 != 0) ++count;
        }
        uint256[] memory indices = new uint256[](count);
        uint256 pos;
        for (uint256 i; i < n; ++i) {
            if ((selected >> i) & 1 != 0) indices[pos++] = i;
        }
        bytes32[] memory t = MerkleTreeLib.build(leaves);
        bytes32 beforeHash = keccak256(abi.encode(t, indices));
        (bytes32[] memory proof, bool[] memory flags) = t.multiProofForLeaves(indices);
        (bytes32[] memory expectedProof, bool[] memory expectedFlags) = _referenceProof(t, indices);
        assertEq(abi.encode(proof, flags), abi.encode(expectedProof, expectedFlags));
        assertEq(beforeHash, keccak256(abi.encode(t, indices)));
        assertTrue(MerkleProofLib.verifyMultiProof(proof, t.root(), t.gatherLeaves(indices), flags));
    }

    // Independent append-only queue, with oversized results copied to exact-sized arrays.
    function _referenceProof(bytes32[] memory t, uint256[] memory indices)
        private
        pure
        returns (bytes32[] memory proof, bool[] memory flags)
    {
        uint256[] memory q = new uint256[](t.length + 1);
        bool[] memory f = new bool[](t.length);
        bytes32[] memory p = new bytes32[](t.length);
        uint256 end = indices.length;
        for (uint256 i; i < end; ++i) {
            q[i] = t.length - 1 - indices[i];
        }
        uint256 start;
        uint256 nf;
        uint256 np;
        while (q[start] != 0) {
            uint256 node = q[start++];
            uint256 sibling = node % 2 == 0 ? node - 1 : node + 1;
            if (start < end && q[start] == sibling) {
                f[nf] = true;
                ++start;
            } else {
                p[np++] = t[sibling];
            }
            ++nf;
            q[end++] = (node - 1) / 2;
        }
        proof = new bytes32[](np);
        flags = new bool[](nf);
        for (uint256 i; i < np; ++i) {
            proof[i] = p[i];
        }
        for (uint256 i; i < nf; ++i) {
            flags[i] = f[i];
        }
    }
}
