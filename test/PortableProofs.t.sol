// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/SoladyTest.sol";
import {MerkleTreeLib} from "../src/utils/MerkleTreeLib.sol";
import {MerkleProofLib} from "../src/utils/MerkleProofLib.sol";

contract PortableProofsHarness {
    function proof(bytes32[] memory tree, uint256[] memory indices)
        external
        pure
        returns (bytes32[] memory, bool[] memory)
    {
        return MerkleTreeLib.multiProofForLeaves(tree, indices);
    }
}

contract PortableProofsTest is SoladyTest {
    PortableProofsHarness private harness;
    bytes32[] private tree;

    function setUp() public {
        harness = new PortableProofsHarness();
        bytes32[] memory leaves = new bytes32[](256);
        for (uint256 i; i < leaves.length; ++i) {
            leaves[i] = keccak256(abi.encode(i));
        }
        tree = MerkleTreeLib.build(leaves);
    }

    function testSingleLeaf() public {
        _check(1);
    }

    function testSparseLeaves() public {
        _check(8);
    }

    function testAllLeaves() public {
        _check(256);
    }

    function _check(uint256 count) private {
        uint256[] memory indices = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            indices[i] = i * (256 / count);
        }
        bytes32[] memory t = tree;
        (bytes32[] memory proof, bool[] memory flags) = harness.proof(t, indices);
        assertTrue(
            MerkleProofLib.verifyMultiProof(
                proof, t[0], MerkleTreeLib.gatherLeaves(t, indices), flags
            )
        );
        assertEq(proof.length + count, flags.length + 1);
    }
}
