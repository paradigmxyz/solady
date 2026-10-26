// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/SoladyTest.sol";
import {LibRLP} from "../src/utils/LibRLP.sol";

contract PortableRLPHarness {
    using LibRLP for LibRLP.List;

    function encodeList(bytes memory data, uint256 n) external pure returns (bytes memory) {
        return LibRLP.p(data).p(n).encode();
    }

    function encodeScalar(uint256 n) external pure returns (bytes memory) {
        return LibRLP.encode(n);
    }
}

contract PortableRLPTest is SoladyTest {
    PortableRLPHarness private harness;

    function setUp() public {
        harness = new PortableRLPHarness();
    }

    function testSmallList() public {
        assertEq(harness.encodeList("dog", 128), hex"c683646f678180");
    }

    function testLargeList() public {
        bytes memory data = new bytes(256);
        assertEq(
            harness.encodeList(data, 128), abi.encodePacked(hex"f90105b90100", data, hex"8180")
        );
    }

    function testLargeInteger() public {
        assertEq(
            harness.encodeScalar(type(uint256).max),
            abi.encodePacked(hex"a0", bytes32(type(uint256).max))
        );
    }
}
