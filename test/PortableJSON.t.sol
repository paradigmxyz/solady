// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./utils/SoladyTest.sol";
import {JSONParserLib} from "../src/utils/JSONParserLib.sol";
import {JSONParserLib as GlobalJSON} from "../src/utils/g/JSONParserLib.sol";
import {Item as GlobalItem} from "../src/utils/g/JSONParserLib.sol";

contract PortableJSONTest is SoladyTest {
    using JSONParserLib for JSONParserLib.Item;

    function testNodeTableGrowthKeepsParentsAndCaches() public {
        // Open parents must survive several node-table reallocations before they close.
        bytes memory source = new bytes(131);
        for (uint256 i; i < 65; ++i) {
            source[i] = "[";
            source[130 - i] = "]";
        }
        source[65] = "7";
        JSONParserLib.Item memory root = JSONParserLib.parse(string(source));
        JSONParserLib.Item memory node = root;
        for (uint256 i; i < 65; ++i) {
            assertEq(node.size(), 1);
            JSONParserLib.Item memory child = node.at(0);
            // Querying values updates a shared cache, including through the parent link.
            assertEq(child.parent().value(), node.value());
            assertEq(child.parent()._data, node._data);
            assertEq(child.index(), 0);
            node = child;
        }
        assertTrue(node.isNumber());
        assertEq(node.value(), "7");
        for (uint256 i; i < 65; ++i) {
            node = node.parent();
        }
        assertEq(node.value(), string(source));
        assertTrue(node.parent().isUndefined());
    }

    function testGlobalTreeAndDuplicateKeys() public {
        GlobalItem memory root = GlobalJSON.parse('{"x":[1,{"y":"z"}],"x":false}');
        assertEq(root.size(), 2);
        assertEq(root.at('"x"').value(), "false");
        GlobalItem memory first = root.children()[0];
        assertTrue(first.isArray());
        GlobalItem memory leaf = first.at(1).at('"y"');
        assertEq(leaf.value(), '"z"');
        assertEq(leaf.key(), '"y"');
        assertEq(leaf.parent().parent().parent().value(), root.value());
        assertEq(root.children()[1].value(), "false");
        assertEq(root.children()[1].key(), '"x"');
        assertTrue(root.at('"missing"').isUndefined());
    }

    function testCachedSourceSlicesHaveZeroPadding(bytes32 seed) public brutalizeMemory {
        bytes memory text = new bytes(64);
        for (uint256 i; i < text.length; ++i) {
            text[i] = bytes1(uint8(seed[i % 32]) % 26 + 97);
        }
        string memory source = string(abi.encodePacked('{"k":"', text, '"}'));
        JSONParserLib.Item memory root = JSONParserLib.parse(source);
        JSONParserLib.Item memory leaf = root.at('"k"');
        string memory value = leaf.value();
        string memory key = leaf.key();
        _checkMemory(bytes(value));
        _checkMemory(bytes(key));
        assertEq(value, string(abi.encodePacked('"', text, '"')));
        assertEq(leaf.value(), value);
        assertEq(leaf.key(), key);
        assertEq(JSONParserLib.decodeString(value), string(text));
    }
}
