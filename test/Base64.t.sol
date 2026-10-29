// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./utils/SoladyTest.sol";
import {Base64} from "../src/utils/Base64.sol";
import {LibString} from "../src/utils/LibString.sol";

contract Base64Test is SoladyTest {
    function testExactBufferBoundaries() public {
        uint8[18] memory lengths =
            [0, 1, 2, 3, 22, 23, 24, 25, 31, 32, 33, 47, 48, 49, 63, 64, 65, 97];
        for (uint256 i; i < lengths.length; ++i) {
            for (uint256 mode; mode < 4; ++mode) {
                // Each case gets fresh EVM memory, as an independent call would.
                this.checkBufferBoundary(lengths[i], mode);
            }
        }
    }

    function testBufferBoundary(uint8 n, uint8 mode) public {
        this.checkBufferBoundary(n % 98, mode % 4);
    }

    function checkBufferBoundary(uint256 n, uint256 mode) public {
        bytes memory input = new bytes(n);
        for (uint256 j; j < n; ++j) {
            input[j] = bytes1(uint8(j * 37 + n));
        }
        bytes32 beforeHash = keccak256(input);
        bool fileSafe = mode & 1 != 0;
        bool noPadding = mode & 2 != 0;
        _brutalizeMemory();
        _misalignFreeMemoryPointer();
        string memory encoded = Base64.encode(input, fileSafe, noPadding);
        _checkMemory(encoded);
        assertEq(encoded, _referenceEncode(input, fileSafe, noPadding));
        bytes32 encodedHash = keccak256(bytes(encoded));
        _brutalizeMemory();
        _misalignFreeMemoryPointer();
        bytes memory decoded = Base64.decode(encoded);
        _checkMemory(decoded);
        assertEq(decoded, input);
        assertEq(keccak256(input), beforeHash);
        assertEq(keccak256(bytes(encoded)), encodedHash);
        if (n != 0) {
            decoded[0] = ~decoded[0];
            assertEq(keccak256(input), beforeHash);
            assertEq(keccak256(bytes(encoded)), encodedHash);
        }
    }

    function _referenceEncode(bytes memory input, bool fileSafe, bool noPadding)
        private
        pure
        returns (string memory)
    {
        bytes memory alphabet = fileSafe
            ? bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
            : bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        uint256 used = (input.length * 4 + 2) / 3;
        bytes memory output = new bytes(noPadding ? used : (input.length + 2) / 3 * 4);
        for (uint256 j; j < used; ++j) {
            uint256 bit = j * 6;
            uint256 word = uint256(uint8(input[bit / 8])) << 8;
            if (bit / 8 + 1 < input.length) word |= uint8(input[bit / 8 + 1]);
            output[j] = alphabet[(word >> (10 - bit % 8)) & 63];
        }
        for (uint256 j = used; j < output.length; ++j) {
            output[j] = "=";
        }
        return string(output);
    }

    function testBase64EncodeEmptyString() public {
        _testBase64Encode("", "");
    }

    function testBase64EncodeShortStrings() public {
        _testBase64Encode("M", "TQ==");
        _testBase64Encode("Mi", "TWk=");
        _testBase64Encode("Mil", "TWls");
        _testBase64Encode("Mila", "TWlsYQ==");
        _testBase64Encode("Milad", "TWlsYWQ=");
        _testBase64Encode("Milady", "TWlsYWR5");
    }

    function testBase64EncodeToStringWithDoublePadding() public {
        _testBase64Encode("test", "dGVzdA==");
    }

    function testBase64EncodeToStringWithSinglePadding() public {
        _testBase64Encode("test1", "dGVzdDE=");
    }

    function testBase64EncodeToStringWithNoPadding() public {
        _testBase64Encode("test12", "dGVzdDEy");
    }

    function testBase64EncodeSentence() public {
        _testBase64Encode(
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4="
        );
    }

    function testBase64WordBoundary() public {
        // Base64.encode allocates memory in multiples of 32 bytes.
        // This checks if the amount of memory allocated is enough.
        _testBase64Encode("012345678901234567890", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkw");
        _testBase64Encode("0123456789012345678901", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMQ==");
        _testBase64Encode("01234567890123456789012", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=");
        _testBase64Encode("012345678901234567890123", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz");
        _testBase64Encode("0123456789012345678901234", "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==");
    }

    function _testBase64Encode(string memory input, string memory output) private {
        assertEq(Base64.encode(_withDirtyEndBits(bytes(input))), output);
    }

    function _withDirtyEndBits(bytes memory input) private view returns (bytes memory output) {
        /// @solidity memory-safe-assembly
        assembly {
            output := mload(0x40)
            let n := mload(input)

            mstore(0x00, gas())
            let r := keccak256(0x00, 0x60)
            mstore(add(output, add(0x20, n)), r)
            mstore(add(output, add(0x40, n)), r)

            pop(staticcall(gas(), 4, input, add(0x20, n), output, add(0x20, n)))

            mstore(0x40, add(output, add(0x40, n)))
        }
    }

    function testBase64EncodeDecode(bytes memory input) public {
        string memory encoded = Base64.encode(input);
        bytes memory decoded = Base64.decode(encoded);

        assertEq(input, decoded);
    }

    function testBase64DecodeShortStringGas() public {
        assertEq(Base64.decode("TWlsYWR5").length, 6);
    }

    function testBase64DecodeSentenceGas() public {
        assertEq(
            Base64.decode(
                "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4="
            )
            .length,
            56
        );
    }

    function testBase64EncodeDecodeAltModes(bytes memory input) public brutalizeMemory {
        for (uint256 i; i < 2; ++i) {
            _misalignFreeMemoryPointer();
            if (_randomChance(2)) {
                input = _withDirtyEndBits(input);
            }
            string memory encoded = Base64.encode(input);
            _checkMemory(encoded);

            if (_random() & 1 == 0) {
                encoded = LibString.replace(encoded, "=", "");
            }
            if (_random() & 1 == 0) {
                encoded = LibString.replace(encoded, "/", ",");
            }
            if (_random() & 1 == 0) {
                encoded = LibString.replace(encoded, "/", "_");
            }
            if (_random() & 1 == 0) {
                encoded = LibString.replace(encoded, "+", "-");
            }

            _misalignFreeMemoryPointer();
            bytes memory decoded = Base64.decode(encoded);
            _checkMemory(decoded);

            assertEq(input, decoded);

            input = abi.encode(encoded);
        }
    }

    function testBase64EncodeFileSafeAndNoPadding(bytes memory input, bool fileSafe, bool noPadding)
        public
    {
        string memory expectedEncoded = Base64.encode(input);

        if (fileSafe) {
            expectedEncoded = LibString.replace(expectedEncoded, "+", "-");
            expectedEncoded = LibString.replace(expectedEncoded, "/", "_");
        }
        if (noPadding) {
            expectedEncoded = LibString.replace(expectedEncoded, "=", "");
        }

        assertEq(Base64.encode(input, fileSafe, noPadding), expectedEncoded);
    }

    function testSmallBuffersRetainOwnedPadding() public {
        bytes memory input = new bytes(33);
        for (uint256 i; i < input.length; ++i) {
            input[i] = bytes1(uint8(i * 37 + 251));
        }
        bytes32 inputHash = keccak256(input);
        _brutalizeMemory();
        _misalignFreeMemoryPointer();
        string memory first = Base64.encode(input, true, true);
        _checkMemory(first);
        bytes32 firstHash = keccak256(bytes(first));

        _brutalizeMemory();
        _misalignFreeMemoryPointer();
        string memory second = Base64.encode(input);
        _checkMemory(second);
        assertEq(first, _referenceEncode(input, true, true));
        assertEq(second, _referenceEncode(input, false, false));

        _brutalizeMemory();
        _misalignFreeMemoryPointer();
        bytes memory decoded = Base64.decode(first);
        _checkMemory(decoded);
        assertEq(decoded, input);
        assertEq(keccak256(bytes(first)), firstHash);
        assertEq(keccak256(input), inputHash);
        _checkMemory(first);
        _checkMemory(second);
    }
}
