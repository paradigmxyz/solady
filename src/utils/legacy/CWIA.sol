// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

/// @notice Class with helper read functions for clone with immutable args.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/legacy/CWIA.sol)
/// @author Adapted from clones with immutable args by zefram.eth, Saw-mon & Natalie
/// (https://github.com/Saw-mon-and-Natalie/clones-with-immutable-args)
///
/// The checked port reads the arguments from `msg.data` with slices and conversions, which
/// need Solidity 0.8.5. A word or byte past the end of the calldata reads as zero and offsets
/// add with wrap-around, as `calldataload` and `calldatacopy` read them; an array is a copy of
/// the bytes, which the trusted `_cwiaToUint256Array` and `_cwiaToBytes32Array` reinterpret in
/// place, since Solidity cannot. A length that no gas could copy reverts without data, as the
/// copy running out of gas does upstream. One deliberate difference: an array length of 2**251
/// or more, whose byte size upstream wraps into a short copy that returns an array longer than
/// its memory, also reverts without data.
/// @custom:solar-safe memory arithmetic
abstract contract CWIA {
    /// @dev Reads all of the immutable args.
    function _getArgBytes() internal pure returns (bytes memory arg) {
        uint256 offset = _getImmutableArgsOffset();
        // 2 bytes are used for the length.
        arg = _cwiaCalldataBytes(offset, _cwiaSub(_cwiaSub(msg.data.length, offset), 2));
    }

    /// @dev Reads an immutable arg with type bytes.
    function _getArgBytes(uint256 argOffset, uint256 length)
        internal
        pure
        returns (bytes memory arg)
    {
        uint256 offset = _getImmutableArgsOffset();
        arg = _cwiaCalldataBytes(_cwiaAdd(offset, argOffset), length);
    }

    /// @dev Reads an immutable arg with type address.
    function _getArgAddress(uint256 argOffset) internal pure returns (address arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = address(bytes20(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))));
    }

    /// @dev Reads a uint256 array stored in the immutable args.
    function _getArgUint256Array(uint256 argOffset, uint256 length)
        internal
        pure
        returns (uint256[] memory arg)
    {
        uint256 offset = _getImmutableArgsOffset();
        arg = _cwiaToUint256Array(_cwiaCalldataWords(_cwiaAdd(offset, argOffset), length));
    }

    /// @dev Reads a bytes32 array stored in the immutable args.
    function _getArgBytes32Array(uint256 argOffset, uint256 length)
        internal
        pure
        returns (bytes32[] memory arg)
    {
        uint256 offset = _getImmutableArgsOffset();
        arg = _cwiaToBytes32Array(_cwiaCalldataWords(_cwiaAdd(offset, argOffset), length));
    }

    /// @dev Reads an immutable arg with type bytes32.
    function _getArgBytes32(uint256 argOffset) internal pure returns (bytes32 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = _cwiaCalldataWord(_cwiaAdd(offset, argOffset));
    }

    /// @dev Reads an immutable arg with type uint256.
    function _getArgUint256(uint256 argOffset) internal pure returns (uint256 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset)));
    }

    /// @dev Reads an immutable arg with type uint248.
    function _getArgUint248(uint256 argOffset) internal pure returns (uint248 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint248(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 8);
    }

    /// @dev Reads an immutable arg with type uint240.
    function _getArgUint240(uint256 argOffset) internal pure returns (uint240 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint240(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 16);
    }

    /// @dev Reads an immutable arg with type uint232.
    function _getArgUint232(uint256 argOffset) internal pure returns (uint232 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint232(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 24);
    }

    /// @dev Reads an immutable arg with type uint224.
    function _getArgUint224(uint256 argOffset) internal pure returns (uint224 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint224(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 32);
    }

    /// @dev Reads an immutable arg with type uint216.
    function _getArgUint216(uint256 argOffset) internal pure returns (uint216 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint216(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 40);
    }

    /// @dev Reads an immutable arg with type uint208.
    function _getArgUint208(uint256 argOffset) internal pure returns (uint208 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint208(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 48);
    }

    /// @dev Reads an immutable arg with type uint200.
    function _getArgUint200(uint256 argOffset) internal pure returns (uint200 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint200(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 56);
    }

    /// @dev Reads an immutable arg with type uint192.
    function _getArgUint192(uint256 argOffset) internal pure returns (uint192 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint192(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 64);
    }

    /// @dev Reads an immutable arg with type uint184.
    function _getArgUint184(uint256 argOffset) internal pure returns (uint184 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint184(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 72);
    }

    /// @dev Reads an immutable arg with type uint176.
    function _getArgUint176(uint256 argOffset) internal pure returns (uint176 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint176(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 80);
    }

    /// @dev Reads an immutable arg with type uint168.
    function _getArgUint168(uint256 argOffset) internal pure returns (uint168 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint168(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 88);
    }

    /// @dev Reads an immutable arg with type uint160.
    function _getArgUint160(uint256 argOffset) internal pure returns (uint160 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint160(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 96);
    }

    /// @dev Reads an immutable arg with type uint152.
    function _getArgUint152(uint256 argOffset) internal pure returns (uint152 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint152(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 104);
    }

    /// @dev Reads an immutable arg with type uint144.
    function _getArgUint144(uint256 argOffset) internal pure returns (uint144 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint144(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 112);
    }

    /// @dev Reads an immutable arg with type uint136.
    function _getArgUint136(uint256 argOffset) internal pure returns (uint136 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint136(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 120);
    }

    /// @dev Reads an immutable arg with type uint128.
    function _getArgUint128(uint256 argOffset) internal pure returns (uint128 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint128(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 128);
    }

    /// @dev Reads an immutable arg with type uint120.
    function _getArgUint120(uint256 argOffset) internal pure returns (uint120 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint120(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 136);
    }

    /// @dev Reads an immutable arg with type uint112.
    function _getArgUint112(uint256 argOffset) internal pure returns (uint112 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint112(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 144);
    }

    /// @dev Reads an immutable arg with type uint104.
    function _getArgUint104(uint256 argOffset) internal pure returns (uint104 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint104(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 152);
    }

    /// @dev Reads an immutable arg with type uint96.
    function _getArgUint96(uint256 argOffset) internal pure returns (uint96 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint96(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 160);
    }

    /// @dev Reads an immutable arg with type uint88.
    function _getArgUint88(uint256 argOffset) internal pure returns (uint88 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint88(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 168);
    }

    /// @dev Reads an immutable arg with type uint80.
    function _getArgUint80(uint256 argOffset) internal pure returns (uint80 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint80(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 176);
    }

    /// @dev Reads an immutable arg with type uint72.
    function _getArgUint72(uint256 argOffset) internal pure returns (uint72 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint72(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 184);
    }

    /// @dev Reads an immutable arg with type uint64.
    function _getArgUint64(uint256 argOffset) internal pure returns (uint64 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint64(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 192);
    }

    /// @dev Reads an immutable arg with type uint56.
    function _getArgUint56(uint256 argOffset) internal pure returns (uint56 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint56(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 200);
    }

    /// @dev Reads an immutable arg with type uint48.
    function _getArgUint48(uint256 argOffset) internal pure returns (uint48 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint48(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 208);
    }

    /// @dev Reads an immutable arg with type uint40.
    function _getArgUint40(uint256 argOffset) internal pure returns (uint40 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint40(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 216);
    }

    /// @dev Reads an immutable arg with type uint32.
    function _getArgUint32(uint256 argOffset) internal pure returns (uint32 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint32(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 224);
    }

    /// @dev Reads an immutable arg with type uint24.
    function _getArgUint24(uint256 argOffset) internal pure returns (uint24 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint24(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 232);
    }

    /// @dev Reads an immutable arg with type uint16.
    function _getArgUint16(uint256 argOffset) internal pure returns (uint16 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint16(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 240);
    }

    /// @dev Reads an immutable arg with type uint8.
    function _getArgUint8(uint256 argOffset) internal pure returns (uint8 arg) {
        uint256 offset = _getImmutableArgsOffset();
        arg = uint8(uint256(_cwiaCalldataWord(_cwiaAdd(offset, argOffset))) >> 248);
    }

    /// @return offset The offset of the packed immutable args in calldata.
    function _getImmutableArgsOffset() internal pure returns (uint256 offset) {
        uint256 n = msg.data.length;
        // The number in the last 2 bytes of the calldata, or zero for calldata shorter than
        // that, which the assembly loads from past the end.
        uint256 extraLength;
        if (n >= 32) extraLength = uint16(uint256(abi.decode(msg.data[n - 32:], (bytes32))));
        else if (n >= 2) extraLength = uint16(bytes2(msg.data[n - 2:]));
        offset = _cwiaSub(n, extraLength);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `a + b` modulo `2**256`, as `add` computes it.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _cwiaAdd(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev `a - b` modulo `2**256`, as `sub` computes it.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _cwiaSub(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a - b;
        }
    }

    /// @dev The calldata word at `start`, whose bytes past the end of the calldata read as zero.
    /// @custom:solar-inline always
    function _cwiaCalldataWord(uint256 start) private pure returns (bytes32 w) {
        uint256 n = msg.data.length;
        if (start < n) {
            if (n - start >= 32) return abi.decode(msg.data[start:], (bytes32));
            w = bytes32(msg.data[start:]);
        }
    }

    /// @dev The `count` bytes of the calldata from `start`, of which those past its end read as
    /// zero. A count that no gas could copy reverts without data, as running out of gas does.
    function _cwiaCalldataBytes(uint256 start, uint256 count)
        private
        pure
        returns (bytes memory result)
    {
        uint256 n = msg.data.length;
        if (start <= n && count <= n - start) return msg.data[start:start + count];
        if (count > 0xffffffff) revert();
        result = new bytes(count);
        if (start < n) {
            for (uint256 k; k < n - start; ++k) {
                result[k] = msg.data[start + k];
            }
        }
    }

    /// @dev The `count` calldata words from `start`, as bytes. A count whose byte size does not
    /// fit in a word reverts without data.
    function _cwiaCalldataWords(uint256 start, uint256 count) private pure returns (bytes memory) {
        if (count > type(uint256).max >> 5) revert();
        return _cwiaCalldataBytes(start, count << 5);
    }

    /// @dev Reinterprets `b`, whose length is a multiple of 32, as its words, in place.
    /// Solidity cannot convert between array types.
    /// @custom:solar-trusted
    function _cwiaToUint256Array(bytes memory b) private pure returns (uint256[] memory a) {
        uint256 n = b.length >> 5;
        /// @solidity memory-safe-assembly
        assembly {
            a := b
            mstore(a, n)
        }
    }

    /// @dev Reinterprets `b`, whose length is a multiple of 32, as its words, in place.
    /// Solidity cannot convert between array types.
    /// @custom:solar-trusted
    function _cwiaToBytes32Array(bytes memory b) private pure returns (bytes32[] memory a) {
        uint256 n = b.length >> 5;
        /// @solidity memory-safe-assembly
        assembly {
            a := b
            mstore(a, n)
        }
    }
}
