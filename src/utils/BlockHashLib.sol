// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for accessing block hashes way beyond the 256-block limit.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/BlockHashLib.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Blockhash.sol)
/// @dev The checked port compares the block number with `blockNumber + 256` modulo `2**256`,
/// as the assembly adds, computed so that it cannot overflow, and asks the history storage
/// contract through the trusted `_staticCallWord`: all the gas left, the block number as the
/// 32 bytes of calldata, and at most the first word of the answer, of a success or of a
/// revert, copied into scratch space zeroed before the call, as the assembly does, where
/// Solidity's `staticcall` copies the whole answer into new memory.
/// @custom:solar-safe memory arithmetic
library BlockHashLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Ethereum block header fields relevant to historical MPT proofs.
    struct ShortHeader {
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        bytes32[8] logsBloom;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The keccak256 of the RLP-encoded block header does not equal the block hash.
    error BlockHashMismatch();

    /// @dev The block header is not properly RLP-encoded.
    error InvalidBlockHeaderEncoding();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Address of the EIP-2935 history storage contract.
    /// See: https://eips.ethereum.org/EIPS/eip-2935
    address internal constant HISTORY_STORAGE_ADDRESS = 0x0000F90827F1C53a10cb7A02335B175320002935;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         OPERATIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Retrieves the block hash for any historical block within the supported range.
    /// The function gracefully handles future blocks and blocks beyond the history window by returning zero,
    /// consistent with the EVM's native `BLOCKHASH` behavior.
    function blockHash(uint256 blockNumber) internal view returns (bytes32 result) {
        // If `blockNumber + 256` overflows:
        // - Typical chain height (`block.number > 255`) -> `staticcall` -> 0.
        // - Very early chain (`block.number <= 255`) -> `blockhash` -> 0.
        uint256 end = blockNumber > type(uint256).max - 256
            ? blockNumber - (type(uint256).max - 255)
            : blockNumber + 256;
        if (block.number <= end) return blockhash(blockNumber);
        (,, result) = _staticCallWord(HISTORY_STORAGE_ADDRESS, gasleft(), abi.encode(blockNumber));
    }

    /// @dev Reverts if `keccak256(encodedHeader) != blockHash(blockNumber)`.
    /// Else, returns the block hash. This checks the hash without validating the RLP encoding.
    function verifyBlock(bytes calldata encodedHeader, uint256 blockNumber)
        internal
        view
        returns (bytes32 result)
    {
        result = blockHash(blockNumber);
        if (keccak256(encodedHeader) != result) revert BlockHashMismatch();
    }

    /// @dev Extracts the leading fields relevant to historical MPT proofs.
    /// Like the original, checks only the `0xf9` list prefix and the 448-byte minimum length.
    function toShortHeader(bytes calldata encodedHeader)
        internal
        pure
        returns (ShortHeader memory result)
    {
        if (encodedHeader.length < 448 || encodedHeader[0] != 0xf9) {
            revert InvalidBlockHeaderEncoding();
        }
        result.parentHash = bytes32(encodedHeader[4:36]);
        result.stateRoot = bytes32(encodedHeader[91:123]);
        result.transactionsRoot = bytes32(encodedHeader[124:156]);
        result.receiptsRoot = bytes32(encodedHeader[157:189]);
        for (uint256 i; i < 8; ++i) {
            uint256 offset = 192 + i * 32;
            result.logsBloom[i] = bytes32(encodedHeader[offset:offset + 32]);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and copies at most the
    /// first word of the answer into scratch space zeroed before the call. Returns whether the
    /// call succeeded, the answer's size and that word. Solidity's `staticcall` copies the whole
    /// answer into new memory instead.
    /// @custom:solar-trusted
    /// @custom:solar-inline
    function _staticCallWord(address target, uint256 gasLimit, bytes memory payload)
        private
        view
        returns (bool success, uint256 size, bytes32 word)
    {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0)
            success := staticcall(gasLimit, target, add(payload, 0x20), mload(payload), 0x00, 0x20)
            size := returndatasize()
            word := mload(0x00)
        }
    }
}
