// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Library for efficient querying of the delegate registries.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/ext/delegate/DelegateCheckerLib.sol)
///
/// The checked port encodes each V2 query with `abi.encodeWithSelector`, and makes the V1
/// fallback query from the same buffer with the V1 selector and fewer words, as the assembly
/// does. The trusted `_staticCallWord` calls with the calldata and gas the assembly passes
/// and copies only the first word of the returndata, as the assembly does. A boolean query is
/// valid when its call succeeds and returns a word that is 1; an amount is the first word a
/// successful call returns, with any bytes it does not return read as zeros, as the assembly
/// reads them. One deliberate difference: the assembly of the two `checkDelegateForAll`
/// functions reads a reverting call's first 31 bytes of revert data, after a stale scratch
/// byte, as its answer, so a registry reverting with 1 there can pass; the port never counts
/// a reverting call as valid.
/// @custom:solar-safe memory arithmetic
library DelegateCheckerLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The canonical delegate registry V1.
    /// See: https://etherscan.io/address/0x00000000000076a84fef008cdabe6409d2fe638b
    address internal constant DELEGATE_REGISTRY_V1 = 0x00000000000076A84feF008CDAbe6409d2FE638B;

    /// @dev The canonical delegate registry V2.
    /// See: https://etherscan.io/address/0x00000000000000447e69651d841bD8D104Bed493
    address internal constant DELEGATE_REGISTRY_V2 = 0x00000000000000447e69651d841bD8D104Bed493;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                DELEGATE CHECKING OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note:
    // - `to` is the delegate. Typically called the "hot wallet".
    // - `from` is the grantor of the delegate rights. Typically called the "cold vault".

    /// @dev Returns if `to` is a delegate of `from`.
    /// ```
    ///     v2.checkDelegateForAll(to, from, "") ||
    ///     v1.checkDelegateForAll(to, from)
    /// ```
    function checkDelegateForAll(address to, address from) internal view returns (bool isValid) {
        // `checkDelegateForAll(address,address,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xe839bd53, to, from, bytes32(0));
        isValid = _isOne(DELEGATE_REGISTRY_V2, data, data.length);
        if (!isValid) {
            // `checkDelegateForAll(address,address)`, on the leading words.
            _setSelector(data, 0x9c395bc2);
            isValid = _isOne(DELEGATE_REGISTRY_V1, data, 0x44);
        }
    }

    /// @dev Returns if `to` is a delegate of `from`.
    /// ```
    ///     v2.checkDelegateForAll(to, from, rights) ||
    ///     (rights == "" && v1.checkDelegateForAll(to, from))
    /// ```
    function checkDelegateForAll(address to, address from, bytes32 rights)
        internal
        view
        returns (bool isValid)
    {
        // `checkDelegateForAll(address,address,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xe839bd53, to, from, rights);
        isValid = _isOne(DELEGATE_REGISTRY_V2, data, data.length);
        if (!isValid && rights == 0) {
            // `checkDelegateForAll(address,address)`, on the leading words.
            _setSelector(data, 0x9c395bc2);
            isValid = _isOne(DELEGATE_REGISTRY_V1, data, 0x44);
        }
    }

    /// @dev Returns if `to` is a delegate of `from` for the specified `contract_`.
    /// ```
    ///     v2.checkDelegateForContract(to, from, contract_, "") ||
    ///     v1.checkDelegateForContract(to, from, contract_)
    /// ```
    /// Returns true if `checkDelegateForAll(to, from)` returns true.
    function checkDelegateForContract(address to, address from, address contract_)
        internal
        view
        returns (bool isValid)
    {
        // `checkDelegateForContract(address,address,address,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0x8988eea9, to, from, contract_, bytes32(0));
        isValid = _isOne(DELEGATE_REGISTRY_V2, data, data.length);
        if (!isValid) {
            // `checkDelegateForContract(address,address,address)`, on the leading words.
            _setSelector(data, 0x90c9a2d0);
            isValid = _isOne(DELEGATE_REGISTRY_V1, data, 0x64);
        }
    }

    /// @dev Returns if `to` is a delegate of `from` for the specified `contract_`.
    /// ```
    ///     v2.checkDelegateForContract(to, from, contract_, rights) ||
    ///     (rights == "" && v1.checkDelegateForContract(to, from, contract_))
    /// ```
    /// Returns true if `checkDelegateForAll(to, from, rights)` returns true.
    function checkDelegateForContract(address to, address from, address contract_, bytes32 rights)
        internal
        view
        returns (bool isValid)
    {
        // `checkDelegateForContract(address,address,address,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0x8988eea9, to, from, contract_, rights);
        isValid = _isOne(DELEGATE_REGISTRY_V2, data, data.length);
        if (!isValid && rights == 0) {
            // `checkDelegateForContract(address,address,address)`, on the leading words.
            _setSelector(data, 0x90c9a2d0);
            isValid = _isOne(DELEGATE_REGISTRY_V1, data, 0x64);
        }
    }

    /// @dev Returns if `to` is a delegate of `from` for the specified `contract_` and token `id`.
    /// ```
    ///     v2.checkDelegateForERC721(to, from, contract_, id, "") ||
    ///     v1.checkDelegateForToken(to, from, contract_, id)
    /// ```
    /// Returns true if `checkDelegateForContract(to, from, contract_)` returns true.
    function checkDelegateForERC721(address to, address from, address contract_, uint256 id)
        internal
        view
        returns (bool isValid)
    {
        // `checkDelegateForERC721(address,address,address,uint256,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xb9f36874, to, from, contract_, id, bytes32(0));
        isValid = _isOne(DELEGATE_REGISTRY_V2, data, data.length);
        if (!isValid) {
            // `checkDelegateForToken(address,address,address,uint256)`, on the leading words.
            _setSelector(data, 0xaba69cf8);
            isValid = _isOne(DELEGATE_REGISTRY_V1, data, 0x84);
        }
    }

    /// @dev Returns if `to` is a delegate of `from` for the specified `contract_` and token `id`.
    /// ```
    ///     v2.checkDelegateForERC721(to, from, contract_, id, rights) ||
    ///     (rights == "" && v1.checkDelegateForToken(to, from, contract_, id))
    /// ```
    /// Returns true if `checkDelegateForContract(to, from, contract_, rights)` returns true.
    function checkDelegateForERC721(
        address to,
        address from,
        address contract_,
        uint256 id,
        bytes32 rights
    ) internal view returns (bool isValid) {
        // `checkDelegateForERC721(address,address,address,uint256,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xb9f36874, to, from, contract_, id, rights);
        isValid = _isOne(DELEGATE_REGISTRY_V2, data, data.length);
        if (!isValid && rights == 0) {
            // `checkDelegateForToken(address,address,address,uint256)`, on the leading words.
            _setSelector(data, 0xaba69cf8);
            isValid = _isOne(DELEGATE_REGISTRY_V1, data, 0x84);
        }
    }

    /// @dev Returns the amount of an ERC20 token for `contract_`
    /// that `to` is granted rights to act on the behalf of `from`.
    /// ```
    ///     max(
    ///         v2.checkDelegateForERC20(to, from, contract_, ""),
    ///         v1.checkDelegateForContract(to, from, contract_) ? type(uint256).max : 0
    ///     )
    /// ```
    /// Returns `type(uint256).max` if `checkDelegateForContract(to, from, contract_)` returns true.
    function checkDelegateForERC20(address to, address from, address contract_)
        internal
        view
        returns (uint256 amount)
    {
        // `checkDelegateForERC20(address,address,address,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xba63c817, to, from, contract_, bytes32(0));
        amount = _word(DELEGATE_REGISTRY_V2, data);
        if (amount != type(uint256).max) {
            // `checkDelegateForContract(address,address,address)`, on the leading words.
            _setSelector(data, 0x90c9a2d0);
            if (_isOne(DELEGATE_REGISTRY_V1, data, 0x64)) amount = type(uint256).max;
        }
    }

    /// @dev Returns the amount of an ERC20 token for `contract_`
    /// that `to` is granted rights to act on the behalf of `from`.
    /// ```
    ///     max(
    ///         v2.checkDelegateForERC20(to, from, contract_, rights),
    ///         (rights == "" && v1.checkDelegateForContract(to, from, contract_)) ? type(uint256).max : 0
    ///     )
    /// ```
    /// Returns `type(uint256).max` if `checkDelegateForContract(to, from, contract_, rights)` returns true.
    function checkDelegateForERC20(address to, address from, address contract_, bytes32 rights)
        internal
        view
        returns (uint256 amount)
    {
        // `checkDelegateForERC20(address,address,address,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xba63c817, to, from, contract_, rights);
        amount = _word(DELEGATE_REGISTRY_V2, data);
        if (rights == 0 && amount != type(uint256).max) {
            // `checkDelegateForContract(address,address,address)`, on the leading words.
            _setSelector(data, 0x90c9a2d0);
            if (_isOne(DELEGATE_REGISTRY_V1, data, 0x64)) amount = type(uint256).max;
        }
    }

    /// @dev Returns the amount of an ERC1155 token `id` for `contract_`
    /// that `to` is granted rights to act on the behalf of `from`.
    /// ```
    ///     max(
    ///         v2.checkDelegateForERC1155(to, from, contract_, id, ""),
    ///         v1.checkDelegateForContract(to, from, contract_, id) ? type(uint256).max : 0
    ///     )
    /// ```
    /// Returns `type(uint256).max` if `checkDelegateForContract(to, from, contract_)` returns true.
    function checkDelegateForERC1155(address to, address from, address contract_, uint256 id)
        internal
        view
        returns (uint256 amount)
    {
        // `checkDelegateForERC1155(address,address,address,uint256,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xb8705875, to, from, contract_, id, bytes32(0));
        amount = _word(DELEGATE_REGISTRY_V2, data);
        if (amount != type(uint256).max) {
            // `checkDelegateForContract(address,address,address)`, on the leading words.
            _setSelector(data, 0x90c9a2d0);
            if (_isOne(DELEGATE_REGISTRY_V1, data, 0x64)) amount = type(uint256).max;
        }
    }

    /// @dev Returns the amount of an ERC1155 token `id` for `contract_`
    /// that `to` is granted rights to act on the behalf of `from`.
    /// ```
    ///     max(
    ///         v2.checkDelegateForERC1155(to, from, contract_, id, rights),
    ///         (rights == "" && v1.checkDelegateForContract(to, from, contract_, id)) ? type(uint256).max : 0
    ///     )
    /// ```
    /// Returns `type(uint256).max` if `checkDelegateForContract(to, from, contract_, rights)` returns true.
    function checkDelegateForERC1155(
        address to,
        address from,
        address contract_,
        uint256 id,
        bytes32 rights
    ) internal view returns (uint256 amount) {
        // `checkDelegateForERC1155(address,address,address,uint256,bytes32)`.
        bytes memory data = abi.encodeWithSelector(0xb8705875, to, from, contract_, id, rights);
        amount = _word(DELEGATE_REGISTRY_V2, data);
        if (rights == 0 && amount != type(uint256).max) {
            // `checkDelegateForContract(address,address,address)`, on the leading words.
            _setSelector(data, 0x90c9a2d0);
            if (_isOne(DELEGATE_REGISTRY_V1, data, 0x64)) amount = type(uint256).max;
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Whether a static call to `registry` with the first `length` bytes of `data`
    /// succeeds and returns a first word of 1. A word of fewer than 32 returned bytes ends in a
    /// zero byte, so it is not 1.
    /// @custom:solar-inline always
    function _isOne(address registry, bytes memory data, uint256 length)
        private
        view
        returns (bool)
    {
        (bool success, bytes32 word) = _staticCallWord(registry, gasleft(), data, length);
        return success && uint256(word) == 1;
    }

    /// @dev The first word that a static call to `registry` with `data` returns, with any bytes
    /// it does not return read as zeros, or zero if the call fails.
    /// @custom:solar-inline always
    function _word(address registry, bytes memory data) private view returns (uint256) {
        (bool success, bytes32 word) = _staticCallWord(registry, gasleft(), data, data.length);
        return success ? uint256(word) : 0;
    }

    /// @dev Sets the function selector of `data` to `s`.
    /// @custom:solar-inline always
    function _setSelector(bytes memory data, bytes4 s) private pure {
        for (uint256 k; k < 4; ++k) {
            data[k] = s[k];
        }
    }

    /// @dev Static-calls `target` with the first `length` bytes of `payload` and `gasLimit`
    /// gas, and returns the first word of the returndata, right padded with zeros, which is all
    /// of it that is copied. Solidity sends a whole buffer and copies the whole returndata.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _staticCallWord(address target, uint256 gasLimit, bytes memory payload, uint256 length)
        private
        view
        returns (bool success, bytes32 word)
    {
        if (length > payload.length) revert();
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0)
            success := staticcall(gasLimit, target, add(payload, 0x20), length, 0x00, 0x20)
            word := mload(0x00)
        }
    }
}
