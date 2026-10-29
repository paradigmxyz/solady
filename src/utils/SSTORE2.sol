// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Read and write to persistent storage at a fraction of the cost.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SSTORE2.sol)
/// @author Saw-mon-and-Natalie (https://github.com/Saw-mon-and-Natalie)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SSTORE2.sol)
/// @author Modified from 0xSequence (https://github.com/0xSequence/sstore2/blob/master/contracts/SSTORE2.sol)
/// @author Modified from SSTORE3 (https://github.com/Philogy/sstore3)
/// @dev The checked port keeps a data contract's layout: `data` as its code after one STOP
/// byte, so it cannot be called. Writing deploys it with the trusted `_createDeploy`; reading
/// copies a range of it into a new buffer with the trusted `_codeRead`, which reads zeros past
/// the code as the assembly does. A short slice is copied first and, when its last byte is
/// zero, cut at the end of the data with the trusted `_setLength`; any other read is cut with
/// the code's size first. The creation code is `abi.encodePacked` of a fixed prefix and
/// `data`. Two deliberate differences, both where the assembly runs out of gas: data too long
/// for the two-byte length the creation code pushes fails with `DeploymentFailed()`, and
/// reading an account without code fails with `Panic(0x11)`.
/// @custom:solar-safe memory arithmetic
library SSTORE2 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The proxy initialization code.
    bytes internal constant _CREATE3_PROXY_INITCODE = hex"67363d3d37363d34f03d5260086018f3";

    /// @dev Hash of the `_CREATE3_PROXY_INITCODE`.
    /// Equivalent to `keccak256(abi.encodePacked(hex"67363d3d37363d34f03d5260086018f3"))`.
    bytes32 internal constant CREATE3_PROXY_INITCODE_HASH =
        0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Unable to deploy the storage contract.
    error DeploymentFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         WRITE LOGIC                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Writes `data` into the bytecode of a storage contract and returns its address.
    function write(bytes memory data) internal returns (address pointer) {
        return
            _createDeploy(
                abi.encodePacked(hex"61", _codeSize(data), hex"80600a3d393df300", data), 0
            );
    }

    /// @dev Writes `data` into the bytecode of a storage contract with `salt`
    /// and returns its normal CREATE2 deterministic address.
    function writeCounterfactual(bytes memory data, bytes32 salt)
        internal
        returns (address pointer)
    {
        return _createDeploy2(
            abi.encodePacked(hex"61", _codeSize(data), hex"80600a3d393df300", data), salt, 0
        );
    }

    /// @dev Writes `data` into the bytecode of a storage contract and returns its address.
    /// This uses the so-called "CREATE3" workflow,
    /// which means that `pointer` is agnostic to `data, and only depends on `salt`.
    function writeDeterministic(bytes memory data, bytes32 salt)
        internal
        returns (address pointer)
    {
        address proxy = _createDeploy2(_CREATE3_PROXY_INITCODE, salt, 0);
        pointer = _proxyDeployment(proxy);
        // The proxy creates a contract from its calldata and returns nothing.
        (bool success,,) = _callBounded(
            proxy,
            0,
            gasleft(),
            abi.encodePacked(hex"61", _codeSize(data), hex"80600a3d393df300", data),
            0
        );
        if (!success || pointer.code.length == 0) revert DeploymentFailed();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    ADDRESS CALCULATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the initialization code hash of the storage contract for `data`.
    /// Used for mining vanity addresses with create2crunch.
    function initCodeHash(bytes memory data) internal pure returns (bytes32 hash) {
        return keccak256(abi.encodePacked(hex"61", _codeSize(data), hex"80600a3d393df300", data));
    }

    /// @dev Equivalent to `predictCounterfactualAddress(data, salt, address(this))`
    function predictCounterfactualAddress(bytes memory data, bytes32 salt)
        internal
        view
        returns (address pointer)
    {
        pointer = predictCounterfactualAddress(data, salt, address(this));
    }

    /// @dev Returns the CREATE2 address of the storage contract for `data`
    /// deployed with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictCounterfactualAddress(bytes memory data, bytes32 salt, address deployer)
        internal
        pure
        returns (address predicted)
    {
        return _createPredict2(deployer, salt, initCodeHash(data));
    }

    /// @dev Equivalent to `predictDeterministicAddress(salt, address(this))`.
    function predictDeterministicAddress(bytes32 salt) internal view returns (address pointer) {
        pointer = predictDeterministicAddress(salt, address(this));
    }

    /// @dev Returns the "CREATE3" deterministic address for `salt` with `deployer`.
    function predictDeterministicAddress(bytes32 salt, address deployer)
        internal
        pure
        returns (address pointer)
    {
        return _proxyDeployment(_createPredict2(deployer, salt, CREATE3_PROXY_INITCODE_HASH));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         READ LOGIC                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `read(pointer, 0, 2 ** 256 - 1)`.
    /// @custom:solar-inline always
    function read(address pointer) internal view returns (bytes memory data) {
        // The data is the code after the STOP byte.
        uint256 n = pointer.code.length - 1;
        if (n == 0) return data;
        return _codeRead(pointer, 1, n);
    }

    /// @dev Equivalent to `read(pointer, start, 2 ** 256 - 1)`.
    /// @custom:solar-inline always
    function read(address pointer, uint256 start) internal view returns (bytes memory data) {
        uint256 n = pointer.code.length - 1;
        if (start >= n) return "";
        return _codeRead(pointer, start + 1, n - start);
    }

    /// @dev Returns a slice of the data on `pointer` from `start` to `end`.
    /// `start` and `end` will be clamped to the range `[0, args.length]`.
    /// The `pointer` MUST be deployed via the SSTORE2 write functions.
    /// Otherwise, the behavior is undefined.
    /// Out-of-gas reverts if `pointer` does not have any code.
    /// @custom:solar-inline always
    function read(address pointer, uint256 start, uint256 end)
        internal
        view
        returns (bytes memory data)
    {
        // A short range is copied first, as the assembly does. Past the code the
        // copy reads zeros, so a last byte that is not zero lies inside the code,
        // and so does the whole range; otherwise the end of the data cuts it, and
        // the zeros past it stay as padding.
        if (start < end && end - start <= 0x40) {
            uint256 d = end - start;
            data = _codeRead(pointer, start + 1, d);
            if (data[d - 1] != 0) return data;
            uint256 n = pointer.code.length - 1;
            if (end > n) _setLength(data, start < n ? n - start : 0);
            return data;
        }
        // The data is the code after the STOP byte.
        uint256 n = pointer.code.length - 1;
        if (end > n) end = n;
        if (start >= end) return "";
        return _codeRead(pointer, start + 1, end - start);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The code size the creation code of the storage contract for `data`
    /// pushes: `data` and the STOP byte before it. The creation code,
    /// `hex"61", _codeSize(data), hex"80600a3d393df300", data`, copies them out
    /// as the deployed code with
    /// PUSH2 l, DUP1, PUSH1 0x0a, RETURNDATASIZE, CODECOPY, RETURNDATASIZE, RETURN, STOP.
    function _codeSize(bytes memory data) private pure returns (uint16) {
        if (data.length > 0xfffe) revert DeploymentFailed();
        return uint16(data.length + 1);
    }

    /// @dev The address a CREATE3 proxy's one deployment gets: its first
    /// CREATE, at nonce one.
    function _proxyDeployment(address proxy) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }

    /// @dev Calls `target` with `payload`, `value` wei and `gasLimit` gas, and
    /// copies at most `maxCopy` bytes of the response into a new buffer sized to
    /// what it holds, allocated after the call. `totalSize` is how many bytes
    /// there were.
    /// @custom:solar-trusted
    function _callBounded(
        address target,
        uint256 value,
        uint256 gasLimit,
        bytes memory payload,
        uint256 maxCopy
    ) private returns (bool success, bytes memory output, uint256 totalSize) {
        /// @solidity memory-safe-assembly
        assembly {
            success := call(gasLimit, target, value, add(payload, 0x20), mload(payload), 0x00, 0x00)
            totalSize := returndatasize()
            let copied := totalSize
            if gt(copied, maxCopy) { copied := maxCopy }
            output := mload(0x40)
            mstore(output, copied)
            returndatacopy(add(output, 0x20), 0x00, copied)
            mstore(0x40, and(add(add(output, 0x3f), copied), not(0x1f)))
        }
    }

    /// @dev Deploys `initcode` with `value` wei and returns the new address.
    /// @custom:solar-trusted
    function _createDeploy(bytes memory initcode, uint256 value)
        private
        returns (address deployed)
    {
        /// @solidity memory-safe-assembly
        assembly {
            deployed := create(value, add(initcode, 0x20), mload(initcode))
        }
        if (deployed == address(0)) revert DeploymentFailed();
    }

    /// @dev Deploys `initcode` with `value` wei at the address `salt` selects.
    /// @custom:solar-trusted
    function _createDeploy2(bytes memory initcode, bytes32 salt, uint256 value)
        private
        returns (address deployed)
    {
        /// @solidity memory-safe-assembly
        assembly {
            deployed := create2(value, add(initcode, 0x20), mload(initcode), salt)
        }
        if (deployed == address(0)) revert DeploymentFailed();
    }

    /// @dev The address `deploy2` gives `deployer` for `salt` and initcode
    /// hashing to `initcodeHash`. Computes only; deploys nothing.
    function _createPredict2(address deployer, bytes32 salt, bytes32 initcodeHash)
        private
        pure
        returns (address)
    {
        return address(
            uint160(
                uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initcodeHash)))
            )
        );
    }

    /// @dev The `count` bytes of `target`'s code from `start`, as a new buffer right padded
    /// with zeros. Past the code the copy reads zeros. Solidity only gives an account's whole
    /// code.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _codeRead(address target, uint256 start, uint256 count)
        private
        view
        returns (bytes memory out)
    {
        /// @solidity memory-safe-assembly
        assembly {
            out := mload(0x40)
            mstore(out, count)
            let o := add(out, 0x20)
            extcodecopy(target, o, start, count)
            mstore(add(o, count), 0) // Zeroize the slot after the bytes.
            mstore(0x40, add(o, and(add(count, 0x1f), not(0x1f)))) // Allocate the memory.
        }
    }

    /// @dev Shrinks `b` to its first `n` bytes in place. The bytes past `n` in its
    /// last word are zero. Solidity cannot spell a shorter length for an existing buffer.
    /// @custom:solar-trusted
    function _setLength(bytes memory b, uint256 n) private pure {
        if (n > b.length) n = _outOfBounds();
        /// @solidity memory-safe-assembly
        assembly {
            mstore(b, n)
        }
    }

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the
    /// portable spelling of a failed range check.
    function _outOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }
}
