// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Clones with immutable args (CWIA) deployment library
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/legacy/CWIA.sol)
/// @author Clones with immutable args by wighawag, zefram.eth, Saw-mon & Natalie
/// (https://github.com/Saw-mon-and-Natalie/clones-with-immutable-args)
///
/// @dev
/// The implementation of CWIA here implements a `receive()` method that emits the
/// `ReceiveETH(uint256)` event. This skips the `DELEGATECALL` when there is no calldata,
/// enabling us to accept hard gas-capped `sends` & `transfers` for maximum backwards
/// composability. The minimal proxy implementation does not offer this feature.
///
/// The checked port assembles the creation code the assembly writes around `data` with
/// `abi.encodePacked` in new memory, and deploys it with the trusted `_createDeploy` and
/// `_createDeploy2`, which Solidity cannot express and which fail with `DeploymentFailed()`.
/// Data too long for the clone's two-byte sizes gets a creation code of the same length that
/// starts with a `REVERT` that underflows the stack, as upstream's does. Where the assembly
/// runs out of gas on purpose, `initCode` and `initCodeHash` revert without data.
/// @custom:solar-safe memory arithmetic
library LibCWIA {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Unable to deploy the clone.
    error DeploymentFailed();

    /// @dev The salt must start with either the zero address or `by`.
    error SaltDoesNotStartWith();

    /// @dev The ETH transfer has failed.
    error ETHTransferFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*           CLONES WITH IMMUTABLE ARGS OPERATIONS            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: This implementation of CWIA differs from the original implementation.
    // If the calldata is empty, it will emit a `ReceiveETH(uint256)` event and skip the `DELEGATECALL`.

    /// @dev Deploys a clone of `implementation` with immutable arguments encoded in `data`.
    function clone(address implementation, bytes memory data) internal returns (address instance) {
        instance = clone(0, implementation, data);
    }

    /// @dev Deploys a clone of `implementation` with immutable arguments encoded in `data`.
    /// Deposits `value` ETH during deployment.
    function clone(uint256 value, address implementation, bytes memory data)
        internal
        returns (address instance)
    {
        // The `creationSize` is `extraLength + 108`
        // The `runSize` is `creationSize - 10`.

        /**
         * ---------------------------------------------------------------------------------------------------+
         * CREATION (10 bytes)                                                                                |
         * ---------------------------------------------------------------------------------------------------|
         * Opcode     | Mnemonic          | Stack     | Memory                                                |
         * ---------------------------------------------------------------------------------------------------|
         * 61 runSize | PUSH2 runSize     | r         |                                                       |
         * 3d         | RETURNDATASIZE    | 0 r       |                                                       |
         * 81         | DUP2              | r 0 r     |                                                       |
         * 60 offset  | PUSH1 offset      | o r 0 r   |                                                       |
         * 3d         | RETURNDATASIZE    | 0 o r 0 r |                                                       |
         * 39         | CODECOPY          | 0 r       | [0..runSize): runtime code                            |
         * f3         | RETURN            |           | [0..runSize): runtime code                            |
         * ---------------------------------------------------------------------------------------------------|
         * RUNTIME (98 bytes + extraLength)                                                                   |
         * ---------------------------------------------------------------------------------------------------|
         * Opcode   | Mnemonic       | Stack                    | Memory                                      |
         * ---------------------------------------------------------------------------------------------------|
         *                                                                                                    |
         * ::: if no calldata, emit event & return w/o `DELEGATECALL` ::::::::::::::::::::::::::::::::::::::: |
         * 36       | CALLDATASIZE   | cds                      |                                             |
         * 60 0x2c  | PUSH1 0x2c     | 0x2c cds                 |                                             |
         * 57       | JUMPI          |                          |                                             |
         * 34       | CALLVALUE      | cv                       |                                             |
         * 3d       | RETURNDATASIZE | 0 cv                     |                                             |
         * 52       | MSTORE         |                          | [0..0x20): callvalue                        |
         * 7f sig   | PUSH32 0x9e..  | sig                      | [0..0x20): callvalue                        |
         * 59       | MSIZE          | 0x20 sig                 | [0..0x20): callvalue                        |
         * 3d       | RETURNDATASIZE | 0 0x20 sig               | [0..0x20): callvalue                        |
         * a1       | LOG1           |                          | [0..0x20): callvalue                        |
         * 00       | STOP           |                          | [0..0x20): callvalue                        |
         * 5b       | JUMPDEST       |                          |                                             |
         *                                                                                                    |
         * ::: copy calldata to memory :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
         * 36       | CALLDATASIZE   | cds                      |                                             |
         * 3d       | RETURNDATASIZE | 0 cds                    |                                             |
         * 3d       | RETURNDATASIZE | 0 0 cds                  |                                             |
         * 37       | CALLDATACOPY   |                          | [0..cds): calldata                          |
         *                                                                                                    |
         * ::: keep some values in stack :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
         * 3d       | RETURNDATASIZE | 0                        | [0..cds): calldata                          |
         * 3d       | RETURNDATASIZE | 0 0                      | [0..cds): calldata                          |
         * 3d       | RETURNDATASIZE | 0 0 0                    | [0..cds): calldata                          |
         * 3d       | RETURNDATASIZE | 0 0 0 0                  | [0..cds): calldata                          |
         * 61 extra | PUSH2 extra    | e 0 0 0 0                | [0..cds): calldata                          |
         *                                                                                                    |
         * ::: copy extra data to memory :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
         * 80       | DUP1           | e e 0 0 0 0              | [0..cds): calldata                          |
         * 60 0x62  | PUSH1 0x62     | 0x62 e e 0 0 0 0         | [0..cds): calldata                          |
         * 36       | CALLDATASIZE   | cds 0x62 e e 0 0 0 0     | [0..cds): calldata                          |
         * 39       | CODECOPY       | e 0 0 0 0                | [0..cds): calldata, [cds..cds+e): extraData |
         *                                                                                                    |
         * ::: delegate call to the implementation contract ::::::::::::::::::::::::::::::::::::::::::::::::: |
         * 36       | CALLDATASIZE   | cds e 0 0 0 0            | [0..cds): calldata, [cds..cds+e): extraData |
         * 01       | ADD            | cds+e 0 0 0 0            | [0..cds): calldata, [cds..cds+e): extraData |
         * 3d       | RETURNDATASIZE | 0 cds+e 0 0 0 0          | [0..cds): calldata, [cds..cds+e): extraData |
         * 73 addr  | PUSH20 addr    | addr 0 cds+e 0 0 0 0     | [0..cds): calldata, [cds..cds+e): extraData |
         * 5a       | GAS            | gas addr 0 cds+e 0 0 0 0 | [0..cds): calldata, [cds..cds+e): extraData |
         * f4       | DELEGATECALL   | success 0 0              | [0..cds): calldata, [cds..cds+e): extraData |
         *                                                                                                    |
         * ::: copy return data to memory ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
         * 3d       | RETURNDATASIZE | rds success 0 0          | [0..cds): calldata, [cds..cds+e): extraData |
         * 3d       | RETURNDATASIZE | rds rds success 0 0      | [0..cds): calldata, [cds..cds+e): extraData |
         * 93       | SWAP4          | 0 rds success 0 rds      | [0..cds): calldata, [cds..cds+e): extraData |
         * 80       | DUP1           | 0 0 rds success 0 rds    | [0..cds): calldata, [cds..cds+e): extraData |
         * 3e       | RETURNDATACOPY | success 0 rds            | [0..rds): returndata                        |
         *                                                                                                    |
         * 60 0x60  | PUSH1 0x60     | 0x60 success 0 rds       | [0..rds): returndata                        |
         * 57       | JUMPI          | 0 rds                    | [0..rds): returndata                        |
         *                                                                                                    |
         * ::: revert ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
         * fd       | REVERT         |                          | [0..rds): returndata                        |
         *                                                                                                    |
         * ::: return ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: |
         * 5b       | JUMPDEST       | 0 rds                    | [0..rds): returndata                        |
         * f3       | RETURN         |                          | [0..rds): returndata                        |
         * ---------------------------------------------------------------------------------------------------+
         */
        instance = _createDeploy(_creationCode(implementation, data), value);
    }

    /// @dev Deploys a deterministic clone of `implementation`
    /// with immutable arguments encoded in `data` and `salt`.
    function cloneDeterministic(address implementation, bytes memory data, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = cloneDeterministic(0, implementation, data, salt);
    }

    /// @dev Deploys a deterministic clone of `implementation`
    /// with immutable arguments encoded in `data` and `salt`.
    function cloneDeterministic(
        uint256 value,
        address implementation,
        bytes memory data,
        bytes32 salt
    ) internal returns (address instance) {
        instance = _createDeploy2(_creationCode(implementation, data), salt, value);
    }

    /// @dev Returns the initialization code hash of the clone of `implementation`
    /// using immutable arguments encoded in `data`.
    function initCode(address implementation, bytes memory data)
        internal
        pure
        returns (bytes memory result)
    {
        // Revert, as running out of gas does upstream, if `dataLength` is too big.
        // 0xffff - 0x02 - 0x62 = 0xff9b.
        if (data.length > 0xff9b) revert();
        result = _creationCode(implementation, data);
    }

    /// @dev Returns the initialization code hash of the clone of `implementation`
    /// using immutable arguments encoded in `data`.
    /// Used for mining vanity addresses with create2crunch.
    function initCodeHash(address implementation, bytes memory data)
        internal
        pure
        returns (bytes32 hash)
    {
        // Revert, as running out of gas does upstream, if `dataLength` is too big.
        // 0xffff - 0x02 - 0x62 = 0xff9b.
        if (data.length > 0xff9b) revert();
        hash = keccak256(_creationCode(implementation, data));
    }

    /// @dev Returns the address of the deterministic clone of
    /// `implementation` using immutable arguments encoded in `data`, with `salt`, by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddress(
        address implementation,
        bytes memory data,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        bytes32 hash = initCodeHash(implementation, data);
        predicted = predictDeterministicAddress(hash, salt, deployer);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      OTHER OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the address when a contract with initialization code hash,
    /// `hash`, is deployed with `salt`, by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddress(bytes32 hash, bytes32 salt, address deployer)
        internal
        pure
        returns (address predicted)
    {
        predicted = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, hash))))
        );
    }

    /// @dev Requires that `salt` starts with either the zero address or `by`.
    function checkStartsWith(bytes32 salt, address by) internal pure {
        // If the salt does not start with the zero address or `by`.
        uint256 prefix = uint256(salt) >> 96;
        if (prefix != 0 && prefix != uint160(by)) revert SaltDoesNotStartWith();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The creation code of the clone of `implementation` with the immutable arguments
    /// `data`, 0x6e bytes longer than `data`, laid out in the table of `clone`.
    /// @custom:solar-inline always
    function _creationCode(address implementation, bytes memory data)
        private
        pure
        returns (bytes memory)
    {
        // +2 bytes for telling how much data there is appended to the call.
        uint256 extraLength = data.length + 2;
        return abi.encodePacked(
            // Start with a `REVERT` if `extraLength` is too big. 0xffff - 0x62 + 0x01 = 0xff9e.
            extraLength < 0xff9e ? bytes1(0x61) : bytes1(0xfd),
            uint16(extraLength + 0x62),
            hex"3d81600a3d39f336602c57343d527f",
            // `keccak256("ReceiveETH(uint256)")`
            bytes32(0x9e4ac34f21c619cefc926c8bd93b54bf5a39c7ab2127a895af1cc0691d7e3dff),
            hex"593da1005b363d3d373d3d3d3d61",
            uint16(extraLength),
            hex"806062363936013d73",
            implementation,
            hex"5af43d3d93803e606057fd5bf3",
            data,
            uint16(extraLength)
        );
    }

    /// @dev Deploys `initcode` with `value` wei and returns the new address. Solidity creates
    /// only contracts it compiles.
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

    /// @dev Deploys `initcode` with `value` wei at the address `salt` selects. Solidity creates
    /// only contracts it compiles.
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
}
