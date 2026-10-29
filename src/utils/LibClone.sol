// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Minimal proxy library.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/LibClone.sol)
/// @author Minimal proxy by 0age (https://github.com/0age)
/// @author Clones with immutable args by wighawag, zefram.eth, Saw-mon & Natalie
/// (https://github.com/Saw-mon-and-Natalie/clones-with-immutable-args)
/// @author Minimal ERC1967 proxy by jtriley-eth (https://github.com/jtriley-eth/minimum-viable-proxy)
///
/// @dev Minimal proxy:
/// Although the sw0nt pattern saves 5 gas over the ERC1167 pattern during runtime,
/// it is not supported out-of-the-box on Etherscan. Hence, we choose to use the 0age pattern,
/// which saves 4 gas over the ERC1167 pattern during runtime, and has the smallest bytecode.
/// - Automatically verified on Etherscan.
///
/// @dev Minimal proxy (PUSH0 variant):
/// This is a new minimal proxy that uses the PUSH0 opcode introduced during Shanghai.
/// It is optimized first for minimal runtime gas, then for minimal bytecode.
/// The PUSH0 clone functions are intentionally postfixed with a jarring "_PUSH0" as
/// many EVM chains may not support the PUSH0 opcode in the early months after Shanghai.
/// Please use with caution.
/// - Automatically verified on Etherscan.
///
/// @dev Clones with immutable args (CWIA):
/// The implementation of CWIA here does NOT append the immutable args into the calldata
/// passed into delegatecall. It is simply an ERC1167 minimal proxy with the immutable arguments
/// appended to the back of the runtime bytecode.
/// - Uses the identity precompile (0x4) to copy args during deployment.
///
/// @dev Minimal ERC1967 proxy:
/// A minimal ERC1967 proxy, intended to be upgraded with UUPS.
/// This is NOT the same as ERC1967Factory's transparent proxy, which includes admin logic.
/// - Automatically verified on Etherscan.
///
/// @dev Minimal ERC1967 proxy with immutable args:
/// - Uses the identity precompile (0x4) to copy args during deployment.
/// - Automatically verified on Etherscan.
///
/// @dev ERC1967I proxy:
/// A variant of the minimal ERC1967 proxy, with a special code path that activates
/// if `calldatasize() == 1`. This code path skips the delegatecall and directly returns the
/// `implementation` address. The returned implementation is guaranteed to be valid if the
/// keccak256 of the proxy's code is equal to `ERC1967I_CODE_HASH`.
///
/// @dev ERC1967I proxy with immutable args:
/// A variant of the minimal ERC1967 proxy, with a special code path that activates
/// if `calldatasize() == 1`. This code path skips the delegatecall and directly returns the
/// - Uses the identity precompile (0x4) to copy args during deployment.
///
/// @dev Minimal ERC1967 beacon proxy:
/// A minimal beacon proxy, intended to be upgraded with an upgradable beacon.
/// - Automatically verified on Etherscan.
///
/// @dev Minimal ERC1967 beacon proxy with immutable args:
/// - Uses the identity precompile (0x4) to copy args during deployment.
/// - Automatically verified on Etherscan.
///
/// @dev ERC1967I beacon proxy:
/// A variant of the minimal ERC1967 beacon proxy, with a special code path that activates
/// if `calldatasize() == 1`. This code path skips the delegatecall and directly returns the
/// `implementation` address. The returned implementation is guaranteed to be valid if the
/// keccak256 of the proxy's code is equal to `ERC1967I_CODE_HASH`.
///
/// @dev ERC1967I proxy with immutable args:
/// A variant of the minimal ERC1967 beacon proxy, with a special code path that activates
/// if `calldatasize() == 1`. This code path skips the delegatecall and directly returns the
/// - Uses the identity precompile (0x4) to copy args during deployment.
///
/// The checked port builds each proxy's creation code from the bytes the assembly writes, assembled
/// with `abi.encodePacked` around its implementation or beacon, and deploys it with the trusted
/// `_createDeploy`, which fails with the same `DeploymentFailed()`. The `initCode` functions end
/// the encoding with a zero word that the trusted `_setLength` cuts off, so the bytes past their
/// result are zero wherever the free memory pointer ends. A proxy's arguments follow its runtime
/// code and are read back into a new buffer with the trusted `_codeRead`, which reads zeros past
/// the code as the assembly does: a short slice is copied first and, when its last byte is zero,
/// cut at the end of the arguments with `_setLength`; any other read is cut with the code's size
/// first. `implementationOf` reads the code's head the same way. Three deliberate differences:
/// arguments too long for the two-byte runtime size fail with `DeploymentFailed()` where the
/// assembly runs out of gas outside a deployment; reading the arguments of an account whose code is
/// shorter than the proxy's fails with `Panic(0x11)` instead of running out of gas; and `argLoad`
/// reads zeros past the end of `args`, where the assembly reads whatever memory follows, which the
/// `argsOn` functions leave zeroed.
/// @custom:solar-safe memory arithmetic
library LibClone {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The keccak256 of deployed code for the clone proxy,
    /// with the implementation set to `address(0)`.
    bytes32 internal constant CLONE_CODE_HASH =
        0x48db2cfdb2853fce0b464f1f93a1996469459df3ab6c812106074c4106a1eb1f;

    /// @dev The keccak256 of deployed code for the PUSH0 proxy,
    /// with the implementation set to `address(0)`.
    bytes32 internal constant PUSH0_CLONE_CODE_HASH =
        0x67bc6bde1b84d66e267c718ba44cf3928a615d29885537955cb43d44b3e789dc;

    /// @dev The keccak256 of deployed code for the ERC-1167 CWIA proxy,
    /// with the implementation set to `address(0)`.
    bytes32 internal constant CWIA_CODE_HASH =
        0x3cf92464268225a4513da40a34d967354684c32cd0edd67b5f668dfe3550e940;

    /// @dev The keccak256 of the deployed code for the ERC1967 proxy.
    bytes32 internal constant ERC1967_CODE_HASH =
        0xaaa52c8cc8a0e3fd27ce756cc6b4e70c51423e9b597b11f32d3e49f8b1fc890d;

    /// @dev The keccak256 of the deployed code for the ERC1967I proxy.
    bytes32 internal constant ERC1967I_CODE_HASH =
        0xce700223c0d4cea4583409accfc45adac4a093b3519998a9cbbe1504dadba6f7;

    /// @dev The keccak256 of the deployed code for the ERC1967 beacon proxy.
    bytes32 internal constant ERC1967_BEACON_PROXY_CODE_HASH =
        0x14044459af17bc4f0f5aa2f658cb692add77d1302c29fe2aebab005eea9d1162;

    /// @dev The keccak256 of the deployed code for the ERC1967 beacon proxy.
    bytes32 internal constant ERC1967I_BEACON_PROXY_CODE_HASH =
        0xf8c46d2793d5aa984eb827aeaba4b63aedcab80119212fce827309788735519a;

    /// @dev The creation code of a minimal proxy up to its implementation.
    bytes20 private constant _CLONE_HEAD = hex"602c3d8160093d39f33d3d3d3d363d3d37363d73";

    /// @dev The runtime code after the address.
    bytes13 private constant _CLONE_TAIL = hex"5af43d3d93803e602a57fd5bf3";

    /// @dev The creation code of a PUSH0 minimal proxy up to its implementation.
    bytes18 private constant _PUSH0_CLONE_HEAD = hex"602d5f8160095f39f35f5f365f5f37365f73";

    /// @dev The runtime code after the address.
    bytes16 private constant _PUSH0_CLONE_TAIL = hex"5af43d5f5f3e6029573d5ffd5b3d5ff3";

    /// @dev The creation code of a minimal ERC1967 proxy up to its implementation.
    bytes9 private constant _ERC1967_HEAD = hex"603d3d8160223d3973";

    /// @dev The runtime code after the address.
    bytes private constant _ERC1967_TAIL =
        hex"60095155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3";

    /// @dev The creation code of an ERC1967I proxy up to its implementation.
    bytes9 private constant _ERC1967I_HEAD = hex"60523d8160223d3973";

    /// @dev The runtime code after the address.
    bytes private constant _ERC1967I_TAIL =
        hex"600f5155f3365814604357363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d6000803e603e573d6000fd5b3d6000f35b6020600f3d393d51543d52593df3";

    /// @dev The creation code of an ERC1967 beacon proxy up to its beacon.
    bytes9 private constant _ERC1967_BEACON_PROXY_HEAD = hex"60523d8160223d3973";

    /// @dev The runtime code after the address.
    bytes private constant _ERC1967_BEACON_PROXY_TAIL =
        hex"60195155f3363d3d373d3d363d602036600436635c60da1b60e01b36527fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50545afa5036515af43d6000803e604d573d6000fd5b3d6000f3";

    /// @dev The creation code of an ERC1967I beacon proxy up to its beacon.
    bytes9 private constant _ERC1967I_BEACON_PROXY_HEAD = hex"60573d8160223d3973";

    /// @dev The runtime code after the address.
    bytes private constant _ERC1967I_BEACON_PROXY_TAIL =
        hex"60195155f3363d3d373d3d363d602036600436635c60da1b60e01b36527fa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50545afa361460525736515af43d600060013e6052573d6001fd5b3d6001f3";

    /// @dev The creation code of the ERC1967 bootstrap up to its authorized
    /// upgrader.
    bytes12 private constant _ERC1967_BOOTSTRAP_HEAD = hex"606880600a3d393df3fe3373";

    /// @dev The runtime code after the address.
    bytes private constant _ERC1967_BOOTSTRAP_TAIL =
        hex"0338573d3560601c7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc55601436116049575b005b363d3d373d3d6014360360143d3560601c5af46047573d6000383e3d38fd";

    /// @dev The creation code of a clone with arguments, between the runtime
    /// size it pushes and the address; its runtime is 0x2d bytes before the
    /// arguments.
    bytes17 private constant _CWIA_ARGS_HEAD = hex"3d81600a3d39f3363d3d373d3d3d363d73";

    /// @dev The runtime code of a clone with arguments after the address.
    bytes15 private constant _CWIA_TAIL = hex"5af43d82803e903d91602b57fd5bf3";

    /// @dev The creation code of an ERC1967 proxy of any kind with arguments,
    /// between the runtime size it pushes and the address. The runtime is 0x3d
    /// bytes before the arguments for a minimal proxy, 0x52 for an ERC1967I
    /// proxy or a beacon proxy, and 0x57 for an ERC1967I beacon proxy.
    bytes7 private constant _ERC1967_ARGS_HEAD = hex"3d8160233d3973";

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
    /*                  MINIMAL PROXY OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a clone of `implementation`.
    function clone(address implementation) internal returns (address instance) {
        instance = clone(0, implementation);
    }

    /// @dev Deploys a clone of `implementation`.
    /// Deposits `value` ETH during deployment.
    function clone(uint256 value, address implementation) internal returns (address instance) {
        return _createDeploy(abi.encodePacked(_CLONE_HEAD, implementation, _CLONE_TAIL), value);
    }

    /// @dev Deploys a deterministic clone of `implementation` with `salt`.
    function cloneDeterministic(address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = cloneDeterministic(0, implementation, salt);
    }

    /// @dev Deploys a deterministic clone of `implementation` with `salt`.
    /// Deposits `value` ETH during deployment.
    function cloneDeterministic(uint256 value, address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        return _createDeploy2(
            abi.encodePacked(_CLONE_HEAD, implementation, _CLONE_TAIL), salt, value
        );
    }

    /// @dev Returns the initialization code of the clone of `implementation`.
    function initCode(address implementation) internal pure returns (bytes memory c) {
        return
            _withoutZeroWord(abi.encodePacked(_CLONE_HEAD, implementation, _CLONE_TAIL, bytes32(0)));
    }

    /// @dev Returns the initialization code hash of the clone of `implementation`.
    function initCodeHash(address implementation) internal pure returns (bytes32 hash) {
        return keccak256(abi.encodePacked(_CLONE_HEAD, implementation, _CLONE_TAIL));
    }

    /// @dev Returns the address of the clone of `implementation`, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddress(address implementation, bytes32 salt, address deployer)
        internal
        pure
        returns (address predicted)
    {
        predicted = predictDeterministicAddress(initCodeHash(implementation), salt, deployer);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*          MINIMAL PROXY OPERATIONS (PUSH0 VARIANT)          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a PUSH0 clone of `implementation`.
    function clone_PUSH0(address implementation) internal returns (address instance) {
        instance = clone_PUSH0(0, implementation);
    }

    /// @dev Deploys a PUSH0 clone of `implementation`.
    /// Deposits `value` ETH during deployment.
    function clone_PUSH0(uint256 value, address implementation)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(_PUSH0_CLONE_HEAD, implementation, _PUSH0_CLONE_TAIL), value
        );
    }

    /// @dev Deploys a deterministic PUSH0 clone of `implementation` with `salt`.
    function cloneDeterministic_PUSH0(address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = cloneDeterministic_PUSH0(0, implementation, salt);
    }

    /// @dev Deploys a deterministic PUSH0 clone of `implementation` with `salt`.
    /// Deposits `value` ETH during deployment.
    function cloneDeterministic_PUSH0(uint256 value, address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        return _createDeploy2(
            abi.encodePacked(_PUSH0_CLONE_HEAD, implementation, _PUSH0_CLONE_TAIL), salt, value
        );
    }

    /// @dev Returns the initialization code of the PUSH0 clone of `implementation`.
    function initCode_PUSH0(address implementation) internal pure returns (bytes memory c) {
        return _withoutZeroWord(
            abi.encodePacked(_PUSH0_CLONE_HEAD, implementation, _PUSH0_CLONE_TAIL, bytes32(0))
        );
    }

    /// @dev Returns the initialization code hash of the PUSH0 clone of `implementation`.
    function initCodeHash_PUSH0(address implementation) internal pure returns (bytes32 hash) {
        return keccak256(abi.encodePacked(_PUSH0_CLONE_HEAD, implementation, _PUSH0_CLONE_TAIL));
    }

    /// @dev Returns the address of the PUSH0 clone of `implementation`, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddress_PUSH0(
        address implementation,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(initCodeHash_PUSH0(implementation), salt, deployer);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*           CLONES WITH IMMUTABLE ARGS OPERATIONS            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a clone of `implementation` with immutable arguments encoded in `args`.
    function clone(address implementation, bytes memory args) internal returns (address instance) {
        instance = clone(0, implementation, args);
    }

    /// @dev Deploys a clone of `implementation` with immutable arguments encoded in `args`.
    /// Deposits `value` ETH during deployment.
    function clone(uint256 value, address implementation, bytes memory args)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(
                hex"61", _runtimeSize(0x2d, args), _CWIA_ARGS_HEAD, implementation, _CWIA_TAIL, args
            ),
            value
        );
    }

    /// @dev Deploys a deterministic clone of `implementation`
    /// with immutable arguments encoded in `args` and `salt`.
    function cloneDeterministic(address implementation, bytes memory args, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = cloneDeterministic(0, implementation, args, salt);
    }

    /// @dev Deploys a deterministic clone of `implementation`
    /// with immutable arguments encoded in `args` and `salt`.
    function cloneDeterministic(
        uint256 value,
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (address instance) {
        return _createDeploy2(
            abi.encodePacked(
                hex"61", _runtimeSize(0x2d, args), _CWIA_ARGS_HEAD, implementation, _CWIA_TAIL, args
            ),
            salt,
            value
        );
    }

    /// @dev Deploys a deterministic clone of `implementation`
    /// with immutable arguments encoded in `args` and `salt`.
    /// This method does not revert if the clone has already been deployed.
    function createDeterministicClone(address implementation, bytes memory args, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicClone(0, implementation, args, salt);
    }

    /// @dev Deploys a deterministic clone of `implementation`
    /// with immutable arguments encoded in `args` and `salt`.
    /// This method does not revert if the clone has already been deployed.
    function createDeterministicClone(
        uint256 value,
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (bool alreadyDeployed, address instance) {
        return _createDeterministic(
            abi.encodePacked(
                hex"61", _runtimeSize(0x2d, args), _CWIA_ARGS_HEAD, implementation, _CWIA_TAIL, args
            ),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the clone of `implementation`
    /// using immutable arguments encoded in `args`.
    function initCode(address implementation, bytes memory args)
        internal
        pure
        returns (bytes memory c)
    {
        return _withoutZeroWord(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x2d, args),
                _CWIA_ARGS_HEAD,
                implementation,
                _CWIA_TAIL,
                args,
                bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the clone of `implementation`
    /// using immutable arguments encoded in `args`.
    function initCodeHash(address implementation, bytes memory args)
        internal
        pure
        returns (bytes32 hash)
    {
        return keccak256(
            abi.encodePacked(
                hex"61", _runtimeSize(0x2d, args), _CWIA_ARGS_HEAD, implementation, _CWIA_TAIL, args
            )
        );
    }

    /// @dev Returns the address of the clone of
    /// `implementation` using immutable arguments encoded in `args`, with `salt`, by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddress(
        address implementation,
        bytes memory data,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(initCodeHash(implementation, data), salt, deployer);
    }

    /// @dev Equivalent to `argsOnClone(instance, 0, 2 ** 256 - 1)`.
    function argsOnClone(address instance) internal view returns (bytes memory args) {
        return _argsOn(instance, 0x2d);
    }

    /// @dev Equivalent to `argsOnClone(instance, start, 2 ** 256 - 1)`.
    function argsOnClone(address instance, uint256 start)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x2d, start);
    }

    /// @dev Returns a slice of the immutable arguments on `instance` from `start` to `end`.
    /// `start` and `end` will be clamped to the range `[0, args.length]`.
    /// The `instance` MUST be deployed via the clone with immutable args functions.
    /// Otherwise, the behavior is undefined.
    /// Out-of-gas reverts if `instance` does not have any code.
    /// @custom:solar-inline always
    function argsOnClone(address instance, uint256 start, uint256 end)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x2d, start, end);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              MINIMAL ERC1967 PROXY OPERATIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: The ERC1967 proxy here is intended to be upgraded with UUPS.
    // This is NOT the same as ERC1967Factory's transparent proxy, which includes admin logic.

    /// @dev Deploys a minimal ERC1967 proxy with `implementation`.
    function deployERC1967(address implementation) internal returns (address instance) {
        instance = deployERC1967(0, implementation);
    }

    /// @dev Deploys a minimal ERC1967 proxy with `implementation`.
    /// Deposits `value` ETH during deployment.
    function deployERC1967(uint256 value, address implementation)
        internal
        returns (address instance)
    {
        return _createDeploy(abi.encodePacked(_ERC1967_HEAD, implementation, _ERC1967_TAIL), value);
    }

    /// @dev Deploys a deterministic minimal ERC1967 proxy with `implementation` and `salt`.
    function deployDeterministicERC1967(address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967(0, implementation, salt);
    }

    /// @dev Deploys a deterministic minimal ERC1967 proxy with `implementation` and `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967(uint256 value, address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        return
            _createDeploy2(
                abi.encodePacked(_ERC1967_HEAD, implementation, _ERC1967_TAIL), salt, value
            );
    }

    /// @dev Creates a deterministic minimal ERC1967 proxy with `implementation` and `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967(address implementation, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967(0, implementation, salt);
    }

    /// @dev Creates a deterministic minimal ERC1967 proxy with `implementation` and `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967(uint256 value, address implementation, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return _createDeterministic(
            abi.encodePacked(_ERC1967_HEAD, implementation, _ERC1967_TAIL), salt, value
        );
    }

    /// @dev Returns the initialization code of the minimal ERC1967 proxy of `implementation`.
    function initCodeERC1967(address implementation) internal pure returns (bytes memory c) {
        return _withoutZeroWord(
            abi.encodePacked(_ERC1967_HEAD, implementation, _ERC1967_TAIL, bytes32(0))
        );
    }

    /// @dev Returns the initialization code hash of the minimal ERC1967 proxy of `implementation`.
    function initCodeHashERC1967(address implementation) internal pure returns (bytes32 hash) {
        return keccak256(abi.encodePacked(_ERC1967_HEAD, implementation, _ERC1967_TAIL));
    }

    /// @dev Returns the address of the ERC1967 proxy of `implementation`, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967(
        address implementation,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(initCodeHashERC1967(implementation), salt, deployer);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*    MINIMAL ERC1967 PROXY WITH IMMUTABLE ARGS OPERATIONS    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a minimal ERC1967 proxy with `implementation` and `args`.
    function deployERC1967(address implementation, bytes memory args)
        internal
        returns (address instance)
    {
        instance = deployERC1967(0, implementation, args);
    }

    /// @dev Deploys a minimal ERC1967 proxy with `implementation` and `args`.
    /// Deposits `value` ETH during deployment.
    function deployERC1967(uint256 value, address implementation, bytes memory args)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x3d, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967_TAIL,
                args
            ),
            value
        );
    }

    /// @dev Deploys a deterministic minimal ERC1967 proxy with `implementation`, `args` and `salt`.
    function deployDeterministicERC1967(address implementation, bytes memory args, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967(0, implementation, args, salt);
    }

    /// @dev Deploys a deterministic minimal ERC1967 proxy with `implementation`, `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967(
        uint256 value,
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (address instance) {
        return _createDeploy2(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x3d, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Creates a deterministic minimal ERC1967 proxy with `implementation`, `args` and `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967(address implementation, bytes memory args, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967(0, implementation, args, salt);
    }

    /// @dev Creates a deterministic minimal ERC1967 proxy with `implementation`, `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967(
        uint256 value,
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (bool alreadyDeployed, address instance) {
        return _createDeterministic(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x3d, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the minimal ERC1967 proxy of `implementation` and `args`.
    function initCodeERC1967(address implementation, bytes memory args)
        internal
        pure
        returns (bytes memory c)
    {
        return _withoutZeroWord(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x3d, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967_TAIL,
                args,
                bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the minimal ERC1967 proxy of `implementation` and `args`.
    function initCodeHashERC1967(address implementation, bytes memory args)
        internal
        pure
        returns (bytes32 hash)
    {
        return keccak256(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x3d, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967_TAIL,
                args
            )
        );
    }

    /// @dev Returns the address of the ERC1967 proxy of `implementation`, `args`, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967(
        address implementation,
        bytes memory args,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967(implementation, args), salt, deployer
        );
    }

    /// @dev Equivalent to `argsOnERC1967(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967(address instance) internal view returns (bytes memory args) {
        return _argsOn(instance, 0x3d);
    }

    /// @dev Equivalent to `argsOnERC1967(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967(address instance, uint256 start)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x3d, start);
    }

    /// @dev Returns a slice of the immutable arguments on `instance` from `start` to `end`.
    /// `start` and `end` will be clamped to the range `[0, args.length]`.
    /// The `instance` MUST be deployed via the ERC1967 with immutable args functions.
    /// Otherwise, the behavior is undefined.
    /// Out-of-gas reverts if `instance` does not have any code.
    function argsOnERC1967(address instance, uint256 start, uint256 end)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x3d, start, end);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 ERC1967I PROXY OPERATIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: This proxy has a special code path that activates if `calldatasize() == 1`.
    // This code path skips the delegatecall and directly returns the `implementation` address.
    // The returned implementation is guaranteed to be valid if the keccak256 of the
    // proxy's code is equal to `ERC1967I_CODE_HASH`.

    /// @dev Deploys a ERC1967I proxy with `implementation`.
    function deployERC1967I(address implementation) internal returns (address instance) {
        instance = deployERC1967I(0, implementation);
    }

    /// @dev Deploys a ERC1967I proxy with `implementation`.
    /// Deposits `value` ETH during deployment.
    function deployERC1967I(uint256 value, address implementation)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(_ERC1967I_HEAD, implementation, _ERC1967I_TAIL), value
        );
    }

    /// @dev Deploys a deterministic ERC1967I proxy with `implementation` and `salt`.
    function deployDeterministicERC1967I(address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967I(0, implementation, salt);
    }

    /// @dev Deploys a deterministic ERC1967I proxy with `implementation` and `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967I(uint256 value, address implementation, bytes32 salt)
        internal
        returns (address instance)
    {
        return _createDeploy2(
            abi.encodePacked(_ERC1967I_HEAD, implementation, _ERC1967I_TAIL), salt, value
        );
    }

    /// @dev Creates a deterministic ERC1967I proxy with `implementation` and `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967I(address implementation, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967I(0, implementation, salt);
    }

    /// @dev Creates a deterministic ERC1967I proxy with `implementation` and `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967I(uint256 value, address implementation, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return _createDeterministic(
            abi.encodePacked(_ERC1967I_HEAD, implementation, _ERC1967I_TAIL), salt, value
        );
    }

    /// @dev Returns the initialization code of the ERC1967I proxy of `implementation`.
    function initCodeERC1967I(address implementation) internal pure returns (bytes memory c) {
        return _withoutZeroWord(
            abi.encodePacked(_ERC1967I_HEAD, implementation, _ERC1967I_TAIL, bytes32(0))
        );
    }

    /// @dev Returns the initialization code hash of the ERC1967I proxy of `implementation`.
    function initCodeHashERC1967I(address implementation) internal pure returns (bytes32 hash) {
        return keccak256(abi.encodePacked(_ERC1967I_HEAD, implementation, _ERC1967I_TAIL));
    }

    /// @dev Returns the address of the ERC1967I proxy of `implementation`, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967I(
        address implementation,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967I(implementation), salt, deployer
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*       ERC1967I PROXY WITH IMMUTABLE ARGS OPERATIONS        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a minimal ERC1967I proxy with `implementation` and `args`.
    function deployERC1967I(address implementation, bytes memory args) internal returns (address) {
        return deployERC1967I(0, implementation, args);
    }

    /// @dev Deploys a minimal ERC1967I proxy with `implementation` and `args`.
    /// Deposits `value` ETH during deployment.
    function deployERC1967I(uint256 value, address implementation, bytes memory args)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967I_TAIL,
                args
            ),
            value
        );
    }

    /// @dev Deploys a deterministic ERC1967I proxy with `implementation`, `args`, and `salt`.
    function deployDeterministicERC1967I(address implementation, bytes memory args, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967I(0, implementation, args, salt);
    }

    /// @dev Deploys a deterministic ERC1967I proxy with `implementation`, `args`, and `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967I(
        uint256 value,
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (address instance) {
        return _createDeploy2(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967I_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Creates a deterministic ERC1967I proxy with `implementation`, `args` and `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967I(address implementation, bytes memory args, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967I(0, implementation, args, salt);
    }

    /// @dev Creates a deterministic ERC1967I proxy with `implementation`, `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967I(
        uint256 value,
        address implementation,
        bytes memory args,
        bytes32 salt
    ) internal returns (bool alreadyDeployed, address instance) {
        return _createDeterministic(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967I_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the ERC1967I proxy of `implementation` and `args`.
    function initCodeERC1967I(address implementation, bytes memory args)
        internal
        pure
        returns (bytes memory c)
    {
        return _withoutZeroWord(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967I_TAIL,
                args,
                bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the ERC1967I proxy of `implementation` and `args.
    function initCodeHashERC1967I(address implementation, bytes memory args)
        internal
        pure
        returns (bytes32 hash)
    {
        return keccak256(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                implementation,
                _ERC1967I_TAIL,
                args
            )
        );
    }

    /// @dev Returns the address of the ERC1967I proxy of `implementation`, `args` with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967I(
        address implementation,
        bytes memory args,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967I(implementation, args), salt, deployer
        );
    }

    /// @dev Equivalent to `argsOnERC1967I(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967I(address instance) internal view returns (bytes memory args) {
        return _argsOn(instance, 0x52);
    }

    /// @dev Equivalent to `argsOnERC1967I(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967I(address instance, uint256 start)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x52, start);
    }

    /// @dev Returns a slice of the immutable arguments on `instance` from `start` to `end`.
    /// `start` and `end` will be clamped to the range `[0, args.length]`.
    /// The `instance` MUST be deployed via the ERC1967 with immutable args functions.
    /// Otherwise, the behavior is undefined.
    /// Out-of-gas reverts if `instance` does not have any code.
    function argsOnERC1967I(address instance, uint256 start, uint256 end)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x52, start, end);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                ERC1967 BOOTSTRAP OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // A bootstrap is a minimal UUPS implementation that allows an ERC1967 proxy
    // pointing to it to be upgraded. The ERC1967 proxy can then be deployed to a
    // deterministic address independent of the implementation:
    // ```
    //     address bootstrap = LibClone.erc1967Bootstrap();
    //     address instance = LibClone.deployDeterministicERC1967(0, bootstrap, salt);
    //     LibClone.bootstrapERC1967(bootstrap, implementation);
    // ```

    /// @dev Deploys the ERC1967 bootstrap if it has not been deployed.
    function erc1967Bootstrap() internal returns (address) {
        return erc1967Bootstrap(address(this));
    }

    /// @dev Deploys the ERC1967 bootstrap if it has not been deployed.
    function erc1967Bootstrap(address authorizedUpgrader) internal returns (address bootstrap) {
        bytes memory c = initCodeERC1967Bootstrap(authorizedUpgrader);
        bootstrap = predictDeterministicAddress(keccak256(c), bytes32(0), address(this));
        if (bootstrap.code.length == 0) _createDeploy2(c, bytes32(0), 0);
    }

    /// @dev Replaces the implementation at `instance`.
    function bootstrapERC1967(address instance, address implementation) internal {
        // The bootstrap takes the new implementation as its whole calldata.
        (bool success,,) = _callBounded(instance, 0, gasleft(), abi.encodePacked(implementation), 0);
        if (!success) revert DeploymentFailed();
    }

    /// @dev Replaces the implementation at `instance`, and then call it with `data`.
    function bootstrapERC1967AndCall(address instance, address implementation, bytes memory data)
        internal
    {
        // The bootstrap takes the new implementation, then calls it with the rest.
        (bool success, bytes memory result) = instance.call(abi.encodePacked(implementation, data));
        if (!success) {
            if (result.length == 0) revert DeploymentFailed();
            _revertRaw(result);
        }
    }

    /// @dev Returns the implementation address of the ERC1967 bootstrap for this contract.
    function predictDeterministicAddressERC1967Bootstrap() internal view returns (address) {
        return predictDeterministicAddressERC1967Bootstrap(address(this), address(this));
    }

    /// @dev Returns the implementation address of the ERC1967 bootstrap for this contract.
    function predictDeterministicAddressERC1967Bootstrap(
        address authorizedUpgrader,
        address deployer
    ) internal pure returns (address) {
        bytes32 hash = initCodeHashERC1967Bootstrap(authorizedUpgrader);
        return predictDeterministicAddress(hash, bytes32(0), deployer);
    }

    /// @dev Returns the initialization code of the ERC1967 bootstrap.
    function initCodeERC1967Bootstrap(address authorizedUpgrader)
        internal
        pure
        returns (bytes memory c)
    {
        return _withoutZeroWord(
            abi.encodePacked(
                _ERC1967_BOOTSTRAP_HEAD, authorizedUpgrader, _ERC1967_BOOTSTRAP_TAIL, bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the ERC1967 bootstrap.
    function initCodeHashERC1967Bootstrap(address authorizedUpgrader)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(_ERC1967_BOOTSTRAP_HEAD, authorizedUpgrader, _ERC1967_BOOTSTRAP_TAIL)
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*          MINIMAL ERC1967 BEACON PROXY OPERATIONS           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: If you use this proxy, you MUST make sure that the beacon is a
    // valid ERC1967 beacon. This means that the beacon must always return a valid
    // address upon a staticcall to `implementation()`, given sufficient gas.
    // For performance, the deployment operations and the proxy assumes that the
    // beacon is always valid and will NOT validate it.

    /// @dev Deploys a minimal ERC1967 beacon proxy.
    function deployERC1967BeaconProxy(address beacon) internal returns (address instance) {
        instance = deployERC1967BeaconProxy(0, beacon);
    }

    /// @dev Deploys a minimal ERC1967 beacon proxy.
    /// Deposits `value` ETH during deployment.
    function deployERC1967BeaconProxy(uint256 value, address beacon)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(_ERC1967_BEACON_PROXY_HEAD, beacon, _ERC1967_BEACON_PROXY_TAIL), value
        );
    }

    /// @dev Deploys a deterministic minimal ERC1967 beacon proxy with `salt`.
    function deployDeterministicERC1967BeaconProxy(address beacon, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967BeaconProxy(0, beacon, salt);
    }

    /// @dev Deploys a deterministic minimal ERC1967 beacon proxy with `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967BeaconProxy(uint256 value, address beacon, bytes32 salt)
        internal
        returns (address instance)
    {
        return _createDeploy2(
            abi.encodePacked(_ERC1967_BEACON_PROXY_HEAD, beacon, _ERC1967_BEACON_PROXY_TAIL),
            salt,
            value
        );
    }

    /// @dev Creates a deterministic minimal ERC1967 beacon proxy with `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967BeaconProxy(address beacon, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967BeaconProxy(0, beacon, salt);
    }

    /// @dev Creates a deterministic minimal ERC1967 beacon proxy with `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967BeaconProxy(uint256 value, address beacon, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return _createDeterministic(
            abi.encodePacked(_ERC1967_BEACON_PROXY_HEAD, beacon, _ERC1967_BEACON_PROXY_TAIL),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the minimal ERC1967 beacon proxy.
    function initCodeERC1967BeaconProxy(address beacon) internal pure returns (bytes memory c) {
        return _withoutZeroWord(
            abi.encodePacked(
                _ERC1967_BEACON_PROXY_HEAD, beacon, _ERC1967_BEACON_PROXY_TAIL, bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the minimal ERC1967 beacon proxy.
    function initCodeHashERC1967BeaconProxy(address beacon) internal pure returns (bytes32 hash) {
        return
            keccak256(
                abi.encodePacked(_ERC1967_BEACON_PROXY_HEAD, beacon, _ERC1967_BEACON_PROXY_TAIL)
            );
    }

    /// @dev Returns the address of the ERC1967 beacon proxy, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967BeaconProxy(
        address beacon,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967BeaconProxy(beacon), salt, deployer
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*    ERC1967 BEACON PROXY WITH IMMUTABLE ARGS OPERATIONS     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a minimal ERC1967 beacon proxy with `args`.
    function deployERC1967BeaconProxy(address beacon, bytes memory args)
        internal
        returns (address instance)
    {
        instance = deployERC1967BeaconProxy(0, beacon, args);
    }

    /// @dev Deploys a minimal ERC1967 beacon proxy with `args`.
    /// Deposits `value` ETH during deployment.
    function deployERC1967BeaconProxy(uint256 value, address beacon, bytes memory args)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967_BEACON_PROXY_TAIL,
                args
            ),
            value
        );
    }

    /// @dev Deploys a deterministic minimal ERC1967 beacon proxy with `args` and `salt`.
    function deployDeterministicERC1967BeaconProxy(address beacon, bytes memory args, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967BeaconProxy(0, beacon, args, salt);
    }

    /// @dev Deploys a deterministic minimal ERC1967 beacon proxy with `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967BeaconProxy(
        uint256 value,
        address beacon,
        bytes memory args,
        bytes32 salt
    ) internal returns (address instance) {
        return _createDeploy2(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967_BEACON_PROXY_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Creates a deterministic minimal ERC1967 beacon proxy with `args` and `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967BeaconProxy(address beacon, bytes memory args, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967BeaconProxy(0, beacon, args, salt);
    }

    /// @dev Creates a deterministic minimal ERC1967 beacon proxy with `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967BeaconProxy(
        uint256 value,
        address beacon,
        bytes memory args,
        bytes32 salt
    ) internal returns (bool alreadyDeployed, address instance) {
        return _createDeterministic(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967_BEACON_PROXY_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the minimal ERC1967 beacon proxy.
    function initCodeERC1967BeaconProxy(address beacon, bytes memory args)
        internal
        pure
        returns (bytes memory c)
    {
        return _withoutZeroWord(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967_BEACON_PROXY_TAIL,
                args,
                bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the minimal ERC1967 beacon proxy with `args`.
    function initCodeHashERC1967BeaconProxy(address beacon, bytes memory args)
        internal
        pure
        returns (bytes32 hash)
    {
        return keccak256(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x52, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967_BEACON_PROXY_TAIL,
                args
            )
        );
    }

    /// @dev Returns the address of the ERC1967 beacon proxy with `args`, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967BeaconProxy(
        address beacon,
        bytes memory args,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967BeaconProxy(beacon, args), salt, deployer
        );
    }

    /// @dev Equivalent to `argsOnERC1967BeaconProxy(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967BeaconProxy(address instance) internal view returns (bytes memory args) {
        return _argsOn(instance, 0x52);
    }

    /// @dev Equivalent to `argsOnERC1967BeaconProxy(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967BeaconProxy(address instance, uint256 start)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x52, start);
    }

    /// @dev Returns a slice of the immutable arguments on `instance` from `start` to `end`.
    /// `start` and `end` will be clamped to the range `[0, args.length]`.
    /// The `instance` MUST be deployed via the ERC1967 beacon proxy with immutable args functions.
    /// Otherwise, the behavior is undefined.
    /// Out-of-gas reverts if `instance` does not have any code.
    function argsOnERC1967BeaconProxy(address instance, uint256 start, uint256 end)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x52, start, end);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              ERC1967I BEACON PROXY OPERATIONS              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: This proxy has a special code path that activates if `calldatasize() == 1`.
    // This code path skips the delegatecall and directly returns the `implementation` address.
    // The returned implementation is guaranteed to be valid if the keccak256 of the
    // proxy's code is equal to `ERC1967_BEACON_PROXY_CODE_HASH`.
    //
    // If you use this proxy, you MUST make sure that the beacon is a
    // valid ERC1967 beacon. This means that the beacon must always return a valid
    // address upon a staticcall to `implementation()`, given sufficient gas.
    // For performance, the deployment operations and the proxy assumes that the
    // beacon is always valid and will NOT validate it.

    /// @dev Deploys a ERC1967I beacon proxy.
    function deployERC1967IBeaconProxy(address beacon) internal returns (address instance) {
        instance = deployERC1967IBeaconProxy(0, beacon);
    }

    /// @dev Deploys a ERC1967I beacon proxy.
    /// Deposits `value` ETH during deployment.
    function deployERC1967IBeaconProxy(uint256 value, address beacon)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(_ERC1967I_BEACON_PROXY_HEAD, beacon, _ERC1967I_BEACON_PROXY_TAIL),
            value
        );
    }

    /// @dev Deploys a deterministic ERC1967I beacon proxy with `salt`.
    function deployDeterministicERC1967IBeaconProxy(address beacon, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967IBeaconProxy(0, beacon, salt);
    }

    /// @dev Deploys a deterministic ERC1967I beacon proxy with `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967IBeaconProxy(uint256 value, address beacon, bytes32 salt)
        internal
        returns (address instance)
    {
        return _createDeploy2(
            abi.encodePacked(_ERC1967I_BEACON_PROXY_HEAD, beacon, _ERC1967I_BEACON_PROXY_TAIL),
            salt,
            value
        );
    }

    /// @dev Creates a deterministic ERC1967I beacon proxy with `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967IBeaconProxy(address beacon, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967IBeaconProxy(0, beacon, salt);
    }

    /// @dev Creates a deterministic ERC1967I beacon proxy with `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967IBeaconProxy(uint256 value, address beacon, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return _createDeterministic(
            abi.encodePacked(_ERC1967I_BEACON_PROXY_HEAD, beacon, _ERC1967I_BEACON_PROXY_TAIL),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the ERC1967I beacon proxy.
    function initCodeERC1967IBeaconProxy(address beacon) internal pure returns (bytes memory c) {
        return _withoutZeroWord(
            abi.encodePacked(
                _ERC1967I_BEACON_PROXY_HEAD, beacon, _ERC1967I_BEACON_PROXY_TAIL, bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the ERC1967I beacon proxy.
    function initCodeHashERC1967IBeaconProxy(address beacon) internal pure returns (bytes32 hash) {
        return keccak256(
            abi.encodePacked(_ERC1967I_BEACON_PROXY_HEAD, beacon, _ERC1967I_BEACON_PROXY_TAIL)
        );
    }

    /// @dev Returns the address of the ERC1967I beacon proxy, with `salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967IBeaconProxy(
        address beacon,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967IBeaconProxy(beacon), salt, deployer
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*    ERC1967I BEACON PROXY WITH IMMUTABLE ARGS OPERATIONS    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys a ERC1967I beacon proxy with `args.
    function deployERC1967IBeaconProxy(address beacon, bytes memory args)
        internal
        returns (address instance)
    {
        instance = deployERC1967IBeaconProxy(0, beacon, args);
    }

    /// @dev Deploys a ERC1967I beacon proxy with `args.
    /// Deposits `value` ETH during deployment.
    function deployERC1967IBeaconProxy(uint256 value, address beacon, bytes memory args)
        internal
        returns (address instance)
    {
        return _createDeploy(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x57, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967I_BEACON_PROXY_TAIL,
                args
            ),
            value
        );
    }

    /// @dev Deploys a deterministic ERC1967I beacon proxy with `args` and `salt`.
    function deployDeterministicERC1967IBeaconProxy(address beacon, bytes memory args, bytes32 salt)
        internal
        returns (address instance)
    {
        instance = deployDeterministicERC1967IBeaconProxy(0, beacon, args, salt);
    }

    /// @dev Deploys a deterministic ERC1967I beacon proxy with `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    function deployDeterministicERC1967IBeaconProxy(
        uint256 value,
        address beacon,
        bytes memory args,
        bytes32 salt
    ) internal returns (address instance) {
        return _createDeploy2(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x57, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967I_BEACON_PROXY_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Creates a deterministic ERC1967I beacon proxy with `args` and `salt`.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967IBeaconProxy(address beacon, bytes memory args, bytes32 salt)
        internal
        returns (bool alreadyDeployed, address instance)
    {
        return createDeterministicERC1967IBeaconProxy(0, beacon, args, salt);
    }

    /// @dev Creates a deterministic ERC1967I beacon proxy with `args` and `salt`.
    /// Deposits `value` ETH during deployment.
    /// Note: This method is intended for use in ERC4337 factories,
    /// which are expected to NOT revert if the proxy is already deployed.
    function createDeterministicERC1967IBeaconProxy(
        uint256 value,
        address beacon,
        bytes memory args,
        bytes32 salt
    ) internal returns (bool alreadyDeployed, address instance) {
        return _createDeterministic(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x57, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967I_BEACON_PROXY_TAIL,
                args
            ),
            salt,
            value
        );
    }

    /// @dev Returns the initialization code of the ERC1967I beacon proxy with `args`.
    function initCodeERC1967IBeaconProxy(address beacon, bytes memory args)
        internal
        pure
        returns (bytes memory c)
    {
        return _withoutZeroWord(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x57, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967I_BEACON_PROXY_TAIL,
                args,
                bytes32(0)
            )
        );
    }

    /// @dev Returns the initialization code hash of the ERC1967I beacon proxy with `args`.
    function initCodeHashERC1967IBeaconProxy(address beacon, bytes memory args)
        internal
        pure
        returns (bytes32 hash)
    {
        return keccak256(
            abi.encodePacked(
                hex"61",
                _runtimeSize(0x57, args),
                _ERC1967_ARGS_HEAD,
                beacon,
                _ERC1967I_BEACON_PROXY_TAIL,
                args
            )
        );
    }

    /// @dev Returns the address of the ERC1967I beacon proxy, with  `args` and salt` by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddressERC1967IBeaconProxy(
        address beacon,
        bytes memory args,
        bytes32 salt,
        address deployer
    ) internal pure returns (address predicted) {
        predicted = predictDeterministicAddress(
            initCodeHashERC1967IBeaconProxy(beacon, args), salt, deployer
        );
    }

    /// @dev Equivalent to `argsOnERC1967IBeaconProxy(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967IBeaconProxy(address instance) internal view returns (bytes memory args) {
        return _argsOn(instance, 0x57);
    }

    /// @dev Equivalent to `argsOnERC1967IBeaconProxy(instance, start, 2 ** 256 - 1)`.
    function argsOnERC1967IBeaconProxy(address instance, uint256 start)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x57, start);
    }

    /// @dev Returns a slice of the immutable arguments on `instance` from `start` to `end`.
    /// `start` and `end` will be clamped to the range `[0, args.length]`.
    /// The `instance` MUST be deployed via the ERC1967I beacon proxy with immutable args functions.
    /// Otherwise, the behavior is undefined.
    /// Out-of-gas reverts if `instance` does not have any code.
    function argsOnERC1967IBeaconProxy(address instance, uint256 start, uint256 end)
        internal
        view
        returns (bytes memory args)
    {
        return _argsOn(instance, 0x57, start, end);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      OTHER OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `address(0)` if the implementation address cannot be determined.
    function implementationOf(address instance) internal view returns (address result) {
        // The first 0x57 bytes of the code, and zeros past its end.
        bytes memory code = _codeRead(instance, 0, 0x57);
        if (
            _readBytes32(code, 0x2d) != 0
                && (_keccak256Range(code, 0, 0x52) == ERC1967I_CODE_HASH
                    || keccak256(code) == ERC1967I_BEACON_PROXY_CODE_HASH)
        ) {
            // Called with one byte, an ERC1967I proxy answers its implementation. What it
            // answers replaces the start of the code, as the assembly reads it.
            (, bytes memory answer,) =
                _staticCallBounded(instance, gasleft(), _slice(code, 0, 1), 32);
            _copyInto(code, 0, answer, 0, answer.length);
            return address(uint160(uint256(_readBytes32(code, 0))));
        }
        // A minimal proxy holds its implementation at 0x0b, a clone with arguments at 0x0a,
        // and a PUSH0 proxy at 0x09: each is recognized by the hash of its code head with
        // that address zeroed.
        if (_maskedHash(code, 0x0b, 0x2c) == CLONE_CODE_HASH) return _addressAt(code, 0x0b);
        if (_maskedHash(code, 0x0a, 0x2d) == CWIA_CODE_HASH) return _addressAt(code, 0x0a);
        if (_maskedHash(code, 0x09, 0x2d) == PUSH0_CLONE_CODE_HASH) return _addressAt(code, 0x09);
    }

    /// @dev Returns the address when a contract with initialization code hash,
    /// `hash`, is deployed with `salt`, by `deployer`.
    /// Note: The returned result has dirty upper 96 bits. Please clean if used in assembly.
    function predictDeterministicAddress(bytes32 hash, bytes32 salt, address deployer)
        internal
        pure
        returns (address predicted)
    {
        return _createPredict2(deployer, salt, hash);
    }

    /// @dev Requires that `salt` starts with either the zero address or `by`.
    function checkStartsWith(bytes32 salt, address by) internal pure {
        address prefix = address(bytes20(salt));
        if (prefix != address(0) && prefix != by) revert SaltDoesNotStartWith();
    }

    /// @dev Returns the `bytes32` at `offset` in `args`, without any bounds checks.
    /// To load an address, you can use `address(bytes20(argLoad(args, offset)))`.
    function argLoad(bytes memory args, uint256 offset) internal pure returns (bytes32 result) {
        if (offset >= args.length) return 0;
        uint256 available = args.length - offset;
        if (available >= 32) return _readBytes32(args, offset);
        // The word runs past the end of `args`: the missing bytes read as zeros.
        bytes memory word = new bytes(32);
        _copyInto(word, 0, args, offset, available);
        return _readBytes32(word, 0);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The runtime size of a proxy whose code before its arguments is
    /// `base` bytes, which its creation code pushes in two bytes. Arguments that
    /// do not fit fail with `DeploymentFailed()`.
    function _runtimeSize(uint256 base, bytes memory args) private pure returns (uint16) {
        if (args.length > 0xffff - base) revert DeploymentFailed();
        return uint16(base + args.length);
    }

    /// @dev Deploys `c` with `salt` unless its address already has code, and
    /// sends `value` there either way.
    function _createDeterministic(bytes memory c, bytes32 salt, uint256 value)
        private
        returns (bool alreadyDeployed, address instance)
    {
        instance = predictDeterministicAddress(keccak256(c), salt, address(this));
        if (instance.code.length == 0) return (false, _createDeploy2(c, salt, value));
        if (value != 0) {
            (bool sent,,) = _callBounded(instance, value, gasleft(), "", 0);
            if (!sent) revert ETHTransferFailed();
        }
        return (true, instance);
    }

    /// @dev The arguments of the proxy `instance`, whose code before them is
    /// `base` bytes.
    /// @custom:solar-inline always
    function _argsOn(address instance, uint256 base) private view returns (bytes memory) {
        return _codeRead(instance, base, instance.code.length - base);
    }

    /// @dev The arguments of the proxy `instance` from `start`.
    /// @custom:solar-inline always
    function _argsOn(address instance, uint256 base, uint256 start)
        private
        view
        returns (bytes memory)
    {
        uint256 n = instance.code.length - base;
        if (start >= n) return "";
        return _codeRead(instance, base + start, n - start);
    }

    /// @dev The arguments of the proxy `instance` from `start` to `end`, which is
    /// clamped to the arguments and to `0xffff`. A short range is copied first, as
    /// the assembly does. Past the code the copy reads zeros, so a last byte that is
    /// not zero lies inside the code, and so does the whole range; otherwise the end
    /// of the arguments cuts it, and the zeros past it stay as padding.
    /// @custom:solar-inline always
    function _argsOn(address instance, uint256 base, uint256 start, uint256 end)
        private
        view
        returns (bytes memory args)
    {
        if (start < end && end <= 0xffff && end - start <= 0x40) {
            uint256 d = end - start;
            args = _codeRead(instance, base + start, d);
            if (args[d - 1] != 0) return args;
            uint256 available = instance.code.length - base;
            if (end > available) _setLength(args, start < available ? available - start : 0);
            return args;
        }
        uint256 n = instance.code.length - base;
        if (end > n) end = n;
        if (end > 0xffff) end = 0xffff;
        if (start >= end) return "";
        return _codeRead(instance, base + start, end - start);
    }

    /// @dev The hash of the first `length` bytes of `code` with the 20 bytes at
    /// `at` zeroed.
    function _maskedHash(bytes memory code, uint256 at, uint256 length)
        private
        pure
        returns (bytes32)
    {
        bytes memory head = _slice(code, 0, length);
        _fill(head, at, 20, 0x00);
        return keccak256(head);
    }

    /// @dev The address held in the 20 bytes of `code` at `at`.
    function _addressAt(bytes memory code, uint256 at) private pure returns (address) {
        return address(_readBytes20(code, at));
    }

    /// @dev Copies `count` bytes from `src` at `srcOffset` to `dst` at
    /// `dstOffset`. The ranges may overlap: the result is as if the source
    /// were read in full before the first write.
    function _copyInto(
        bytes memory dst,
        uint256 dstOffset,
        bytes memory src,
        uint256 srcOffset,
        uint256 count
    ) private pure {
        // Both ranges are validated before anything is written, so a copy
        // running downwards fails on its range the way one running upwards
        // does, rather than on the arithmetic reaching its far end.
        if (
            count > dst.length || dstOffset > dst.length - count || count > src.length
                || srcOffset > src.length - count
        ) count = _outOfBounds();
        if (dstOffset > srcOffset) {
            for (uint256 k = count; k > 0; --k) {
                dst[dstOffset + k - 1] = src[srcOffset + k - 1];
            }
        } else {
            for (uint256 k; k < count; ++k) {
                dst[dstOffset + k] = src[srcOffset + k];
            }
        }
    }

    /// @dev Sets `count` bytes of `dst` at `offset` to `value`.
    function _fill(bytes memory dst, uint256 offset, uint256 count, bytes1 value) private pure {
        for (uint256 k; k < count; ++k) {
            dst[offset + k] = value;
        }
    }

    /// @dev The 20 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes20(bytes memory b, uint256 offset) private pure returns (bytes20 result) {
        for (uint256 k; k < 20; ++k) {
            result |= bytes20(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev The 32 bytes of `b` at `offset`.
    /// @custom:solar-inline always
    function _readBytes32(bytes memory b, uint256 offset) private pure returns (bytes32 result) {
        for (uint256 k; k < 32; ++k) {
            result |= bytes32(b[offset + k]) >> (8 * k);
        }
    }

    /// @dev A copy of the `count` bytes of `b` at `offset`. Reverts with
    /// `Panic(0x32)` unless they all lie inside `b`, before allocating.
    function _slice(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes memory result)
    {
        if (offset > b.length || count > b.length - offset) offset = _outOfBounds();
        result = new bytes(count);
        for (uint256 k; k < count; ++k) {
            result[k] = b[offset + k];
        }
    }

    /// @dev The keccak-256 hash of the `count` bytes of `b` at `offset`.
    function _keccak256Range(bytes memory b, uint256 offset, uint256 count)
        private
        pure
        returns (bytes32)
    {
        if (count > b.length || offset > b.length - count) count = _outOfBounds();
        bytes memory range = new bytes(count);
        for (uint256 k; k < count; ++k) {
            range[k] = b[offset + k];
        }
        return keccak256(range);
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

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and copies
    /// at most `maxCopy` bytes of the response into a new buffer, as
    /// `callBounded` does.
    /// @custom:solar-trusted
    function _staticCallBounded(
        address target,
        uint256 gasLimit,
        bytes memory payload,
        uint256 maxCopy
    ) private view returns (bool success, bytes memory output, uint256 totalSize) {
        /// @solidity memory-safe-assembly
        assembly {
            success := staticcall(gasLimit, target, add(payload, 0x20), mload(payload), 0x00, 0x00)
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

    /// @dev `c` without its last 32 bytes, which are zeros, so that the bytes past its
    /// end read as zero padding wherever the free memory pointer ends up.
    /// @custom:solar-inline always
    function _withoutZeroWord(bytes memory c) private pure returns (bytes memory) {
        _setLength(c, c.length - 32);
        return c;
    }

    /// @dev Reverts the current call with exactly `data`.
    /// @custom:solar-trusted
    function _revertRaw(bytes memory data) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            revert(add(data, 0x20), mload(data))
        }
    }

    /// @dev Raises the `Panic(0x32)` an out-of-range index raises, which is the
    /// portable spelling of a failed range check.
    function _outOfBounds() private pure returns (uint256) {
        return new uint256[](0)[0];
    }
}
