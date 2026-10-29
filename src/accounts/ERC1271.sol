// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import {EIP712} from "../utils/EIP712.sol";
import {SignatureCheckerLib} from "../utils/SignatureCheckerLib.sol";

/// @notice ERC1271 mixin with nested EIP-712 approach.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC1271.sol)
///
/// The checked port reads the signature through calldata slices and words, and builds the
/// `TypedDataSign` type and the hashes with `abi.encodePacked` and `abi.encode`, keeping the
/// assembly's byte layouts, its checks of `contentsName` (skipping the bytes no check looks for
/// a word at a time), the hash it corrupts with one more zero byte for an invalid name, and its
/// fallbacks to `PersonalSign`. Like the assembly, it follows an ERC6492 wrapper's offsets
/// wherever they point, past the signature or the calldata, reads the magic suffix of a
/// signature shorter than a word from before the signature, and reads past the calldata as
/// zeros, as `CALLDATALOAD` does: Solidity cannot read a slice's calldata offset, slice past
/// `msg.data`, nor add offsets with wrap-around, so three trusted helpers do just that, and the
/// zero bytes the assembly hashes come from a slice past the calldata. The RPC check makes a
/// trusted static call that reads at most a word of the answer, and halts with a trusted
/// `invalid()`, which Solidity cannot spell. At address zero, where the assembly mistakes
/// the `TypedDataSign` workflow's buffer for its `PersonalSign` flag, the port works as at any
/// other address. The helpers' names carry an `_erc1271` prefix, so that a contract can
/// inherit this alongside other ports.
/// @custom:solar-safe memory arithmetic
abstract contract ERC1271 is EIP712 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `keccak256("PersonalSign(bytes prefixed)")`.
    bytes32 internal constant _PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC1271 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Validates the signature with ERC1271 return,
    /// so that this account can also be used as a signer.
    function isValidSignature(bytes32 hash, bytes calldata signature)
        public
        view
        virtual
        returns (bytes4 result)
    {
        // For automatic detection that the smart account supports the nested EIP-712 workflow,
        // See: https://eips.ethereum.org/EIPS/eip-7739.
        // If `hash` is `0x7739...7739`, returns `bytes4(0x77390001)`.
        // The returned number MAY be increased in future ERC7739 versions.
        if (signature.length == uint256(0)) {
            // `0x7739...7739`, compared whole rather than computed from the length.
            if (hash == 0x7739773977397739773977397739773977397739773977397739773977397739) {
                return 0x77390001;
            }
        }
        bool success = _erc1271IsValidSignature(hash, _erc1271UnwrapSignature(signature));
        // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
        // We use `0xffffffff` for invalid, in convention with the reference implementation.
        result = bytes4(uint32(success ? 0x1626ba7e : 0xffffffff));
    }

    /// @dev Returns the ERC1271 signer.
    /// Override to return the signer `isValidSignature` checks against.
    function _erc1271Signer() internal view virtual returns (address);

    /// @dev Returns whether the `msg.sender` is considered safe, such
    /// that we don't need to use the nested EIP-712 workflow.
    /// Override to return true for more callers.
    /// See: https://mirror.xyz/curiousapple.eth/pFqAdW2LiJ-6S4sg_u1z08k4vK6BCJ33LcyXpnNb8yU
    function _erc1271CallerIsSafe() internal view virtual returns (bool) {
        // The canonical `MulticallerWithSigner` at 0x000000000000D9ECebf3C23529de49815Dac1c4c
        // is known to include the account in the hash to be signed.
        return msg.sender == 0x000000000000D9ECebf3C23529de49815Dac1c4c;
    }

    /// @dev Returns whether the `hash` and `signature` are valid.
    /// Override if you need non-ECDSA logic.
    /// @custom:solar-inline always
    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bool)
    {
        return SignatureCheckerLib.isValidSignatureNowCalldata(_erc1271Signer(), hash, signature);
    }

    /// @dev Unwraps and returns the signature.
    /// @custom:solar-inline always
    function _erc1271UnwrapSignature(bytes calldata signature)
        internal
        view
        virtual
        returns (bytes calldata result)
    {
        result = signature;
        // Unwraps the ERC6492 wrapper if it exists.
        // See: https://eips.ethereum.org/EIPS/eip-6492
        // The assembly adds calldata offsets with wrap-around, and reads past the calldata as
        // zeros, so it reads the magic suffix of a signature shorter than a word from before
        // the signature, and follows the wrapper's offsets wherever they point.
        uint256 o = _erc1271CalldataOffset(result);
        // `0x6492...6492`.
        if (
            _erc1271CalldataWord(_erc1271Add(_erc1271Add(o, result.length), ~uint256(0x1f)))
                == 0x6492649264926492649264926492649264926492649264926492649264926492
        ) {
            o = _erc1271Add(o, uint256(_erc1271CalldataWord(_erc1271Add(o, 0x40))));
            result = _erc1271CalldataSlice(_erc1271Add(o, 0x20), uint256(_erc1271CalldataWord(o)));
        }
    }

    /// @dev Returns whether the `signature` is valid for the `hash.
    function _erc1271IsValidSignature(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bool)
    {
        return _erc1271IsValidSignatureViaSafeCaller(hash, signature)
            || _erc1271IsValidSignatureViaNestedEIP712(hash, signature)
            || _erc1271IsValidSignatureViaRPC(hash, signature);
    }

    /// @dev Performs the signature validation without nested EIP-712 if the caller is
    /// a safe caller. A safe caller must include the address of this account in the hash.
    function _erc1271IsValidSignatureViaSafeCaller(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bool result)
    {
        if (_erc1271CallerIsSafe()) {
            result = _erc1271IsValidSignatureNowCalldata(hash, signature);
        }
    }

    /// @dev ERC1271 signature validation (Nested EIP-712 workflow).
    ///
    /// This uses ECDSA recovery by default (see: `_erc1271IsValidSignatureNowCalldata`).
    /// It also uses a nested EIP-712 approach to prevent signature replays when a single EOA
    /// owns multiple smart contract accounts,
    /// while still enabling wallet UIs (e.g. Metamask) to show the EIP-712 values.
    ///
    /// Crafted for phishing resistance, efficiency, flexibility.
    /// __________________________________________________________________________________________
    ///
    /// Glossary:
    ///
    /// - `APP_DOMAIN_SEPARATOR`: The domain separator of the `hash` passed in by the application.
    ///   Provided by the front end. Intended to be the domain separator of the contract
    ///   that will call `isValidSignature` on this account.
    ///
    /// - `ACCOUNT_DOMAIN_SEPARATOR`: The domain separator of this account.
    ///   See: `EIP712._domainSeparator()`.
    /// __________________________________________________________________________________________
    ///
    /// For the `TypedDataSign` workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 ‖ APP_DOMAIN_SEPARATOR ‖
    ///         hashStruct(TypedDataSign({
    ///             contents: hashStruct(originalStruct),
    ///             name: keccak256(bytes(eip712Domain().name)),
    ///             version: keccak256(bytes(eip712Domain().version)),
    ///             chainId: eip712Domain().chainId,
    ///             verifyingContract: eip712Domain().verifyingContract,
    ///             salt: eip712Domain().salt
    ///         }))
    ///     )
    /// ```
    /// where `‖` denotes the concatenation operator for bytes.
    /// The order of the fields is important: `contents` comes before `name`.
    ///
    /// The signature will be `r ‖ s ‖ v ‖ APP_DOMAIN_SEPARATOR ‖
    ///     contents ‖ contentsDescription ‖ uint16(contentsDescription.length)`,
    /// where:
    /// - `contents` is the bytes32 struct hash of the original struct.
    /// - `contentsDescription` can be either:
    ///     a) `contentsType` (implicit mode)
    ///         where `contentsType` starts with `contentsName`.
    ///     b) `contentsType ‖ contentsName` (explicit mode)
    ///         where `contentsType` may not necessarily start with `contentsName`.
    ///
    /// The `APP_DOMAIN_SEPARATOR` and `contents` will be used to verify if `hash` is indeed correct.
    /// __________________________________________________________________________________________
    ///
    /// For the `PersonalSign` workflow, the final hash will be:
    /// ```
    ///     keccak256(\x19\x01 ‖ ACCOUNT_DOMAIN_SEPARATOR ‖
    ///         hashStruct(PersonalSign({
    ///             prefixed: keccak256(bytes(\x19Ethereum Signed Message:\n ‖
    ///                 base10(bytes(someString).length) ‖ someString))
    ///         }))
    ///     )
    /// ```
    /// where `‖` denotes the concatenation operator for bytes.
    ///
    /// The `PersonalSign` type hash will be `keccak256("PersonalSign(bytes prefixed)")`.
    /// The signature will be `r ‖ s ‖ v`.
    /// __________________________________________________________________________________________
    ///
    /// For demo and typescript code, see:
    /// - https://github.com/junomonster/nested-eip-712
    /// - https://github.com/frangio/eip712-wrapper-for-eip1271
    ///
    /// Their nomenclature may differ from ours, although the high-level idea is similar.
    ///
    /// Of course, if you have control over the codebase of the wallet client(s) too,
    /// you can choose a more minimalistic signature scheme like
    /// `keccak256(abi.encode(address(this), hash))` instead of all these acrobatics.
    /// All these are just for widespread out-of-the-box compatibility with other wallet clients.
    /// We want to create bazaars, not walled castles.
    /// And we'll use push the Turing Completeness of the EVM to the limits to do so.
    function _erc1271IsValidSignatureViaNestedEIP712(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bool result)
    {
        // The account's domain, whose fields the `TypedDataSign` workflow hashes.
        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = eip712Domain();
        uint256 n = signature.length;
        // `c` is `contentsDescription.length`, which is stored in the last 2 bytes of the signature.
        // A signature shorter than `0x42` bytes takes the `PersonalSign` workflow whatever `c` is.
        uint256 c = uint256(
            _erc1271CalldataWord(
                _erc1271Add(_erc1271Add(_erc1271CalldataOffset(signature), n), ~uint256(1))
            )
        ) >> 240;
        uint256 l = 0x42 + c; // Total length of appended data (32 + 32 + c + 2).
        // Use the `PersonalSign` workflow if the reconstructed hash doesn't match,
        // or if the appended data is invalid, i.e.
        // `appendedData.length > signature.length || contentsDescription.length == 0`.
        if (
            n < l || c == 0
                || keccak256(abi.encodePacked(hex"1901", signature[n - l:n - l + 0x40])) != hash
        ) {
            // Compute the `PersonalSign` struct hash, whose `prefixed` is `hash`.
            hash = _hashTypedData(keccak256(abi.encode(_PERSONAL_SIGN_TYPEHASH, hash)));
        } else {
            // Else, use the `TypedDataSign` workflow.
            hash = _erc1271TypedDataSignHash(
                signature[n - l:n - 2],
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract,
                salt
            );
            signature = signature[:n - l]; // Truncate the signature.
        }
        result = _erc1271IsValidSignatureNowCalldata(hash, signature);
    }

    /// @dev Performs the signature validation without nested EIP-712 to allow for easy sign ins.
    /// This function must always return false or revert if called on-chain.
    function _erc1271IsValidSignatureViaRPC(bytes32 hash, bytes calldata signature)
        internal
        view
        virtual
        returns (bool result)
    {
        // Non-zero gasprice is a heuristic to check if a call is on-chain,
        // but we can't fully depend on it because it can be manipulated.
        // See: https://x.com/NoahCitron/status/1580359718341484544
        if (tx.gasprice == uint256(0)) {
            // See: https://gist.github.com/Vectorized/3c9b63524d57492b265454f62d895f71
            address b = 0x000000000000378eDCD5B5B0A24f5342d8C10485; // Basefee contract,
            // If `gasprice < basefee`, the call cannot be on-chain, and we can skip the gas burn.
            // The first word of the answer or the revert, zero-padded past its end.
            bytes memory empty;
            if (_erc1271StaticCallWord(b, 0xffff, empty) == bytes32(0)) {
                // Recycle `b` to denote if we need to burn gas.
                bytes32 burn = bytes32(uint256(uint160(b)));
                uint256 gasToBurn = _erc1271Add(0xffff, block.gaslimit) | block.gaslimit;
                // Burns gas computationally efficiently. Also, requires that `gas > gasToBurn`.
                if (hash == burn || gasleft() < gasToBurn) _erc1271Invalid();
                // Make a call to this with `b`, efficiently burning the gas provided.
                // No valid transaction can consume more than the gaslimit.
                // See: https://ethereum.github.io/yellowpaper/paper.pdf
                // Most RPCs perform calls with a gas budget greater than the gaslimit.
                // `isValidSignature(bytes32,bytes)`, with `b` and empty bytes.
                _erc1271StaticCallWord(
                    address(this),
                    gasToBurn,
                    abi.encodeWithSelector(0x1626ba7e, burn, uint256(0x40), uint256(0))
                );
            }
            result = _erc1271IsValidSignatureNowCalldata(hash, signature);
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The final hash of the `TypedDataSign` workflow for `appended`, the signature's
    /// `APP_DOMAIN_SEPARATOR ‖ contents ‖ contentsDescription`, and the account's name hash,
    /// version hash, chain id, verifying contract and salt.
    function _erc1271TypedDataSignHash(
        bytes calldata appended,
        bytes32 nameHash,
        bytes32 versionHash,
        uint256 chainId,
        address verifyingContract,
        bytes32 salt
    ) private pure returns (bytes32) {
        // `APP_DOMAIN_SEPARATOR ‖ contents`, at `o`.
        uint256 o = _erc1271CalldataOffset(appended);
        (bytes32 typedDataSignTypehash, bool invalid) =
            _erc1271TypedDataSignTypehash(appended[0x40:]);
        // `hashStruct(typedDataSign)`.
        bytes32 structHash = keccak256(
            abi.encode(
                typedDataSignTypehash,
                _erc1271CalldataWord(_erc1271Add(o, 0x20)),
                nameHash,
                versionHash,
                chainId,
                verifyingContract,
                salt
            )
        );
        // Compute the final hash, corrupted with one more zero byte if `contentsName` is invalid.
        return keccak256(
            abi.encodePacked(
                hex"1901",
                _erc1271CalldataWord(o),
                structHash,
                _erc1271CalldataSlice(msg.data.length, invalid ? 1 : 0)
            )
        );
    }

    /// @dev The `typedDataSignTypehash` for `contentsDescription`, and whether its
    /// `contentsName` is invalid.
    /// @custom:solar-inline always
    function _erc1271TypedDataSignTypehash(bytes calldata contentsDescription)
        private
        pure
        returns (bytes32 typedDataSignTypehash, bool invalid)
    {
        uint256 c = contentsDescription.length;
        // `TypedDataSign({ContentsName} contents,string name,...){ContentsType}`.
        bytes calldata contentsType = contentsDescription;
        // The bytes `contentsName` is read from, up to the first '('.
        bytes calldata contentsName = contentsDescription;
        bool implicitMode = contentsDescription[c - 1] == ")";
        if (!implicitMode) {
            // `c - i` is the length of `contentsName` in explicit mode.
            uint256 i = c - 1;
            // Scan backwards until we encounter a ')'.
            while (i != 0 && uint8(contentsDescription[i - 1]) != 0x29) --i;
            // Truncate `contentsDescription` to `contentsType`.
            contentsType = contentsDescription[:i];
            contentsName = contentsDescription[i:];
        }
        uint256 k;
        (k, invalid) = _erc1271ScanContentsName(contentsName);
        // Without a '(', the assembly reads `contentsName` on into the 31 zero bytes before
        // the '(' it stores a word after the end, which makes it invalid.
        bytes calldata zeros =
            _erc1271CalldataSlice(msg.data.length, implicitMode && k == c ? 31 : 0);
        typedDataSignTypehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName[:k],
                zeros,
                " contents,string name,string" " version,uint256 chainId,address"
                " verifyingContract,bytes32 salt)",
                contentsType
            )
        );
    }

    /// @dev The length of `contentsName` up to its first '(', or all of it, and whether it
    /// is invalid: it starts with `[a-z(]`, or has a byte in ", )\x00" before that '('.
    /// It skips, a word at a time, the bytes before the first one below `0x2d`, which neither
    /// '(' nor a banned byte is, then reads the rest a byte at a time.
    /// @custom:solar-inline always
    function _erc1271ScanContentsName(bytes calldata contentsName)
        private
        pure
        returns (uint256 k, bool invalid)
    {
        uint256 n = contentsName.length;
        uint256 o = _erc1271CalldataOffset(contentsName);
        // The next 32 bytes from `k`, read past the end of `contentsName`.
        uint256 w = uint256(_erc1271CalldataWord(o));
        // `d & 1 == 1` means that `contentsName` is invalid.
        uint256 d = 0x7fffffe000000000000010000000000 >> (w >> 248); // Starts with `[a-z(]`.
        uint256 low = type(uint256).max / 0xff * 0x7f; // `0x7f7f...7f`.
        while (true) {
            // The bytes below `0x2d`, with their top bit set, and those past the end of
            // `contentsName`. The sum of a byte's low 7 bits and `0x53` cannot carry.
            uint256 stop = ~((((w & low) + low / 0x7f * 0x53) | w) | low)
                | (type(uint256).max >> ((n - k) << 3));
            if (stop != 0) {
                // Advance `k` to the first of them.
                uint256 r;
                if (stop >> 128 == 0) (r, stop) = (16, stop << 128);
                if (stop >> 192 == 0) (r, stop) = (r + 8, stop << 64);
                if (stop >> 224 == 0) (r, stop) = (r + 4, stop << 32);
                if (stop >> 240 == 0) (r, stop) = (r + 2, stop << 16);
                if (stop >> 248 == 0) r += 1;
                k += r;
                break;
            }
            k += 32;
            w = uint256(_erc1271CalldataWord(_erc1271Add(o, k)));
        }
        // Advance `k` until we encounter '('.
        for (; k < n; ++k) {
            uint256 b = uint8(contentsName[k]);
            if (b == 0x28) break;
            d |= 0x120100000001 >> b; // Has a byte in ", )\x00".
        }
        invalid = d & 1 != 0;
    }

    /// @dev The word of calldata at `offset`, zero-padded past the end of the calldata, as
    /// `CALLDATALOAD` reads it.
    /// @custom:solar-inline always
    function _erc1271CalldataWord(uint256 offset) private pure returns (bytes32) {
        return bytes32(_erc1271CalldataSlice(offset, 0x20));
    }

    /// @dev `a + b` modulo `2**256`, as the assembly adds calldata offsets. Solidity's
    /// addition reverts where this wraps around.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc1271Add(uint256 a, uint256 b) private pure returns (uint256 c) {
        unchecked {
            c = a + b;
        }
    }

    /// @dev The calldata offset of `s`. Solidity cannot read a calldata slice's offset.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc1271CalldataOffset(bytes calldata s) private pure returns (uint256 offset) {
        /// @solidity memory-safe-assembly
        assembly {
            offset := s.offset
        }
    }

    /// @dev The calldata slice of `length` bytes at `offset`, which may lie past the end of
    /// the calldata, where reads give zeros. Solidity slices only within `msg.data`.
    /// @custom:solar-trusted
    /// @custom:solar-inline always
    function _erc1271CalldataSlice(uint256 offset, uint256 length)
        private
        pure
        returns (bytes calldata s)
    {
        /// @solidity memory-safe-assembly
        assembly {
            s.offset := offset
            s.length := length
        }
    }

    /// @dev Static-calls `target` with `payload` and `gasLimit` gas, and returns the first word
    /// of the answer or the revert, zero-padded past its end, read through the scratch space.
    /// @custom:solar-trusted
    function _erc1271StaticCallWord(address target, uint256 gasLimit, bytes memory payload)
        private
        view
        returns (bytes32 word)
    {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0)
            pop(staticcall(gasLimit, target, add(payload, 0x20), mload(payload), 0x00, 0x20))
            word := mload(0x00)
        }
    }

    /// @dev Halts with the designated invalid instruction, which consumes all the gas left.
    /// Solidity cannot spell it: its failures revert.
    /// @custom:solar-trusted
    function _erc1271Invalid() private pure {
        /// @solidity memory-safe-assembly
        assembly {
            invalid()
        }
    }
}
