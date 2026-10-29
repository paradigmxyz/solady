#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-abi==5.2.0", "eth-hash[pycryptodome]==0.7.1"]
# ///
"""Run the pinned upstream tests for the ported libraries whose suites compile.

Original test helpers remain test oracles, including their assembly. Only the
selected production sources are replaced in the safe legs; `--ported` also
replaces every other ported source the suites import. A library is named by its path below `src/`, or by
its bare name for `src/utils/`; its suite is `test/<name>.t.sol` unless
`SUITES` names another. This is an additional correctness check, not the gas
benchmark or safety audit.

`--fair` instead compares gas: it runs upstream built by solc and the port
built by Solar on the same inputs and memory, and writes each suite's ratio to
`gas.md`. Correctness comes from the normal run.

A leg whose inputs are unchanged since an earlier run, down to the bytes of the
compiler and of forge, reuses that run's results from the cache `benchmark.py`
also keeps, `--cache-dir`; `--no-cache` runs every leg.
"""

import argparse
import contextlib
import gzip
import json
import os
import subprocess
from pathlib import Path

from benchmark import (
    ARCHIVE,
    REPO,
    ROOT,
    Cache,
    closure,
    default_cache_dir,
    digest,
    file_sha256,
    tool_identity,
)

LIBRARIES = [
    "SafeCastLib",
    "LibBit",
    "Base64",
    "ECDSA",
    "SignatureCheckerLib",
    "MerkleProofLib",
    "EfficientHashLib",
    "LibBytes",
    "LibString",
    "LibSort",
    "LibBitmap",
    "LibMap",
    "DateTimeLib",
    "LibPRNG",
    "FixedPointMathLib",
    "EnumerableSetLib",
    "DynamicBufferLib",
    "DynamicArrayLib",
    "MinHeapLib",
    "JSONParserLib",
    "LibCall",
    "SSTORE2",
    "SafeTransferLib",
    "LibClone",
    "tokens/ERC20",
    "tokens/WETH",
    "tokens/ERC4626",
    "tokens/ERC721",
    "tokens/ERC1155",
    "tokens/ERC6909",
    "auth/Ownable",
    "auth/OwnableRoles",
    "accounts/Receiver",
    "ReentrancyGuard",
    "Initializable",
    "CREATE3",
    "UpgradeableBeacon",
    "ERC1967FactoryConstants",
    "ERC1967Factory",
    "EnumerableMapLib",
    "LibStorage",
    "RedBlackTreeLib",
    "auth/EnumerableRoles",
    "auth/TimedRoles",
    "tokens/ERC2981",
    "tokens/ERC20Votes",
    "Multicallable",
    "MetadataReaderLib",
    "Lifebuoy",
    "DeploylessPredeployQueryer",
    "utils/ext/delegatexyz/DelegateCheckerLib",
    "utils/legacy/LibCWIA",
    "utils/legacy/CWIA",
    "accounts/LibERC7579",
    "accounts/LibERC6551",
    "accounts/ERC7821",
    "accounts/Timelock",
    "CallContextChecker",
    "UUPSUpgradeable",
    "EIP712",
    "accounts/ERC1271",
    "accounts/ERC4337Factory",
    "P256",
    "WebAuthn",
    "MerkleTreeLib",
    "GasBurnerLib",
    "LibZip",
    "accounts/ERC4337",
    "accounts/ERC6551",
    "accounts/ERC6551Proxy",
    "SemVerLib",
    "Base58",
    "LibRLP",
]


# Tests that fail on upstream's own build too, for reasons outside the
# sources under test. A leg succeeds when no other test fails.
KNOWN_FAILURES = {
    # Upstream's `toNibbles` allocates too little memory for the long input the
    # fuzzer draws, which the test's memory check catches; the ports pass it.
    "test/LibBit.t.sol:LibBitTest::testToNibblesDifferential(uint256,bytes)",
    # The fuzzer draws Foundry's console address as the deployer, whose calls
    # Foundry intercepts, on every leg.
    "test/Lifebuoy.t.sol:LifebuoyTest::testLifebuoyCreateDeployment(address,address,uint256)",
}

# Tests the ports built by solc may fail for gas alone. The ports read words
# with byte loops, Solidity's only safe spelling of a word read at an offset in
# memory, which Solar turns into one load and solc runs byte by byte: built by
# solc, LibZip's FastLZ codec spends about 31x upstream's gas on a 6 KB input,
# beyond the suite's gas limit when the fuzzer draws one that long.
SOLC_SAFE_GAS_FAILURES = {
    "test/LibZip.t.sol:LibZipTest::testFlzCompressDecompress(bytes)",
}

# What `--fair` changes in the test helpers of both legs. The Brutalizer fills
# memory with junk seeded by `gas()`, and TestPlus hashes the free memory
# pointer into its randomness, so two builds would otherwise run different
# inputs on different memory; Foundry also draws fuzz inputs from each build's
# bytecode, which `--fair` turns off. Helpers that copy the test contract's own
# code into random values, random bytes or memory copy the call's calldata
# instead, or hash, so neither the inputs nor what the copies cost depend on
# each build's bytecode.
FAIR_PATCHES = {
    "test/utils/Brutalizer.sol": [
        (
            f"function {name}() internal view {{",
            f"function {name}() internal view {{\n        if (address(this) != address(0)) return;",
        )
        for name in ("_brutalizeMemory", "_brutalizeScratchSpace", "_brutalizeLowerMemory")
    ],
    "test/utils/TestPlus.sol": [
        (
            "mstore(0x20, sValue)\n            let r := keccak256(0x20, 0x40)",
            "mstore(0x20, sValue)\n            let r := keccak256(0x20, 0x20)",
        ),
        (
            "mstore(0x1f, sValue)\n                sValue := keccak256(0x20, 0x40)",
            "mstore(0x00, sValue)\n                sValue := keccak256(0x00, 0x20)",
        ),
        (
            "codecopy(0x00, mod(and(y, 0xffff), add(codesize(), 0x20)), 0x20)",
            "mstore(0x00, keccak256(0x00, 0x20))",
        ),
        (
            "{ codecopy(result, byte(1, r), codesize()) }",
            "{ calldatacopy(result, byte(1, r), add(n, 0x40)) }",
        ),
        (
            "codecopy(add(result, n), byte(2, r), 0x40)",
            "calldatacopy(add(result, n), byte(2, r), 0x40)",
        ),
    ],
    "test/JSONParserLib.t.sol": [
        (
            "codecopy(mload(0x40), 0, codesize())",
            "calldatacopy(mload(0x40), 0, calldatasize())",
        ),
    ],
    **{
        suite: [
            (
                "codecopy(add(result, 0x20), byte(1, r), add(n, 0x40))",
                "calldatacopy(add(result, 0x20), byte(1, r), add(n, 0x40))",
            ),
        ]
        for suite in ("test/ERC4337.t.sol", "test/ERC6551.t.sol")
    },
}

# The port keeps public behavior but uses typed lists and Solidity-managed token
# storage. The role oracle gives each set a separate mapping entry. These test
# helpers use only public APIs in both legs: no returned recursive List, packed-list
# offsets, hashed allowance slots, adjacent raw set slots, or mover-code probe.
# Native port tests separately check the typed list's internal invariants.
FAIR_COMPATIBILITY_PATCHES = {
    "test/LibRLP.t.sol": [
        (
            "function testRLPMemory(bytes32) public returns (LibRLP.List memory l) {",
            "function testRLPMemory(bytes32) public {\n        LibRLP.List memory l;",
        ),
        (
            """    function _getUint256(LibRLP.List memory l, uint256 i) internal pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, 0)
            let head := and(mload(l), 0xffffffffff)
            if head {
                for { let j := 0 } iszero(eq(j, i)) { j := add(j, 1) } {
                    head := and(mload(head), 0xffffffffff)
                }
                result := shr(48, mload(head))
                if eq(1, byte(26, mload(head))) { result := mload(result) }
            }
        }
    }""",
            """    function _getUint256(LibRLP.List memory l, uint256 i) internal pure returns (uint256 result) {
        bytes memory encoded = l.encode();
        uint256 prefix = uint8(encoded[0]);
        require(prefix >= 0xc0);
        uint256 cursor = prefix <= 0xf7 ? 1 : 1 + prefix - 0xf7;
        for (uint256 j;; ++j) {
            prefix = uint8(encoded[cursor]);
            uint256 length = 1;
            if (prefix >= 0x80) {
                require(prefix <= 0xa0);
                length = prefix - 0x80;
                ++cursor;
            }
            if (j == i) {
                for (uint256 k; k < length; ++k) {
                    result = (result << 8) | uint8(encoded[cursor + k]);
                }
                return result;
            }
            cursor += length;
        }
    }""",
        ),
        (
            """    function _checkMemory(LibRLP.List memory l) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let v := mload(l)
            if gt(shr(40, v), m) { invalid() }
            for { let head := and(v, 0xffffffffff) } head {} {
                if gt(head, m) { invalid() }
                head := and(mload(head), 0xffffffffff)
            }
        }
        _checkMemory();
    }""",
            """    function _checkMemory(LibRLP.List memory l) internal pure {
        // Native tests retain the private node-layout checks.
        // testRLPMemory still checks the encoded result's memory at the end.
        _checkMemory();
    }""",
        ),
    ],
    "test/SafeTransferLib.t.sol": [
        (
            """            bytes32 allowanceSlot;
            /// @solidity memory-safe-assembly
            assembly {
                mstore(0x20, to)
                mstore(0x0c, 0x7f5e9f20) // `_ALLOWANCE_SLOT_SEED`.
                mstore(0x00, from)
                allowanceSlot := keccak256(0x0c, 0x34)
            }
            vm.store(token, allowanceSlot, bytes32(uint256(amount)));""",
            """            vm.prank(from);
            erc20.approve(to, amount);""",
        ),
        (
            """        if (SafeTransferLib.ETH_MOVER.code.length == 0) {
            address vault = this.safeMoveETH(to, amount1);
            assertEq(vault.balance, amount1);
            assertEq(to.balance, amount0);
            assertEq(address(this).balance, selfBalanceBefore - amount0 - amount1);
        } else {
            assertEq(this.safeMoveETH(to, amount1), address(0));
            assertEq(to.balance, amount0 + amount1);
            assertEq(address(this).balance, selfBalanceBefore - amount0 - amount1);
        }""",
            """        address vault = this.safeMoveETH(to, amount1);
        if (vault == address(0)) {
            assertEq(to.balance, amount0 + amount1);
        } else {
            assertEq(vault.balance, amount1);
            assertEq(to.balance, amount0);
        }
        assertEq(address(this).balance, selfBalanceBefore - amount0 - amount1);""",
        ),
    ],
    "test/EnumerableRoles.t.sol": [
        (
            "    MockEnumerableRoles mockEnumerableRoles;",
            "    MockEnumerableRoles mockEnumerableRoles;\n\n"
            "    mapping(uint256 => EnumerableSetLib.AddressSet) private _expectedRoleHolders;",
        ),
        (
            """    function _roleHolders(uint256 role)
        internal
        pure
        returns (EnumerableSetLib.AddressSet storage holders)
    {
        /// @solidity memory-safe-assembly
        assembly {
            holders.slot := add(role, 0x97)
        }
    }""",
            """    function _roleHolders(uint256 role)
        internal
        view
        returns (EnumerableSetLib.AddressSet storage holders)
    {
        return _expectedRoleHolders[role];
    }""",
        ),
    ],
}


# Suites not named after the library they test.
SUITES = {
    "RedBlackTreeLib": "test/RedBlackTree.t.sol",
    "ERC1967FactoryConstants": "test/ERC1967Factory.t.sol",
    "accounts/ERC6551Proxy": "test/ERC6551.t.sol",
    "utils/legacy/CWIA": "test/LibCWIA.t.sol",
    "utils/ext/delegatexyz/DelegateCheckerLib": "test/ext/delegatexyz/DelegateCheckerLib.t.sol",
}


def source_path(library):
    return f"src/{library}.sol" if "/" in library else f"src/utils/{library}.sol"


def test_path(library):
    return SUITES.get(library, f"test/{library.rsplit('/', 1)[-1]}.t.sol")


def project_files(folder):
    """Each file of a generated project, by its path below `folder`, with its sha256."""
    return [
        [path.relative_to(folder).as_posix(), digest(path.read_bytes())]
        for path in sorted(folder.rglob("*"))
        if path.is_file()
    ]


def foundry_environment(env):
    """The variables that configure Foundry, its threads or Solar's solc wrapper.

    `FOUNDRY_SOLC` is left out: it is the compiler's path, and keys hold the
    compiler's contents instead.
    """
    return sorted(
        [name, value]
        for name, value in env.items()
        if name.startswith(("FOUNDRY_", "DAPP_", "RAYON_", "SOLC_WRAPPER"))
        and name != "FOUNDRY_SOLC"
    )


def suite_key(folder, command, compiler, env, forge):
    """The key of everything a leg's test results depend on.

    That is every file of the generated project, whose `foundry.toml` holds the
    settings, remappings, fuzz runs and seed; the compiler's and forge's
    binaries; Foundry's environment and global configuration; the command; and
    the number of CPUs, since forge splits each fuzz test's runs between up to
    one worker per CPU, each drawing its own inputs from the seed. The
    project's own path, the command's only path, is left out: the tests name
    their files relative to the root.
    """
    config = Path.home() / ".foundry" / "foundry.toml"
    return Cache.key(
        "suite",
        project_files(folder),
        file_sha256(compiler),
        tool_identity(forge),
        foundry_environment(env),
        config.read_text() if config.is_file() else None,
        ["<root>" if part == str(folder) else part for part in command[1:]],
        os.cpu_count(),
    )


def forge_test(cache, key, label, command, folder, env):
    """Runs a leg's `forge test`, or returns the outputs of an identical earlier run.

    Only a run whose tests ran is kept: an exit code of 0 or 1 with a JSON
    report. Anything else, such as a build failure or a crash, runs again.
    """
    entry = cache.get("suite", key)
    print(f"Running {label}" + (" (cached)" if entry else ""), flush=True)
    if entry is not None:
        return entry
    result = subprocess.run(
        command,
        cwd=folder,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    entry = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    if result.returncode in (0, 1):
        with contextlib.suppress(ValueError):
            if isinstance(json.loads(result.stdout), dict):
                cache.put("suite", key, entry)
    return entry


def apply_fair_patches(folder):
    """Apply identical input and API-compatibility recipes to either benchmark leg."""
    applied = []
    for name, patches in (FAIR_PATCHES | FAIR_COMPATIBILITY_PATCHES).items():
        path = folder / name
        if not path.exists():
            continue
        text = path.read_text()
        for old, new in patches:
            if text.count(old) != 1:
                raise SystemExit(f"--fair: {name} must contain exactly one {old!r}")
            text = text.replace(old, new, 1)
            applied.append({
                "source": name,
                "kind": "compatibility" if name in FAIR_COMPATIBILITY_PATCHES else "inputs",
                "old_sha256": digest(old.encode()),
                "new_sha256": digest(new.encode()),
            })
        path.write_text(text)
    return applied


def gas_report(results):
    """Each suite's gas, the port built by Solar against upstream built by solc, over the tests
    both pass; `test__codesize` reports a size, not gas."""
    upstream = results["solc-upstream"]["tests"]
    port = results["solar-safe"]["tests"]
    totals = {}
    for name, test in upstream.items():
        other = port.get(name)
        if (
            other is None
            or test["status"] != "Success"
            or other["status"] != "Success"
            or test["gas"] is None
            or other["gas"] is None
            or name.endswith("::test__codesize()")
        ):
            continue
        total = totals.setdefault(name.split(":", 1)[0], [0, 0, 0])
        total[0] += test["gas"]
        total[1] += other["gas"]
        total[2] += 1
    if not totals:
        return "No comparable passing tests\n"
    lines = [
        "| Suite | Tests | Upstream, solc | Port, Solar | Ratio |",
        "|---|---:|---:|---:|---:|",
    ]
    for suite, (up, ours, count) in sorted(totals.items(), key=lambda item: -item[1][1] / item[1][0]):
        lines.append(f"| `{suite}` | {count} | {up:,} | {ours:,} | {ours / up:.4f}x |")
    up = sum(total[0] for total in totals.values())
    ours = sum(total[1] for total in totals.values())
    count = sum(total[2] for total in totals.values())
    lines.append(f"| All {len(totals)} suites | {count} | {up:,} | {ours:,} | {ours / up:.4f}x |")
    return "\n".join(lines) + "\n"


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cache = Cache(None if args.no_cache else args.cache_dir)
    libraries = args.library or LIBRARIES
    archive = json.loads(gzip.decompress(ARCHIVE.read_bytes()))
    sources = closure(archive["sources"], sorted({test_path(name) for name in libraries}))
    replaced = {source_path(name) for name in libraries}
    if args.ported:
        replaced |= {
            name
            for name in sources
            if name.startswith("src/")
            and (ROOT / name).exists()
            and "@custom:solar-safe" in (ROOT / name).read_text()
        }
    results = {}
    legs = [
        ("solc-upstream", args.solc, False),
        ("solc-safe", args.solc, True),
        ("solar-safe", args.solar, True),
    ]
    if args.fair:
        legs = [leg for leg in legs if leg[0] != "solc-safe"]
    for label, compiler, safe in legs:
        folder = output / label
        folder.mkdir()
        hashes = {}
        for name, source in sources.items():
            text = source["content"]
            if safe and name in replaced:
                text = (ROOT / name).read_text()
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            hashes[name] = digest(text.encode())
        applied = apply_fair_patches(folder) if args.fair else []
        hashes = {name: digest((folder / name).read_bytes()) for name in hashes}
        # Test data the suites read, such as P256's Wycheproof vectors, as the pinned
        # release has it.
        for data in sorted((ROOT / "test/data").glob("*")):
            target = folder / "test/data" / data.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.read_bytes())
        (folder / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = []\n'
            'evm_version = "cancun"\noptimizer = true\noptimizer_runs = 200\n'
            f'via_ir = {"false" if args.legacy else "true"}\nbytecode_hash = "none"\n'
            'cbor_metadata = false\n'
            'gas_limit = 100000000\nremappings = ["forge-std/=test/utils/forge-std/"]\n'
            'fs_permissions = [{ access = "read", path = "./test/data" }]\n'
            f'[profile.default.fuzz]\nruns = {args.fuzz_runs}\nseed = "0x20260910"\n'
            + ("dictionary_weight = 0\n" if args.fair else "")
        )
        env = os.environ.copy()
        env["FOUNDRY_SOLC"] = str(compiler.resolve())
        if label == "solar-safe":
            env["SOLC_WRAPPER"] = "1"
            env["SOLC_WRAPPER_VERSION"] = args.solc_version
        else:
            env.pop("SOLC_WRAPPER", None)
        command = [args.forge, "test", "--root", str(folder), "--force", "--json"]
        key = suite_key(folder, command, compiler, env, args.forge)
        result = forge_test(cache, key, label, command, folder, env)
        (folder / "stdout.json").write_text(result["stdout"])
        (folder / "stderr.txt").write_text(result["stderr"])
        tests = {}
        if result["stdout"].lstrip().startswith("{"):
            for contract, data in json.loads(result["stdout"]).items():
                for name, test in data.get("test_results", {}).items():
                    kind = test.get("kind", {})
                    # NOTE: forge splits a fuzz test's runs between parallel
                    # workers and stops them all at the first failure, so the
                    # mean gas of a failing fuzz test changes from run to run;
                    # a cached leg keeps the one its run saw.
                    tests[f"{contract}::{name}"] = {
                        "status": test["status"],
                        "reason": test.get("reason"),
                        "gas": kind["Unit"]["gas"]
                        if "Unit" in kind
                        else kind["Fuzz"]["mean_gas"]
                        if "Fuzz" in kind
                        else None,
                    }
        complete = all(
            any(name.startswith(f"{test_path(lib)}:") for name in tests)
            for lib in libraries
        )
        failures = {
            name for name, test in tests.items() if test["status"] != "Success"
        }
        allowed = KNOWN_FAILURES | (SOLC_SAFE_GAS_FAILURES if label == "solc-safe" else set())
        succeeded = complete and (
            result["returncode"] == 0 if not failures else failures <= allowed
        )
        results[label] = {
            "exit_code": result["returncode"],
            "succeeded": succeeded,
            "tests": tests,
            "source_sha256": hashes,
            "test_patches": applied,
            "command": command,
            "compiler_sha256": file_sha256(compiler),
        }
        print(f"{label}: exit {result['returncode']}", flush=True)
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    if args.fair:
        report = gas_report(results)
        (output / "gas.md").write_text(report)
        print(report, end="")
    return int(any(not r["succeeded"] for r in results.values()))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solc", type=Path, required=True)
    parser.add_argument("--solc-version", default="0.8.37")
    parser.add_argument(
        "--solar", type=Path, default=REPO.parent / "solar/target/debug/solar"
    )
    parser.add_argument("--forge", default="forge")
    parser.add_argument(
        "--library",
        action="append",
        help="library to test, repeatable (default: every library whose suite passes)",
    )
    parser.add_argument("--fuzz-runs", type=int, default=256)
    parser.add_argument(
        "--legacy", action="store_true", help="build solc's legs without via-IR"
    )
    parser.add_argument(
        "--ported",
        action="store_true",
        help="also swap in every other ported source the suites import",
    )
    parser.add_argument(
        "--fair",
        action="store_true",
        help="compare gas: same inputs and memory on both legs, no solc-safe leg, writes gas.md",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=default_cache_dir(),
        help="reuse the results of legs with unchanged inputs from here (default: %(default)s)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="run every leg, neither reading nor writing the cache",
    )
    raise SystemExit(run(parser.parse_args()))
