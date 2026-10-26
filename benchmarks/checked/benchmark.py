#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-abi==5.2.0", "eth-hash[pycryptodome]==0.7.1"]
# ///
"""Compare checked Solidity with pinned upstream Solady on identical ABI calls.

Every implementation is compiled by both compilers. solc runs through both code
paths; the primary comparison uses its cheaper upstream result for each call.
All measured cases must match a separate Python oracle, including revert bytes.

A content-addressed cache, `--cache-dir`, reuses every build and trace whose
inputs are unchanged since an earlier run; `--no-cache` bypasses it.
"""

from __future__ import annotations

import argparse
import base64
import urllib.parse
import contextlib
import functools
import gzip
import hashlib
import inspect
import json
import os
import posixpath
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import zlib
from pathlib import Path

from eth_abi import encode
from eth_hash.auto import keccak

ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT
ARCHIVE = Path(__file__).resolve().with_name("upstream-solady-0.1.26.json.gz")
CHECKED_LIBRARIES = (
    "Base64",
    "EfficientHashLib",
    "LibBit",
    "LibBytes",
    "LibSort",
    "LibString",
    "MerkleProofLib",
    "SafeCastLib",
    "ECDSA",
    "SignatureCheckerLib",
)
MAX = (1 << 256) - 1
# EIP-170's limit on deployed runtime code, in bytes.
CODE_SIZE_LIMIT = 0x6000
# Harnesses Solar builds for size in every optimized build: built for gas, the combined
# LibString harness exceeds EIP-170 at high optimizer runs. Other compilers read the
# `@custom:solar-optimize` tag as documentation.
SIZE_HARNESSES = frozenset({"LibString"})


def mask(n):
    return (1 << n) - 1


def digest(data):
    return hashlib.sha256(data).hexdigest()


def compile_json(binary, payload):
    process = subprocess.run(
        [str(binary), "--standard-json"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(process.stderr or process.stdout)
    output = json.loads(process.stdout)
    errors = [x for x in output.get("errors", []) if x.get("severity") == "error"]
    if errors:
        raise RuntimeError("\n".join(x.get("formattedMessage", str(x)) for x in errors))
    return output


# Every cache key starts with this version; bump it when a cached value changes
# meaning or layout, so that no entry written before is read again.
CACHE_FORMAT = 1


def default_cache_dir():
    """Where the runners keep their cache unless told otherwise: outside the repository."""
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else Path.home() / ".cache") / "solady-checked"


class Cache:
    """Content-addressed results of the slow steps: builds, suites and traces.

    A key is the sha256 of the format version and of every input that affects
    the value, so a changed input misses instead of finding a stale value, and
    no entry ever needs invalidating. An entry is one gzip-compressed JSON file,
    `<directory>/<kind>/<key>.json.gz`, written to a temporary file and renamed
    into place, so a reader never sees a partial one; an unreadable entry is a
    miss. Nothing is evicted: deleting the directory empties the cache. A cache
    without a directory keeps nothing, for `--no-cache`.
    """

    def __init__(self, directory=None):
        self.directory = directory

    @staticmethod
    def key(kind, *inputs):
        # Dictionaries keep their order, which a compiler may depend on.
        text = json.dumps([CACHE_FORMAT, kind, *inputs], separators=(",", ":"))
        return digest(text.encode())

    def path(self, kind, key):
        return self.directory / kind / f"{key}.json.gz"

    def get(self, kind, key):
        if self.directory is None:
            return None
        try:
            return json.loads(gzip.decompress(self.path(kind, key).read_bytes()))
        except (OSError, EOFError, ValueError, zlib.error):
            return None

    def put(self, kind, key, value):
        if self.directory is None:
            return
        path = self.path(kind, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(value, separators=(",", ":")).encode()
        handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(handle, "wb") as file:
                file.write(gzip.compress(data, compresslevel=1, mtime=0))
            os.replace(temporary, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
            raise


@functools.cache
def file_sha256(path):
    """The sha256 of a file's bytes, read once per run."""
    return digest(Path(path).read_bytes())


@functools.cache
def tool_identity(tool):
    """A command-line tool's `--version` and the sha256 of its binary, for cache keys."""
    path = shutil.which(str(tool))
    if path is None:
        raise FileNotFoundError(f"{tool} not found")
    version = subprocess.check_output([path, "--version"], text=True).strip()
    return {"version": version, "sha256": file_sha256(Path(path).resolve())}


def compile_cached(cache, binary, payload, label=None):
    """`compile_json` through `cache`, with the seconds the compile took.

    A hit returns the seconds of the compile that produced the output. With a
    `label`, prints the progress line for the build.
    """
    key = cache.key("compile", file_sha256(binary), payload)
    entry = cache.get("compile", key)
    if label is not None:
        print(f"Compiling {label}" + (" (cached)" if entry else ""), flush=True)
    if entry is None:
        start = time.monotonic()
        output = compile_json(binary, payload)
        entry = {"output": output, "seconds": time.monotonic() - start}
        cache.put("compile", key, entry)
    return entry["output"], entry["seconds"]


def walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


TRUSTED_TAG = "@custom:solar-trusted"


def is_trusted(node):
    """Whether a declaration's NatSpec has a line starting with the trusted tag."""
    documentation = node.get("documentation")
    text = documentation.get("text", "") if isinstance(documentation, dict) else ""
    return any(line.strip().startswith(TRUSTED_TAG) for line in text.splitlines())


def unsafe_nodes(node):
    """Yields assembly and unchecked blocks outside declarations tagged trusted."""
    if isinstance(node, dict):
        if node.get("nodeType") in {
            "ContractDefinition",
            "FunctionDefinition",
            "ModifierDefinition",
        } and is_trusted(node):
            return
        if node.get("nodeType") in {"InlineAssembly", "UncheckedBlock"}:
            yield node
        for value in node.values():
            yield from unsafe_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from unsafe_nodes(value)


def safety_violations(output, *, assembly_free=False, allow_unchecked=False):
    # The port has no compiler-owned library. Capabilities with no Solidity
    # spelling (shrinking an array in place, a raw revert, creating code from
    # bytes, arbitrary storage slots) stay in small declarations tagged
    # `@custom:solar-trusted`, which Solar's `@custom:solar-safe` profile also
    # recognizes. Every other line of every safe source and dependency is held
    # to the policy.
    # The stricter assembly-free audit also inspects trusted declarations.
    # Unchecked arithmetic is allowed, as in the default solar-safe profile.
    nodes = walk if assembly_free else unsafe_nodes
    return [
        (path, node["nodeType"])
        for path, source in output["sources"].items()
        for node in nodes(source["ast"])
        if (not assembly_free or node.get("nodeType") == "InlineAssembly")
        and (not allow_unchecked or node.get("nodeType") != "UncheckedBlock")
    ]


def trusted_declarations(output):
    """The `@custom:solar-trusted` declarations of every safe source, for the audit."""
    found = []
    for path, source in output["sources"].items():
        for node in walk(source["ast"]):
            if node.get("nodeType") == "ContractDefinition":
                for item in [node, *node.get("nodes", [])]:
                    if is_trusted(item):
                        name = node["name"] + ("" if item is node else "." + item.get("name", ""))
                        found.append(f"{path}:{name}")
    return sorted(set(found))


def type_name(parameter):
    return re.sub(
        r" (memory|calldata|storage)( (ref|pointer))?$",
        "",
        parameter["typeDescriptions"]["typeString"],
    )


def api_rows(ast):
    rows = []
    for contract in ast.get("nodes", []):
        if contract.get("nodeType") != "ContractDefinition":
            continue
        for fn in contract["nodes"]:
            if (
                fn.get("nodeType") != "FunctionDefinition"
                or fn["visibility"] == "private"
            ):
                continue
            params = [
                (type_name(p), p["storageLocation"])
                for p in fn["parameters"]["parameters"]
            ]
            returns = [
                (type_name(p), p["storageLocation"])
                for p in fn["returnParameters"]["parameters"]
            ]
            rows.append(
                {
                    "library": contract["name"],
                    "name": fn["name"],
                    "params": params,
                    "parameter_names": [
                        p["name"] for p in fn["parameters"]["parameters"]
                    ],
                    "returns": returns,
                    "visibility": fn["visibility"],
                    "mutability": fn["stateMutability"],
                    "signature": fn["name"]
                    + "("
                    + ",".join(p[0] for p in params)
                    + ")",
                }
            )
    return rows


def closure(sources, roots):
    result = {}
    pending = list(roots)
    while pending:
        path = pending.pop()
        if path in result:
            continue
        result[path] = sources[path]
        for imp in re.findall(
            r'\bimport\s+(?:[^;]*?from\s+)?["\']([^"\']+)["\']',
            sources[path]["content"],
        ):
            pending.append(
                posixpath.normpath(posixpath.join(posixpath.dirname(path), imp))
                if imp.startswith(".")
                else imp
            )
    return result


def opcode_gas(logs) -> int:
    """Opcode gas the call spent, excluding the transaction's intrinsic gas.

    A step's `gasCost` is what it deducted, except for a call, which reports
    the allowance it forwarded; a precompile leaves no steps of its own, so a
    sum of the costs would bill a precompile call everything it forwarded.
    The gas the outer frame had at its first step, less what it had left
    after its last, counts every call at what it used, and equals that sum
    for code that makes no call.
    """
    if not logs:
        return 0
    depth = logs[0]["depth"]
    last = next(step for step in reversed(logs) if step["depth"] == depth)
    return int(logs[0]["gas"]) - int(last["gas"]) + int(last["gasCost"])


def dispatch_gas(logs, code: bytes, selector: bytes) -> int | None:
    """Opcode gas spent before the selector dispatch enters the wrapper.

    The dispatch ends at the jump decided by comparing the call's selector
    with its own `PUSH4` immediate: taken after `EQ`, or not taken after
    `SUB`/`XOR`, with every `ISZERO` in between flipping the sense. A jump is
    taken when the next step does not follow it. Other shapes return None.
    Each compiler's shared prologue, such as free-memory setup or call-value
    checks, counts on whichever side of the dispatch it places it.
    """
    spent = 0
    state = None  # "armed", or whether a taken jump means the selector matched
    for index, step in enumerate(logs):
        spent += int(step["gasCost"])
        op = step["op"]
        if op == "PUSH4":
            pc = step["pc"]
            state = "armed" if code[pc + 1 : pc + 5] == selector else None
            continue
        if state is None or op.startswith(("DUP", "SWAP")):
            continue
        if state == "armed":
            state = True if op == "EQ" else False if op in ("SUB", "XOR") else None
            continue
        if op == "ISZERO":
            state = not state
            continue
        if op.startswith("PUSH"):
            continue
        if op == "JUMPI":
            taken = index + 1 < len(logs) and logs[index + 1]["pc"] != step["pc"] + 1
            if taken == state:
                return spent
        state = None
    return None


# LibBytes operations LibString's cases cover on their strings' bytes.
SHARED_TEXT_APIS = frozenset(
    {
        "replace",
        "indexOf",
        "lastIndexOf",
        "contains",
        "startsWith",
        "endsWith",
        "repeat",
        "slice",
        "sliceCalldata",
        "indicesOf",
        "split",
        "concat",
        "eq",
        "eqs",
        "cmp",
    }
)
# The most word arguments a harness wrapper can take; see `prepare`.
MAX_WRAPPER_PARAMS = 12


def wrapper_name(library: str, signature: str) -> str:
    """Names an API's harness wrapper after the API alone.

    The name fixes the wrapper's selector and so its dispatch position, which
    then stays put when other APIs join or leave the harness.
    """
    return "f" + keccak(f"{library}.{signature}".encode())[:4].hex()


def select_harness_apis(apis, api_filters, isolate):
    requested = set(api_filters or ())
    found = {row["library"] + "." + row["signature"] for row in apis}
    if requested - found:
        raise ValueError(f"unknown API filters: {sorted(requested - found)}")
    if isolate and not requested:
        raise ValueError("--isolate-api requires at least one --api filter")
    if not isolate:
        return apis
    return [
        row
        for row in apis
        if row["library"] + "." + row["signature"] in requested
    ]


def prepare(
    solc,
    out,
    api_filters=(),
    isolate=False,
    upstream_overrides=(),
    cache=Cache(),
):
    archive = json.loads(gzip.decompress(ARCHIVE.read_bytes()))
    # Upstream ships per-fork variants of some libraries (`src/utils/clz/`).
    # An override measures against the variant a user of that fork imports,
    # under the path the shared harness already names. The API check below
    # still requires its declarations to match the port's.
    overridden = {}
    for item in upstream_overrides:
        path, _, source = item.partition("=")
        if path not in archive["sources"] or not source:
            raise ValueError(f"bad --upstream-override: {item}")
        content = Path(source).read_text()
        archive["sources"][path] = {"content": content}
        overridden[path] = digest(content.encode())
    safe = closure(
        {
            p.relative_to(ROOT).as_posix(): {"content": p.read_text()}
            for p in sorted((ROOT / "src").rglob("*.sol"))
        },
        [f"src/utils/{name}.sol" for name in CHECKED_LIBRARIES],
    )
    safe = dict(sorted(safe.items()))
    ast_settings = {"outputSelection": {"*": {"": ["ast"]}}}
    safe_ast, _ = compile_cached(
        cache, solc, {"language": "Solidity", "sources": safe, "settings": ast_settings}
    )
    violations = safety_violations(safe_ast)
    if violations:
        raise ValueError(f"safe source audit failed: {violations}")
    # Parse the whole pinned archive for honest API coverage, without generating bytecode.
    original_ast, _ = compile_cached(
        cache,
        solc,
        {
            "language": "Solidity",
            "sources": archive["sources"],
            "settings": ast_settings,
        },
    )
    inventory = []
    apis = []
    for path, v in original_ast["sources"].items():
        if not path.startswith("src/"):
            continue
        upstream = api_rows(v["ast"])
        rewritten = api_rows(safe_ast["sources"][path]["ast"]) if path in safe else []
        upstream_by_sig = {r["signature"]: r for r in upstream}
        for row in rewritten:
            if row != upstream_by_sig.get(row["signature"]):
                raise ValueError(f"API declaration mismatch: {path}: {row}")
            apis.append(row)
        inventory.append(
            {
                "path": path,
                "upstream_apis": len(upstream),
                "rewritten_apis": len(rewritten),
                "missing": [r["signature"] for r in upstream if r not in rewritten],
            }
        )
    apis.sort(key=lambda x: (x["library"], x["signature"]))
    for row in apis:
        row["wrapper"] = wrapper_name(row["library"], row["signature"])
    if len({row["wrapper"] for row in apis}) != len(apis):
        raise ValueError("harness wrapper names collide")
    for row in apis:
        returns = list(row["returns"])
        # A storage parameter is the harness's own state variable, whose words
        # the runner writes before the call; the call takes the rest.
        row["storage"] = [
            i for i, (_, loc) in enumerate(row["params"]) if loc == "storage"
        ]
        row["wrapper_params"] = [
            (i, p) for i, p in enumerate(row["params"]) if i not in row["storage"]
        ]
        # Observe in-place updates through the identical wrapper in both sources:
        # a function without results returns every memory argument it may update.
        # A storage update is observed through the words it leaves in storage.
        row["observed"] = []
        if row["storage"]:
            pass
        elif not returns:
            row["observed"] = [
                i for i, (_, loc) in enumerate(row["params"]) if loc == "memory"
            ] or [0]
            returns = [row["params"][i] for i in row["observed"]]
        row["outputs"] = [t for t, _ in returns]
        row["wrapper_returns"] = returns
    # solc's legacy pipeline cannot keep more than twelve word arguments on its
    # stack while it encodes a call, so no leg could compile a wrapper for them.
    # A storage pointer result, such as a cast between storage structs, has no
    # ABI encoding for a wrapper to return.
    harness_apis = [
        row
        for row in select_harness_apis(apis, api_filters, isolate)
        if len(row["wrapper_params"]) <= MAX_WRAPPER_PARAMS
        and all(loc != "storage" for _, loc in row["wrapper_returns"])
    ]
    # Files the port adds have no upstream counterpart, so the shared harness
    # cannot import them by name: the upstream leg would not resolve the path.
    # The safe leg still reaches them through the libraries that use them.
    port_only = sorted(path for path in safe if path not in archive["sources"])
    harness = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
    for path in safe:
        if path not in port_only:
            harness += f'import "{path}";\n'
    for library in sorted({r["library"] for r in harness_apis}):
        if library in SIZE_HARNESSES:
            harness += "/// @custom:solar-optimize size\n"
        harness += f"contract {library}Harness {{\n"
        rows = [row for row in harness_apis if row["library"] == library]
        slots = 0
        for row in rows:
            params = ", ".join(
                t + ("" if loc == "default" else " " + loc) + f" a{i}"
                for i, (t, loc) in row["wrapper_params"]
            )
            result_types = ", ".join(
                t + ("" if loc == "default" else " " + loc)
                for t, loc in row["wrapper_returns"]
            )
            state = "s" + row["wrapper"]
            args = [
                state if i in row["storage"] else f"a{i}"
                for i in range(len(row["params"]))
            ]
            call = row["library"] + "." + row["name"] + "(" + ", ".join(args) + ")"
            # A wrapper keeps its API's mutability: the precompile hashes are
            # `view`, since a staticcall is not provably pure, and a function
            # that may call out with side effects is neither.
            mutability = {"view": "view", "pure": "pure"}.get(row["mutability"], "")
            if row["storage"]:
                # Every struct here occupies one slot, in declaration order.
                struct = row["params"][row["storage"][0]][0].removeprefix("struct ")
                harness += f"{struct} internal {state};\n"
                row["storage_slot"] = slots
                slots += 1
                mutability = "view" if row["mutability"] == "view" else ""
                body = f"return {call};" if row["returns"] else f"{call};"
            else:
                observed = ", ".join(f"a{i}" for i in row["observed"])
                body = f"return {call};" if row["returns"] else f"{call}; return ({observed});"
            returns_clause = f" returns ({result_types})" if result_types else ""
            harness += f"function {row['wrapper']}({params}) external {mutability}{returns_clause} {{ {body} }}\n"
        harness += "}\n"
    safe["Harness.sol"] = {"content": harness}
    # Sorted like the safe sources: the closure's order follows a set's, which
    # changes from run to run, and a compiler may depend on the input's order.
    upstream = dict(
        sorted(
            closure(archive["sources"], safe.keys() - {"Harness.sol"} - set(port_only)).items()
        )
    )
    upstream["Harness.sol"] = {"content": harness}
    (out / "Harness.sol").write_text(harness)
    audit = {
        "archive": str(ARCHIVE.relative_to(REPO)),
        "archive_sha256": digest(ARCHIVE.read_bytes()),
        "policy": "no InlineAssembly or UncheckedBlock in any safe source or dependency outside declarations tagged @custom:solar-trusted",
        "trusted_declarations": trusted_declarations(safe_ast),
        "port_only_sources": port_only,
        "upstream_overrides": overridden,
        "source_sha256": {p: digest(v["content"].encode()) for p, v in safe.items()},
        "libraries": inventory,
        "implemented_apis": len(apis),
        "harness_apis": [
            row["library"] + "." + row["signature"] for row in harness_apis
        ],
        "isolated_harness": isolate,
        "library_count": sum(1 for p in safe if p != "Harness.sol"),
        "total_source_files": len(inventory),
    }
    (out / "api-coverage.json").write_text(json.dumps(audit, indent=2) + "\n")
    # A run measures the APIs the harness wraps.
    return safe, upstream, harness_apis, audit


# The words a storage case sets up and observes: the root slot and this many
# words derived from it, which covers every value the storage vectors store.
STORAGE_WORDS = 12


def storage_slots(slot):
    """The root slot and the derived slots whose words a storage case covers."""
    base = int.from_bytes(keccak(slot.to_bytes(32, "big")), "big")
    return [slot] + [(base + k) % (1 << 256) for k in range(STORAGE_WORDS)]

def packed_words(value, base=None):
    """The words of `value` stored over `base` in the `BytesStorage` layout.

    Up to 254 bytes keep the length in the root's low byte and the first 31
    bytes above it; a longer value keeps 0xff there and its length above. The
    rest follows in the derived words, and words a shorter value does not
    reach keep what `base` left in them.
    """
    words = list(base) if base else [bytes(32)] * (STORAGE_WORDS + 1)
    n = len(value)
    if n < 0xFF:
        words[0] = value[:31].ljust(31, b"\0") + bytes([n])
        start = 31
    else:
        words[0] = ((n << 8) | 0xFF).to_bytes(32, "big")
        start = 0
    for k, i in enumerate(range(start, n, 32)):
        words[1 + k] = value[i : i + 32].ljust(32, b"\0")
    return words


class EncodedArguments(bytes):
    """A case's arguments, already ABI-encoded.

    A case gives these to lay calldata out in a way no encoder would, such as
    one argument that points inside another.
    """


def as_bytes(value):
    """A string case's bytes: each string encoded, through lists."""
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, list):
        return [as_bytes(v) for v in value]
    return value


def storage_vectors(name, values, convert):
    """Cases for the `BytesStorage` operations.

    Each case is its arguments, its result, the words storage starts from and,
    for a store, the words it must leave. Every read is set up over a longer
    value, so words and bytes past the stored value's end hold what the longer
    value left there.
    """
    longer = packed_words(bytes((i * 13 + 5) % 95 + 32 for i in range(300)))
    if name in ("set", "setCalldata"):
        for base in (packed_words(b""), longer):
            for v in values:
                yield [convert(v)], [], base, packed_words(v, base)
    elif name == "clear":
        for v in values:
            words = packed_words(v, longer)
            yield [], [], words, [bytes(32)] + words[1:]
    elif name in ("get", "length", "isEmpty"):
        for v in values:
            out = convert(v) if name == "get" else len(v) if name == "length" else len(v) == 0
            yield [], [out], packed_words(v, longer)
    elif name == "uint8At":
        for v in values:
            n = len(v)
            for i in sorted({0, 1, 30, 31, 32, 62, 63, 64, max(n - 1, 0), n, n + 1, 300, MAX}):
                yield [i], [v[i] if i < n else 0], packed_words(v, longer)
    else:
        raise ValueError(f"no storage oracle for {name}")


def test_vectors(row, rng):
    name = row["name"]
    types = [t for t, _ in row["params"]]
    scalars = [0, 1, 2, 3, 255, 256, 257, 1 << 128, (1 << 255) - 1, 1 << 255, MAX]
    scalars += [rng.getrandbits(256) for _ in range(8)]
    blobs = [
        bytes((i * 37 + 11) % 256 for i in range(n))
        for n in [0, 1, 2, 3, 15, 16, 31, 32, 33, 63, 64, 65, 256]
    ]
    blobs += [bytes(range(256)), bytes(64), bytes([255]) * 64]
    if row["library"] == "EfficientHashLib":
        def words(values):
            return b"".join(v.to_bytes(32, "big") for v in values)

        def clamp(n, start, end):
            end = min(end, n)
            start = min(start, n)
            return start, max(end - start, 0)

        digest_of = hashlib.sha256 if name.startswith("sha2") else None

        def as_type(ty, value):
            return value.to_bytes(32, "big") if ty == "bytes32" else value

        if name == "set":
            for n in [1, 2, 8]:
                buffer = [rng.getrandbits(256) for _ in range(n)]
                for i in [0, n - 1]:
                    value = rng.getrandbits(256)
                    expected = list(buffer)
                    expected[i] = value
                    yield (
                        [[v.to_bytes(32, "big") for v in buffer], i, as_type(types[2], value)],
                        [[v.to_bytes(32, "big") for v in expected]],
                    )
            return
        if name == "malloc":
            for n in [0, 1, 2, 8, 33]:
                yield [n], [[bytes(32)] * n]
            return
        if name == "free":
            # Freeing hands a buffer's memory back, where the wrapper then
            # encodes its result; only the empty buffer, which `free` leaves
            # in place, can be returned afterwards.
            yield [[]], [[]]
            return
        if name == "eq":
            for b in blobs + [bytes(32), bytes([7]) * 32]:
                word = b[:32].rjust(32, b"\0")
                args = [word, b] if types[0] == "bytes32" else [b, word]
                yield args, [len(b) == 32 and b == word]
            return
        if types == ["bytes32[]"]:
            for n in [0, 1, 2, 3, 8, 33]:
                buffer = [rng.getrandbits(256) for _ in range(n)]
                yield [[v.to_bytes(32, "big") for v in buffer]], [keccak(words(buffer))]
            return
        if name == "sha2" and types == ["bytes32"]:
            for v in scalars:
                word = v.to_bytes(32, "big")
                yield [word], [hashlib.sha256(word).digest()]
            return
        if types and all(t in ("bytes32", "uint256") for t in types):
            # Every arity, with the neighbours of the word boundaries.
            picks = [0, 1, MAX, 1 << 255, (1 << 128) - 1] + [
                rng.getrandbits(256) for _ in range(3)
            ]
            for i in range(len(picks)):
                chosen = [picks[(i + j) % len(picks)] for j in range(len(types))]
                args = [as_type(t, v) for t, v in zip(types, chosen)]
                yield args, [keccak(words(chosen))]
            return
        if types and types[0] == "bytes":
            for b in blobs:
                spans = [(0, len(b)), (0, 0), (1, 1), (0, len(b) + 8), (len(b) + 4, len(b) + 9)]
                spans += [(len(b) // 2, len(b)), (len(b), 0)]
                for start, end in spans:
                    if len(types) == 3:
                        args = [b, start, end]
                    elif len(types) == 2:
                        args, end = [b, start], len(b)
                    else:
                        args, start, end = [b], 0, len(b)
                    offset, count = clamp(len(b), start, end)
                    part = b[offset : offset + count]
                    yield args, [digest_of(part).digest() if digest_of else keccak(part)]
                    if len(types) < 3:
                        break
            return
        raise ValueError(f"no oracle for {row}")
    if row["library"] == "SafeCastLib":
        bits = int(re.search(r"\d+", name)[0])
        signed = name.startswith("toInt")
        low = -(1 << (bits - 1)) if signed else 0
        high = (1 << (bits - 1 if signed else bits)) - 1
        values = {low - 1, low, low + 1, high - 1, high, high + 1, -1, 0, 1, MAX}
        domain = (-(1 << 255), (1 << 255) - 1) if types[0] == "int256" else (0, MAX)
        for value in sorted(v for v in values if domain[0] <= v <= domain[1]):
            yield (
                [value],
                [value] if low <= value <= high else keccak(b"Overflow()")[:4],
            )
        return
    if row["library"] == "MerkleProofLib":
        yield from merkle_vectors(name, rng)
        return
    if row["library"] == "ECDSA":
        yield from ecdsa_vectors(name, types, rng, blobs)
        return
    if row["library"] == "SignatureCheckerLib":
        yield from signature_checker_vectors(name, types, rng, blobs)
        return
    if row["library"] == "Base64":
        if name == "encode":
            for b in blobs:
                for mode in range(1 << (len(types) - 1)):
                    opts = [bool(mode & (1 << j)) for j in range(len(types) - 1)]
                    out = (
                        base64.urlsafe_b64encode
                        if opts and opts[0]
                        else base64.b64encode
                    )(b)
                    if len(opts) == 2 and opts[1]:
                        out = out.rstrip(b"=")
                    yield [b, *opts], [out.decode()]
        else:
            for b in blobs:
                for url in [False, True]:
                    encoded = (base64.urlsafe_b64encode if url else base64.b64encode)(
                        b
                    ).decode()
                    for v in sorted(
                        {encoded, encoded.rstrip("="), encoded.replace("/", ",")}
                    ):
                        yield [v], [b]
        return
    if row["library"] == "LibSort":
        t = types[0][:-2]
        arrays = []
        for n in [0, 1, 2, 15, 16, 17, 31, 32, 33, 64]:
            for shape in ["sorted", "reverse", "equal", "mixed"]:
                a = (
                    list(range(n))
                    if shape in ["sorted", "reverse"]
                    else [7] * n
                    if shape == "equal"
                    else [rng.randrange(0, 20) for _ in range(n)]
                )
                if shape == "reverse":
                    a.reverse()
                if t == "int256":
                    a = [x - 10 for x in a]
                arrays.append(a)
        low, high = (
            (-(1 << 255), (1 << 255) - 1)
            if t == "int256"
            else (0, mask(160) if t == "address" else MAX)
        )
        extremes = [low, high, low + 1, high - 1, 0, 1]
        arrays += [
            extremes,
            sorted(extremes),
            sorted(extremes, reverse=True),
            [high] * 33,
            [low, high] * 17,
            [high - i * (1 << 128) for i in range(33)],
        ]
        def typed(values):
            if t == "address":
                return ["0x" + x.to_bytes(20, "big").hex() for x in values]
            if t == "bytes32":
                return [x.to_bytes(32, "big") for x in values]
            return list(values)

        def search_sorted(values, needle):
            # The upstream probe sequence: a one-based binary search whose
            # last probe decides the nearest index when the needle is absent.
            l, h, t, index = 1, len(values), None, 0
            while True:
                index = (l + h) // 2
                if index != 0:
                    t = values[index - 1]
                if l > h or (index != 0 and t == needle):
                    break
                if needle <= t:
                    h = index - 1
                else:
                    l = index + 1
            found = index != 0 and t == needle
            return found, (index - 1 if index != 0 else 0)

        if name in ["searchSorted", "inSorted"]:
            for a in arrays:
                u = sorted(set(a))
                needles = set(u)
                needles |= {x + 1 for x in u if x + 1 <= high}
                needles |= {x - 1 for x in u if x - 1 >= low}
                needles |= {low, high, 0}
                for needle in sorted(needles):
                    found, index = search_sorted(u, needle)
                    yield [typed(u), typed([needle])[0]], (
                        [found] if name == "inSorted" else [found, index]
                    )
            return
        if name == "groupSum":
            def panic(code):
                return keccak(b"Panic(uint256)")[:4] + code.to_bytes(32, "big")

            def grouped(keys, values):
                # Keys order by their word value, so negative `int256` keys come last.
                if len(keys) != len(values):
                    return panic(0x32)
                if len(keys) < 2:
                    return [typed(keys), values]
                sums = {}
                for key, value in zip(keys, values):
                    word = key % (1 << 256)
                    sums[word] = sums.get(word, 0) + value
                if any(total > MAX for total in sums.values()):
                    return panic(0x11)
                words = sorted(sums)
                kept = [w - (1 << 256) if t == "int256" and w >> 255 else w for w in words]
                return [typed(kept), [sums[w] for w in words]]

            cases = []
            for a in arrays:
                cases.append((a, [rng.randrange(1 << 64) for _ in a]))
                # Few distinct keys make long runs of equal keys.
                cases.append(([a[i % 3] for i in range(len(a))] if a else a, list(range(len(a)))))
            base = [low, high, 0, 1]
            cases += [
                (base[:2], [5]),
                (base[:1], []),
                ([], [3]),
                ([1, 1], [MAX, 1]),
                ([2, 1, 2], [MAX - 5, 3, 6]),
                ([2, 1, 2], [MAX - 5, 3, 5]),
                (base * 5, [MAX // 11] * 20),
            ]
            for keys, values in cases:
                yield [typed(keys), values], grouped(keys, values)
            return
        if name in ["difference", "intersection", "union"]:
            uniques = [sorted(set(a)) for a in arrays]
            for u1, u2 in zip(uniques, uniques[1:] + uniques[:1]):
                for x, y in [(u1, u2), (u1, u1), (u1, []), ([], u2)]:
                    expected = {
                        "difference": set(x) - set(y),
                        "intersection": set(x) & set(y),
                        "union": set(x) | set(y),
                    }[name]
                    yield [typed(x), typed(y)], [typed(sorted(expected))]
            return
        for a in arrays:
            if t == "address":
                a = ["0x" + x.to_bytes(20, "big").hex() for x in a]
            elif t == "bytes32":
                a = [x.to_bytes(32, "big") for x in a]
            if name in ["sort", "insertionSort"]:
                expected = sorted(a)
            elif name == "reverse":
                expected = list(reversed(a))
            elif name in ["copy", "clean"]:
                expected = list(a)
            elif name == "hasDuplicate":
                expected = len(set(a)) != len(a)
            elif name == "isSortedAndUniquified":
                expected = all(a[i - 1] < a[i] for i in range(1, len(a)))
            elif name == "uniquifySorted":
                # The input must be sorted; equal neighbours collapse and the
                # in-place wrapper returns the shortened array.
                a = sorted(a)
                expected = sorted(set(a))
            else:
                expected = a == sorted(a)
            yield [a], [expected]
        return
    if row["library"] == "LibBit":
        if types == ["uint256"]:
            # Exercise every bit position, every population count and both
            # neighbours of powers of two, including the highest EVM bit.
            scalars += [
                v for bit in range(256) for v in [1 << bit, MAX ^ (1 << bit), mask(bit)]
            ]
            scalars = list(dict.fromkeys(scalars))
        if types == ["bool"] * len(types):
            for i in range(1 << len(types)):
                args = [bool(i & (1 << j)) for j in range(len(types))]
                expected = (
                    int(args[0])
                    if name in ["toUint", "rawToUint"]
                    else all(args)
                    if name in ["and", "rawAnd"]
                    else any(args)
                )
                yield args, [expected]
        elif types == ["bytes"]:
            scan_cases = (
                [
                    bytes(256),
                    bytes(257),
                    bytes(1024),
                    bytes([0, 1]) * 512,
                    bytes([1]) * 1023 + bytes([0]),
                ]
                if name.startswith("countZeroBytes")
                else []
            )
            for b in blobs + [bytes(33)] + scan_cases:
                yield (
                    [b],
                    [
                        bytes(y for x in b for y in (x >> 4, x & 15))
                        if name == "toNibbles"
                        else b.count(0)
                    ],
                )
        else:
            for x in scalars:
                if len(types) == 2:
                    for y in [x, 0, MAX, rng.getrandbits(256)]:
                        s = (x ^ y).bit_length()
                        width = (
                            1
                            if name == "commonBitPrefix"
                            else 4
                            if name == "commonNibblePrefix"
                            else 8
                        )
                        s = ((s + width - 1) // width) * width
                        yield [x, y], [(x >> s) << s]
                else:
                    result = {
                        "fls": x.bit_length() - 1 if x else 256,
                        "clz": 256 - x.bit_length(),
                        "ffs": (x & -x).bit_length() - 1 if x else 256,
                        "popCount": x.bit_count(),
                        "countZeroBytes": x.to_bytes(32, "big").count(0),
                        "isPo2": bool(x and not x & (x - 1)),
                        "reverseBytes": int.from_bytes(x.to_bytes(32, "big"), "little"),
                        "reverseBits": int(f"{x:0256b}"[::-1], 2),
                    }[name]
                    yield [x], [result]
        return
    if row["library"] == "LibBytes" and row["storage"]:
        blobs = [
            bytes((i * 37 + 11) % 256 for i in range(n))
            for n in [0, 1, 5, 31, 32, 33, 63, 64, 100, 254, 255, 256, 300]
        ]
        yield from storage_vectors(name, blobs, bytes)
        return
    if row["library"] == "LibBytes":
        yield from bytes_vectors(row, types, blobs, rng)
        return
    if row["library"] == "LibString":
        NOT_FOUND = MAX
        words = ["", "a", "ab", "abc", "hello world", "aaa", "banana", "a" * 32, "a" * 33]
        needles = ["", "a", "aa", "an", "na", "world", "xyz", "b" * 40]

        def checksummed(address):
            digits = address[2:].lower()
            hashed = keccak(digits.encode())
            out = ""
            for i, c in enumerate(digits):
                nibble = hashed[i // 2] >> (4 if i % 2 == 0 else 0) & 15
                out += c.upper() if c.isalpha() and nibble >= 8 else c
            return "0x" + out

        def indices_of(subject, needle):
            found, i = [], 0
            if len(needle) > len(subject):
                return found
            while i + len(needle) <= len(subject):
                if subject[i : i + len(needle)] == needle:
                    found.append(i)
                    i += len(needle) or 1
                else:
                    i += 1
            return found

        def small_length(word):
            n = 0
            while n < 32 and word[n] != 0:
                n += 1
            return n

        def escape_json(subject, quotes):
            out = ""
            for c in subject:
                if ord(c) >= 0x20:
                    out += "\\" + c if c in '"\\' else c
                elif c in "\b\t\n\f\r":
                    out += {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}[c]
                else:
                    out += "\\u%04x" % ord(c)
            return '"' + out + '"' if quotes else out

        small = [b"", b"a", b"hello", b"ab\x00cd", b"z" * 31, b"z" * 32, b"\x00abc"]
        if row["storage"]:
            texts = [
                bytes((i * 7 + 3) % 95 + 32 for i in range(n))
                for n in [0, 1, 5, 31, 32, 33, 63, 64, 100, 254, 255, 256, 300]
            ]
            yield from storage_vectors(name, texts, bytes.decode)
            return
        if name == "directReturn":
            for n in [0, 1, 31, 32, 33, 64, 100, 300]:
                s = "".join(chr((i * 7 + 3) % 95 + 32) for i in range(n))
                yield [s], [s]
            return
        if name == "toHexStringChecksummed":
            for x in scalars:
                address = "0x" + (x & mask(160)).to_bytes(20, "big").hex()
                yield [address], [checksummed(address)]
        elif name == "replace":
            for subject in words:
                for needle in needles:
                    for replacement in ["", "-", "xyz"]:
                        yield [subject, needle, replacement], [subject.replace(needle, replacement)]
        elif name in ["indexOf", "lastIndexOf"]:
            for subject in words:
                for needle in needles:
                    froms = [0, 1, 2, 5, len(subject), len(subject) + 1, MAX] if len(types) == 3 else [None]
                    for start in froms:
                        n, m = len(subject), len(needle)
                        if name == "indexOf":
                            f = 0 if start is None else start
                            if m == 0:
                                expected = min(f, n)
                            elif f >= n or m > n - f:
                                expected = NOT_FOUND
                            else:
                                hit = subject.find(needle, f)
                                expected = NOT_FOUND if hit < 0 else hit
                        else:
                            f = MAX if start is None else start
                            if m > n:
                                expected = NOT_FOUND
                            else:
                                f = min(f, n - m)
                                hit = subject.rfind(needle, 0, f + m)
                                expected = NOT_FOUND if hit < 0 else hit
                        yield ([subject, needle] + ([] if start is None else [start])), [expected]
        elif name in ["contains", "startsWith", "endsWith"]:
            for subject in words:
                for needle in needles:
                    expected = {
                        "contains": needle in subject,
                        "startsWith": subject.startswith(needle),
                        "endsWith": subject.endswith(needle),
                    }[name]
                    yield [subject, needle], [expected]
        elif name == "repeat":
            for subject in ["", "a", "ab", "abc" * 11]:
                for times in [0, 1, 2, 3, 33]:
                    yield [subject, times], [subject * times]
        elif name == "slice":
            for subject in words:
                for start in [0, 1, 2, 5, 32, 33, MAX]:
                    if len(types) == 3:
                        for end in [0, 1, 2, 5, 32, 33, MAX]:
                            s2, e2 = min(start, len(subject)), min(end, len(subject))
                            yield [subject, start, end], [subject[s2:e2] if s2 < e2 else ""]
                    else:
                        yield [subject, start], [subject[min(start, len(subject)) :]]
        elif name == "indicesOf":
            for subject in words:
                for needle in needles:
                    yield [subject, needle], [indices_of(subject, needle)]
        elif name == "split":
            for subject in words + ["a,b,,c", ",", "a,", ",a"]:
                for delimiter in ["", ",", "a", "an", "xyz"]:
                    if delimiter == "":
                        expected = list(subject)
                    else:
                        expected = subject.split(delimiter)
                    yield [subject, delimiter], [expected]
        elif name == "fromSmallString":
            for word in small:
                padded = word.ljust(32, b"\x00")
                yield [padded], [padded[: small_length(padded)].decode()]
        elif name == "normalizeSmallString":
            for word in small:
                padded = word.ljust(32, b"\x00")
                n = small_length(padded)
                yield [padded], [padded[:n] + bytes(32 - n)]
        elif name == "toSmallString":
            for subject in ["", "a", "hello", "z" * 31, "z" * 32, "z" * 33, "a" * 64]:
                yield (
                    [subject],
                    [subject.encode().ljust(32, b"\x00")]
                    if len(subject) <= 32
                    else keccak(b"TooBigForSmallString()")[:4],
                )
        elif name == "escapeHTML":
            for subject in ["", "plain", "<a href=\"x\">Tom & Jerry's</a>", "é<>", "&" * 33]:
                yield (
                    [subject],
                    [
                        subject.replace("&", "&amp;")
                        .replace('"', "&quot;")
                        .replace("'", "&#39;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                    ],
                )
        elif name == "escapeJSON":
            for subject in ["", "plain", 'say "hi"\\', "tab\tnew\nline", "\x01\x0b\x1f", "é" * 20]:
                for quotes in [False, True] if len(types) == 2 else [False]:
                    yield ([subject, quotes] if len(types) == 2 else [subject]), [
                        escape_json(subject, quotes)
                    ]
        elif name == "encodeURIComponent":
            for subject in ["", "abc-_.!~*'()", "a b&c=d/e?f", "é日本", "%" * 33]:
                yield [subject], [urllib.parse.quote(subject, safe="-_.!~*'()")]
        elif name == "eqs":
            for subject in ["", "a", "hello", "ab", "z" * 32]:
                for word in small:
                    padded = word.ljust(32, b"\x00")
                    yield [subject, padded], [subject.encode() == padded[: small_length(padded)]]
        elif name == "cmp":
            for a in ["", "a", "ab", "b", "abc", "z" * 33, "z" * 32 + "a"]:
                for b in ["", "a", "ab", "b", "abd", "z" * 33]:
                    x, y = a.encode(), b.encode()
                    yield [a, b], [0 if x == y else (-1 if x < y else 1)]
        elif name == "packOne":
            for subject in ["", "a", "hello", "z" * 31, "z" * 32]:
                data = subject.encode()
                packed = bytes([len(data)]) + data if 0 < len(data) < 32 else b""
                yield [subject], [packed.ljust(32, b"\x00")]
        elif name == "unpackOne":
            for subject in ["", "a", "hello", "z" * 31]:
                data = subject.encode()
                packed = (bytes([len(data)]) + data if data else b"").ljust(32, b"\x00")
                yield [packed], [subject]
        elif name == "packTwo":
            for a in ["", "a", "hello", "z" * 15]:
                for b in ["", "b", "world", "y" * 15, "y" * 16]:
                    x, y = a.encode(), b.encode()
                    total = len(x) + len(y)
                    packed = bytes([len(x)]) + x + bytes([len(y)]) + y if 0 < total <= 30 else b""
                    yield [a, b], [packed.ljust(32, b"\x00")]
        elif name == "unpackTwo":
            for a in ["", "a", "hello", "z" * 15]:
                for b in ["", "b", "world", "y" * 15]:
                    x, y = a.encode(), b.encode()
                    if len(x) + len(y) == 0:
                        packed = bytes(32)
                    else:
                        packed = (bytes([len(x)]) + x + bytes([len(y)]) + y).ljust(32, b"\x00")
                    yield [packed], [a, b]
        elif name == "toString":
            for x in scalars:
                if types[0] == "int256" and x >= 1 << 255:
                    x -= 1 << 256
                yield [x], [str(x)]
        elif name.startswith("to") and "HexString" in name:
            prefix = "" if "NoPrefix" in name else "0x"
            if types[0] == "bytes":
                for b in blobs:
                    yield [b], [prefix + b.hex()]
            else:
                for x in scalars:
                    if types[0] == "address":
                        x &= mask(160)
                    arg = (
                        "0x" + x.to_bytes(20, "big").hex()
                        if types[0] == "address"
                        else x
                    )
                    if len(types) == 2:
                        for n in [0, 1, 16, 20, 31, 32, 33]:
                            yield (
                                [arg, n],
                                [prefix + x.to_bytes(n, "big").hex()]
                                if x.bit_length() <= 8 * n
                                else keccak(b"HexLengthInsufficient()")[:4],
                            )
                    else:
                        h = format(x, "x")
                        if "Minimal" not in name:
                            h = h.zfill(
                                40 if types[0] == "address" else (len(h) + 1) // 2 * 2
                            )
                        yield [arg], [prefix + h]
        elif name == "runeCount":
            for s in ["", "hello", "é", "日本語", "🐱" * 33, "a" * 256]:
                yield [s], [len(s)]
        elif name in ["concat", "eq"]:
            for a, b in [("", ""), ("a", "b"), ("same", "same"), ("a" * 33, "b" * 64)]:
                yield [a, b], [a + b if name == "concat" else a == b]
        elif name in ["lower", "upper", "toCase"]:
            for s in ["", "Hello WORLD 0![]", "aBcD" * 16]:
                for upper in [False, True] if name == "toCase" else [name == "upper"]:
                    yield (
                        [s, upper] if name == "toCase" else [s],
                        [s.upper() if upper else s.lower()],
                    )
        else:
            for s in [
                "",
                "ASCII",
                "a" * 31,
                "a" * 32,
                "a" * 33,
                "a" * 256,
                "a" * 1024,
                "é",
                "a" * 32 + "é",
                "é" + "a" * 1023,
                "a" * 1023 + "é",
                "\0",
            ]:
                if name == "to7BitASCIIAllowedLookup":
                    yield (
                        [s],
                        [sum(1 << x for x in set(s.encode()))]
                        if s.isascii()
                        else keccak(b"StringNot7BitASCII()")[:4],
                    )
                elif len(types) == 2:
                    for allowed in [0, mask(128), 1 << 65]:
                        yield [s, allowed], [all(allowed >> x & 1 for x in s.encode())]
                else:
                    yield [s], [s.isascii()]
        return
    raise ValueError(f"no oracle for {row}")


def bytes_vectors(row, types, blobs, rng):
    """Cases for LibBytes' operations on memory and calldata bytes."""
    name = row["name"]

    def word(value):
        return value.to_bytes(32, "big")

    def padded(data):
        return data + bytes(-len(data) % 32)

    def tail(data):
        return word(len(data)) + padded(data)

    if name in SHARED_TEXT_APIS or name == "directReturn" and types == ["bytes"]:
        # LibString runs these on its strings' bytes, so its cases carry over.
        shared = {**row, "library": "LibString", "name": name.removesuffix("Calldata")}
        for args, expected in test_vectors(shared, rng):
            yield as_bytes(args), as_bytes(expected)
    elif name == "directReturn":
        for items in [[], [b""], [b"a"], [b"hello", b"", b"x" * 33], [blobs[-1]] * 3]:
            yield [items], [items]
    elif name == "indexOfByte":
        for subject in blobs + [b"no needle until here: a", b"a" * 33]:
            for needle in [b"\x00", b"\x0b", b"a", b"\xff"]:
                n = len(subject)
                if len(types) == 2:
                    froms = [None]
                else:
                    froms = sorted({0, 1, 31, 32, 33, max(n - 1, 0), n, n + 1, MAX})
                for start in froms:
                    f = start or 0
                    hit = subject.find(needle, f) if f < n else -1
                    args = [subject, needle] + ([] if start is None else [start])
                    yield args, [MAX if hit < 0 else hit]
    elif name in ("truncate", "truncatedCalldata"):
        for subject in blobs:
            n = len(subject)
            for size in sorted({0, 1, 31, 32, 33, max(n - 1, 0), n, n + 1, MAX}):
                yield [subject, size], [subject[:size]]
    elif name in ("load", "loadCalldata"):
        # A read past the end sees whatever follows the bytes, which differs
        # between builds, so only whole words inside them are compared.
        for subject in blobs:
            for offset in sorted({0, 1, 31, 32, len(subject) - 32}):
                if 0 <= offset <= len(subject) - 32:
                    yield [subject, offset], [subject[offset : offset + 32]]
    elif name in ("staticStructInCalldata", "dynamicStructInCalldata", "bytesInCalldata"):
        payloads = [b"", b"z", b"y" * 32, b"x" * 33]
        subjects = [b"", b"\x01" * 31, bytes(32), word(32), word(1 << 64), word(MAX)]
        subjects += [encode(["uint256", "bytes", "uint256"], [7, p, 9]) for p in payloads]
        # A relative offset whose bytes run past the end.
        subjects += [word(0x20) + word(0x40) + b"short"]
        for subject in subjects:
            n = len(subject)
            for offset in sorted(o for o in {0, 1, 0x20, 0x40, n - 32, n - 31, n, MAX} if o >= 0):
                fits = n >= 32 and offset <= n - 32
                s = int.from_bytes(subject[offset : offset + 32], "big") if fits else 0
                if name == "staticStructInCalldata":
                    yield [subject, offset], [subject[offset:]] if fits else b""
                elif name == "dynamicStructInCalldata":
                    if fits and s >> 64 == 0 and s > n:
                        # The original's length wraps here, so its encoding
                        # runs out of gas rather than reverting.
                        continue
                    yield [subject, offset], [subject[s:]] if fits and s >> 64 == 0 else b""
                else:
                    if fits and s >> 64 == 0 and s <= n - 32:
                        size = int.from_bytes(subject[s : s + 32], "big")
                        if size >> 64 == 0 and s + size <= n - 32:
                            yield [subject, offset], [subject[s + 32 : s + 32 + size]]
                            continue
                    yield [subject, offset], b""
    elif name == "checkInCalldata" and types[0] == "bytes":
        # In ABI order the first argument comes first, outside the second.
        for x, a in [(b"", b""), (b"ab", b"abc"), (b"x" * 33, b"x" * 64)]:
            yield [x, a], b""
        for a in [b"", b"z", b"y" * 32, b"x" * 33]:
            # Both point at the same bytes.
            yield EncodedArguments(word(0x40) + word(0x40) + tail(a)), [a]
        for size, inner in [(0, b""), (3, b"abc"), (3, b"abcdef"), (40, b"q" * 40)]:
            # `x` starts inside `a`, at `a`'s second word.
            a = word(size) + inner
            fits = 0x20 + size <= len(a)
            x = (inner + bytes(64))[:size]
            yield EncodedArguments(word(0x60) + word(0x40) + tail(a)), [x] if fits else b""
        # `x` runs past `a` into the padding after it.
        yield EncodedArguments(word(0x60) + word(0x40) + tail(word(5) + b"abc")), b""
    elif name == "checkInCalldata":
        for items in [[], [b"a"], [b"", b"xyz" * 20]]:
            yield [items, encode(["bytes[]"], [items])], b""
            # `x` is the array `a` holds the encoding of: its length word is
            # `a`'s second word.
            a = encode(["bytes[]"], [items])
            yield EncodedArguments(word(0x80) + word(0x40) + tail(a)), [items]
            if items:
                # `a` ends a word early, cutting its last element off.
                yield EncodedArguments(word(0x80) + word(0x40) + word(len(a) - 32) + a), b""
    elif name == "emptyCalldata":
        yield [], [b""]
    elif name in ("msbToAddress", "lsbToAddress"):
        for x in [0, 1, MAX, 1 << 255, (1 << 160) - 1] + [rng.getrandbits(256) for _ in range(4)]:
            raw = word(x)
            address = raw[:20] if name == "msbToAddress" else raw[12:]
            yield [raw], ["0x" + address.hex()]
    else:
        raise ValueError(f"no oracle for {row}")


def merkle_pair(a, b):
    # The smaller word is hashed first, as the assembly orders them in scratch.
    return keccak(min(a, b) + max(a, b))


def merkle_tree(leaves):
    # OpenZeppelin's array layout: leaves at the end, in reverse, and each
    # node the hash of its two children.
    n = len(leaves)
    tree = [b""] * (2 * n - 1)
    for i, leaf in enumerate(leaves):
        tree[len(tree) - 1 - i] = leaf
    for i in range(len(tree) - 1 - n, -1, -1):
        tree[i] = merkle_pair(tree[2 * i + 1], tree[2 * i + 2])
    return tree


def merkle_proof(tree, index):
    proof = []
    while index > 0:
        proof.append(tree[index - 1 if index % 2 == 0 else index + 1])
        index = (index - 1) // 2
    return proof


def merkle_multiproof(tree, indices):
    # OpenZeppelin's `getMultiProof`: a queue of tree indices, deepest first.
    stack = sorted(indices, reverse=True)
    leaves = [tree[i] for i in stack]
    proof, flags = [], []
    while stack and stack[0] > 0:
        j = stack.pop(0)
        sibling = j - 1 if j % 2 == 0 else j + 1
        if stack and stack[0] == sibling:
            flags.append(True)
            stack.pop(0)
        else:
            flags.append(False)
            proof.append(tree[sibling])
        stack.append((j - 1) // 2)
    return proof, leaves, flags


def merkle_fold(proof, leaf):
    for sibling in proof:
        leaf = merkle_pair(leaf, sibling)
    return leaf


def merkle_verify_multi(proof, root, leaves, flags):
    # The assembly's queue, which returns false wherever it would read past
    # the written queue or the proof: its final proof check fails there.
    if len(leaves) + len(proof) != len(flags) + 1:
        return False
    if not flags:
        return (proof[0] if len(proof) == 1 else leaves[0]) == root
    hashes, front, used = list(leaves), 0, 0
    for flag in flags:
        if front == len(hashes):
            return False
        a = hashes[front]
        front += 1
        if flag:
            if front == len(hashes):
                return False
            b = hashes[front]
            front += 1
        else:
            if used == len(proof):
                return False
            b = proof[used]
            used += 1
        hashes.append(merkle_pair(a, b))
    return hashes[-1] == root and used == len(proof)


def merkle_vectors(name, rng):
    def word():
        return rng.getrandbits(256).to_bytes(32, "big")

    if name in ("emptyProof", "emptyLeaves", "emptyFlags"):
        yield [], [[]]
        return

    trees = []
    for n in [1, 2, 3, 4, 5, 7, 8, 16, 33]:
        leaves = [word() for _ in range(n)]
        trees.append((leaves, merkle_tree(leaves)))
    if name.startswith("verifyMultiProof"):
        for leaves, tree in trees:
            n = len(leaves)
            first = len(tree) - n
            picks = {(), (first,), (len(tree) - 1,), tuple(range(first, len(tree)))}
            picks |= {tuple(sorted(rng.sample(range(first, len(tree)), min(k, n)))) for k in [2, 3]}
            for pick in sorted(picks):
                proof, chosen, flags = merkle_multiproof(tree, list(pick))
                if not chosen:
                    proof = [tree[0]]
                root = tree[0]
                variants = [
                    (proof, root, chosen, flags),
                    (proof, word(), chosen, flags),
                    (proof[:-1], root, chosen, flags),
                    (proof, root, chosen, flags + [True]),
                    (proof, root, chosen, [not f for f in flags]),
                    (proof, root, list(reversed(chosen)), flags),
                    (proof + [word()], root, chosen, flags + [False]),
                    (proof, root, chosen, [True] * len(flags)),
                    (proof, root, chosen, [False] * len(flags)),
                ]
                for proof_v, root_v, leaves_v, flags_v in variants:
                    yield (
                        [proof_v, root_v, leaves_v, flags_v],
                        [merkle_verify_multi(proof_v, root_v, leaves_v, flags_v)],
                    )
        return
    for leaves, tree in trees:
        n = len(leaves)
        root = tree[0]
        for i in sorted({0, n // 2, n - 1}):
            index = len(tree) - 1 - i
            proof = merkle_proof(tree, index)
            leaf = tree[index]
            for proof_v, root_v, leaf_v in [
                (proof, root, leaf),
                (proof, root, word()),
                (proof, word(), leaf),
                (proof[:-1], root, leaf),
                (proof + [word()], root, leaf),
                (list(reversed(proof)), root, leaf),
            ]:
                yield [proof_v, root_v, leaf_v], [merkle_fold(proof_v, leaf_v) == root_v]
    for length in [0, 1, 2, 9]:
        proof = [word() for _ in range(length)]
        leaf = word()
        yield [proof, merkle_fold(proof, leaf), leaf], [True]


SECP_P = (1 << 256) - (1 << 32) - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
SECP_HALF_N_PLUS_1 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % SECP_P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], -1, SECP_P)
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], -1, SECP_P)
    x = (m * m - a[0] - b[0]) % SECP_P
    return x, (m * (a[0] - x) - a[1]) % SECP_P


def ec_mul(k, point):
    result = None
    while k:
        if k & 1:
            result = ec_add(result, point)
        point = ec_add(point, point)
        k >>= 1
    return result


def ec_address(point):
    return "0x" + keccak(point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))[12:].hex()


def ec_sign(z, d, k):
    point = ec_mul(k, SECP_G)
    r = point[0] % SECP_N
    s = pow(k, -1, SECP_N) * (z + r * d) % SECP_N
    return 27 + (point[1] & 1), r, s


def ec_recover(z, v, r, s):
    # The precompile: `v` exactly 27 or 28, `r` and `s` in [1, N), and `r` an
    # x-coordinate on the curve; the zero address stands for no answer.
    zero = "0x" + "00" * 20
    if v not in (27, 28) or not 0 < r < SECP_N or not 0 < s < SECP_N:
        return zero
    y2 = (pow(r, 3, SECP_P) + 7) % SECP_P
    y = pow(y2, (SECP_P + 1) // 4, SECP_P)
    if y * y % SECP_P != y2:
        return zero
    if y & 1 != v - 27:
        y = SECP_P - y
    r_inv = pow(r, -1, SECP_N)
    point = ec_add(ec_mul(-z * r_inv % SECP_N, SECP_G), ec_mul(s * r_inv % SECP_N, (r, y)))
    return zero if point is None else ec_address(point)


def ecdsa_vectors(name, types, rng, blobs):
    invalid = keccak(b"InvalidSignature()")[:4]
    zero = "0x" + "00" * 20

    def word(value):
        return value.to_bytes(32, "big")

    # (hash, v, r, s): signatures by three keys, then broken ones.
    tuples = []
    for key in [1, 2, rng.randrange(1, SECP_N)]:
        for _ in range(3):
            z = rng.getrandbits(256)
            tuples.append((z,) + ec_sign(z, key, rng.randrange(1, SECP_N)))
    z, v, r, s = tuples[0]
    tuples += [
        (z ^ 1, v, r, s),
        (z, 55 - v, r, s),
        (z, 0, r, s),
        (z, 29, r, s),
        (z, v, 0, s),
        (z, v, r, 0),
        (z, v, SECP_N, s),
        (z, v, r, SECP_N),
        (z, v, r, SECP_N - s),
        (z, 27, 1, 1),
    ]
    if name in ("recover", "tryRecover") and types == ["bytes32", "uint8", "bytes32", "bytes32"]:
        for z, v, r, s in tuples:
            got = ec_recover(z, v, r, s)
            yield [word(z), v, word(r), word(s)], (invalid if name == "recover" and got == zero else [got])
        return
    if name in ("recover", "tryRecover") and types == ["bytes32", "bytes32", "bytes32"]:
        for z, v, r, s in tuples:
            if v not in (27, 28) or s >> 255:
                continue
            vs = s | ((v - 27) << 255)
            got = ec_recover(z, v, r, s)
            yield [word(z), word(r), word(vs)], (invalid if name == "recover" and got == zero else [got])
        return
    if name in ("recover", "tryRecover", "recoverCalldata", "tryRecoverCalldata"):
        reverting = name.startswith("recover")
        for z, v, r, s in tuples:
            forms = [(word(r) + word(s) + bytes([v % 256]), ec_recover(z, v, r, s))]
            if v in (27, 28) and not s >> 255:
                vs = s | ((v - 27) << 255)
                forms.append((word(r) + word(vs), ec_recover(z, v, r, s)))
            for signature, got in forms:
                yield [word(z), signature], (invalid if reverting and got == zero else [got])
        for signature in [b"", bytes(63), bytes(66), bytes(65), bytes(64)]:
            yield [word(z), signature], (invalid if reverting else [zero])
        return
    if name == "toEthSignedMessageHash" and types == ["bytes32"]:
        for _ in range(4):
            h = word(rng.getrandbits(256))
            yield [h], [keccak(b"\x19Ethereum Signed Message:\n32" + h)]
        return
    if name == "toEthSignedMessageHash":
        messages = list(blobs) + [bytes(n) for n in [9, 10, 99, 100, 999, 1000, 9999, 10000]]
        for m in messages:
            yield [m], [keccak(b"\x19Ethereum Signed Message:\n" + str(len(m)).encode() + m)]
        return

    def canonical(r, v, s):
        if s >= SECP_HALF_N_PLUS_1:
            v ^= 7
            s = (SECP_N - s) % (1 << 256)
        return keccak(word(r) + word(s) + bytes([v % 256]))

    highs = [0, 1, SECP_HALF_N_PLUS_1 - 1, SECP_HALF_N_PLUS_1, SECP_N - 1, SECP_N, SECP_N + 1, MAX]
    if name == "canonicalHash" and types == ["uint8", "bytes32", "bytes32"]:
        for v in [0, 27, 28, 255]:
            for s in highs:
                r = rng.getrandbits(256)
                yield [v, word(r), word(s)], [canonical(r, v, s)]
        return
    if name == "canonicalHash" and types == ["bytes32", "bytes32"]:
        for vs in highs + [s | (1 << 255) for s in highs if s < (1 << 255)]:
            r = rng.getrandbits(256)
            v, s = 27 + (vs >> 255), vs & ((1 << 255) - 1)
            yield [word(r), word(vs)], [keccak(word(r) + word(s) + bytes([v]))]
        return
    if name in ("canonicalHash", "canonicalHashCalldata"):
        for s in highs:
            r = rng.getrandbits(256)
            for v in [0, 27, 28, 255]:
                yield [word(r) + word(s) + bytes([v])], [canonical(r, v, s)]
            yield [word(r) + word(s)], [canonical(r, 27 + (s >> 255), s & ((1 << 255) - 1))]
        for signature in [b"", bytes(1), bytes(63), bytes(66), bytes(range(100))]:
            digest = int.from_bytes(keccak(signature), "big") ^ 0xD62F1AB2
            yield [signature], [word(digest)]
        return
    if name == "emptySignature":
        yield [], [b""]
        return
    raise ValueError(f"no ECDSA vectors for {name}")


ERC1271_MAGIC = bytes.fromhex("1626ba7e")
ERC6492_SUFFIX = bytes.fromhex("6492" * 16)
ERC6492_VERIFIER = "0x0000bc370E4DC924F427d84e2f4B9Ec81626ba7E"
ERC6492_REVERTING_VERIFIER = "0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e"


def keccak_gate(expected_calldata, accept, reject):
    # Runtime code that hashes its calldata and ends with `accept` when the
    # hash is the one of `expected_calldata`, and with `reject` otherwise.
    head = bytes.fromhex("365f5f37365f20") + b"\x7f" + keccak(expected_calldata) + b"\x14"
    target = len(head) + 3 + len(reject)
    return "0x" + (head + bytes([0x60, target, 0x57]) + reject + b"\x5b" + accept).hex()


def return_word(word, opcode=0xF3):
    # mstore(0, word) then return|revert(0, 32)
    return b"\x7f" + word + bytes([0x5F, 0x52, 0x60, 0x20, 0x5F, opcode])


def fixed_answer(data, opcode=0xF3):
    # codecopy the bytes after the code to 0 and return|revert them.
    return "0x" + (
        bytes([0x60, len(data), 0x60, 0x0A, 0x5F, 0x39, 0x60, len(data), 0x5F, opcode]) + data
    ).hex()


def erc1271_payload(h, signature):
    return ERC1271_MAGIC + h + (0x40).to_bytes(32, "big") + len(signature).to_bytes(32, "big") + signature


def signature_checker_vectors(name, types, rng, blobs):
    def word(value):
        return value.to_bytes(32, "big")

    magic_word = ERC1271_MAGIC + bytes(28)
    wallet = "0x" + "a1" * 20
    no_code = "0x"
    key = rng.randrange(1, SECP_N)
    eoa = ec_address(ec_mul(key, SECP_G))
    h = word(rng.getrandbits(256))
    v, r, s = ec_sign(int.from_bytes(h, "big"), key, rng.randrange(1, SECP_N))
    long_form = word(r) + word(s) + bytes([v])
    short_form = word(r) + word(s | ((v - 27) << 255)) if not s >> 255 else None

    def recovers(signature, signer):
        if len(signature) == 65:
            got = ec_recover(int.from_bytes(h, "big"), signature[64], int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:64], "big"))
        elif len(signature) == 64:
            vs = int.from_bytes(signature[32:], "big")
            got = ec_recover(int.from_bytes(h, "big"), 27 + (vs >> 255), int.from_bytes(signature[:32], "big"), vs & ((1 << 255) - 1))
        else:
            return False
        return got != "0x" + "00" * 20 and got == signer.lower()

    def wallets(payload):
        # (code, verdict) for wallets answering the ERC1271 call `payload`.
        return [
            (keccak_gate(payload, return_word(magic_word), return_word(bytes(32))), True),
            (keccak_gate(payload + b"\x00", return_word(magic_word), return_word(bytes(32))), False),
            (fixed_answer(magic_word), True),
            (fixed_answer(magic_word + bytes(32)), True),
            (fixed_answer(ERC1271_MAGIC), False),
            (fixed_answer(magic_word, 0xFD), False),
            (fixed_answer(bytes(31) + b"\x01"), False),
        ]

    signatures = [long_form, bytes(64), bytes(65), b"", bytes(range(100))]
    if short_form:
        signatures.append(short_form)
    if name in ("isValidSignatureNow", "isValidSignatureNowCalldata", "isValidERC1271SignatureNow", "isValidERC1271SignatureNowCalldata") and types[2] == "bytes":
        erc1271_only = name.startswith("isValidERC1271")
        for signature in signatures:
            for signer in [eoa, "0x" + "00" * 20, "0x" + "b2" * 20]:
                expected = False if erc1271_only else (signer != "0x" + "00" * 20 and recovers(signature, signer))
                yield [signer, h, signature], [expected], None, None, {signer: no_code}
            for code, verdict in wallets(erc1271_payload(h, signature)):
                yield [wallet, h, signature], [verdict], None, None, {wallet: code}
        return
    if name in ("isValidSignatureNow", "isValidERC1271SignatureNow") and types[2:] == ["bytes32", "bytes32"]:
        erc1271_only = name.startswith("isValidERC1271")
        forms = [(r, s | ((v - 27) << 255))] if short_form else []
        forms += [(r, s), (0, 0), (r, s | (1 << 255))]
        for rr, vs in forms:
            vv, ss = 27 + (vs >> 255), vs & ((1 << 255) - 1)
            for signer in [eoa, "0x" + "00" * 20]:
                expected = False if erc1271_only else (signer != "0x" + "00" * 20 and recovers(word(rr) + word(vs), signer))
                yield [signer, h, word(rr), word(vs)], [expected], None, None, {signer: no_code}
            payload = ERC1271_MAGIC + h + (0x40).to_bytes(32, "big") + (65).to_bytes(32, "big") + word(rr) + word(ss) + bytes([vv])
            for code, verdict in wallets(payload):
                yield [wallet, h, word(rr), word(vs)], [verdict], None, None, {wallet: code}
        return
    if name in ("isValidSignatureNow", "isValidERC1271SignatureNow"):
        erc1271_only = name.startswith("isValidERC1271")
        for vv, rr, ss in [(v, r, s), (55 - v, r, s), (0, r, s), (v, 0, s), (255, r, SECP_N - 1)]:
            for signer in [eoa, "0x" + "00" * 20]:
                expected = False if erc1271_only else (
                    signer != "0x" + "00" * 20 and recovers(word(rr) + word(ss) + bytes([vv]), signer)
                )
                yield [signer, h, vv, word(rr), word(ss)], [expected], None, None, {signer: no_code}
            payload = ERC1271_MAGIC + h + (0x40).to_bytes(32, "big") + (65).to_bytes(32, "big") + word(rr) + word(ss) + bytes([vv])
            for code, verdict in wallets(payload):
                yield [wallet, h, vv, word(rr), word(ss)], [verdict], None, None, {wallet: code}
        return
    if name.startswith("isValidERC6492SignatureNow"):
        reverting = name == "isValidERC6492SignatureNow"
        verifier = ERC6492_REVERTING_VERIFIER if reverting else ERC6492_VERIFIER
        other = ERC6492_VERIFIER if reverting else ERC6492_REVERTING_VERIFIER
        opcode = 0xFD if reverting else 0xF3

        def inner_of(signature):
            # The `bytes` the third head word points at, when it lies inside.
            n = len(signature)
            if n < 96:
                return None
            offset = int.from_bytes(signature[64:96], "big")
            if offset > n - 32:
                return None
            length = int.from_bytes(signature[offset : offset + 32], "big")
            if length > n - 32 - offset:
                return None
            return signature[offset + 32 : offset + 32 + length]

        wrapped = [
            encode(["address", "bytes", "bytes"], ["0x" + "c3" * 20, bytes(range(37)), inner])
            + ERC6492_SUFFIX
            for inner in [long_form, bytes(range(70))]
        ]
        for signature in wrapped + [long_form, ERC6492_SUFFIX]:
            is_6492 = len(signature) >= 32 and signature[-32:] == ERC6492_SUFFIX
            inner = inner_of(signature) if is_6492 else None
            signers = [(eoa, no_code, False)]
            # A wallet only sees an inner signature the assembly reads in bounds.
            if not is_6492 or inner is not None:
                target = inner if is_6492 else signature
                signers += [(wallet, code, verdict) for code, verdict in wallets(erc1271_payload(h, target))[:3]]
            for signer, signer_code, signer_verdict in signers:
                has_code = signer_code != no_code
                payload = bytes(12) + bytes.fromhex(signer[2:]) + h + signature
                verifiers = [
                    (keccak_gate(payload, return_word(word(1), opcode), bytes([0x5F, 0x5F, opcode])), True),
                    (keccak_gate(payload + b"\x01", return_word(word(1), opcode), bytes([0x5F, 0x5F, opcode])), False),
                    (no_code, False),
                ]
                for verifier_code, verifier_ok in verifiers:
                    if is_6492:
                        expected = (has_code and signer_verdict) or verifier_ok
                    else:
                        expected = has_code and signer_verdict
                    if not has_code and not expected:
                        expected = recovers(signature, signer)
                    yield (
                        [signer, h, signature],
                        [expected],
                        None,
                        None,
                        {signer: signer_code, verifier: verifier_code, other: no_code},
                    )
        return
    if name == "toEthSignedMessageHash" and types == ["bytes32"]:
        for _ in range(4):
            value = word(rng.getrandbits(256))
            yield [value], [keccak(b"\x19Ethereum Signed Message:\n32" + value)]
        return
    if name == "toEthSignedMessageHash":
        for m in list(blobs) + [bytes(n) for n in [9, 10, 99, 100, 999, 1000]]:
            yield [m], [keccak(b"\x19Ethereum Signed Message:\n" + str(len(m)).encode() + m)]
        return
    if name == "emptySignature":
        yield [], [b""]
        return
    raise ValueError(f"no SignatureCheckerLib vectors for {name}")


def send_transaction(url, sender, to, data):
    tx = rpc(
        url,
        "eth_sendTransaction",
        [{"from": sender, "to": to, "data": "0x" + data.hex(), "gas": hex(80000000)}],
    )
    for _ in range(400):
        receipt = rpc(url, "eth_getTransactionReceipt", [tx])
        if receipt is not None:
            if int(receipt["status"], 16) != 1:
                raise RuntimeError(f"setup transaction failed: {to}")
            return
        time.sleep(0.02)
    raise RuntimeError(f"setup receipt timed out: {to}")


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        payload = json.load(response)
    if "error" in payload:
        raise RuntimeError(f"{method}: {payload['error']}")
    return payload["result"]


def launch_anvil(evm):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # A combined harness holds every API of a library in one contract, an
    # aggregate for measurement rather than an application, and a build that
    # trades bytes for gas can pass the deployment size limit with it. Deploy
    # it anyway; the report records every contract's size against the limit.
    process = subprocess.Popen(
        [
            "anvil",
            "--port",
            str(port),
            "--hardfork",
            evm,
            "--steps-tracing",
            "--gas-limit",
            "100000000",
            "--disable-code-size-limit",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("anvil exited before startup")
        try:
            accounts = rpc(url, "eth_accounts", [])
            return process, url, accounts[0]
        except (OSError, RuntimeError):
            time.sleep(0.1)
    process.terminate()
    process.wait(timeout=10)
    raise RuntimeError("anvil startup timed out")


def case_identity(library, api, calldata, evm_version, optimizer_runs, artifact):
    """Returns a stable identity for one compiler/input comparison."""
    fields = {
        "library": library,
        "api": api,
        "calldata": "0x" + calldata.hex(),
        "evm_version": evm_version,
        "optimizer_runs": optimizer_runs,
        "safe_input_sha256": artifact["input_sha256"],
        "solar_compiler_sha256": artifact["compiler_sha256"],
    }
    return digest(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode())


def trace_call(url, sender, address, code, calldata, slots, setup, accounts, observe):
    """Runs one case on the harness at `address` and returns what the node measured.

    The case first sets the storage words and account code it reads, so the
    call depends on no earlier one. A store (`observe`) then runs for real and
    reads its words back.
    """
    # The words storage starts from, written by the node itself.
    for slot, word in zip(slots, setup or []):
        rpc(url, "anvil_setStorageAt", [address, hex(slot), "0x" + word.hex()])
    for account, account_code in (accounts or {}).items():
        rpc(url, "anvil_setCode", [account, account_code])
    tx = {
        "from": sender,
        "to": address,
        "data": "0x" + calldata.hex(),
        "gas": hex(80000000),
    }
    trace = rpc(
        url,
        "debug_traceCall",
        [
            tx,
            "latest",
            {
                "disableStorage": True,
                "disableStack": True,
                "enableMemory": False,
            },
        ],
    )
    logs = trace["structLogs"]
    traced = {
        "opcode_gas": opcode_gas(logs),
        "dispatch_gas": dispatch_gas(logs, code, calldata[:4]),
        "trace_gas": trace.get("gas"),
        "failed": trace.get("failed", False),
        "return_data": "0x" + trace.get("returnValue", "").removeprefix("0x"),
    }
    if observe:
        # A store is observed through the words it leaves: run it for real
        # and read them back.
        send_transaction(url, sender, address, calldata)
        traced["storage"] = [
            rpc(url, "eth_getStorageAt", [address, hex(slot), "latest"])
            for slot in slots
        ]
    return traced


def trace_environment(evm_version, sender):
    """The key of what every trace depends on besides its harness and case.

    That is the node, its fork and account, and the code that turns a call into
    the measurements the cache keeps, so that changing how a call is measured
    traces every case afresh.
    """
    return Cache.key(
        "trace-environment",
        tool_identity("anvil"),
        evm_version,
        sender,
        [
            inspect.getsource(function)
            for function in (launch_anvil, trace_call, send_transaction, opcode_gas, dispatch_gas)
        ],
    )


def trace_case_key(calldata, slots, setup, accounts, observe):
    """The key of one case's inputs to `trace_call`."""
    return Cache.key(
        "trace-case",
        calldata.hex(),
        [hex(slot) for slot in slots],
        [word.hex() for word in setup] if setup else None,
        sorted((accounts or {}).items()),
        observe,
    )


class TraceCache:
    """Traces kept in a `Cache` by harness, then by case.

    A harness is one deployed contract: its address and its creation and
    runtime code, on a node `environment` describes. A leg whose bytecode is
    unchanged finds every trace it made before, and a changed harness traces
    its cases afresh. Reusing some cases while tracing others gives the results
    of tracing them all because calls share no state: a case sets the storage
    words and account code its call reads, and no harness reads the block or
    the sender's balance, which the stores of earlier cases advance.
    """

    def __init__(self, cache, environment):
        self.cache = cache
        self.environment = environment
        self.harnesses = {}
        self.changed = set()
        self.reused = 0
        self.traced = 0

    def harness(self, address, creation, runtime):
        """The key of the harness at `address`; `creation` is hex, `runtime` bytes."""
        return Cache.key("trace", self.environment, address, creation, runtime.hex())

    def get(self, harness, case):
        """The cached trace of `case` on `harness`, or None."""
        traces = self.harnesses.get(harness)
        if traces is None:
            traces = self.harnesses[harness] = self.cache.get("trace", harness) or {}
        traced = traces.get(case)
        if traced is not None:
            self.reused += 1
        return traced

    def put(self, harness, case, traced):
        """Keeps a new trace of `case` on `harness` and returns it."""
        if self.cache.directory is not None:
            self.harnesses.setdefault(harness, {})[case] = traced
            self.changed.add(harness)
        self.traced += 1
        return traced

    def save(self):
        """Writes every harness that gained traces back to the cache.

        Traces another run saved for the harness meanwhile are kept too.
        """
        for harness in sorted(self.changed):
            traces = self.cache.get("trace", harness) or {}
            traces.update(self.harnesses[harness])
            self.cache.put("trace", harness, traces)
        self.changed.clear()


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    cache = Cache(None if args.no_cache else args.cache_dir)
    safe, upstream, apis, audit = prepare(
        args.solc,
        out,
        args.api,
        args.isolate_api,
        upstream_overrides=args.upstream_override or (),
        cache=cache,
    )
    variants = [
        (
            f"{compiler}-{source}"
            + ("" if compiler == "solar" else "-ir" if ir else "-legacy"),
            binary,
            sources,
            ir,
        )
        for compiler, binary in [("solc", args.solc), ("solar", args.solar)]
        for source, sources in [("upstream", upstream), ("safe", safe)]
        for ir in ([False, True] if compiler == "solc" else [True])
    ]
    binaries = {}
    artifacts = {}
    for label, binary, sources, ir in variants:
        settings = {
            "optimizer": {"enabled": True, "runs": args.runs},
            "evmVersion": args.evm_version,
            "viaIR": ir,
            "metadata": {"bytecodeHash": "none", "appendCBOR": False},
            "outputSelection": {
                "Harness.sol": {
                    "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"]
                },
                "*": {"": ["ast"]},
            },
        }
        payload = {"language": "Solidity", "sources": sources, "settings": settings}
        result, elapsed = compile_cached(cache, binary, payload, label)
        if label.startswith("solc-safe") and safety_violations(result):
            raise ValueError(f"{label} safety audit failed")
        folder = out / label
        folder.mkdir()
        (folder / "input.json").write_text(json.dumps(payload, indent=2) + "\n")
        (folder / "output.json").write_text(json.dumps(result, indent=2) + "\n")
        binaries[label] = result["contracts"]["Harness.sol"]
        artifacts[label] = {
            "compiler": subprocess.check_output(
                [str(binary), "--version"], text=True
            ).strip(),
            "compiler_sha256": file_sha256(binary),
            "input_sha256": digest(json.dumps(payload, sort_keys=True).encode()),
            "compile_seconds": elapsed,
            "contracts": {},
        }
    first = next(iter(binaries.values()))
    for label, contracts in binaries.items():
        for contract, artifact in contracts.items():
            if [x for x in artifact["abi"] if x["type"] != "error"] != [
                x for x in first[contract]["abi"] if x["type"] != "error"
            ]:
                raise ValueError(f"callable ABI mismatch for {label}: {contract}")
    proc, url, sender = launch_anvil(args.evm_version)
    cases = []
    failures = []
    traces = None
    try:
        traces = TraceCache(cache, trace_environment(args.evm_version, sender))
        addresses = {}
        runtime_code = {}
        for label, contracts in binaries.items():
            addresses[label] = {}
            runtime_code[label] = {}
            for name, artifact in contracts.items():
                bytecode = artifact["evm"]["bytecode"]["object"]
                tx = rpc(
                    url,
                    "eth_sendTransaction",
                    [{"from": sender, "data": "0x" + bytecode, "gas": hex(80000000)}],
                )
                receipt = None
                for _ in range(200):
                    receipt = rpc(url, "eth_getTransactionReceipt", [tx])
                    if receipt is not None:
                        break
                    time.sleep(0.05)
                if receipt is None:
                    raise RuntimeError(f"deployment receipt timed out: {label}/{name}")
                if int(receipt["status"], 16) != 1:
                    raise RuntimeError(f"deployment failed: {label}/{name}")
                addresses[label][name] = receipt["contractAddress"]
                runtime = rpc(
                    url, "eth_getCode", [receipt["contractAddress"], "latest"]
                )
                runtime_code[label][name] = bytes.fromhex(runtime.removeprefix("0x"))
                artifacts[label]["contracts"][name] = {
                    "creation_bytes": len(bytecode) // 2,
                    "runtime_bytes": (len(runtime) - 2) // 2,
                    "deployment_gas": int(receipt["gasUsed"], 16),
                    "exceeds_code_size_limit": (len(runtime) - 2) // 2 > CODE_SIZE_LIMIT,
                }
        # Every leg is deployed, reused or not, so each harness has the address
        # a run without the cache gives it.
        harnesses = {
            label: {
                name: traces.harness(
                    addresses[label][name],
                    artifact["evm"]["bytecode"]["object"],
                    runtime_code[label][name],
                )
                for name, artifact in contracts.items()
            }
            for label, contracts in binaries.items()
        }
        selected_apis = [
            row
            for row in apis
            if not args.api
            or row["library"] + "." + row["signature"] in set(args.api)
        ]
        for row in selected_apis:
            rng = random.Random("20260910:" + row["library"] + "." + row["signature"])
            vectors = list(test_vectors(row, rng))
            if not vectors:
                raise ValueError(f"no test vectors for {row}")
            print(
                f"{row['library']}.{row['signature']}: {len(vectors)} cases", flush=True
            )
            for index, (values, expected, *extra) in enumerate(vectors):
                types = [t for _, (t, _) in row["wrapper_params"]]
                signature = row["wrapper"] + "(" + ",".join(types) + ")"
                calldata = keccak(signature.encode())[:4] + (
                    values if isinstance(values, EncodedArguments) else encode(types, values)
                )
                # Storage the call starts from and must leave, and the code the
                # accounts it calls hold, "0x" for none.
                setup, final, accounts = (extra + [None, None, None])[:3]
                slots = storage_slots(row["storage_slot"]) if setup else []
                expected_revert = isinstance(expected, bytes)
                expected_bytes = (
                    expected if expected_revert else encode(row["outputs"], expected)
                )
                case_key = trace_case_key(calldata, slots, setup, accounts, final is not None)
                measurements = {}
                for label in binaries:
                    name = row["library"] + "Harness"
                    harness = harnesses[label][name]
                    traced = traces.get(harness, case_key)
                    if traced is None:
                        traced = traces.put(
                            harness,
                            case_key,
                            trace_call(
                                url,
                                sender,
                                addresses[label][name],
                                runtime_code[label][name],
                                calldata,
                                slots,
                                setup,
                                accounts,
                                final is not None,
                            ),
                        )
                    actual = traced["return_data"].removeprefix("0x")
                    measurement = {
                        "matches_oracle": (
                            traced["failed"] == expected_revert
                            and actual.lower() == expected_bytes.hex()
                        ),
                        "opcode_gas": traced["opcode_gas"],
                        "dispatch_gas": traced["dispatch_gas"],
                        "trace_gas": traced["trace_gas"],
                        "failed": traced["failed"],
                        "return_data": traced["return_data"],
                    }
                    if final is not None:
                        words = traced["storage"]
                        measurement["storage"] = words
                        measurement["matches_oracle"] &= [
                            int(word, 16) for word in words
                        ] == [int.from_bytes(word, "big") for word in final]
                    if not measurement["matches_oracle"]:
                        failures.append(
                            {
                                "library": row["library"],
                                "api": row["signature"],
                                "case": index,
                                "variant": label,
                                "expected_revert": expected_revert,
                                "expected": "0x" + expected_bytes.hex(),
                                "actual": measurement,
                                "calldata": "0x" + calldata.hex(),
                            }
                        )
                    measurements[label] = measurement
                cases.append(
                    {
                        "case_id": case_identity(
                            row["library"],
                            row["signature"],
                            calldata,
                            args.evm_version,
                            args.runs,
                            artifacts["solar-safe"],
                        ),
                        "comparable": all(
                            m["matches_oracle"] for m in measurements.values()
                        ),
                        "library": row["library"],
                        "api": row["signature"],
                        "case": index,
                        "calldata": "0x" + calldata.hex(),
                        "expected_revert": expected_revert,
                        "expected": "0x" + expected_bytes.hex(),
                        "expected_storage": (
                            ["0x" + word.hex() for word in final] if final is not None else None
                        ),
                        "variants": measurements,
                    }
                )
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        if traces is not None:
            traces.save()
    print(f"Traced {traces.traced} calls; reused {traces.reused} from the cache", flush=True)
    report = {
        "schema": "safe-solady-comparison@2",
        "evm_version": args.evm_version,
        "optimizer_runs": args.runs,
        "isolated_harness": args.isolate_api,
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
        ).strip(),
        "audit": audit,
        "artifacts": artifacts,
        "cases": cases,
        "failures": failures,
    }
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    write_report(report, out / "report.md")
    write_api_report(report, out / "api-gas.md")
    print(
        f"{len(cases)} cases, {len(failures)} mismatches; {out / 'report.md'}",
        flush=True,
    )
    return int(bool(failures))


def comparison_delta(case):
    # An incorrect result must never earn a performance win, on either side.
    if not all(v["matches_oracle"] for v in case["variants"].values()):
        return None
    reference = min(
        case["variants"][x]["opcode_gas"]
        for x in ["solc-upstream-ir", "solc-upstream-legacy"]
    )
    return case["variants"]["solar-safe"]["opcode_gas"] - reference


def body_delta(case):
    """`comparison_delta` over the gas spent after each selector dispatch."""
    if comparison_delta(case) is None:
        return None
    variants = case["variants"]
    labels = ["solar-safe", "solc-upstream-ir", "solc-upstream-legacy"]
    if any(variants[x].get("dispatch_gas") is None for x in labels):
        return None
    body = {x: variants[x]["opcode_gas"] - variants[x]["dispatch_gas"] for x in labels}
    return body["solar-safe"] - min(body["solc-upstream-ir"], body["solc-upstream-legacy"])


def write_report(report, path):
    comparable = [r for r in report["cases"] if comparison_delta(r) is not None]
    lines = [
        "# Safe Solady comparison",
        "",
        "**The full API compatibility and equal-or-better gas target is not met.**",
        "",
        f"EVM: {report['evm_version']}; optimizer runs: {report['optimizer_runs']}; solc legacy and via-IR are both included.",
        "",
        f"{report['audit']['implemented_apis']} function signatures implemented in {report['audit']['library_count']} libraries; the pinned archive has {report['audit']['total_source_files']} source files. This is a partial port.",
        "",
        (
            f"{len(report['cases'])} deterministic differential cases; {len(report['failures'])} mismatching executions. "
            f"{len(report['cases']) - len(comparable)} cases are excluded from performance comparisons because at least one implementation disagrees with the oracle."
        ),
        "",
        (
            "Gas is the sum of executed opcode gas costs from debug_traceCall, excluding transaction intrinsic gas. "
            "Wrappers, inputs, optimizer runs and fork are identical. Calls do not share execution state. "
            "These library harness costs include ABI decoding, dispatch and encoding, and are not isolated instruction costs."
        ),
        "",
        (
            "The reference is the cheaper upstream solc result for each call (legacy or via-IR). "
            "This envelope is stricter than choosing one compiler pipeline for a whole deployment. "
            "All six raw legs, revert checks, input calldata and every per-call result are in results.json. "
            "Case counts are coverage counts, not a workload-weighted score."
        ),
        "",
        "| Library | Comparable / excluded cases | Safe Solar wins / ties / losses | Worst gas delta |",
        "|---|---:|---:|---:|",
    ]
    for library in sorted({r["library"] for r in report["cases"]}):
        cases = [r for r in report["cases"] if r["library"] == library]
        deltas = [d for r in cases if (d := comparison_delta(r)) is not None]
        lines.append(
            f"| {library} | {len(deltas)} / {len(cases) - len(deltas)} | "
            f"{sum(d < 0 for d in deltas)} / {deltas.count(0)} / {sum(d > 0 for d in deltas)} | "
            + (f"{max(deltas):+d}" if deltas else "n/a")
            + " |"
        )
    lines += [
        "",
        (
            "The same comparison after each selector dispatch enters its wrapper, which "
            "separates library code from the selector's place in each compiler's dispatch. "
            "Shared prologues count on whichever side each compiler places them: solc sets the "
            "free-memory pointer before dispatching, so the first memory expansion counts against "
            "its dispatch, while solar checks the call value there. Cases whose dispatch shape is "
            "not recognized are left out."
        ),
        "",
        "| Library | Measured cases | Safe Solar wins / ties / losses after dispatch | Worst gas delta |",
        "|---|---:|---:|---:|",
    ]
    for library in sorted({r["library"] for r in report["cases"]}):
        cases = [r for r in report["cases"] if r["library"] == library]
        deltas = [d for r in cases if (d := body_delta(r)) is not None]
        lines.append(
            f"| {library} | {len(deltas)} | "
            f"{sum(d < 0 for d in deltas)} / {deltas.count(0)} / {sum(d > 0 for d in deltas)} | "
            + (f"{max(deltas):+d}" if deltas else "n/a")
            + " |"
        )
    labels = list(report["artifacts"])
    lines += [
        "",
        "Runtime bytes for identical harnesses (partial libraries still omit the missing APIs):",
        "",
        "| Harness | " + " | ".join(labels) + " |",
        "|---|" + "---:|" * len(labels),
    ]
    for name in sorted(report["artifacts"]["solar-safe"]["contracts"]):
        contracts = [report["artifacts"][x]["contracts"][name] for x in labels]
        sizes = [
            str(c["runtime_bytes"])
            + (" (over EIP-170)" if c.get("exceeds_code_size_limit") else "")
            for c in contracts
        ]
        lines.append(f"| {name} | " + " | ".join(sizes) + " |")
    lines += [
        "",
        "Compatibility failures (retained as failures; the runner exits nonzero):",
        "",
        "| Library | API | Variant | Mismatching cases |",
        "|---|---|---|---:|",
    ]
    groups = {}
    for f in report["failures"]:
        key = (f["library"], f["api"], f["variant"])
        groups[key] = groups.get(key, 0) + 1
    for (library, api, variant), count in sorted(groups.items()):
        lines.append(f"| {library} | `{api}` | {variant} | {count} |")
    if not groups:
        lines.append("| — | — | — | 0 |")
    lines += [
        "",
        (
            "No production safety claim or all-input equivalence proof is made by these tests. "
            "Missing APIs, malformed-input contracts, memory aliasing and storage layout require separate review."
        ),
    ]
    path.write_text("\n".join(lines) + "\n")


def write_api_report(report, path):
    lines = [
        "# Per-function gas comparison",
        "",
        (
            "Gas includes each identical library harness's dispatch and ABI handling. "
            "Reference gas is the per-call minimum of upstream solc legacy and via-IR. "
            "Mismatches are excluded; results.json retains their calldata and outcomes."
        ),
        "",
        "| Library | Function | Comparable / excluded | Wins / ties / losses | Best delta | Worst delta |",
        "|---|---|---:|---:|---:|---:|",
    ]
    groups = {}
    for case in report["cases"]:
        groups.setdefault((case["library"], case["api"]), []).append(case)
    for (library, api), cases in sorted(groups.items()):
        deltas = [d for c in cases if (d := comparison_delta(c)) is not None]
        lines.append(
            f"| {library} | `{api}` | {len(deltas)} / {len(cases) - len(deltas)} | "
            f"{sum(d < 0 for d in deltas)} / {deltas.count(0)} / {sum(d > 0 for d in deltas)} | "
            + (f"{min(deltas):+d} | {max(deltas):+d}" if deltas else "n/a | n/a")
            + " |"
        )
    path.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solc", type=Path, required=True)
    parser.add_argument(
        "--solar", type=Path, default=REPO.parent / "solar/target/debug/solar"
    )
    parser.add_argument("--evm-version", default="cancun")
    parser.add_argument("--runs", type=int, default=200)
    parser.add_argument(
        "--api",
        action="append",
        help="measure only this Library.signature after compiling the complete harness",
    )
    parser.add_argument(
        "--isolate-api",
        action="store_true",
        help="compile a harness containing only the APIs selected by --api",
    )
    parser.add_argument(
        "--upstream-override",
        action="append",
        metavar="PATH=FILE",
        help="measure against FILE as the upstream source at PATH, e.g. a fork variant",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=default_cache_dir(),
        help="reuse builds and traces whose inputs are unchanged from here (default: %(default)s)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="build and trace every leg, neither reading nor writing the cache",
    )
    raise SystemExit(run(parser.parse_args()))
