#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["eth-abi==5.2.0", "eth-hash[pycryptodome]==0.7.1"]
# ///
"""Audit the checked port against the pinned Solady 0.1.26 archive, source by source.

The port is one to one: every `src/` source of the archive has a port that
carries `@custom:solar-safe` and keeps its original's file. For each port the
audit checks:

- api: every non-private function, with its parameter names, types and
  locations, returns, visibility and mutability, and every error, event,
  non-private constant, modifier and struct;
- layout: the imports, the section banners in order, and the non-private
  declarations in the original's order, each with the original's NatSpec as
  the start of its own, so a port may add notes and tags but not drop or
  reword any;
- pragma: the original's version, or the release that introduced a feature
  the port uses (a `bytes` value or slice converted to `bytesN`,
  `block.basefee`, a user-defined value type); with `--old-solc`, each given
  older solc that compiles the original must also compile the port;
- safety: no inline assembly or `unchecked` block outside a declaration
  tagged `@custom:solar-trusted`, in the port or anything it imports;
  with `--assembly-free`, unchecked arithmetic is allowed, but inline
  assembly is rejected even in trusted declarations;
- mixins: no two ported contracts define a private function with the same
  name and parameter types, which a contract inheriting both could not
  compile, beyond the clashes the originals already have;
- generated: each `src/utils/g/` source is what the original's
  `prep/gen-globalized-libs.js` makes of its ported base (needs `node`).

Prints one line per source with its problems, then the checks of the whole
port; exits 1 if any check fails.
"""

import argparse
import gzip
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

from benchmark import (
    ARCHIVE,
    ROOT,
    api_rows,
    closure,
    compile_json,
    safety_violations,
    trusted_declarations,
    walk,
)

SAFE_TAG = "@custom:solar-safe"
SETTINGS = {"outputSelection": {"*": {"": ["ast"]}}}
BANNER = re.compile(r"/\*\s+([A-Z0-9][A-Z0-9 /,&()'-]*[A-Z0-9)])\s+\*/")
PRAGMA = re.compile(r"pragma solidity \^?(0\.8\.\d+);")


def documentation(node):
    text = node.get("documentation")
    text = text.get("text", "") if isinstance(text, dict) else (text or "")
    return text.strip()


def functions(ast):
    """`benchmark.api_rows`, keyed apart for a constructor, a fallback and a receive
    function, which all have an empty name."""
    rows = api_rows(ast)
    kinds = [
        fn.get("kind")
        for contract in ast.get("nodes", [])
        if contract.get("nodeType") == "ContractDefinition"
        for fn in contract["nodes"]
        if fn.get("nodeType") == "FunctionDefinition" and fn["visibility"] != "private"
    ]
    for row, kind in zip(rows, kinds):
        if kind in ("constructor", "fallback", "receive"):
            row["signature"] = kind + row["signature"]
    return rows


def members(ast):
    """Errors, events, non-private constants, modifiers and structs, by owner."""
    found = set()
    for item in ast.get("nodes", []):
        if item.get("nodeType") == "ContractDefinition":
            nodes = [(item["name"], node) for node in item["nodes"]]
        else:
            nodes = [("", item)]
        for owner, node in nodes:
            kind = node.get("nodeType")
            if kind in ("ErrorDefinition", "EventDefinition"):
                params = ",".join(
                    p["typeDescriptions"]["typeString"] for p in node["parameters"]["parameters"]
                )
                found.add(f"{kind[:-10].lower()} {owner}.{node['name']}({params})")
            elif (
                kind == "VariableDeclaration"
                and node.get("constant")
                and node.get("visibility") != "private"
            ):
                found.add(f"constant {owner}.{node['name']}")
            elif kind == "ModifierDefinition":
                found.add(f"modifier {owner}.{node['name']}")
            elif kind == "StructDefinition":
                fields = ",".join(m["typeDescriptions"]["typeString"] for m in node["members"])
                found.add(f"struct {owner}.{node['name']}{{{fields}}}")
    return found


def declarations(ast):
    """Non-private declarations in source order, with their NatSpec."""
    found = []
    for item in ast.get("nodes", []):
        kind = item.get("nodeType")
        if kind != "ContractDefinition":
            if kind in (
                "StructDefinition",
                "ErrorDefinition",
                "EventDefinition",
                "FunctionDefinition",
                "VariableDeclaration",
                "UserDefinedValueTypeDefinition",
            ):
                found.append(("file", kind, item.get("name", ""), documentation(item)))
            continue
        found.append((item["name"], "Contract", item["name"], documentation(item)))
        for node in item["nodes"]:
            kind = node.get("nodeType")
            if node.get("visibility") == "private" or kind == "UsingForDirective":
                continue
            name = node.get("name") or node.get("kind", "")
            if kind == "FunctionDefinition":
                params = ",".join(
                    p["typeDescriptions"]["typeString"] for p in node["parameters"]["parameters"]
                )
                name = f"{node.get('kind')} {name}({params})"
            found.append((item["name"], kind, name, documentation(node)))
    return found


def check_api(upstream, port):
    problems = []
    rows = {(r["library"], r["signature"]): r for r in functions(port)}
    expected = functions(upstream)
    for row in expected:
        if rows.get((row["library"], row["signature"])) != row:
            problems.append(f"function differs or is missing: {row['library']}.{row['signature']}")
    for member in sorted(members(upstream) - members(port)):
        problems.append(f"member differs or is missing: {member}")
    return len(expected), problems


def check_layout(upstream_text, port_text, upstream, port):
    problems = []
    imports = re.findall(r"^import .*$", upstream_text, re.M)
    if imports != re.findall(r"^import .*$", port_text, re.M):
        problems.append(f"imports differ from {imports}")
    # The port may add banners, such as its PRIVATE HELPERS; the original's come in order.
    banners = iter(BANNER.findall(port_text))
    if not all(any(banner == b for b in banners) for banner in BANNER.findall(upstream_text)):
        problems.append("section banners differ")
    expected = declarations(upstream)
    found = declarations(port)
    keys = [d[:3] for d in found]
    expected_keys = [d[:3] for d in expected]
    for key in expected_keys:
        if key not in keys:
            problems.append(f"declaration missing: {key}")
    present = [key for key in keys if key in expected_keys]
    order = [key for key in expected_keys if key in keys]
    if present != order:
        index = next(i for i, (a, b) in enumerate(zip(present, order)) if a != b)
        problems.append(f"order: {present[index]} where the original has {order[index]}")
    docs = {d[:3]: d[3] for d in expected}
    for owner, kind, name, text in found:
        original = docs.get((owner, kind, name))
        if original is not None and not text.startswith(original):
            problems.append(f"NatSpec of {owner}.{name} does not start with the original's")
    return problems


def version(text):
    return tuple(int(part) for part in text.split("."))


def features(ast):
    """Language features newer than 0.8.4 that the source uses, by the release that added
    them."""
    found = set()
    for node in walk(ast):
        kind = node.get("nodeType")
        if kind == "FunctionCall" and node.get("kind") == "typeConversion" and node.get("arguments"):
            to = node.get("typeDescriptions", {}).get("typeString", "")
            argument = node["arguments"][0].get("typeDescriptions", {}).get("typeString", "")
            if re.fullmatch(r"bytes\d+", to) and (
                argument.startswith("bytes ") or "slice" in argument
            ):
                found.add((0, 8, 5))
        if kind == "MemberAccess" and node.get("memberName") == "basefee":
            found.add((0, 8, 7))
        if kind == "UserDefinedValueTypeDefinition":
            found.add((0, 8, 8))
    return found


def check_pragma(upstream_text, port_text, port):
    original = PRAGMA.search(upstream_text)
    pragma = PRAGMA.search(port_text)
    if not original or not pragma:
        return ["no `pragma solidity ^0.8.x;` line"]
    want = max([version(original.group(1)), *features(port)])
    if version(pragma.group(1)) == want:
        return []
    expected = ".".join(map(str, want))
    return [f"pragma ^{pragma.group(1)} where the original and the features used ask ^{expected}"]


def compiles(binary, sources):
    payload = {"language": "Solidity", "sources": dict(sorted(sources.items())), "settings": SETTINGS}
    result = subprocess.run(
        [binary, "--standard-json"], input=json.dumps(payload), capture_output=True, text=True
    )
    output = json.loads(result.stdout)
    return not any(e.get("severity") == "error" for e in output.get("errors", []))


def check_old_solcs(path, archive, disk, old_solcs):
    """Every given older solc that compiles the original must compile the port."""
    problems = []
    for old, binary in old_solcs:
        if compiles(binary, closure(archive, [path])) and not compiles(binary, closure(disk, [path])):
            problems.append(f"solc {'.'.join(map(str, old))} compiles the original but not the port")
    return problems


def mixin_clashes(asts, paths):
    """Private functions of ported contracts (not libraries) by name and parameter types."""
    seen = defaultdict(set)
    for path in paths:
        if path not in asts:
            continue
        for item in asts[path]["ast"]["nodes"]:
            if item.get("nodeType") != "ContractDefinition" or item.get("contractKind") != "contract":
                continue
            for fn in item["nodes"]:
                if fn.get("nodeType") == "FunctionDefinition" and fn.get("visibility") == "private":
                    params = ",".join(
                        p["typeDescriptions"]["typeString"] for p in fn["parameters"]["parameters"]
                    )
                    seen[f"{fn['name']}({params})"].add(f"{path}:{item['name']}")
    return seen


def generated_sources(archive):
    """What `prep/gen-globalized-libs.js` makes of the tree's `src/utils/` sources."""
    node = shutil.which("node")
    if node is None:
        return None
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        shutil.copytree(ROOT / "prep", folder / "prep")
        (folder / "src/utils").mkdir(parents=True)
        for path in sorted((ROOT / "src/utils").glob("*.sol")):
            shutil.copy(path, folder / "src/utils" / path.name)
        subprocess.run(
            [node, "prep/gen-globalized-libs.js"], cwd=folder, check=True, capture_output=True
        )
        return {
            path: (folder / path).read_text() if (folder / path).exists() else None
            for path in archive
            if path.startswith("src/utils/g/")
        }


def run(args):
    archive = json.loads(gzip.decompress(ARCHIVE.read_bytes()))["sources"]
    disk = {
        path.relative_to(ROOT).as_posix(): {"content": path.read_text()}
        for path in sorted((ROOT / "src").rglob("*.sol"))
    }
    expected = sorted(path for path in archive if path.startswith("src/"))
    ported = sorted(path for path, source in disk.items() if SAFE_TAG in source["content"])
    paths = args.source or expected
    old_solcs = []
    for binary in args.old_solc:
        output = subprocess.run([binary, "--version"], capture_output=True, text=True).stdout
        old_solcs.append((version(re.search(r"Version: (\d+\.\d+\.\d+)", output).group(1)), binary))

    port_closure = closure(disk, [path for path in paths if path in ported])
    port = compile_json(
        args.solc,
        {"language": "Solidity", "sources": dict(sorted(port_closure.items())), "settings": SETTINGS},
    )["sources"]
    upstream = compile_json(
        args.solc,
        {"language": "Solidity", "sources": dict(sorted(archive.items())), "settings": SETTINGS},
    )["sources"]
    generated = generated_sources(archive) if any("/g/" in path for path in paths) else {}

    failed = 0
    total_functions = 0
    for path in paths:
        if path not in ported:
            print(f"FAIL {path}: not ported (no {SAFE_TAG})")
            failed += 1
            continue
        if path not in archive:
            print(f"FAIL {path}: not in the archive")
            failed += 1
            continue
        upstream_text = archive[path]["content"]
        port_text = disk[path]["content"]
        count, problems = check_api(upstream[path]["ast"], port[path]["ast"])
        total_functions += count
        problems += check_layout(upstream_text, port_text, upstream[path]["ast"], port[path]["ast"])
        problems += check_pragma(upstream_text, port_text, port[path]["ast"])
        problems += check_old_solcs(path, archive, disk, old_solcs)
        if path.startswith("src/utils/g/"):
            if generated is None:
                problems.append("`node` is missing, so the generated source is unchecked")
            elif generated.get(path) != port_text:
                problems.append("differs from what prep/gen-globalized-libs.js makes of its base")
        trusted = trusted_declarations({"sources": {path: port[path]}})
        status = "FAIL" if problems else "OK"
        failed += bool(problems)
        print(f"{status:4} {path}: {count} functions, {len(trusted)} trusted declarations")
        for problem in problems:
            print(f"     {problem}")
        if args.trusted:
            for name in trusted:
                print(f"     trusted {name.split(':', 1)[1]}")

    violations = safety_violations({"sources": port}, assembly_free=args.assembly_free)
    for path, kind in violations:
        scope = "" if args.assembly_free else " outside a declaration tagged @custom:solar-trusted"
        print(f"UNSAFE {path}: {kind}{scope}")
    mine = mixin_clashes(port, paths)
    theirs = mixin_clashes(upstream, paths)
    clashes = {
        name: owners
        for name, owners in mine.items()
        if len(owners) > 1 and not owners <= theirs.get(name, set())
    }
    for name, owners in sorted(clashes.items()):
        print(f"CLASH private {name}: {', '.join(sorted(owners))}")
    failed += len(violations) + len(clashes)

    done = len([path for path in paths if path in ported])
    print(
        f"{done} of {len(paths)} sources ported, {total_functions} original functions,"
        f" {len(trusted_declarations({'sources': port}))} trusted declarations in their closure"
    )
    print("PASS" if not failed else "FAIL")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--solc", required=True, help="solc binary for the ASTs")
    parser.add_argument(
        "--old-solc",
        action="append",
        default=[],
        help="an older solc that must compile every port whose original it compiles (repeatable)",
    )
    parser.add_argument(
        "--trusted", action="store_true", help="list each port's trusted declarations"
    )
    parser.add_argument(
        "--assembly-free",
        action="store_true",
        help="reject all inline assembly, including trusted code, and allow unchecked arithmetic",
    )
    parser.add_argument("source", nargs="*", help="sources to audit (default: the whole archive)")
    sys.exit(run(parser.parse_args()))


if __name__ == "__main__":
    main()
