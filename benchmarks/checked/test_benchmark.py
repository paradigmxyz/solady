"""Guard against counting incorrect executions as optimization wins, and
against reusing a cached result whose inputs changed."""

import contextlib
import copy
import gzip
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import benchmark
import port_audit
import upstream_tests


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.case = {
            "variants": {
                "solc-upstream-legacy": {"matches_oracle": True, "opcode_gas": 100},
                "solc-upstream-ir": {"matches_oracle": True, "opcode_gas": 120},
                "solc-safe-legacy": {"matches_oracle": True, "opcode_gas": 200},
                "solc-safe-ir": {"matches_oracle": True, "opcode_gas": 150},
                "solar-upstream": {"matches_oracle": True, "opcode_gas": 90},
                "solar-safe": {"matches_oracle": True, "opcode_gas": 80},
            }
        }

    def test_reference_uses_cheaper_upstream_solc_pipeline(self):
        self.assertEqual(benchmark.comparison_delta(self.case), -20)
        self.case["variants"]["solc-upstream-ir"]["opcode_gas"] = 70
        self.assertEqual(benchmark.comparison_delta(self.case), 10)

    def test_any_incorrect_leg_excludes_case(self):
        for label in self.case["variants"]:
            with self.subTest(variant=label):
                case = copy.deepcopy(self.case)
                case["variants"][label] = {"matches_oracle": False, "opcode_gas": 0}
                self.assertIsNone(benchmark.comparison_delta(case))

    def test_missing_correctness_evidence_is_not_accepted(self):
        del self.case["variants"]["solar-safe"]["matches_oracle"]
        with self.assertRaises(KeyError):
            benchmark.comparison_delta(self.case)


class SafetyAuditTests(unittest.TestCase):
    def test_struct_change_requires_explicit_acceptance_and_existing_struct(self):
        upstream = {
            "nodes": [{
                "nodeType": "StructDefinition", "name": "State",
                "members": [{"typeDescriptions": {"typeString": "uint256"}}],
            }]
        }
        port = copy.deepcopy(upstream)
        port["nodes"][0]["members"].append(
            {"typeDescriptions": {"typeString": "mapping(uint256 => uint256)"}}
        )
        self.assertEqual(len(port_audit.check_api(upstream, port)[1]), 1)
        self.assertEqual(port_audit.check_api(upstream, port, allowed_structs=["State"]), (0, []))
        self.assertEqual(len(port_audit.check_api(upstream, port, allowed_structs=["Other"])[1]), 1)
        self.assertEqual(
            len(port_audit.check_api(upstream, {"nodes": []}, allowed_structs=["State"])[1]), 1
        )

    def test_inventory_counts_trusted_assembly_and_dependencies(self):
        sources = {
            "src/Clean.sol": {"ast": {"nodeType": "UncheckedBlock"}},
            "src/Dependency.sol": {
                "ast": {
                    "nodeType": "ContractDefinition",
                    "documentation": "@custom:solar-trusted",
                    "nodes": [{"nodeType": "InlineAssembly"}, {"nodeType": "InlineAssembly"}],
                }
            },
        }
        self.assertEqual(
            port_audit.assembly_counts(sources),
            {"src/Clean.sol": 0, "src/Dependency.sol": 2},
        )

    def test_nested_unsafe_blocks_in_dependencies_are_rejected(self):
        output = {
            "sources": {
                "Harness.sol": {"ast": {"nodeType": "SourceUnit"}},
                "src/Dependency.sol": {
                    "ast": {
                        "nodes": [
                            {
                                "body": {
                                    "statements": [
                                        {"nodeType": "UncheckedBlock"},
                                        {"nodeType": "InlineAssembly"},
                                    ]
                                }
                            }
                        ]
                    }
                },
            }
        }
        self.assertEqual(
            benchmark.safety_violations(output),
            [
                ("src/Dependency.sol", "UncheckedBlock"),
                ("src/Dependency.sol", "InlineAssembly"),
            ],
        )

    def test_trusted_declarations_may_hold_assembly(self):
        trusted = {"nodeType": "StructuredDocumentation", "text": "@dev Shrinks.\n @custom:solar-trusted"}
        output = {
            "sources": {
                "src/Lib.sol": {
                    "ast": {
                        "nodeType": "SourceUnit",
                        "nodes": [
                            {
                                "nodeType": "ContractDefinition",
                                "name": "Lib",
                                "nodes": [
                                    {
                                        "nodeType": "FunctionDefinition",
                                        "name": "_truncate",
                                        "documentation": trusted,
                                        "body": {"statements": [{"nodeType": "InlineAssembly"}]},
                                    },
                                    {
                                        "nodeType": "FunctionDefinition",
                                        "name": "f",
                                        "body": {"statements": [{"nodeType": "UncheckedBlock"}]},
                                    },
                                ],
                            }
                        ],
                    }
                }
            }
        }
        self.assertEqual(
            benchmark.safety_violations(output), [("src/Lib.sol", "UncheckedBlock")]
        )
        self.assertEqual(benchmark.trusted_declarations(output), ["src/Lib.sol:Lib._truncate"])
        self.assertEqual(
            benchmark.safety_violations(output, assembly_free=True),
            [("src/Lib.sol", "InlineAssembly")],
        )

    def test_assembly_free_audit_checks_inside_unchecked_and_trusted_contracts(self):
        output = {
            "sources": {
                "src/Trusted.sol": {
                    "ast": {
                        "nodeType": "ContractDefinition",
                        "documentation": {"text": "@custom:solar-trusted"},
                        "nodes": [
                            {
                                "nodeType": "UncheckedBlock",
                                "statements": [{"nodeType": "InlineAssembly"}],
                            }
                        ],
                    }
                }
            }
        }
        self.assertEqual(benchmark.safety_violations(output), [])
        self.assertEqual(
            benchmark.safety_violations(output, assembly_free=True),
            [("src/Trusted.sol", "InlineAssembly")],
        )

    def test_assembly_free_audit_allows_unchecked_arithmetic(self):
        output = {"sources": {"src/Wrap.sol": {"ast": {"nodeType": "UncheckedBlock"}}}}
        self.assertEqual(benchmark.safety_violations(output, assembly_free=True), [])

    def test_allow_unchecked_still_checks_nested_assembly(self):
        output = {
            "sources": {
                "src/Wrap.sol": {
                    "ast": {
                        "nodeType": "UncheckedBlock",
                        "statements": [{"nodeType": "InlineAssembly"}],
                    }
                }
            }
        }
        self.assertEqual(
            benchmark.safety_violations(output, allow_unchecked=True),
            [("src/Wrap.sol", "InlineAssembly")],
        )
        self.assertEqual(
            benchmark.safety_violations(output),
            [("src/Wrap.sol", "UncheckedBlock"), ("src/Wrap.sol", "InlineAssembly")],
        )

    def test_allow_unchecked_does_not_weaken_strict_assembly_audit(self):
        output = {
            "sources": {
                "src/Trusted.sol": {
                    "ast": {
                        "nodeType": "ContractDefinition",
                        "documentation": {"text": "@custom:solar-trusted"},
                        "nodes": [{"nodeType": "InlineAssembly"}],
                    }
                }
            }
        }
        self.assertEqual(benchmark.safety_violations(output, allow_unchecked=True), [])
        self.assertEqual(
            benchmark.safety_violations(output, assembly_free=True, allow_unchecked=True),
            [("src/Trusted.sol", "InlineAssembly")],
        )

    def test_a_mention_of_the_tag_is_not_the_tag(self):
        prose = {"nodeType": "StructuredDocumentation", "text": "Not `@custom:solar-trusted` here."}
        node = {"nodeType": "FunctionDefinition", "documentation": prose}
        self.assertFalse(benchmark.is_trusted(node))

    def test_comments_do_not_create_false_violations(self):
        output = {
            "sources": {
                "src/Safe.sol": {
                    "ast": {
                        "nodeType": "SourceUnit",
                        "documentation": "No assembly or unchecked blocks.",
                    }
                }
            }
        }
        self.assertEqual(benchmark.safety_violations(output), [])

    def test_missing_ast_is_an_error(self):
        with self.assertRaises(KeyError):
            benchmark.safety_violations({"sources": {"src/Missing.sol": {}}})
        with self.assertRaises(KeyError):
            benchmark.safety_violations({"sources": {"src/Missing.sol": {}}}, assembly_free=True)


class HarnessSelectionTests(unittest.TestCase):
    def setUp(self):
        self.apis = [
            {"library": "Lib", "signature": "a(uint256)"},
            {"library": "Lib", "signature": "b(bytes)"},
        ]

    def test_combined_harness_keeps_every_api(self):
        self.assertIs(
            benchmark.select_harness_apis(
                self.apis, ["Lib.a(uint256)"], isolate=False
            ),
            self.apis,
        )

    def test_isolated_harness_keeps_only_requested_api(self):
        self.assertEqual(
            benchmark.select_harness_apis(
                self.apis, ["Lib.b(bytes)"], isolate=True
            ),
            [self.apis[1]],
        )

    def test_isolation_requires_a_known_api(self):
        with self.assertRaisesRegex(ValueError, "requires at least one"):
            benchmark.select_harness_apis(self.apis, [], isolate=True)
        with self.assertRaisesRegex(ValueError, "unknown API"):
            benchmark.select_harness_apis(self.apis, ["Lib.missing()"], isolate=True)


class DispatchGasTests(unittest.TestCase):
    SELECTOR = bytes.fromhex("12345678")

    def trace(self, steps):
        # steps: (pc, op, gas); code holds the selector after PUSH4s at pc 10.
        return [{"pc": pc, "op": op, "gasCost": gas} for pc, op, gas in steps]

    def code(self):
        code = bytearray(64)
        code[11:15] = self.SELECTOR
        code[31:35] = bytes.fromhex("87654321")
        return bytes(code)

    def test_taken_equality_jump_ends_the_dispatch(self):
        logs = self.trace([
            (30, "PUSH4", 3), (35, "EQ", 3), (36, "PUSH2", 3), (39, "JUMPI", 10),
            (40, "PUSH4", 3), (10, "PUSH4", 3), (15, "EQ", 3), (16, "PUSH2", 3),
            (19, "JUMPI", 10), (50, "JUMPDEST", 1), (51, "STOP", 0),
        ])
        # The first comparison is a different selector and falls through.
        self.assertEqual(benchmark.dispatch_gas(logs, self.code(), self.SELECTOR), 41)

    def test_mismatch_branch_falls_through_on_the_selector(self):
        logs = self.trace([
            (10, "PUSH4", 3), (15, "XOR", 3), (16, "PUSH2", 3), (19, "JUMPI", 10),
            (20, "JUMPDEST", 1),
        ])
        self.assertEqual(benchmark.dispatch_gas(logs, self.code(), self.SELECTOR), 19)

    def test_split_on_the_selector_is_not_the_match(self):
        logs = self.trace([
            (10, "PUSH4", 3), (15, "GT", 3), (16, "PUSH2", 3), (19, "JUMPI", 10),
            (50, "JUMPDEST", 1),
        ])
        self.assertIsNone(benchmark.dispatch_gas(logs, self.code(), self.SELECTOR))


class WrapperNameTests(unittest.TestCase):
    def test_name_depends_only_on_the_api(self):
        name = benchmark.wrapper_name("LibSort", "sort(uint256[])")
        self.assertEqual(name, benchmark.wrapper_name("LibSort", "sort(uint256[])"))
        self.assertRegex(name, "^f[0-9a-f]{8}$")
        self.assertNotEqual(name, benchmark.wrapper_name("LibSort", "sort(int256[])"))
        self.assertNotEqual(name, benchmark.wrapper_name("LibBit", "sort(uint256[])"))


class StorageLayoutTests(unittest.TestCase):
    def test_short_value_packs_its_length_below_its_bytes(self):
        words = benchmark.packed_words(b"abc")
        self.assertEqual(words[0], b"abc" + bytes(28) + bytes([3]))
        self.assertEqual(words[1:], [bytes(32)] * benchmark.STORAGE_WORDS)

    def test_short_value_continues_from_byte_31_in_derived_words(self):
        value = bytes(range(40))
        words = benchmark.packed_words(value)
        self.assertEqual(words[0], value[:31] + bytes([40]))
        self.assertEqual(words[1], value[31:].ljust(32, b"\0"))
        self.assertEqual(words[2], bytes(32))

    def test_long_value_keeps_its_length_in_the_root(self):
        value = bytes(i % 251 for i in range(300))
        words = benchmark.packed_words(value)
        self.assertEqual(words[0], ((300 << 8) | 0xFF).to_bytes(32, "big"))
        self.assertEqual(b"".join(words[1:11])[:300], value)
        self.assertEqual(words[10][300 - 288 :], bytes(20))

    def test_shorter_value_leaves_later_words_of_a_longer_one(self):
        longer = benchmark.packed_words(b"y" * 300)
        words = benchmark.packed_words(b"x" * 40, longer)
        self.assertEqual(words[1], b"x" * 9 + bytes(23))
        self.assertEqual(words[2:], longer[2:])

    def test_reads_start_from_the_stored_words(self):
        cases = list(benchmark.storage_vectors("length", [b"", b"ab"], bytes))
        self.assertEqual([case[1] for case in cases], [[0], [2]])
        self.assertEqual(cases[1][2][0][-1], 2)

    def test_stores_expect_the_words_they_leave(self):
        base, value = benchmark.packed_words(b""), b"z" * 40
        cases = list(benchmark.storage_vectors("set", [value], bytes))
        self.assertEqual(cases[0], ([value], [], base, benchmark.packed_words(value)))

    def test_derived_slots_follow_the_root_hash(self):
        slots = benchmark.storage_slots(3)
        base = int.from_bytes(benchmark.keccak((3).to_bytes(32, "big")), "big")
        self.assertEqual(slots[:3], [3, base, base + 1])
        self.assertEqual(len(slots), benchmark.STORAGE_WORDS + 1)


class CaseIdentityTests(unittest.TestCase):
    def test_identity_covers_input_source_and_compiler(self):
        artifact = {"input_sha256": "safe", "compiler_sha256": "solar"}
        identity = benchmark.case_identity("Lib", "f(bytes)", b"abc", "cancun", 200, artifact)
        self.assertEqual(
            identity,
            benchmark.case_identity("Lib", "f(bytes)", b"abc", "cancun", 200, artifact),
        )
        changed = dict(artifact, compiler_sha256="other")
        self.assertNotEqual(
            identity,
            benchmark.case_identity("Lib", "f(bytes)", b"abc", "cancun", 200, changed),
        )


class CacheTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.cache = benchmark.Cache(self.root)

    def test_key_covers_the_format_the_kind_and_every_input(self):
        inputs = ("abc", {"sources": {"a": 1, "b": 2}})
        key = benchmark.Cache.key("compile", *inputs)
        self.assertRegex(key, "^[0-9a-f]{64}$")
        self.assertEqual(key, benchmark.Cache.key("compile", *inputs))
        self.assertNotEqual(key, benchmark.Cache.key("suite", *inputs))
        self.assertNotEqual(key, benchmark.Cache.key("compile", "abd", inputs[1]))
        self.assertNotEqual(key, benchmark.Cache.key("compile", *inputs, None))
        # A compiler may read sources in the order it is given them.
        reordered = {"sources": {"b": 2, "a": 1}}
        self.assertNotEqual(key, benchmark.Cache.key("compile", "abc", reordered))
        with mock.patch.object(benchmark, "CACHE_FORMAT", benchmark.CACHE_FORMAT + 1):
            self.assertNotEqual(key, benchmark.Cache.key("compile", *inputs))

    def test_an_entry_reads_back_and_leaves_no_temporary_file(self):
        self.assertIsNone(self.cache.get("suite", "k"))
        entry = {"returncode": 1, "stdout": '{"a": "\u00e9"}', "seconds": 0.1}
        self.cache.put("suite", "k", entry)
        self.assertEqual(self.cache.get("suite", "k"), entry)
        self.assertEqual([p.name for p in (self.root / "suite").iterdir()], ["k.json.gz"])
        self.cache.put("suite", "k", {"returncode": 0})
        self.assertEqual(self.cache.get("suite", "k"), {"returncode": 0})

    def test_an_unreadable_entry_is_a_miss(self):
        path = self.cache.path("suite", "k")
        path.parent.mkdir(parents=True)
        unparsable = benchmark.gzip.compress(b"{")
        for data in [b"not gzip", unparsable[:-4], unparsable]:
            path.write_bytes(data)
            self.assertIsNone(self.cache.get("suite", "k"))

    def test_a_cache_without_a_directory_keeps_nothing(self):
        cache = benchmark.Cache()
        cache.put("suite", "k", {"returncode": 0})
        self.assertIsNone(cache.get("suite", "k"))

    def test_the_default_directory_is_outside_the_repository(self):
        with mock.patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.root)}):
            self.assertEqual(benchmark.default_cache_dir(), self.root / "solady-checked")
        with mock.patch.dict(os.environ):
            os.environ.pop("XDG_CACHE_HOME", None)
            directory = benchmark.default_cache_dir()
        self.assertEqual(directory, Path.home() / ".cache" / "solady-checked")
        self.assertFalse(directory.is_relative_to(benchmark.ROOT))


class CompileCacheTests(unittest.TestCase):
    def test_a_build_is_reused_for_the_same_compiler_and_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = benchmark.Cache(root / "cache")
            solc, solar = root / "solc", root / "solar"
            solc.write_bytes(b"one compiler")
            solar.write_bytes(b"another compiler")
            builds = []

            def compile_json(binary, payload):
                builds.append((binary, payload))
                return {"contracts": {"Harness.sol": len(builds)}}

            payload = {"sources": {"A.sol": {"content": "contract A {}"}}}
            with mock.patch.object(benchmark, "compile_json", compile_json):
                first = benchmark.compile_cached(cache, solc, payload)
                self.assertEqual(benchmark.compile_cached(cache, solc, payload), first)
                self.assertEqual(len(builds), 1)
                benchmark.compile_cached(cache, solar, payload)
                benchmark.compile_cached(cache, solc, {"sources": {}})
                self.assertEqual(len(builds), 3)
                benchmark.compile_cached(benchmark.Cache(), solc, payload)
                self.assertEqual(len(builds), 4)


class TraceCacheTests(unittest.TestCase):
    CASE = {
        "calldata": bytes.fromhex("12345678"),
        "slots": [3, 4],
        "setup": [bytes(32), bytes([1]) * 32],
        "accounts": {"0x" + "a1" * 20: "0x60", "0x" + "b2" * 20: "0x"},
        "observe": True,
    }

    def test_case_key_covers_every_input_of_a_call(self):
        key = benchmark.trace_case_key(**self.CASE)
        self.assertEqual(key, benchmark.trace_case_key(**self.CASE))
        accounts = dict(reversed(self.CASE["accounts"].items()))
        self.assertEqual(key, benchmark.trace_case_key(**dict(self.CASE, accounts=accounts)))
        for change in [
            {"calldata": bytes.fromhex("12345679")},
            {"slots": [3, 5]},
            {"setup": [bytes(32), bytes(32)]},
            {"setup": None, "slots": []},
            {"accounts": {"0x" + "a1" * 20: "0x61"}},
            {"accounts": None},
            {"observe": False},
        ]:
            with self.subTest(change=change):
                self.assertNotEqual(key, benchmark.trace_case_key(**dict(self.CASE, **change)))

    def test_traces_are_reused_only_on_the_same_harness(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = benchmark.Cache(Path(directory))
            traces = benchmark.TraceCache(cache, "environment")
            harness = traces.harness("0x01", "6000", b"\x00")
            self.assertIsNone(traces.get(harness, "case"))
            traces.put(harness, "case", {"opcode_gas": 21})
            traces.save()
            again = benchmark.TraceCache(cache, "environment")
            self.assertEqual(
                again.get(again.harness("0x01", "6000", b"\x00"), "case"), {"opcode_gas": 21}
            )
            self.assertIsNone(again.get(again.harness("0x01", "6000", b"\x00"), "other case"))
            self.assertEqual((again.reused, again.traced), (1, 0))
            elsewhere = benchmark.TraceCache(cache, "another node")
            for other in [
                again.harness("0x02", "6000", b"\x00"),
                again.harness("0x01", "6001", b"\x00"),
                again.harness("0x01", "6000", b"\x01"),
                elsewhere.harness("0x01", "6000", b"\x00"),
            ]:
                self.assertIsNone(again.get(other, "case"))

    def test_saving_keeps_the_traces_another_run_saved(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = benchmark.Cache(Path(directory))
            first, second = (benchmark.TraceCache(cache, "environment") for _ in range(2))
            harness = first.harness("0x01", "6000", b"\x00")
            self.assertIsNone(first.get(harness, "a"))
            self.assertIsNone(second.get(harness, "b"))
            first.put(harness, "a", {"opcode_gas": 1})
            second.put(harness, "b", {"opcode_gas": 2})
            first.save()
            second.save()
            self.assertEqual(
                cache.get("trace", harness), {"a": {"opcode_gas": 1}, "b": {"opcode_gas": 2}}
            )

    def test_environment_covers_the_code_that_measures_a_call(self):
        identity = {"version": "anvil 1", "sha256": "a"}
        with mock.patch.object(benchmark, "tool_identity", return_value=identity):
            key = benchmark.trace_environment("cancun", "0x01")
            self.assertEqual(key, benchmark.trace_environment("cancun", "0x01"))
            self.assertNotEqual(key, benchmark.trace_environment("prague", "0x01"))
            self.assertNotEqual(key, benchmark.trace_environment("cancun", "0x02"))
            with mock.patch.object(benchmark.inspect, "getsource", lambda f: f.__name__):
                self.assertNotEqual(key, benchmark.trace_environment("cancun", "0x01"))
        rebuilt = dict(identity, sha256="b")
        with mock.patch.object(benchmark, "tool_identity", return_value=rebuilt):
            self.assertNotEqual(key, benchmark.trace_environment("cancun", "0x01"))


class FairFixtureTests(unittest.TestCase):
    def setUp(self):
        self.archive = json.loads(gzip.decompress(benchmark.ARCHIVE.read_bytes()))["sources"]
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def project(self, label):
        folder = self.root / label
        for name in upstream_tests.FAIR_COMPATIBILITY_PATCHES:
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.archive[name]["content"])
        path = folder / "src/utils/LibRLP.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(label)
        return folder

    def test_api_compatibility_patches_are_identical_on_both_legs(self):
        original = copy.deepcopy(self.archive)
        upstream = self.project("upstream")
        safe = self.project("safe")
        before = {
            name: (upstream / name).read_text()
            for name in upstream_tests.FAIR_COMPATIBILITY_PATCHES
        }
        changes = upstream_tests.apply_fair_patches(upstream)
        self.assertEqual(changes, upstream_tests.apply_fair_patches(safe))
        self.assertEqual(len(changes), 7)
        self.assertEqual({change["kind"] for change in changes}, {"compatibility"})
        for name, text in before.items():
            patched = (upstream / name).read_text()
            self.assertEqual(patched, (safe / name).read_text())
            for old, new in upstream_tests.FAIR_COMPATIBILITY_PATCHES[name]:
                self.assertIn(new, patched)
            expected = text
            for old, new in upstream_tests.FAIR_COMPATIBILITY_PATCHES[name]:
                expected = expected.replace(old, new, 1)
            self.assertEqual(patched, expected)
        self.assertEqual(self.archive, original)
        self.assertEqual((upstream / "src/utils/LibRLP.sol").read_text(), "upstream")
        self.assertEqual((safe / "src/utils/LibRLP.sol").read_text(), "safe")

    def test_compatibility_helpers_keep_behavior_checks_and_test_entry_points(self):
        folder = self.project("safe")
        upstream_tests.apply_fair_patches(folder)
        rlp = (folder / "test/LibRLP.t.sol").read_text()
        transfers = (folder / "test/SafeTransferLib.t.sol").read_text()
        roles = (folder / "test/EnumerableRoles.t.sol").read_text()
        self.assertIn("return _expectedRoleHolders[role];", roles)
        self.assertIn("mapping(uint256 => EnumerableSetLib.AddressSet)", roles)
        self.assertNotIn("holders.slot := add(role, 0x97)", roles)
        self.assertIn("function testRLPMemory(bytes32) public {", rlp)
        self.assertIn("LibRLP.List memory l;", rlp)
        self.assertIn("assertEq(_getUint256(l, i), y);", rlp)
        start = rlp.index("function testRLPMemory(bytes32) public {")
        end = rlp.index("\n    }", start)
        self.assertEqual(rlp[start:end].count("_checkMemory(l.encode());"), 1)
        checker = upstream_tests.FAIR_COMPATIBILITY_PATCHES["test/LibRLP.t.sol"][2][1]
        self.assertNotIn(".encode()", checker)
        self.assertIn("_checkMemory();", checker)
        self.assertIn("require(prefix <= 0xa0);", rlp)
        self.assertIn('assertEq(ERC20(token).allowance(from, to), amount, "wrong allowance");', transfers)
        self.assertIn("assertEq(vault.balance, amount1);", transfers)
        self.assertIn("assertEq(to.balance, amount0 + amount1);", transfers)
        self.assertIn("assertEq(address(this).balance, selfBalanceBefore - amount0 - amount1);", transfers)
        for name in upstream_tests.FAIR_COMPATIBILITY_PATCHES:
            original = self.archive[name]["content"]
            patched = (folder / name).read_text()
            original_tests = original.count("function test")
            self.assertEqual(patched.count("function test"), original_tests)

    def test_changed_or_duplicated_fixture_fails_closed(self):
        for mode in ("missing", "duplicate"):
            with self.subTest(mode=mode):
                folder = self.project(mode)
                name = "test/LibRLP.t.sol"
                old = upstream_tests.FAIR_COMPATIBILITY_PATCHES[name][0][0]
                path = folder / name
                text = path.read_text()
                changed = text.replace(old, old.replace("public", "public ", 1), 1)
                path.write_text(changed if mode == "missing" else text + old)
                with self.assertRaisesRegex(SystemExit, "must contain exactly one"):
                    upstream_tests.apply_fair_patches(folder)

    def test_patch_records_identify_the_exact_source_changes(self):
        folder = self.project("upstream")
        records = upstream_tests.apply_fair_patches(folder)
        expected = [
            {
                "source": name,
                "kind": "compatibility",
                "old_sha256": benchmark.digest(old.encode()),
                "new_sha256": benchmark.digest(new.encode()),
            }
            for name, patches in upstream_tests.FAIR_COMPATIBILITY_PATCHES.items()
            for old, new in patches
        ]
        self.assertEqual(records, expected)

    def test_empty_gas_report_is_explicit(self):
        passing = {"status": "Success", "gas": 10}
        failed = {"status": "Failure", "gas": 10}
        cases = [
            ({}, {}),
            ({"test/A.t.sol:T::testA()": passing}, {}),
            ({"test/A.t.sol:T::testA()": passing}, {"test/A.t.sol:T::testA()": failed}),
        ]
        for upstream, safe in cases:
            with self.subTest(upstream=upstream, safe=safe):
                results = {
                    "solc-upstream": {"tests": upstream},
                    "solar-safe": {"tests": safe},
                }
                self.assertEqual(upstream_tests.gas_report(results), "No comparable passing tests\n")


class SuiteCacheTests(unittest.TestCase):
    FILES = {
        "foundry.toml": '[profile.default.fuzz]\nruns = 256\nseed = "0x20260910"\n',
        "src/utils/Lib.sol": "library Lib {}",
        "test/Lib.t.sol": 'import "src/utils/Lib.sol";',
    }

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.compiler = self.root / "solc"
        self.compiler.write_bytes(b"compiler")
        self.projects = 0

    def project(self, files):
        self.projects += 1
        folder = self.root / f"project-{self.projects}"
        for name, text in files.items():
            (folder / name).parent.mkdir(parents=True, exist_ok=True)
            (folder / name).write_text(text)
        return folder

    def key(self, folder, env=None, forge="forge 1.7.1"):
        command = ["forge", "test", "--root", str(folder), "--force", "--json"]
        identity = {"version": forge, "sha256": "f"}
        with mock.patch.object(upstream_tests, "tool_identity", return_value=identity):
            return upstream_tests.suite_key(folder, command, self.compiler, env or {}, "forge")

    def test_key_does_not_depend_on_where_the_project_is(self):
        self.assertEqual(self.key(self.project(self.FILES)), self.key(self.project(self.FILES)))

    def test_key_covers_files_settings_tools_and_environment(self):
        key = self.key(self.project(self.FILES))
        seed = self.FILES["foundry.toml"].replace("0x20260910", "0x1")
        for files in [
            dict(self.FILES, **{"foundry.toml": seed}),
            dict(self.FILES, **{"src/utils/Lib.sol": "library Lib { }"}),
            dict(self.FILES, **{"test/data/vectors.jsonl": "{}"}),
        ]:
            with self.subTest(files=files):
                self.assertNotEqual(key, self.key(self.project(files)))
        folder = self.project(self.FILES)
        self.assertNotEqual(key, self.key(folder, env={"FOUNDRY_FUZZ_RUNS": "1"}))
        self.assertNotEqual(key, self.key(folder, env={"SOLC_WRAPPER": "1"}))
        self.assertNotEqual(key, self.key(folder, forge="forge 1.7.2"))
        # The compiler counts by its contents, not by the path forge finds it at.
        self.assertEqual(key, self.key(folder, env={"FOUNDRY_SOLC": "/elsewhere/solc"}))
        with mock.patch.object(upstream_tests.os, "cpu_count", return_value=1):
            self.assertNotEqual(key, self.key(folder))

    def test_a_run_whose_tests_ran_is_reused(self):
        cache = benchmark.Cache(self.root / "cache")
        finished = subprocess.CompletedProcess([], 1, stdout='{"test/Lib.t.sol:T": {}}', stderr="")
        broken = subprocess.CompletedProcess([], 1, stdout="", stderr="Compiler run failed")
        crashed = subprocess.CompletedProcess([], -9, stdout='{"test/Lib.t.sol:T": {}}', stderr="")
        for result, runs in [(finished, 1), (broken, 2), (crashed, 2)]:
            with self.subTest(result=result), contextlib.redirect_stdout(io.StringIO()):
                key = upstream_tests.Cache.key("suite", result.stdout, result.returncode)
                arguments = (cache, key, "leg", ["forge"], self.root, {})
                with mock.patch.object(upstream_tests.subprocess, "run") as run:
                    run.return_value = result
                    first = upstream_tests.forge_test(*arguments)
                    second = upstream_tests.forge_test(*arguments)
                self.assertEqual(run.call_count, runs)
                self.assertEqual(first, second)
                self.assertEqual(first["stdout"], result.stdout)

    def test_no_cache_runs_every_time(self):
        finished = subprocess.CompletedProcess([], 0, stdout="{}", stderr="")
        with contextlib.redirect_stdout(io.StringIO()):
            with mock.patch.object(upstream_tests.subprocess, "run", return_value=finished) as run:
                for _ in range(2):
                    upstream_tests.forge_test(
                        benchmark.Cache(), "k", "leg", ["forge"], self.root, {}
                    )
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
