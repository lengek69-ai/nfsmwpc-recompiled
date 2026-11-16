#!/usr/bin/env python3
"""Focused unit tests for out-of-function branch emission."""
import sys
import types
import unittest

# mw_lifter only needs the upstream class as a base while these pure helper
# tests run; the real class is loaded by the Android workflow after patching.
stub = types.ModuleType("lift32")
stub.Lifter = type("BaseLifterStub", (), {})
sys.modules.setdefault("lift32", stub)

from mw_lifter import route_external_local_gotos


class ExternalBranchRoutingTests(unittest.TestCase):
    def test_routes_conditional_goto_and_preserves_nested_condition(self):
        line = (
            "if (recomp_cond_cf(_flag_k, helper(a, b), c, CC_NE, _cf)) "
            "goto L_00B07956; /* jcc */"
        )
        result, count = route_external_local_gotos(
            [line], 0x00B07956, {0x00B078BC}
        )
        self.assertEqual(count, 1)
        self.assertEqual(
            result,
            [
                "if (recomp_cond_cf(_flag_k, helper(a, b), c, CC_NE, _cf)) "
                "{ RECOMP_ITAIL(0x00B07956u); return; } /* jcc */"
            ],
        )

    def test_routes_unconditional_goto(self):
        result, count = route_external_local_gotos(
            ["    goto L_00B07956; /* jmp */"],
            0x00B07956,
            {0x00B078BC},
        )
        self.assertEqual(count, 1)
        self.assertEqual(
            result, ["    RECOMP_ITAIL(0x00B07956u); return; /* jmp */"]
        )

    def test_preserves_case_prefix(self):
        result, count = route_external_local_gotos(
            ["case 0x00B07956u: goto L_00B07956;"],
            0x00B07956,
            set(),
        )
        self.assertEqual(count, 1)
        self.assertEqual(
            result,
            ["case 0x00B07956u: RECOMP_ITAIL(0x00B07956u); return;"],
        )

    def test_keeps_local_goto_unchanged(self):
        line = "if (value) goto L_00B07956;"
        result, count = route_external_local_gotos(
            [line], 0x00B07956, {0x00B07956}
        )
        self.assertEqual(count, 0)
        self.assertEqual(result, [line])

    def test_leaves_unrelated_lines_unchanged(self):
        lines = ["eax = ebx;", "return;"]
        result, count = route_external_local_gotos(
            lines, 0x00B07956, {0x00B078BC}
        )
        self.assertEqual(count, 0)
        self.assertEqual(result, lines)


if __name__ == "__main__":
    unittest.main(verbosity=2)
