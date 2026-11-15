#!/usr/bin/env python3
"""Apply the Android-specific local-branch safety fix to the pinned pcrecomp lifter.

The upstream lifter already handles missing labels for jcc and jmp, but its
jecxz/jcxz and loop-family emitters previously generated unconditional local
gotos. When the target is not part of the current function CFG, Clang rejects
the generated C with an undeclared-label error. Route those taken branches
through the recompilation dispatcher instead.
"""
from pathlib import Path
import sys


def replace_once(source: str, old: str, new: str, description: str) -> str:
    count = source.count(old)
    if count == 0:
        if new in source:
            print(f"[ok] already patched: {description}")
            return source
        raise SystemExit(f"Could not locate expected upstream code for: {description}")
    if count != 1:
        raise SystemExit(f"Expected one occurrence for {description}, found {count}")
    print(f"[patch] {description}")
    return source.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {Path(sys.argv[0]).name} path/to/pcrecomp/tools/lift/lift32.py")

    path = Path(sys.argv[1])
    if not path.is_file():
        raise SystemExit(f"pcrecomp lifter not found: {path}")

    source = path.read_text(encoding="utf-8")

    old_jcxz = """            if t is not None:
                lines.append(f"if ({reg} == 0) goto L_{t:08X}; {comment}")

        elif m in ('loop', 'loope', 'loopne'):
"""
    new_jcxz = """            if t is not None:
                if self._labels is not None and t not in self._labels:
                    lines.append(f"if ({reg} == 0) {{ RECOMP_ITAIL(0x{t:08X}u); return; }} {comment}")
                else:
                    lines.append(f"if ({reg} == 0) goto L_{t:08X}; {comment}")

        elif m in ('loop', 'loope', 'loopne'):
"""
    source = replace_once(source, old_jcxz, new_jcxz, "jecxz/jcxz external-target handling")

    old_loop = """            t = ops[0].imm if ops and ops[0].type == X86_OP_IMM else None
            extra = {'loop': '', 'loope': ' && _cf == 0', 'loopne': ' && _cf == 0'}[m]
            if t is not None:
                lines.append(f"if (--ecx != 0{extra}) goto L_{t:08X}; {comment}")

        elif m == 'scasd':
"""
    new_loop = """            t = ops[0].imm if ops and ops[0].type == X86_OP_IMM else None
            # LOOPcc tests ZF, not CF. Reuse the same lazy-flag evaluator as
            # JE/JNE so loope and loopne preserve x86 condition semantics.
            extra = {'loop': '', 'loope': f" && ({self._make_condition('je')})",
                     'loopne': f" && ({self._make_condition('jne')})"}[m]
            if t is not None:
                condition = f"--ecx != 0{extra}"
                if self._labels is not None and t not in self._labels:
                    lines.append(f"if ({condition}) {{ RECOMP_ITAIL(0x{t:08X}u); return; }} {comment}")
                else:
                    lines.append(f"if ({condition}) goto L_{t:08X}; {comment}")

        elif m == 'scasd':
"""
    source = replace_once(source, old_loop, new_loop, "loop-family target handling and ZF semantics")

    path.write_text(source, encoding="utf-8")
    print(f"[ok] Android branch-safety patch applied to {path}")


if __name__ == "__main__":
    main()
