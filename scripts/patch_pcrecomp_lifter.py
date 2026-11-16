#!/usr/bin/env python3
"""Apply Android branch-safety fixes to the pinned pcrecomp checkout.

The local lifter patch routes direct branches that leave the current function
through the recompilation dispatcher. The disassembler patch discovers
conditional destinations and restores surviving direct-branch targets as
alias entries after overlap pruning.
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


def patch_lifter(path: Path) -> None:
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

        elif m in ('loop', 'loope', 'loopz', 'loopne', 'loopnz'):
"""
    source = replace_once(source, old_jcxz, new_jcxz, "jecxz/jcxz external-target handling")

    old_loop = """            t = ops[0].imm if ops and ops[0].type == X86_OP_IMM else None
            extra = {'loop': '', 'loope': ' && _cf == 0', 'loopne': ' && _cf == 0'}[m]
            if t is not None:
                lines.append(f"if (--ecx != 0{extra}) goto L_{t:08X}; {comment}")

        elif m == 'scasd':
"""
    new_loop = """            t = ops[0].imm if ops and ops[0].type == X86_OP_IMM else None
            # LOOPcc tests ZF, not CF. Reuse the lazy-flag evaluator as JE/JNE.
            extra = {
                'loop': '',
                'loope': f" && ({self._make_condition('je')})",
                'loopz': f" && ({self._make_condition('je')})",
                'loopne': f" && ({self._make_condition('jne')})",
                'loopnz': f" && ({self._make_condition('jne')})",
            }[m]
            if t is not None:
                condition = f"--ecx != 0{extra}"
                if self._labels is not None and t not in self._labels:
                    lines.append(f"if ({condition}) {{ RECOMP_ITAIL(0x{t:08X}u); return; }} {comment}")
                else:
                    lines.append(f"if ({condition}) goto L_{t:08X}; {comment}")

        elif m == 'scasd':
"""
    source = replace_once(source, old_loop, new_loop, "LOOPcc aliases, ZF semantics and external-target handling")

    compile(source, str(path), "exec")
    path.write_text(source, encoding="utf-8")
    print(f"[ok] lifter patch applied to {path}")


def patch_disassembler(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"pcrecomp disassembler not found: {path}")
    source = path.read_text(encoding="utf-8")
    old = "if not (ins.is_uncond_jump or ins.is_call):"
    new = "if not (ins.is_jump or ins.is_call):"
    source = replace_once(
        source, old, new,
        "harvest direct conditional-branch targets into the dispatch catalog",
    )

    old_prune = """        for a in list(functions):
            if a not in sizes:
                del functions[a]

        # An entry on int3 is alignment padding that a pointer-shaped constant
"""
    new_prune = """        for a in list(functions):
            if a not in sizes:
                del functions[a]

        # A direct branch is stronger evidence than an overlapping decode from
        # a different candidate. The lifter must be able to dispatch to the exact
        # target, even when another decode stream marked that byte as interior.
        # Rebuild only targets reached by functions that survived the overlap
        # filter, so a discarded false-positive body cannot preserve its targets.
        direct_branch_sources = {}
        for source, function in functions.items():
            local_blocks = set(function.blocks)
            for block in function.blocks.values():
                for ins in block.instructions:
                    if not ins.is_jump:
                        continue
                    target = ins.get_branch_target()
                    if (target is None or target in local_blocks
                            or not code_start <= target < code_end):
                        continue
                    direct_branch_sources.setdefault(target, set()).add(source)

        restored = 0
        for target, sources in sorted(direct_branch_sources.items()):
            if target in functions or not any(source in functions for source in sources):
                continue
            alias = self.disassemble_function(target, iat_map)
            if alias and alias.blocks:
                alias.entry_kind = "alias"
                functions[target] = alias
                restored += 1

        if restored:
            print(f"[*] Restored {restored} direct branch destinations as aliases")

        # An entry on int3 is alignment padding that a pointer-shaped constant
"""
    source = replace_once(
        source, old_prune, new_prune,
        "restore surviving direct branch destinations after overlap pruning",
    )
    compile(source, str(path), "exec")
    path.write_text(source, encoding="utf-8")
    print(f"[ok] disassembler patch applied to {path}")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            f"Usage: {Path(sys.argv[0]).name} path/to/lift32.py path/to/disasm32.py"
        )
    patch_lifter(Path(sys.argv[1]))
    patch_disassembler(Path(sys.argv[2]))


if __name__ == "__main__":
    main()
