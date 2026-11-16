"""Need for Speed Most Wanted corrections to the shared pcrecomp lifter.

FCOM/FUCOM/FTST update the x87 status word, not integer EFLAGS. MW's
0x81CDC6 sound routine schedules CMP channel,-1; FUCOMPP; JNE: replacing
the CMP flags sends the all-channel sentinel through a single-channel write,
overwriting its effects callback at voice+0x118 with a floating-point gain.
Keep the integer lazy flags until TEST/SAHF explicitly transfers the status.
"""
from lift32 import Lifter as BaseLifter


def route_external_local_gotos(lines, target, labels):
    """Replace a goto to a block absent from this function with a tail dispatch.

    The base lifter already handles most out-of-function branches. This final
    guard covers any branch emitter that still produces a local goto when its
    destination is not among the labels emitted for the current function.
    """
    if target is None or (labels is not None and target in labels):
        return list(lines), 0

    label = f"L_{target:08X}"
    token = f"goto {label};"
    routed = []
    count = 0
    for line in lines:
        if token not in line:
            routed.append(line)
            continue

        prefix, suffix = line.split(token, 1)
        stripped = prefix.rstrip()
        dispatch = f"RECOMP_ITAIL(0x{target:08X}u); return;"
        if stripped.lstrip().startswith("if "):
            if not stripped.endswith(")"):
                raise RuntimeError(
                    f"Cannot safely route conditional branch to {label}: {line.strip()}"
                )
            routed.append(f"{stripped} {{ {dispatch} }}{suffix}")
        else:
            # Preserve a switch-case label or indentation before the branch.
            routed.append(f"{prefix}{dispatch}{suffix}")
        count += 1
    return routed, count


class Lifter(BaseLifter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.external_branch_targets = set()
        self.external_branch_sites = {}
        self.current_function_address = None
        self.external_branch_gotos = 0

    def lift_instruction(self, insn):
        lines = super().lift_instruction(insn)
        if not getattr(insn, "is_jump", False):
            return lines

        target = insn.get_branch_target()
        if target is None:
            return lines

        labels = getattr(self, "_labels", None)
        if labels is None or target not in labels:
            self.external_branch_targets.add(target)
            self.external_branch_sites.setdefault(target, []).append({
                "function": self.current_function_address,
                "instruction": insn.address,
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
                "bytes": bytes(insn.bytes).hex(),
                "local_labels": sorted(labels) if labels is not None else None,
            })
        lines, routed = route_external_local_gotos(lines, target, labels)
        self.external_branch_gotos += routed
        return lines

    def _lift_instruction(self, insn):
        if insn.mnemonic not in {'fcom', 'fcomp', 'fcompp',
                                 'fucom', 'fucomp', 'fucompp', 'ftst'}:
            return super()._lift_instruction(insn)
        state, seq = self._flag_state, self._flag_seq
        lines = super()._lift_instruction(insn)
        self._flag_state, self._flag_seq = state, seq
        return [line for line in lines
                if line != '_flag_a = (uint32_t)_fpu_cmp; _flag_b = 0;']
