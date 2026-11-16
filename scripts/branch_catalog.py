"""Recover direct-branch destinations from functions restored after catalog closure."""

from collections import deque


def _direct_branch_target(instruction):
    """Read a branch target even when the catalog pass released Capstone operands."""
    getter = getattr(instruction, "get_branch_target", None)
    if callable(getter):
        target = getter()
        if target is not None:
            return int(target) & 0xFFFFFFFF

    # find_functions(..., release_operands=True) retains op_str but drops operands.
    # Capstone formats direct relative branch operands as absolute hexadecimal VAs.
    operand = str(getattr(instruction, "op_str", "")).strip()
    try:
        return int(operand, 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


def restore_late_branch_targets(disassembler, iat_map, functions, code_start, code_end):
    """Add alias entries for direct jumps discovered in late-restored seed functions.

    find_functions() closes branch targets before run_lift.py's restore_seeds()
    runs. A function restored from a data/code seed therefore bypasses that
    closure pass. Its jcc/jmp can later become RECOMP_ITAIL(), but its destination
    is absent from the dispatch table. Re-scan all catalog functions after seed
    recovery and recursively add every in-range direct branch destination.

    Direct branch evidence is intentional here: unlike pointer-shaped constants,
    an executed branch proves the destination is a control-flow entry, including
    overlapping x86 entry points.
    """
    pending = deque()
    queued = set()
    origins = {}

    def enqueue_from(function):
        local_blocks = set(function.blocks)
        for block in function.blocks.values():
            for instruction in block.instructions:
                if not getattr(instruction, "is_jump", False):
                    continue
                target = _direct_branch_target(instruction)
                if target is None or not code_start <= target < code_end:
                    continue
                if target in local_blocks or target in functions:
                    continue
                origins.setdefault(target, set()).add(function.address)
                if target not in queued:
                    queued.add(target)
                    pending.append(target)

    # This includes functions that find_functions() found and functions that
    # restore_seeds() or forced_seeds added afterwards.
    for function in list(functions.values()):
        enqueue_from(function)

    restored = []
    failures = []
    while pending:
        target = pending.popleft()
        if target in functions:
            continue
        try:
            alias = disassembler.disassemble_function(target, iat_map)
        except Exception as exc:  # noqa: BLE001
            failures.append((target, repr(exc)))
            continue
        if alias is None or not alias.blocks:
            failures.append((target, "destination did not decode to a non-empty function"))
            continue

        alias.entry_kind = "alias"
        functions[target] = alias
        restored.append(target)
        enqueue_from(alias)

    if failures:
        details = []
        for target, reason in failures[:32]:
            callers = ", ".join(f"0x{source:08X}" for source in sorted(origins.get(target, ())))
            details.append(
                f"target=0x{target:08X} from={callers or 'unknown'}: {reason}"
            )
        raise RuntimeError(
            "Late direct-branch destination(s) could not be added to the dispatch "
            "catalog:\n" + "\n".join(details)
        )

    return restored
