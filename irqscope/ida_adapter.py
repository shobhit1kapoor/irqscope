"""IDA-facing discovery helpers. Import this module only from inside IDA."""

import re
from typing import Dict, List, Optional, Tuple

import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_lines
import ida_segment
import ida_ua
import idautils
import idc

from .model import (
    AnalysisCancelled,
    CFGBlock,
    DeviceModel,
    InterruptConfigEvent,
    MMIOAccess,
    VectorEntry,
    VectorTableCandidate,
)
from .interrupts import (
    mask_effect_for_call,
    normalize_mask_value,
    nvic_event_for_call,
    nvic_operation_for_store,
)
from .svd import check_write_constraints

MAX_SCAN_WARNINGS = 256
CONSTANT_PROPAGATION_MNEMONICS = {
    "mov", "movs", "movw", "movt", "mvn", "mvns",
    "add", "adds", "sub", "subs", "addw", "subw",
    "rsb", "rsbs", "neg", "negs",
    "and", "ands", "orr", "orrs", "eor", "eors", "bic", "bics", "orn", "orns",
    "lsl", "lsls", "lsr", "lsrs", "asr", "asrs", "ror", "rors",
    "ubfx", "sbfx", "bfi", "bfc",
    "adr", "mrs", "msr", "cpsid", "cpsie",
}


def _segments():
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg is not None:
            yield seg


def _mapped_code_pointer(value: int) -> Optional[int]:
    target = value & ~1
    seg = ida_segment.getseg(target)
    if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC):
        return None
    return target


def _writable_segment_contains(value: int) -> bool:
    seg = ida_segment.getseg(value - 1 if value else value)
    return bool(seg and seg.perm & ida_segment.SEGPERM_WRITE)


def detect_vector_tables(limit_per_segment: int = 0x400) -> List[VectorTableCandidate]:
    """Rank plausible Cortex-M vector tables; never changes the IDB."""
    candidates = []
    seen = set()
    for seg in _segments():
        if seg.end_ea - seg.start_ea < 64:
            continue
        stop = min(seg.end_ea - 64, seg.start_ea + limit_per_segment)
        start = (seg.start_ea + 3) & ~3
        for base in range(start, stop, 4):
            if base in seen:
                continue
            sp = ida_bytes.get_dword(base)
            reset = ida_bytes.get_dword(base + 4)
            if sp in (0, 0xFFFFFFFF) or not _writable_segment_contains(sp):
                continue
            reset_ea = _mapped_code_pointer(reset)
            if reset_ea is None:
                continue
            mapped = 0
            checked = 0
            for slot in range(2, min(48, (seg.end_ea - base) // 4)):
                value = ida_bytes.get_dword(base + slot * 4)
                if value in (0, 0xFFFFFFFF):
                    continue
                checked += 1
                if _mapped_code_pointer(value) is not None:
                    mapped += 1
            if mapped < 2:
                continue
            score = min(1.0, 0.45 + mapped / max(checked, 1) * 0.45 + min(mapped, 16) / 100.0)
            candidates.append(VectorTableCandidate(base, sp, reset_ea, mapped, score))
            seen.add(base)
    return sorted(candidates, key=lambda item: (-item.score, item.address))[:64]


def read_vector_table(base: int, max_slots: int = 128) -> List[VectorEntry]:
    entries = []
    for slot in range(max_slots):
        value = ida_bytes.get_dword(base + slot * 4)
        if value in (0, 0xFFFFFFFF):
            continue
        target = _mapped_code_pointer(value)
        if target is None:
            continue
        func = ida_funcs.get_func(target)
        function_ea = func.start_ea if func else None
        if slot == 0:
            name = "Initial Stack Pointer"
        elif slot == 1:
            name = "Reset"
        elif slot < 16:
            core_names = {
                2: "NMI", 3: "HardFault", 4: "MemManage", 5: "BusFault",
                6: "UsageFault", 11: "SVCall", 12: "DebugMonitor",
                14: "PendSV", 15: "SysTick",
            }
            name = core_names.get(slot, f"Core Exception {slot}")
        else:
            name = f"External IRQ {slot - 16}"
        entries.append(VectorEntry(slot, target, function_ea, name))
    return entries


def _operation(mnemonic: str) -> str:
    mnem = mnemonic.lower()
    if mnem.startswith(("ldr", "ldm", "ld1", "ld2", "ld3", "ld4")):
        return "read"
    if mnem.startswith(("str", "stm", "st1", "st2", "st3", "st4")):
        return "write"
    return "unknown"


def _is_call(insn, mnemonic: str) -> bool:
    feature = insn.get_canon_feature()
    return bool(feature & getattr(ida_idp, "CF_CALL", 0)) or mnemonic in (
        "bl", "blx", "blxns", "call", "callq"
    )


def _fresh_state():
    return ({}, {"primask": None, "basepri": None, "faultmask": None}, {})


def _merge_states(states):
    if not states:
        return _fresh_state()
    common_regs = dict(states[0][0])
    for key in list(common_regs):
        if any(state[0].get(key) != common_regs[key] for state in states[1:]):
            del common_regs[key]
    masks = {}
    for name in ("primask", "basepri", "faultmask"):
        values = [state[1].get(name) for state in states]
        masks[name] = values[0] if all(value == values[0] for value in values) else None
    saved = dict(states[0][2])
    for key in list(saved):
        if any(state[2].get(key) != saved[key] for state in states[1:]):
            del saved[key]
    return common_regs, masks, saved


def _propagate_cfg_states(blocks, entry_id, transfer, iteration_limit=None,
                          edge_filter=None):
    """Run bounded forward dataflow and report whether its fixed point was reached."""
    if iteration_limit is None:
        iteration_limit = max(8, len(blocks) * 8)
    in_states = {block.id: None for block in blocks}
    out_states = {block.id: None for block in blocks}
    in_states[entry_id] = _fresh_state()
    for iteration in range(1, iteration_limit + 1):
        changed = False
        for block in blocks:
            if block.id == entry_id:
                incoming = _fresh_state()
            else:
                predecessors = []
                for pred in block.preds():
                    predecessor_state = out_states[pred.id]
                    if predecessor_state is None:
                        continue
                    if edge_filter is not None and not edge_filter(
                            pred, block, predecessor_state):
                        continue
                    predecessors.append(predecessor_state)
                if not predecessors:
                    if in_states[block.id] is not None or out_states[block.id] is not None:
                        in_states[block.id] = None
                        out_states[block.id] = None
                        changed = True
                    continue
                incoming = _merge_states(predecessors)
            if in_states[block.id] != incoming:
                in_states[block.id] = incoming
                changed = True
            outgoing = transfer(block, incoming)
            if out_states[block.id] != outgoing:
                out_states[block.id] = outgoing
                changed = True
        if not changed:
            return in_states, out_states, True, iteration
    return in_states, out_states, False, iteration_limit


def _literal_constants(ea: int):
    values = set()
    for target in idautils.DataRefsFrom(ea):
        seg = ida_segment.getseg(target)
        if seg is None or seg.perm & ida_segment.SEGPERM_EXEC:
            continue
        value = ida_bytes.get_dword(target)
        if value not in (0, 0xFFFFFFFF):
            values.add(int(value))
    return values


def _parse_arm_memory_operand(rendered: str, operand_type: int, displacement: int):
    """Parse only simple ARM base, optional constant index, LSL, and offset forms."""
    text = (rendered or "").strip().lower()
    if not text.startswith("[") or not text.endswith("]"):
        return None
    parts = [part.strip() for part in text[1:-1].split(",")]
    register_pattern = r"r(?:1[0-5]|[0-9])|sp|lr|pc"
    if not parts or not re.fullmatch(register_pattern, parts[0]):
        return None
    base_name = parts[0]
    index_name = None
    scale = 1
    if len(parts) > 1:
        if re.fullmatch(register_pattern, parts[1]):
            index_name = parts[1]
            if len(parts) == 3:
                shift = re.fullmatch(r"lsl\s+#?((?:0x)?[0-9a-f]+)", parts[2])
                if not shift:
                    return None
                shift_amount = int(shift.group(1), 0 if shift.group(1).startswith("0x") else 10)
                if shift_amount > 4:
                    return None
                scale = 1 << shift_amount
            elif len(parts) != 2:
                return None
        elif len(parts) == 2 and operand_type == ida_ua.o_displ and parts[1].startswith("#"):
            pass
        else:
            return None
    elif len(parts) != 1:
        return None
    offset = int(displacement) & 0xFFFFFFFF if operand_type == ida_ua.o_displ else 0
    if offset & 0x80000000:
        offset -= 0x100000000
    return base_name, index_name, scale, offset


def _memory_operand_addresses(ea, insn, state):
    regs, _, _ = state
    addresses = []
    max_ops = getattr(ida_ua, "UA_MAXOP", 8)
    for index in range(max_ops):
        operand = insn.ops[index]
        if operand.type == ida_ua.o_void:
            break
        if operand.type == ida_ua.o_mem:
            addresses.append((int(operand.addr), index, "absolute-memory-operand"))
        elif operand.type in (ida_ua.o_displ, ida_ua.o_phrase):
            parsed = _parse_arm_memory_operand(
                idc.print_operand(ea, index), operand.type, operand.addr
            )
            if parsed is None:
                continue
            base_name, index_name, scale, displacement = parsed
            try:
                base_reg = int(ida_idp.str2reg(base_name))
                index_reg = int(ida_idp.str2reg(index_name)) if index_name else None
            except (AttributeError, TypeError, ValueError):
                continue
            if base_reg < 0 or (index_reg is not None and index_reg < 0):
                continue
            base = regs.get(base_reg)
            if not isinstance(base, int):
                continue
            index_value = 0
            if index_reg is not None:
                index_value = regs.get(index_reg)
                if not isinstance(index_value, int):
                    continue
            evidence = "constant-index-register" if index_reg is not None else "constant-base-register"
            addresses.append(((base + displacement + index_value * scale) & 0xFFFFFFFF,
                              index, evidence))
    return addresses


def _mask_instruction(ea, insn, mnemonic, state, call_argument_regs=None):
    regs, masks, saved = state
    masks = dict(masks)
    saved = dict(saved)
    operands = [idc.print_operand(ea, i).strip().lower() for i in range(3)]
    if mnemonic in ("cpsid", "cpsie"):
        enabled = mnemonic == "cpsie"
        flags = "".join(operands)
        if "i" in flags:
            masks["primask"] = 0 if enabled else 1
        if "f" in flags:
            masks["faultmask"] = 0 if enabled else 1
    elif mnemonic == "mrs" and insn.ops[0].type == ida_ua.o_reg:
        target = int(insn.ops[0].reg)
        source = operands[1].replace(" ", "")
        source = source.replace("#", "")
        source = source.split("_")[-1]
        if source in masks:
            saved[target] = (source, masks[source])
    elif mnemonic == "msr" and len(operands) > 1:
        target = operands[0].replace(" ", "").replace("_max", "").split("_")[-1]
        source_reg = int(insn.ops[1].reg) if insn.ops[1].type == ida_ua.o_reg else None
        if target in masks and source_reg is not None:
            if source_reg in saved and saved[source_reg][0] == target:
                masks[target] = saved[source_reg][1]
            else:
                value = regs.get(source_reg)
                masks[target] = normalize_mask_value(target, value) if isinstance(value, int) else None
    else:
        call = _is_call(insn, mnemonic)
        if call:
            target = idc.get_operand_value(ea, 0)
            callee = (idc.get_name(target) or "").lower()
            effect = mask_effect_for_call(callee)
            if effect is not None and effect[0] == "per-irq":
                pass
            elif effect is not None:
                operation, mask_name = effect
                if operation == "set":
                    masks[mask_name] = 1
                elif operation == "clear":
                    masks[mask_name] = 0
                else:
                    value_regs = call_argument_regs if call_argument_regs is not None else regs
                    value = value_regs.get(0)
                    if isinstance(value, int):
                        masks[mask_name] = normalize_mask_value(mask_name, value)
                    else:
                        masks[mask_name] = None
            else:
                masks = {"primask": None, "basepri": None, "faultmask": None}
    return regs, masks, saved


def _report_progress(progress, message):
    if progress is not None and progress(message):
        raise AnalysisCancelled(message)


def _has_arm_condition_suffix(ea, mnemonic):
    """Return whether IDA renders this ARM instruction with a condition suffix."""
    line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")
    rendered = (line.strip().split(None, 1) or [""])[0].lower()
    base = mnemonic.lower().split(".", 1)[0]
    bases = {base, base + "s"}
    if base.endswith("s"):
        bases.add(base[:-1])
    conditions = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl",
                  "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le")
    for candidate in bases:
        for condition in conditions:
            for separator in ("", "."):
                for width_suffix in ("", ".w", ".n"):
                    if rendered == f"{candidate}{separator}{condition}{width_suffix}":
                        return True
    for condition in conditions:
        if mnemonic.endswith(condition):
            candidate = mnemonic[:-len(condition)].split(".", 1)[0]
            if (candidate in CONSTANT_PROPAGATION_MNEMONICS
                    or candidate.startswith("ldr")
                    or candidate in {"b", "bl", "blx", "bx"}):
                return True
    return False


def _constant_operand_value(ea, operand_index, operand, registers):
    """Resolve an immediate or a known unshifted/shifted ARM register operand."""
    if operand.type == ida_ua.o_imm:
        return int(operand.value) & 0xFFFFFFFF
    if operand.type != ida_ua.o_reg:
        return None
    rendered = idc.print_operand(ea, operand_index).strip().lower()
    plain = re.fullmatch(r"(r(?:1[0-5]|[0-9])|sp|lr|pc)", rendered)
    if plain:
        register = int(ida_idp.str2reg(plain.group(1)))
        return registers.get(register)
    shifted = re.fullmatch(
        r"(r(?:1[0-5]|[0-9])|sp|lr|pc)\s*,\s*(lsl|lsr|asr|ror)\s+"
        r"(?:#\s*)?(r(?:1[0-5]|[0-9])|sp|lr|pc|0x[0-9a-f]+|[0-9]+[h]?)",
        rendered,
    )
    if not shifted:
        return None
    source_register = int(ida_idp.str2reg(shifted.group(1)))
    source_value = registers.get(source_register)
    if not isinstance(source_value, int):
        return None
    shift_kind = shifted.group(2)
    amount_token = shifted.group(3)
    if re.fullmatch(r"(?:r(?:1[0-5]|[0-9])|sp|lr|pc)", amount_token):
        amount_register = ida_idp.str2reg(amount_token)
        register_amount = True
        amount_value = registers.get(int(amount_register))
        if not isinstance(amount_value, int):
            return None
        amount = amount_value & 0xFF
    else:
        register_amount = False
        try:
            if amount_token.endswith("h"):
                amount = int(amount_token[:-1], 16)
            elif amount_token.startswith("0x"):
                amount = int(amount_token[2:], 16)
            else:
                amount = int(amount_token, 10)
        except ValueError:
            return None
    source_value &= 0xFFFFFFFF
    if shift_kind == "lsl":
        return (0 if amount >= 32 else source_value << amount) & 0xFFFFFFFF
    if shift_kind == "lsr":
        if amount == 0 and not register_amount:
            amount = 32
        return 0 if amount >= 32 else source_value >> amount
    if shift_kind == "asr":
        if amount == 0 and not register_amount:
            amount = 32
        signed_source = (source_value if source_value < 0x80000000
                         else source_value - 0x100000000)
        return ((-1 if signed_source < 0 else 0) if amount >= 32
                else signed_source >> amount) & 0xFFFFFFFF
    if amount % 32 == 0 and not register_amount:
        return None
    rotation = amount % 32
    return source_value if rotation == 0 else (
        (source_value >> rotation) | (source_value << (32 - rotation))
    ) & 0xFFFFFFFF


def _rendered_operand_registers(ea, operand_index):
    """Return register ids spelled in an ARM operand, including shift amounts."""
    rendered = idc.print_operand(ea, operand_index).strip().lower()
    names = re.findall(r"\b(r(?:1[0-5]|[0-9])|sp|lr|pc)\b", rendered)
    return tuple(int(ida_idp.str2reg(name)) for name in names)


def _transfer_block(block, incoming, model, function_ea, function_name, collect=False,
                    nvic_summaries=None, progress=None):
    regs, masks, saved = (dict(incoming[0]), dict(incoming[1]), dict(incoming[2]))
    accesses = []
    interrupt_config = []
    in_thumb_it_block = False
    for instruction_index, ea in enumerate(idautils.Heads(block.start_ea, block.end_ea), 1):
        if instruction_index % 256 == 0:
            _report_progress(
                progress,
                f"Scanning {function_name} at 0x{ea:X} ({instruction_index} instructions in block)",
            )
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            continue
        insn = ida_ua.insn_t()
        if not ida_ua.decode_insn(insn, ea):
            continue
        mnemonic = idc.print_insn_mnem(ea).lower()
        if mnemonic.startswith("it"):
            in_thumb_it_block = True
            regs.clear()
            masks = {"primask": None, "basepri": None, "faultmask": None}
            saved.clear()
            continue
        is_call = _is_call(insn, mnemonic)
        can_propagate_constant = (
            mnemonic in CONSTANT_PROPAGATION_MNEMONICS or mnemonic.startswith("ldr") or is_call
        )
        predicated_instruction = (
            _has_arm_condition_suffix(ea, mnemonic) if can_propagate_constant else False
        )
        old_regs = dict(regs)
        old_saved = dict(saved)
        operation = _operation(mnemonic)
        current = (regs, masks, saved)
        if collect and operation != "unknown":
            for address, operand_index, evidence in _memory_operand_addresses(ea, insn, current):
                register = model.get_register(address)
                if register is None:
                    continue
                operand = insn.ops[operand_index]
                width_by_dtype = {
                    getattr(ida_ua, "dt_byte", -1): 8,
                    getattr(ida_ua, "dt_word", -2): 16,
                    getattr(ida_ua, "dt_dword", -3): 32,
                    getattr(ida_ua, "dt_qword", -4): 64,
                    getattr(ida_ua, "dt_byte16", -5): 128,
                }
                width = width_by_dtype.get(operand.dtype, register.size_bits)
                written_value = None
                value_evidence = None
                if operation == "write" and mnemonic.startswith("str") and not mnemonic.startswith("strd"):
                    source = insn.ops[0]
                    if source.type == ida_ua.o_imm:
                        written_value = int(source.value)
                        value_evidence = "immediate-operand"
                    elif source.type == ida_ua.o_reg:
                        constant = regs.get(int(source.reg))
                        if isinstance(constant, int):
                            written_value = constant
                            value_evidence = "constant-propagated-register"
                    if written_value is not None and width > 0:
                        written_value &= (1 << width) - 1
                write_constraint_checks = (
                    check_write_constraints(
                        register, written_value, width, model.get_registers(address)[1:], address,
                        model.endianness, model.address_unit_bits,
                    )
                    if operation == "write" else ()
                )
                accesses.append(MMIOAccess(
                    ea=ea,
                    function_ea=function_ea,
                    function_name=function_name,
                    register=register,
                    operation=operation,
                    width_bits=width,
                    evidence=evidence,
                    primask=masks.get("primask"),
                    basepri=masks.get("basepri"),
                    faultmask=masks.get("faultmask"),
                    block_start_ea=block.start_ea,
                    register_aliases=model.get_registers(address)[1:],
                    value=written_value,
                    value_evidence=value_evidence,
                    write_constraint_checks=write_constraint_checks,
                ))

        feature = insn.get_canon_feature()
        for op_index, flag_name in enumerate(("CF_CHG1", "CF_CHG2", "CF_CHG3")):
            flag = getattr(ida_idp, flag_name, 0)
            if flag and feature & flag:
                operand = insn.ops[op_index]
                if operand.type == ida_ua.o_reg:
                    regs.pop(int(operand.reg), None)
                    saved.pop(int(operand.reg), None)

        if in_thumb_it_block or predicated_instruction:
            if is_call:
                regs.clear()
            masks = {"primask": None, "basepri": None, "faultmask": None}
            saved.clear()
            continue
        if is_call:
            if collect:
                target = idc.get_operand_value(ea, 0)
                callee = idc.get_name(target) or ""
                action = nvic_event_for_call(callee)
                evidence_basis = "recognized-api-name"
                if action is None and nvic_summaries:
                    target_function = ida_funcs.get_func(target)
                    if target_function is not None:
                        action = nvic_summaries.get(target_function.start_ea)
                        if action is not None:
                            evidence_basis = "constant-base-nvic-store-summary"
                irq_number = old_regs.get(0)
                if action and isinstance(irq_number, int) and 0 <= irq_number <= 1023:
                    priority = old_regs.get(1) if action == "set-priority" else None
                    if callee.lower().startswith("hal_nvic_"):
                        # HAL_NVIC_SetPriority takes preempt/subpriority parts,
                        # which are not a raw encoded NVIC priority value.
                        priority = None
                    interrupt_config.append(InterruptConfigEvent(
                        ea=ea,
                        function_ea=function_ea,
                        function_name=function_name,
                        irq_number=irq_number,
                        operation=action,
                        priority=priority if isinstance(priority, int) else None,
                        evidence_basis=evidence_basis,
                    ))
            regs.clear()
            saved.clear()
        elif mnemonic in ("mov", "movs", "movw", "movt", "mvn", "mvns") and insn.ops[0].type == ida_ua.o_reg:
            dest = int(insn.ops[0].reg)
            src = insn.ops[1]
            if src.type == ida_ua.o_imm:
                value = int(src.value)
                if mnemonic in ("mvn", "mvns"):
                    value = (~value) & 0xFFFFFFFF
                elif mnemonic == "movw":
                    value &= 0xFFFF
                elif mnemonic == "movt":
                    previous = old_regs.get(dest)
                    if isinstance(previous, int):
                        value = (previous & 0xFFFF) | ((value & 0xFFFF) << 16)
                    else:
                        value = None
                regs[dest] = value
            elif mnemonic in ("mov", "movs") and src.type == ida_ua.o_reg:
                value = _constant_operand_value(ea, 1, src, old_regs)
                if isinstance(value, int):
                    regs[dest] = value
                rendered_source = idc.print_operand(ea, 1).strip().lower()
                plain_source = re.fullmatch(
                    r"(r(?:1[0-5]|[0-9])|sp|lr|pc)", rendered_source
                )
                if plain_source:
                    source_reg = int(ida_idp.str2reg(plain_source.group(1)))
                    if source_reg in old_saved:
                        saved[dest] = old_saved[source_reg]
            elif mnemonic in ("mvn", "mvns") and src.type == ida_ua.o_reg:
                value = _constant_operand_value(ea, 1, src, old_regs)
                if isinstance(value, int):
                    regs[dest] = (~value) & 0xFFFFFFFF
        elif mnemonic in ("add", "adds", "sub", "subs", "addw", "subw",
                          "rsb", "rsbs", "neg", "negs") and insn.ops[0].type == ida_ua.o_reg:
            dest = int(insn.ops[0].reg)
            implicit_zero = False
            if mnemonic in ("neg", "negs"):
                source = insn.ops[1]
                base = (old_regs.get(int(source.reg))
                        if source.type == ida_ua.o_reg else None)
                delta = 0
                reverse_subtract = True
                implicit_zero = True
            elif insn.ops[2].type != ida_ua.o_void:
                source = insn.ops[1]
                base = old_regs.get(int(source.reg)) if source.type == ida_ua.o_reg else None
                right_operand = insn.ops[2]
                right_index = 2
                reverse_subtract = mnemonic.startswith("rsb")
            elif mnemonic in ("rsb", "rsbs"):
                base = None
                delta = None
                reverse_subtract = True
                implicit_zero = True
            else:
                base = old_regs.get(dest)
                right_operand = insn.ops[1]
                right_index = 1
                reverse_subtract = mnemonic.startswith("rsb")
            if not implicit_zero:
                delta = _constant_operand_value(ea, right_index, right_operand, old_regs)
            if isinstance(base, int) and isinstance(delta, int):
                if reverse_subtract:
                    value = delta - base
                else:
                    value = base + (delta if mnemonic.startswith("add") else -delta)
                regs[dest] = value & 0xFFFFFFFF
        elif (mnemonic in ("and", "ands", "orr", "orrs", "eor", "eors", "bic", "bics", "orn", "orns")
              and insn.ops[0].type == ida_ua.o_reg and insn.ops[3].type == ida_ua.o_void):
            dest = int(insn.ops[0].reg)
            if insn.ops[2].type != ida_ua.o_void:
                source = insn.ops[1]
                left = old_regs.get(int(source.reg)) if source.type == ida_ua.o_reg else None
                right_operand = insn.ops[2]
                right_index = 2
            else:
                left = old_regs.get(dest)
                right_operand = insn.ops[1]
                right_index = 1
            right = _constant_operand_value(ea, right_index, right_operand, old_regs)
            if isinstance(left, int) and isinstance(right, int):
                base_mnemonic = mnemonic[:-1] if mnemonic.endswith("s") else mnemonic
                if base_mnemonic == "and":
                    value = left & right
                elif base_mnemonic == "orr":
                    value = left | right
                elif base_mnemonic == "eor":
                    value = left ^ right
                elif base_mnemonic == "orn":
                    value = left | ~right
                else:
                    value = left & ~right
                regs[dest] = value & 0xFFFFFFFF
        elif mnemonic in ("ubfx", "sbfx", "bfi", "bfc") and insn.ops[0].type == ida_ua.o_reg:
            dest = int(insn.ops[0].reg)
            if mnemonic == "bfc":
                source_value = old_regs.get(dest)
                lsb_operand = insn.ops[1]
                width_operand = insn.ops[2]
            else:
                source_value = _constant_operand_value(ea, 1, insn.ops[1], old_regs)
                lsb_operand = insn.ops[2]
                width_operand = insn.ops[3]
            if lsb_operand.type == ida_ua.o_imm and width_operand.type == ida_ua.o_imm:
                lsb = int(lsb_operand.value)
                width = int(width_operand.value)
                if 0 <= lsb < 32 and 1 <= width <= 32 and lsb + width <= 32:
                    field_mask = (1 << width) - 1
                    if mnemonic in ("ubfx", "sbfx") and isinstance(source_value, int):
                        field_value = (source_value >> lsb) & field_mask
                        if mnemonic == "sbfx" and field_value & (1 << (width - 1)):
                            field_value |= 0xFFFFFFFF ^ field_mask
                        regs[dest] = field_value & 0xFFFFFFFF
                    elif mnemonic == "bfi" and isinstance(source_value, int):
                        destination_value = old_regs.get(dest)
                        if isinstance(destination_value, int):
                            positioned_mask = (field_mask << lsb) & 0xFFFFFFFF
                            inserted = ((source_value & field_mask) << lsb) & 0xFFFFFFFF
                            regs[dest] = ((destination_value & ~positioned_mask) | inserted) & 0xFFFFFFFF
                    elif mnemonic == "bfc" and isinstance(source_value, int):
                        positioned_mask = (field_mask << lsb) & 0xFFFFFFFF
                        regs[dest] = source_value & ~positioned_mask & 0xFFFFFFFF
        elif mnemonic in ("lsl", "lsls", "lsr", "lsrs", "asr", "asrs", "ror", "rors") \
                and insn.ops[0].type == ida_ua.o_reg:
            dest = int(insn.ops[0].reg)
            if insn.ops[2].type != ida_ua.o_void:
                source = insn.ops[1]
                source_index = 1
                shift_operand = insn.ops[2]
                shift_index = 2
                source_value = (old_regs.get(int(source.reg))
                                if source.type == ida_ua.o_reg else None)
            else:
                source = insn.ops[0]
                source_index = 0
                shift_operand = insn.ops[1]
                shift_index = 1
                source_value = old_regs.get(dest)
            source_name = idc.print_operand(ea, source_index).strip().lower()
            source_is_plain = re.fullmatch(
                r"(?:r(?:1[0-5]|[0-9])|sp|lr|pc)", source_name
            )
            if source_is_plain and isinstance(source_value, int):
                if shift_operand.type == ida_ua.o_imm:
                    amount = int(shift_operand.value)
                    immediate_shift = True
                elif shift_operand.type == ida_ua.o_reg:
                    amount_name = idc.print_operand(ea, shift_index).strip().lower()
                    amount_value = (old_regs.get(int(shift_operand.reg))
                                    if re.fullmatch(
                                        r"(?:r(?:1[0-5]|[0-9])|sp|lr|pc)", amount_name
                                    ) else None)
                    amount = (amount_value & 0xFF
                              if isinstance(amount_value, int) else None)
                    immediate_shift = False
                else:
                    amount = None
                    immediate_shift = False
                if isinstance(amount, int) and amount >= 0:
                    base_mnemonic = mnemonic[:-1] if mnemonic.endswith("s") else mnemonic
                    source_value &= 0xFFFFFFFF
                    if base_mnemonic == "lsl":
                        value = (0 if amount >= 32 else source_value << amount) & 0xFFFFFFFF
                    elif base_mnemonic == "lsr":
                        if immediate_shift and amount == 0:
                            amount = 32
                        value = 0 if amount >= 32 else source_value >> amount
                    elif base_mnemonic == "asr":
                        if immediate_shift and amount == 0:
                            amount = 32
                        signed_source = (source_value if source_value < 0x80000000
                                         else source_value - 0x100000000)
                        value = ((-1 if signed_source < 0 else 0) if amount >= 32
                                 else signed_source >> amount) & 0xFFFFFFFF
                    elif base_mnemonic == "ror":
                        if not immediate_shift or amount % 32 != 0:
                            rotation = amount % 32
                            value = source_value if rotation == 0 else (
                                (source_value >> rotation) | (source_value << (32 - rotation))
                            ) & 0xFFFFFFFF
                        else:
                            value = None
                    else:
                        value = None
                    if isinstance(value, int):
                        regs[dest] = value
        elif mnemonic == "adr" and insn.ops[0].type == ida_ua.o_reg:
            dest = int(insn.ops[0].reg)
            source = insn.ops[1]
            if source.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_imm):
                value = source.addr if source.type != ida_ua.o_imm else source.value
                regs[dest] = int(value) & 0xFFFFFFFF
        elif mnemonic.startswith("ldr") and insn.ops[0].type == ida_ua.o_reg:
            dest = int(insn.ops[0].reg)
            literals = _literal_constants(ea)
            if len(literals) == 1:
                regs[dest] = next(iter(literals))

        regs, masks, saved = _mask_instruction(
            ea, insn, mnemonic, (regs, masks, saved),
            call_argument_regs=old_regs if is_call else None,
        )
    return regs, masks, saved, accesses, interrupt_config


def _printed_memory_base_register(ea, operand_index):
    """Resolve the base register from IDA's rendered ARM memory operand.

    ARM phrase operands may encode addressing modes in processor-specific
    fields rather than storing the base register directly in ``op_t.phrase``.
    Using IDA's own operand rendering and register-name parser avoids treating
    an index register as the constant NVIC base.
    """
    rendered = idc.print_operand(ea, operand_index)
    if not rendered:
        return None
    match = re.match(r"\s*\[\s*([a-z][a-z0-9_]*)", rendered.strip(), re.IGNORECASE)
    if not match:
        return None
    parser = getattr(ida_idp, "str2reg", None)
    if parser is None:
        return None
    register = int(parser(match.group(1)))
    return register if register >= 0 else None


def _nvic_helper_summaries(progress=None):
    """Infer bounded NVIC summaries from constant-base direct or indexed stores."""
    summaries = {}
    functions = list(idautils.Functions())
    for function_index, function_ea in enumerate(functions, 1):
        _report_progress(
            progress,
            f"Indexing NVIC helper evidence ({function_index}/{len(functions)} functions)",
        )
        func = ida_funcs.get_func(function_ea)
        if func is None:
            continue
        regs = {}
        operations = set()
        for instruction_index, ea in enumerate(idautils.FuncItems(func.start_ea), 1):
            if instruction_index % 256 == 0:
                _report_progress(
                    progress,
                    f"Inspecting NVIC wrappers in {idc.get_func_name(func.start_ea) or hex(func.start_ea)}",
                )
            if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
                continue
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                continue
            mnemonic = idc.print_insn_mnem(ea).lower()
            if mnemonic.startswith("str") and insn.ops[1].type in (ida_ua.o_displ, ida_ua.o_phrase):
                memory = insn.ops[1]
                base_reg = _printed_memory_base_register(ea, 1)
                base = regs.get(base_reg) if base_reg is not None else None
                if isinstance(base, int):
                    displacement = int(memory.addr) if memory.type == ida_ua.o_displ else 0
                    if displacement & 0x80000000:
                        displacement -= 0x100000000
                    address = (base + displacement) & 0xFFFFFFFF
                else:
                    address = None
                if mnemonic.startswith("strb"):
                    width = 8
                elif mnemonic.startswith("strh"):
                    width = 16
                elif mnemonic.startswith("strd"):
                    width = 64
                else:
                    width = 32 if mnemonic.startswith("str") else 0
                operation = nvic_operation_for_store(address, width) if address is not None else None
                if operation is not None:
                    operations.add(operation)

            previous_regs = dict(regs)
            if (mnemonic in ("movw", "movt", "mov", "movs")
                    and insn.ops[0].type == ida_ua.o_reg):
                destination = int(insn.ops[0].reg)
                source = insn.ops[1]
                if source.type == ida_ua.o_imm:
                    value = int(source.value)
                    if mnemonic == "movw":
                        regs[destination] = value & 0xFFFF
                    elif mnemonic == "movt":
                        low = previous_regs.get(destination)
                        regs[destination] = (
                            (low & 0xFFFF) | ((value & 0xFFFF) << 16)
                            if isinstance(low, int) else None
                        )
                    else:
                        regs[destination] = value & 0xFFFFFFFF
                elif source.type == ida_ua.o_reg and mnemonic in ("mov", "movs"):
                    value = previous_regs.get(int(source.reg))
                    if isinstance(value, int):
                        regs[destination] = value
                    else:
                        regs.pop(destination, None)
            elif mnemonic.startswith("ldr") and insn.ops[0].type == ida_ua.o_reg:
                values = _literal_constants(ea)
                destination = int(insn.ops[0].reg)
                if len(values) == 1:
                    regs[destination] = next(iter(values))
                else:
                    regs.pop(destination, None)
            else:
                feature = insn.get_canon_feature()
                for op_index, flag_name in enumerate(("CF_CHG1", "CF_CHG2", "CF_CHG3")):
                    flag = getattr(ida_idp, flag_name, 0)
                    if flag and feature & flag and insn.ops[op_index].type == ida_ua.o_reg:
                        regs.pop(int(insn.ops[op_index].reg), None)
            if len(operations) > 1:
                break
        if len(operations) == 1:
            summaries[func.start_ea] = next(iter(operations))
    return summaries


def scan_mmio_with_cfg(model: DeviceModel, progress=None) -> Tuple[List[MMIOAccess], Dict[int, Dict[int, CFGBlock]], List[InterruptConfigEvent], List[str]]:
    """Recover direct references and bounded Cortex-M register constants.

    This CFG dataflow tracks bounded constants, three mask registers, and a
    narrow set of proven constant-branch conditions. It intersects facts at
    joins, forgets register facts across unknown calls, and does not carry
    general path predicates. It resolves rendered base-plus-index
    LSL operands only when both register values are constant; unsupported
    addressing modes and dynamic indices remain unresolved. A separate bounded
    pass recognizes direct or indexed stores through a rendered constant NVIC
    base as heuristic summaries for callers; indexed bounds are not recovered.
    """
    found = {}
    cfg_by_function: Dict[int, Dict[int, CFGBlock]] = {}
    interrupt_config = {}
    scan_warnings: List[str] = []
    scan_warning_count = 0
    functions = list(idautils.Functions())
    nvic_summaries = _nvic_helper_summaries(progress=progress)
    for function_index, function_ea in enumerate(functions, 1):
        _report_progress(progress, f"Recovering MMIO and mask state ({function_index}/{len(functions)} functions)")
        func = ida_funcs.get_func(function_ea)
        if func is None:
            continue
        func_start = func.start_ea
        func_name = idc.get_func_name(func_start) or f"sub_{func_start:X}"
        blocks = list(ida_gdl.FlowChart(func, flags=ida_gdl.FC_NOEXT))
        if not blocks:
            continue
        entry = min(blocks, key=lambda block: block.start_ea)
        iteration_limit = max(8, len(blocks) * 8)
        block_visits = [0]
        pruned_edges = {}
        conditional_branches = {}
        flag_conditions = {
            "beq", "bne", "bmi", "bpl", "bvs", "bvc", "bcs", "bhs",
            "bcc", "blo", "bhi", "bls", "bge", "blt", "bgt", "ble",
        }
        for block_index, candidate_block in enumerate(blocks, 1):
            if block_index % 128 == 0:
                _report_progress(
                    progress,
                    f"Indexing constant-branch candidates in {func_name} ({block_index}/{len(blocks)} blocks)",
                )
            successors = list(candidate_block.succs())
            if len(successors) < 2:
                continue
            code_instructions = []
            for candidate_ea in idautils.Heads(
                    candidate_block.start_ea, candidate_block.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(candidate_ea)):
                    continue
                candidate_insn = ida_ua.insn_t()
                if ida_ua.decode_insn(candidate_insn, candidate_ea):
                    code_instructions.append((candidate_ea, candidate_insn))
            if not code_instructions:
                continue
            branch_ea, branch_insn = code_instructions[-1]
            mnemonic = idc.print_insn_mnem(branch_ea).lower()
            if mnemonic not in ("cbz", "cbnz") and mnemonic not in flag_conditions:
                continue
            target_operand = 1 if mnemonic in ("cbz", "cbnz") else 0
            target_ea = int(idc.get_operand_value(branch_ea, target_operand))
            target_block = next((item for item in blocks
                                 if item.start_ea <= target_ea < item.end_ea), None)
            if target_block is None or target_block.id not in {item.id for item in successors}:
                continue
            if mnemonic in ("cbz", "cbnz"):
                if branch_insn.ops[0].type != ida_ua.o_reg:
                    continue
                conditional_branches[candidate_block.id] = {
                    "kind": "zero",
                    "mnemonic": mnemonic,
                    "register": int(branch_insn.ops[0].reg),
                    "register_name": idc.print_operand(branch_ea, 0)
                    or f"r{int(branch_insn.ops[0].reg)}",
                    "target_block_id": target_block.id,
                }
                continue
            if len(code_instructions) < 2:
                continue
            _, compare_insn = code_instructions[-2]
            compare_ea = code_instructions[-2][0]
            comparison_mnemonic = idc.print_insn_mnem(compare_ea).lower()
            if (comparison_mnemonic not in ("cmp", "cmn", "tst", "teq", "adds", "subs")
                    or compare_insn.ops[0].type != ida_ua.o_reg):
                continue
            if any(idc.print_insn_mnem(item_ea).lower().startswith("it")
                   for item_ea, _ in code_instructions[:-1]):
                continue
            disassembly_line = ida_lines.tag_remove(
                idc.generate_disasm_line(compare_ea, 0) or ""
            )
            disassembly_mnemonic = (disassembly_line.strip().split(None, 1) or [""])[0].lower()
            if re.fullmatch(
                    r"(?:cmp|cmn|tst|teq)\.?(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.w)?",
                    disassembly_mnemonic):
                continue
            if (comparison_mnemonic in ("tst", "teq")
                    and mnemonic not in ("beq", "bne", "bmi", "bpl")):
                continue
            result_register = None
            rhs_operand_index = 1
            if comparison_mnemonic in ("adds", "subs"):
                result_register = int(compare_insn.ops[0].reg)
                if compare_insn.ops[2].type != ida_ua.o_void:
                    source_operand = compare_insn.ops[1]
                    rhs = compare_insn.ops[2]
                    source_operand_index = 1
                    rhs_operand_index = 2
                else:
                    source_operand = compare_insn.ops[0]
                    rhs = compare_insn.ops[1]
                    source_operand_index = 0
                if source_operand.type != ida_ua.o_reg:
                    continue
                source_name = idc.print_operand(compare_ea, source_operand_index)
                source_register = int(source_operand.reg)
                source_registers = _rendered_operand_registers(
                    compare_ea, source_operand_index
                )
                rhs_registers = _rendered_operand_registers(
                    compare_ea, rhs_operand_index
                )
                # The destination contains the post-operation value at the
                # branch. If it also supplies a shift amount, the original
                # comparison operands cannot be reconstructed safely.
                source_shift_registers = source_registers[1:]
                if (result_register in source_shift_registers
                        or result_register in rhs_registers):
                    continue
            else:
                source_operand_index = 0
                source_register = int(compare_insn.ops[0].reg)
                source_name = idc.print_operand(compare_ea, 0)
                rhs = compare_insn.ops[1]
            if rhs.type not in (ida_ua.o_imm, ida_ua.o_reg):
                continue
            conditional_branches[candidate_block.id] = {
                "kind": "arm-flags",
                "operation": (
                    "cmn" if comparison_mnemonic == "adds"
                    else "cmp" if comparison_mnemonic == "subs"
                    else comparison_mnemonic
                ),
                "source_operation": comparison_mnemonic,
                "mnemonic": mnemonic,
                "register": source_register,
                "register_name": source_name or f"r{source_register}",
                "compare_ea": compare_ea,
                "source_operand_index": source_operand_index,
                "rhs_operand_index": rhs_operand_index,
                "rhs_name": idc.print_operand(compare_ea, rhs_operand_index),
                "target_block_id": target_block.id,
                "result_register": result_register,
            }

        def branch_edge_decision(predecessor, successor, outgoing_state):
            branch = conditional_branches.get(predecessor.id)
            if branch is None:
                return None
            mnemonic = branch["mnemonic"]
            target_block_id = branch["target_block_id"]
            register = branch["register"]
            value = outgoing_state[0].get(register)
            if not isinstance(value, int):
                return None
            if branch["kind"] == "zero":
                branch_taken = value == 0 if mnemonic == "cbz" else value != 0
                condition = "equals zero" if mnemonic == "cbz" else "is nonzero"
                reason = (
                    f"{mnemonic.upper()} {branch['register_name']} with propagated value "
                    f"0x{value:X} ({condition})"
                )
            else:
                compare_insn = ida_ua.insn_t()
                if not ida_ua.decode_insn(compare_insn, branch["compare_ea"]):
                    return None
                registers = outgoing_state[0]
                source_index = branch["source_operand_index"]
                rhs_index = branch["rhs_operand_index"]
                value = _constant_operand_value(
                    branch["compare_ea"], source_index,
                    compare_insn.ops[source_index], registers,
                )
                rhs = _constant_operand_value(
                    branch["compare_ea"], rhs_index,
                    compare_insn.ops[rhs_index], registers,
                )
                if not isinstance(value, int) or not isinstance(rhs, int):
                    return None
                value &= 0xFFFFFFFF
                rhs &= 0xFFFFFFFF
                operation = branch["operation"]
                result_register = branch.get("result_register")
                if result_register is not None:
                    result = outgoing_state[0].get(result_register)
                    if not isinstance(result, int):
                        return None
                    result &= 0xFFFFFFFF
                    if register == result_register:
                        value = ((result - rhs) if operation == "cmn"
                                 else (result + rhs)) & 0xFFFFFFFF
                    expected_result = (
                        (value + rhs) if operation == "cmn" else (value - rhs)
                    ) & 0xFFFFFFFF
                    if expected_result != result:
                        return None
                if operation == "cmp":
                    flag_result = (value - rhs) & 0xFFFFFFFF
                elif operation == "cmn":
                    flag_result = (value + rhs) & 0xFFFFFFFF
                elif operation == "tst":
                    flag_result = value & rhs
                elif operation == "teq":
                    flag_result = value ^ rhs
                else:
                    return None
                zero = flag_result == 0
                negative = bool(flag_result & 0x80000000)
                condition_values = {
                    "beq": zero,
                    "bne": not zero,
                    "bmi": negative,
                    "bpl": not negative,
                }
                flag_summary = f"N={int(negative)}, Z={int(zero)}"
                if operation in ("cmp", "cmn"):
                    if operation == "cmp":
                        carry = value >= rhs
                        overflow = bool(((value ^ rhs) & (value ^ flag_result)) & 0x80000000)
                    else:
                        total = value + rhs
                        carry = total > 0xFFFFFFFF
                        overflow = bool((~(value ^ rhs) & (value ^ flag_result)) & 0x80000000)
                    signed_ge = negative == overflow
                    flag_summary += f", C={int(carry)}, V={int(overflow)}"
                    condition_values.update({
                        "bvs": overflow,
                        "bvc": not overflow,
                        "bcs": carry,
                        "bhs": carry,
                        "bcc": not carry,
                        "blo": not carry,
                        "bhi": carry and not zero,
                        "bls": not carry or zero,
                        "bge": signed_ge,
                        "blt": not signed_ge,
                        "bgt": not zero and signed_ge,
                        "ble": zero or not signed_ge,
                    })
                if mnemonic not in condition_values:
                    return None
                branch_taken = condition_values[mnemonic]
                reason = (
                    f"{branch.get('source_operation', operation).upper()} {branch['register_name']}={value:#x} with "
                    f"{branch['rhs_name']}={rhs:#x} gives result {flag_result:#x} "
                    f"({flag_summary}), "
                    f"followed by {mnemonic.upper()}"
                )
            keep_edge = (successor.id == target_block_id) == branch_taken
            return keep_edge, reason

        def edge_filter(predecessor, successor, outgoing_state):
            decision = branch_edge_decision(predecessor, successor, outgoing_state)
            if decision is None:
                return True
            keep_edge, reason = decision
            if not keep_edge:
                pruned_edges[(predecessor.start_ea, successor.start_ea)] = reason
            return keep_edge

        def transfer(block, state):
            block_visits[0] += 1
            if block_visits[0] % 64 == 0:
                _report_progress(
                    progress,
                    f"Propagating CFG state in {func_name} ({block_visits[0]} block visits)",
                )
            return _transfer_block(
                block, state, model, func_start, func_name, progress=progress
            )[0:3]

        in_states, out_states, converged, iterations = _propagate_cfg_states(
            blocks, entry.id, transfer,
            iteration_limit=iteration_limit,
            edge_filter=edge_filter,
        )
        use_path_feasibility = converged
        if not converged:
            scan_warning_count += 1
            if len(scan_warnings) < MAX_SCAN_WARNINGS:
                scan_warnings.append(
                    f"Edge-sensitive CFG propagation for {func_name} at 0x{func_start:X} "
                    f"did not converge within {iteration_limit} passes; rerunning without "
                    "conditional branch pruning."
                )
            pruned_edges.clear()
            use_path_feasibility = False
            in_states, out_states, converged, iterations = _propagate_cfg_states(
                blocks, entry.id, transfer, iteration_limit=iteration_limit
            )
            if not converged:
                scan_warning_count += 1
                if len(scan_warnings) < MAX_SCAN_WARNINGS:
                    scan_warnings.append(
                        f"Conservative CFG propagation for {func_name} at 0x{func_start:X} "
                        f"reached its {iteration_limit}-iteration limit after {iterations} "
                        "pass(es); access and mask facts may be incomplete."
                    )
        if use_path_feasibility:
            pruned_edges.clear()
        for block in blocks:
            if block.id == entry.id or in_states[block.id] is None:
                continue
            predecessor_states = []
            for predecessor in block.preds():
                state = out_states[predecessor.id]
                if state is None:
                    continue
                if use_path_feasibility and not edge_filter(predecessor, block, state):
                    continue
                predecessor_states.append((predecessor, state))
            if len(predecessor_states) < 2:
                continue
            for mask_name in ("primask", "basepri", "faultmask"):
                values = [state[1].get(mask_name) for _, state in predecessor_states]
                if all(value == values[0] for value in values[1:]) or not any(
                        isinstance(value, int) for value in values):
                    continue
                rendered_values = ", ".join(
                    f"0x{predecessor.start_ea:X}="
                    f"{'unknown' if value is None else f'0x{value:X}'}"
                    for (predecessor, _), value in zip(predecessor_states, values)
                )
                scan_warning_count += 1
                if len(scan_warnings) < MAX_SCAN_WARNINGS:
                    scan_warnings.append(
                        f"Mask state for {mask_name.upper()} becomes unknown at CFG block "
                        f"0x{block.start_ea:X} in {func_name}: predecessor states are "
                        f"{rendered_values}."
                    )
        reachable_ids = {block.id for block in blocks if in_states[block.id] is not None}
        cfg_by_function[func_start] = {
            block.start_ea: CFGBlock(
                start_ea=block.start_ea,
                end_ea=block.end_ea,
                successors=tuple(sorted(
                    successor.start_ea for successor in block.succs()
                    if successor.id in reachable_ids
                    and (not use_path_feasibility
                         or edge_filter(block, successor, out_states[block.id]))
                )),
            )
            for block in blocks if block.id in reachable_ids
        }
        for (source_ea, target_ea), reason in sorted(pruned_edges.items()):
            scan_warning_count += 1
            if len(scan_warnings) < MAX_SCAN_WARNINGS:
                scan_warnings.append(
                    f"Path feasibility in {func_name} pruned CFG edge "
                    f"0x{source_ea:X} -> 0x{target_ea:X}: {reason}."
                )
        for block in blocks:
            incoming = in_states[block.id]
            if incoming is None:
                continue
            _, _, _, accesses, config_events = _transfer_block(
                block, incoming, model, func_start, func_name, collect=True,
                nvic_summaries=nvic_summaries, progress=progress,
            )
            for access in accesses:
                found[(access.ea, access.register.address)] = access
            for event in config_events:
                interrupt_config[(event.ea, event.irq_number, event.operation)] = event
    if scan_warning_count > MAX_SCAN_WARNINGS:
        scan_warnings.append(
            f"{scan_warning_count - MAX_SCAN_WARNINGS} additional CFG scan warnings were omitted."
        )
    return (
        sorted(found.values(), key=lambda item: (item.register.address, item.ea)),
        cfg_by_function,
        sorted(interrupt_config.values(), key=lambda item: (item.irq_number, item.ea)),
        scan_warnings,
    )


def scan_mmio(model: DeviceModel) -> List[MMIOAccess]:
    """Compatibility helper when callers do not need control-flow evidence."""
    return scan_mmio_with_cfg(model)[0]
