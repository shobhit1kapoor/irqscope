"""Conservative finding rules over recovered MMIO evidence."""

from collections import deque
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .model import (
    AnalysisCancelled, CFGBlock, Finding, InterleavingWitness, MMIOAccess,
    WriteEffectRelation,
)
from .interrupts import assess_basepri_priority


def _shortest_block_path(start: MMIOAccess, target: MMIOAccess,
                         cfg: Mapping[int, CFGBlock]) -> Optional[Tuple[int, ...]]:
    start_block = start.block_start_ea
    target_block = target.block_start_ea
    if start_block is None or target_block is None or start_block not in cfg or target_block not in cfg:
        return None
    if start_block == target_block:
        if target.ea > start.ea:
            return (start_block,)
        # A repeated instruction EA is a distinct dynamic event only when a
        # recovered CFG cycle returns to its block.
        queue = deque()
        visited = set()
        for successor in cfg[start_block].successors:
            path = (start_block, successor)
            if successor == start_block:
                return path
            if successor in cfg and successor not in visited:
                visited.add(successor)
                queue.append((successor, path))
        while queue:
            current, path = queue.popleft()
            for successor in cfg[current].successors:
                if successor == start_block:
                    return path + (start_block,)
                if successor in cfg and successor not in visited:
                    visited.add(successor)
                    queue.append((successor, path + (successor,)))
        return None

    queue = deque([(start_block, (start_block,))])
    visited = {start_block}
    while queue:
        current, path = queue.popleft()
        for successor in cfg[current].successors:
            if successor == target_block:
                return path + (successor,)
            if successor in cfg and successor not in visited:
                visited.add(successor)
                queue.append((successor, path + (successor,)))
    return None


def _shortest_entry_path(target: MMIOAccess,
                         cfg: Mapping[int, CFGBlock]) -> Tuple[int, ...]:
    target_block = target.block_start_ea
    if target_block is None or target_block not in cfg or not cfg:
        return ()
    entry = min(cfg)
    if entry == target_block:
        return (entry,)
    queue = deque([(entry, (entry,))])
    visited = {entry}
    while queue:
        current, path = queue.popleft()
        for successor in cfg[current].successors:
            if successor == target_block:
                return path + (successor,)
            if successor in cfg and successor not in visited:
                visited.add(successor)
                queue.append((successor, path + (successor,)))
    return ()


def _build_interleaving_witness(foreground: MMIOAccess, interrupt: MMIOAccess,
                                accesses: Sequence[MMIOAccess],
                                cfg_by_function: Mapping[int, Mapping[int, CFGBlock]],
                                preemption_state: str) -> InterleavingWitness:
    cfg = cfg_by_function.get(foreground.function_ea, {})
    reachable = []
    for candidate in accesses:
        if candidate.function_ea != foreground.function_ea:
            continue
        if candidate.register.peripheral != foreground.register.peripheral or candidate.ea == foreground.ea:
            continue
        path = _shortest_block_path(foreground, candidate, cfg)
        if path is None:
            continue
        intra_block_distance = candidate.ea - foreground.ea if len(path) == 1 else 0
        reachable.append(((len(path), intra_block_distance, candidate.ea), candidate, path))
    resume = None
    block_path: Tuple[int, ...] = ()
    if reachable:
        _, resume, block_path = min(reachable, key=lambda item: item[0])

    interrupt_cfg = cfg_by_function.get(interrupt.function_ea, {})
    interrupt_block_path = _shortest_entry_path(interrupt, interrupt_cfg)
    interrupt_block_rank = {ea: index for index, ea in enumerate(interrupt_block_path)}
    interrupt_prefix = tuple(sorted(
        (
            access for access in accesses
            if access.function_ea == interrupt.function_ea
            and access.register.peripheral == interrupt.register.peripheral
            and access.block_start_ea in interrupt_block_rank
            and (access.block_start_ea != interrupt.block_start_ea or access.ea < interrupt.ea)
        ),
        key=lambda access: (interrupt_block_rank[access.block_start_ea], access.ea),
    ))

    if preemption_state == "blocked-at-foreground-access":
        status = "blocked-at-observed-insertion-point"
        explanation = (
            "PRIMASK or FAULTMASK is known set at the selected foreground access, so this witness "
            "does not schedule an external IRQ at that exact point. The pair may require another "
            "insertion point; the full operation boundary is not known."
        )
    elif resume is not None:
        status = "candidate-insertion-sketch"
        explanation = (
            "A later observed MMIO event in the same function is CFG-reachable from the foreground "
            "access. The ISR event is inserted between those observations as a candidate schedule. "
            f"The handler prefix contains {len(interrupt_prefix)} observed same-peripheral MMIO event(s) "
            "along its shortest recovered CFG path. "
            "This is not a proof that the IRQ is enabled, has sufficient priority, or violates a "
            "confirmed peripheral protocol."
        )
    else:
        status = "cross-context-pair-no-resume-path"
        explanation = (
            "No later same-peripheral MMIO event with a recovered CFG path was found in this "
            "foreground function, so IRQScope can show only the cross-context access pair."
        )
    return InterleavingWitness(
        status=status,
        foreground_start=foreground,
        interrupt_event=interrupt,
        foreground_resume=resume,
        block_path=block_path,
        interrupt_block_path=interrupt_block_path,
        interrupt_prefix=interrupt_prefix,
        explanation=explanation,
    )


def _write_effect_definition(effect):
    normalized = "".join(character for character in effect.lower() if character.isalnum())
    return {
        "onetoclear": ("clear", True),
        "zerotoclear": ("clear", False),
        "onetoset": ("set", True),
        "zerotoset": ("set", False),
        "onetotoggle": ("toggle", True),
        "zerototoggle": ("toggle", False),
    }.get(normalized)


def _modeled_write_transform(access: MMIOAccess, register):
    """Return per-bit operations and their active mask for a modeled write.

    A register-level effect applies to the whole word. With no explicit write
    effect, ordinary assignment is modeled for a writable register with no
    field map or a complete writable field map. Field-level side effects are
    accepted only when non-overlapping fields cover every bit.
    """
    if access.operation != "write" or access.value is None:
        return None
    if (not isinstance(register.access, str)
            or register.access.lower() not in {"write-only", "read-write"}):
        return None
    width = register.size_bits
    if width <= 0 or width > 128 or access.width_bits != width:
        return None
    width_mask = (1 << width) - 1
    value = access.value & width_mask
    register_effect = (
        _write_effect_definition(register.modified_write_values)
        if isinstance(register.modified_write_values, str) else None
    )
    fields_inherit_register_effect = all(
        isinstance(field.access, str)
        and field.access.lower() in {"write-only", "read-write"}
        and (
            not field.modified_write_values
            or (isinstance(field.modified_write_values, str)
                and _write_effect_definition(field.modified_write_values) == register_effect)
        )
        for field in register.fields
    )
    if register_effect is not None and fields_inherit_register_effect:
        operation, active_on_ones = register_effect
        active_mask = value if active_on_ones else (~value & width_mask)
        return (operation,) * width, active_mask, "register"

    # The SVD default for an explicitly writable register with no special
    # write effect is an ordinary assignment. Accept that model only when no
    # unsupported register/field side effect or partial field map is present.
    has_register_write_effect = bool(register.modified_write_values)
    has_field_write_effect = any(field.modified_write_values for field in register.fields)
    if not has_register_write_effect and not has_field_write_effect:
        if not register.fields:
            return ("assign",) * width, width_mask, "register-default"
        covered_mask = 0
        for field in register.fields:
            offset = field.bit_offset
            field_width = field.bit_width
            if (not isinstance(field.access, str)
                    or field.access.lower() not in {"write-only", "read-write"}
                    or not isinstance(offset, int) or not isinstance(field_width, int)
                    or offset < 0 or field_width <= 0 or offset + field_width > width):
                return None
            field_mask = ((1 << field_width) - 1) << offset
            if covered_mask & field_mask:
                return None
            covered_mask |= field_mask
        if covered_mask == width_mask:
            return ("assign",) * width, width_mask, "register-default"

    if not register.fields:
        return None
    operations = [None] * width
    covered_mask = 0
    active_mask = 0
    for field in register.fields:
        offset = field.bit_offset
        field_width = field.bit_width
        if (not isinstance(field.access, str)
                or field.access.lower() not in {"write-only", "read-write"}
                or not isinstance(field.modified_write_values, str)
                or not isinstance(offset, int) or not isinstance(field_width, int)
                or offset < 0 or field_width <= 0 or offset + field_width > width):
            return None
        decoded = _write_effect_definition(field.modified_write_values)
        if decoded is None:
            return None
        field_mask = ((1 << field_width) - 1) << offset
        if covered_mask & field_mask:
            return None
        covered_mask |= field_mask
        operation, active_on_ones = decoded
        field_value = (value >> offset) & ((1 << field_width) - 1)
        field_active = field_value if active_on_ones else (~field_value & ((1 << field_width) - 1))
        active_mask |= field_active << offset
        for bit in range(offset, offset + field_width):
            operations[bit] = operation
    if covered_mask != width_mask:
        return None
    return tuple(operations), active_mask, "fields"


def _write_effect_relation(register, interrupt_access: MMIOAccess,
                           foreground_access: MMIOAccess, alias_uncertain: bool):
    """Compare exact full-word writes under supported SVD semantics."""
    if alias_uncertain:
        return None
    interrupt_transform = _modeled_write_transform(interrupt_access, register)
    foreground_transform = _modeled_write_transform(foreground_access, register)
    if interrupt_transform is None or foreground_transform is None:
        return None
    interrupt_operations, interrupt_mask, interrupt_scope = interrupt_transform
    foreground_operations, foreground_mask, foreground_scope = foreground_transform
    if interrupt_scope != foreground_scope:
        return None
    overlap = interrupt_mask & foreground_mask
    conflict_mask = 0
    for bit in range(register.size_bits):
        bit_mask = 1 << bit
        if not overlap & bit_mask:
            continue
        if interrupt_operations[bit] != foreground_operations[bit]:
            conflict_mask |= bit_mask
        elif (interrupt_operations[bit] == "assign"
              and bool(interrupt_access.value & bit_mask)
              != bool(foreground_access.value & bit_mask)):
            conflict_mask |= bit_mask
    return WriteEffectRelation(
        scope=interrupt_scope,
        width_bits=register.size_bits,
        interrupt_operations_by_bit=interrupt_operations,
        interrupt_active_mask=interrupt_mask,
        foreground_operations_by_bit=foreground_operations,
        foreground_active_mask=foreground_mask,
        overlap_mask=overlap,
        conflict_mask=conflict_mask,
        final_state_transforms_commute=not bool(conflict_mask),
    )


def build_candidate_findings(accesses: Sequence[MMIOAccess],
                             interrupt_functions: Mapping[int, int],
                             cfg_by_function: Optional[Mapping[int, Mapping[int, CFGBlock]]] = None,
                             interrupt_configuration=(), progress=None,
                             nvic_priority_bits: Optional[int] = None) -> List[Finding]:
    """Flag review candidates where an ISR and non-ISR both touch one register.

    This is deliberately a triage heuristic, not a race proof: it uses
    per-access mask snapshots but does not establish complete transaction
    coverage, NVIC enable/priority state, or path feasibility.
    """
    grouped = {}
    cfg_by_function = cfg_by_function or {}
    configuration_by_irq = {}
    for event in interrupt_configuration:
        configuration_by_irq.setdefault(event.irq_number, []).append(event)
    for access in accesses:
        grouped.setdefault(access.register.address, []).append(access)

    findings = []
    seen = set()
    pair_count = 0
    for address, group in grouped.items():
        isr_accesses = [access for access in group if access.function_ea in interrupt_functions]
        foreground_accesses = [access for access in group if access.function_ea not in interrupt_functions]
        if not isr_accesses or not foreground_accesses:
            continue
        access_order = {id(access): index for index, access in enumerate(group)}
        for isr in isr_accesses:
            for foreground in foreground_accesses:
                pair_count += 1
                if pair_count % 128 == 0 and progress is not None and progress(
                    f"Building cross-context candidates ({pair_count} access pairs)",
                ):
                    raise AnalysisCancelled("cross-context candidate generation")
                left, right = ((isr, foreground)
                               if access_order[id(isr)] < access_order[id(foreground)]
                               else (foreground, isr))
                isr_slot = interrupt_functions[isr.function_ea]
                reg = isr.register
                if isr_slot < 16:
                    continue
                irq_number = isr_slot - 16
                setup_for_irq = tuple(configuration_by_irq.get(irq_number, ()))
                priority_assessment = assess_basepri_priority(
                    irq_number, foreground.basepri, nvic_priority_bits, setup_for_irq
                )
                if foreground.primask == 1 or foreground.faultmask == 1:
                    preemption_state = "blocked-at-foreground-access"
                elif foreground.primask == 0 and foreground.faultmask == 0 and foreground.basepri == 0:
                    preemption_state = "mask-registers-permit-configurable-irq"
                elif foreground.basepri not in (None, 0):
                    preemption_state = "basepri-priority-relation-unknown"
                else:
                    preemption_state = "mask-state-unknown"
                register_descriptions = (
                    [reg, isr.register, foreground.register]
                    + list(isr.register_aliases) + list(foreground.register_aliases)
                )
                alias_names = sorted({item.display_name for item in register_descriptions if item != reg})
                alias_uncertain = bool(alias_names)
                read_effects = {
                    effect.lower()
                    for item in register_descriptions
                    for effect in ([item.read_action] + [field.read_action for field in item.fields])
                    if effect
                }
                write_effects = {
                    effect.lower()
                    for item in register_descriptions
                    for effect in ([item.modified_write_values] + [field.modified_write_values for field in item.fields])
                    if effect
                }
                destructive_reads = read_effects & {"clear", "modify", "modifyexternal", "set"}
                write_side_effects = write_effects & {
                    "onetoclear", "onetoggle", "onetoset", "zerotoclear", "zerotoggle", "zerotoset", "clear", "set"
                }
                write_effect_relation = None
                if isr.operation == "write" and foreground.operation == "write":
                    write_effect_relation = _write_effect_relation(
                        reg, isr, foreground, alias_uncertain
                    )
                write_semantics_parts = []
                if reg.modified_write_values:
                    write_semantics_parts.append(
                        f"register modifiedWriteValues={reg.modified_write_values}"
                    )
                field_effects = [field for field in reg.fields if field.modified_write_values]
                if field_effects:
                    rendered_field_effects = [
                        f"{field.name}:{field.modified_write_values}"
                        for field in field_effects[:8]
                    ]
                    if len(field_effects) > 8:
                        rendered_field_effects.append(f"+{len(field_effects) - 8} fields")
                    write_semantics_parts.append(
                        "field modifiedWriteValues=" + ", ".join(rendered_field_effects)
                    )
                write_semantics = "; ".join(write_semantics_parts)
                if (write_effect_relation is not None
                        and write_effect_relation.scope == "register-default"):
                    write_semantics = "SVD default full-register assignment semantics"
                if destructive_reads and isr.operation == "read":
                    rule = "IRQSCOPE.DESTRUCTIVE_READ_CROSS_CONTEXT"
                    if preemption_state == "blocked-at-foreground-access":
                        title = "Destructive read candidate; IRQ blocked at foreground access"
                        severity = "low"
                    elif alias_uncertain:
                        title = "Destructive read candidate; SVD aliases are ambiguous"
                        severity = "medium"
                    else:
                        title = "Destructive peripheral read crosses execution contexts"
                        severity = "high"
                    explanation = (
                        f"{isr.function_name} reads {reg.display_name}, whose SVD description "
                        f"reports readAction '{reg.read_action or ', '.join(sorted(destructive_reads))}'. "
                        f"{foreground.function_name} also accesses this register. "
                        "The handler's read may alter state that the foreground operation expects to observe "
                        "if an eligible preemption occurs within that operation."
                    )
                elif (write_effect_relation is not None
                      and write_effect_relation.final_state_transforms_commute):
                    rule = "IRQSCOPE.COMMUTATIVE_SVD_WRITE_EFFECTS"
                    title = "Modeled cross-context writes commute"
                    severity = "low"
                    interrupt_effects = "/".join(sorted(set(
                        write_effect_relation.interrupt_operations_by_bit
                    )))
                    foreground_effects = "/".join(sorted(set(
                        write_effect_relation.foreground_operations_by_bit
                    )))
                    explanation = (
                        f"{isr.function_name} and {foreground.function_name} write "
                        f"{reg.display_name} with recovered full-width constants under "
                        f"{write_semantics}. The modeled {write_effect_relation.scope}-scope "
                        f"{interrupt_effects}/{foreground_effects} transforms "
                        f"{'overlap only on identically transformed bits' if write_effect_relation.overlap_mask else 'affect disjoint bit sets'}, "
                        "so their modeled final-state transforms commute under these SVD semantics. "
                        "Intermediate observations, hardware updates between stores, and other device "
                        "effects are not modeled; this is not proof of complete device behavior."
                    )
                elif write_effect_relation is not None:
                    rule = "IRQSCOPE.CONFLICTING_SVD_WRITE_EFFECTS"
                    title = "Modeled writes are order-dependent on overlapping bits"
                    severity = "medium" if preemption_state == "blocked-at-foreground-access" else "high"
                    explanation = (
                        f"{isr.function_name} and {foreground.function_name} write "
                        f"{reg.display_name} with recovered full-width constants under "
                        f"{write_semantics}. Their modeled transforms disagree on overlapping "
                        f"bits 0x{write_effect_relation.conflict_mask:X}, so the final register state depends on "
                        "write order under this SVD model. This is a semantic conflict candidate, "
                        "not proof that both paths execute or that an interrupt occurs between them."
                    )
                elif "write" in (isr.operation, foreground.operation):
                    rule = "IRQSCOPE.CROSS_CONTEXT_WRITE_SIDE_EFFECT" if write_side_effects else "IRQSCOPE.CROSS_CONTEXT_REGISTER_WRITE"
                    title = "Cross-context write has register side effects" if write_side_effects else "Cross-context register write needs review"
                    severity = "medium" if alias_uncertain or not write_side_effects else "high"
                    explanation = (
                        f"{isr.function_name} and {foreground.function_name} access "
                        f"{reg.display_name}, and at least one access writes it. "
                        + (f"The SVD describes write semantics {', '.join(sorted(write_side_effects))}. " if write_side_effects else "")
                        + "This is an access "
                        "overlap candidate only; IRQScope has not established that the paths can "
                        "overlap or that their effects conflict."
                    )
                else:
                    continue
                if foreground.primask == 1:
                    explanation += (
                        " At the foreground access, PRIMASK is known to be 1, which blocks external "
                        "interrupts at that instruction. This access-level observation does not prove "
                        "that the entire inferred operation is protected."
                    )
                elif foreground.primask == 0:
                    explanation += " PRIMASK is known to be 0 at the foreground access; NVIC enable and priority remain unknown."
                if foreground.basepri not in (None, 0):
                    explanation += f" BASEPRI is known as 0x{foreground.basepri:X}; its relation to the effective IRQ priority remains conditional."
                explanation += " Conditional priority evidence: " + priority_assessment.detail
                key = (rule, address, min(left.ea, right.ea), max(left.ea, right.ea))
                if key in seen:
                    continue
                seen.add(key)
                assumptions = (
                    "The vector table and handler mapping are correct.",
                    "The SVD register semantics are accurate for this device revision.",
                    "Simple PRIMASK/BASEPRI/FAULTMASK state is tracked within recovered paths; NVIC enable, effective priority grouping, callsite reachability, and full operation coverage are not established.",
                    "A BASEPRI priority comparison, when available, uses static CMSIS callsite arguments and is conditional rather than an effective runtime-state claim.",
                ) + (("Multiple SVD descriptions share this address; the active peripheral/register alias is unresolved.",)
                     if alias_uncertain else ())
                if write_effect_relation is not None:
                    assumptions += (
                        "The write comparison uses exact full-width constants under a supported register/field modifiedWriteValues rule or ordinary assignment semantics with complete writable-field coverage; undocumented hardware effects are outside this model.",
                    )
                witness = _build_interleaving_witness(
                    foreground, isr, accesses, cfg_by_function, preemption_state
                )
                explanation += " " + witness.explanation
                findings.append(Finding(
                    rule_id=rule,
                    title=title,
                    severity=severity,
                    confidence="candidate",
                    address=address,
                    register=reg,
                    first=left,
                    second=right,
                    explanation=explanation,
                    assumptions=assumptions,
                    preemption_state=preemption_state,
                    witness=witness,
                    interrupt_configuration=tuple(sorted(
                        setup_for_irq, key=lambda event: event.ea
                    )),
                    priority_assessment=priority_assessment,
                    write_effect_relation=write_effect_relation,
                ))
    return sorted(findings, key=lambda item: (item.severity != "high", item.address, item.first.ea))
