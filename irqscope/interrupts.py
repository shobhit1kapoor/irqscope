"""Pure Cortex-M interrupt API semantics used by the IDA adapter."""

from .model import InterruptConfigEvent, PriorityAssessment


def mask_effect_for_call(callee: str):
    """Classify known CMSIS calls without confusing per-IRQ NVIC control with masks.

    Returns ``(operation, mask_name)`` where operation is ``set``, ``clear``,
    ``assign``, or ``per-irq``. Unknown helpers return ``None`` so callers can
    conservatively discard mask facts.
    """
    name = (callee or "").lower().split("@", 1)[0]
    leaf = name.split("::")[-1].split(".")[-1]
    if leaf == "__disable_irq":
        return "set", "primask"
    if leaf == "__enable_irq":
        return "clear", "primask"
    if leaf == "__disable_fault_irq":
        return "set", "faultmask"
    if leaf == "__enable_fault_irq":
        return "clear", "faultmask"
    if leaf in ("__set_primask", "__set_basepri", "__set_faultmask"):
        return "assign", leaf.removeprefix("__set_")
    # CMSIS and common vendor wrappers change one interrupt or its priority;
    # none of these is equivalent to setting PRIMASK/BASEPRI/FAULTMASK.
    if leaf.startswith(("nvic_", "__nvic_", "hal_nvic_", "tz_nvic_")):
        if any(token in leaf for token in ("enableirq", "disableirq", "setpriority", "clearpending", "setpending")):
            return "per-irq", ""
    return None


def nvic_event_for_call(callee: str):
    """Return the abstract action for recognized per-IRQ CMSIS API calls."""
    name = (callee or "").lower().split("@", 1)[0]
    leaf = name.split("::")[-1].split(".")[-1]
    prefixes = ("nvic_", "__nvic_", "hal_nvic_", "tz_nvic_")
    if not leaf.startswith(prefixes):
        return None
    if leaf.endswith("enableirq"):
        return "enable"
    if leaf.endswith("disableirq"):
        return "disable"
    if leaf.endswith("setpriority"):
        return "set-priority"
    if leaf.endswith("setpendingirq"):
        return "set-pending"
    if leaf.endswith("clearpendingirq"):
        return "clear-pending"
    return None


def normalize_mask_value(mask_name: str, value: int) -> int:
    """Apply the architectural register width to a known integer value."""
    width = 8 if mask_name == "basepri" else 1
    return int(value) & ((1 << width) - 1)


def assess_basepri_priority(irq_number: int, basepri, priority_bits, events):
    """Compare one static CMSIS priority hint with an observed BASEPRI value.

    The result is deliberately conditional: API callsites do not establish
    that a priority write executes or remains effective at the access.
    """
    priority_events = tuple(
        event for event in events
        if isinstance(event, InterruptConfigEvent)
        and event.irq_number == irq_number
        and event.operation == "set-priority"
    )
    callsite_eas = tuple(sorted(event.ea for event in priority_events))
    if basepri is None:
        return PriorityAssessment(
            "unknown", irq_number, priority_bits, callsite_eas=callsite_eas,
            detail="BASEPRI is unknown at the foreground access.",
        )
    basepri &= 0xFF
    if basepri == 0:
        return PriorityAssessment(
            "basepri-clear", irq_number, priority_bits, basepri_threshold=0,
            callsite_eas=callsite_eas,
            detail="BASEPRI is zero at this access and does not mask configurable interrupts.",
        )
    if not isinstance(priority_bits, int) or not 1 <= priority_bits <= 8:
        return PriorityAssessment(
            "unknown", irq_number, callsite_eas=callsite_eas,
            detail="The SVD does not provide a valid NVIC priority-bit count.",
        )
    if not priority_events:
        return PriorityAssessment(
            "unknown", irq_number, priority_bits, callsite_eas=callsite_eas,
            detail="No static CMSIS NVIC_SetPriority callsite is available for this IRQ.",
        )
    priorities = {event.priority for event in priority_events}
    if None in priorities or len(priorities) != 1:
        return PriorityAssessment(
            "unknown", irq_number, priority_bits, callsite_eas=callsite_eas,
            detail="Static priority callsites are missing an encoded argument or disagree.",
        )
    logical_priority = next(iter(priorities))
    max_priority = (1 << priority_bits) - 1
    if not isinstance(logical_priority, int) or not 0 <= logical_priority <= max_priority:
        return PriorityAssessment(
            "unknown", irq_number, priority_bits, logical_priority=logical_priority,
            callsite_eas=callsite_eas,
            detail=f"Static CMSIS priority is outside the SVD's 0..{max_priority} logical range.",
        )
    shift = 8 - priority_bits
    implemented_mask = max_priority << shift
    threshold = basepri & implemented_mask
    encoded_priority = logical_priority << shift
    if threshold == 0:
        return PriorityAssessment(
            "basepri-clear", irq_number, priority_bits, logical_priority,
            encoded_priority, threshold, callsite_eas,
            "BASEPRI has no implemented priority bits set at this access.",
        )
    if encoded_priority >= threshold:
        status = "conditional-basepri-block"
        relation = "same or lower urgency than the BASEPRI threshold"
    else:
        status = "conditional-basepri-permit"
        relation = "higher urgency than the BASEPRI threshold"
    return PriorityAssessment(
        status, irq_number, priority_bits, logical_priority, encoded_priority,
        threshold, callsite_eas,
        f"If the static priority callsite is effective, priority 0x{encoded_priority:02X} is {relation} 0x{threshold:02X}; runtime NVIC state is unproven.",
    )


def nvic_operation_for_store(address: int, width_bits: int):
    """Classify writes through a constant Cortex-M NVIC register base."""
    address = int(address) & 0xFFFFFFFF
    width_bits = int(width_bits)
    if (0xE000E100 <= address < 0xE000E180
            and (address - 0xE000E100) % 4 == 0 and width_bits == 32):
        return "enable"
    if (0xE000E180 <= address < 0xE000E200
            and (address - 0xE000E180) % 4 == 0 and width_bits == 32):
        return "disable"
    if 0xE000E400 <= address < 0xE000E800 and width_bits == 8:
        return "set-priority"
    return None
