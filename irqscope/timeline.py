"""Explicit, conditional timelines for analyst-authored protocol candidates."""


def build_candidate_timeline(finding):
    """Interleave matched contract events at the selected foreground gap.

    The result is a display/export sketch, not a scheduler proof. Event order
    inside each context comes from matched CFG-reachable sequences; the cross-
    context insertion is the analyzer's point-mask-ranked candidate gap.
    """
    foreground = tuple(finding.protocol_events or ())
    interrupt = tuple(finding.protocol_interrupt_events or ())
    insertion = finding.protocol_insertion_index
    if (len(foreground) < 2 or not interrupt or not isinstance(insertion, int)
            or not 0 <= insertion < len(foreground) - 1):
        return None

    steps = []

    def add_step(context, event_index, event, cfg_path=(), path_scope=None):
        steps.append({
            "order": len(steps),
            "context": context,
            "event_index": event_index,
            "event": event,
            "cfg_path": tuple(cfg_path),
            "path_scope": path_scope,
        })

    for index, event in enumerate(foreground):
        path = (finding.protocol_foreground_paths[index]
                if index < len(finding.protocol_foreground_paths) else ())
        add_step("foreground", index, event, path,
                 "to-next-foreground-event" if path else None)
        if index == insertion:
            for interrupt_index, interrupt_event in enumerate(interrupt):
                path_index = interrupt_index - 1
                path = (finding.protocol_interrupt_paths[path_index]
                        if 0 <= path_index < len(finding.protocol_interrupt_paths)
                        else ())
                add_step("interrupt", interrupt_index, interrupt_event, path,
                         "from-previous-interrupt-event" if path else None)

    return {
        "status": "conditional-synchronized-insertion-candidate",
        "insertion_gap": {
            "after_foreground_event_index": insertion,
            "before_foreground_event_index": insertion + 1,
        },
        "mask_snapshot": finding.preemption_state,
        "steps": tuple(steps),
        "limitations": (
            "The foreground transaction and interference pattern are analyst-authored.",
            "Within-context event order follows recovered CFG paths; all branch predicates are not proven.",
            "Cross-context order is a candidate insertion at the selected point mask snapshot, not a verified schedule.",
            "IRQ enable, effective priority, runtime execution, and hardware state evolution remain unknown.",
        ),
    }
