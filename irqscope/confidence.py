"""Evidence-tier explanations for findings; deliberately no numeric score."""


def confidence_vector(finding):
    """Return auditable evidence dimensions derived only from stored analysis facts."""
    accesses = (finding.first, finding.second)
    aliases = any(access.register_aliases for access in accesses)
    address_evidence = sorted({access.evidence for access in accesses if access.evidence})
    address = (
        "ambiguous" if aliases else
        "direct" if address_evidence and all(item == "absolute-memory-operand" for item in address_evidence) else
        "constant-propagated" if address_evidence and all(
            item in {"absolute-memory-operand", "constant-base-register"} for item in address_evidence
        ) else
        "unclassified"
    )

    if finding.preemption_state == "blocked-at-foreground-access":
        preemption = "blocked-at-selected-point"
        preemption_limit = "An IRQ is blocked at this observed instruction only; other insertion points and full-operation coverage are unknown."
    elif finding.preemption_state == "mask-registers-permit-configurable-irq":
        preemption = "possible-under-model"
        preemption_limit = "The mask model permits configurable interrupt delivery; effective NVIC enable state and the complete priority relation remain unknown."
    else:
        preemption = "unknown"
        preemption_limit = "IRQ enable state, effective priority, and mask coverage are not established."
    setup_events = tuple(getattr(finding, "interrupt_configuration", ()))
    preemption_evidence = finding.preemption_state
    if setup_events:
        preemption_evidence += f"; {len(setup_events)} static NVIC setup callsite(s) linked"
    priority_assessment = getattr(finding, "priority_assessment", None)
    if priority_assessment is not None:
        preemption_evidence += f"; conditional priority result={priority_assessment.status}"
        if priority_assessment.detail:
            preemption_evidence += f" ({priority_assessment.detail})"
        preemption_limit += (
            " Static priority arguments and SVD priority-bit counts do not prove that the callsite "
            "executes, remains effective, or reflects priority grouping at this access."
        )

    if finding.protocol_name:
        transaction = "analyst-declared"
        transaction_limit = "The transaction boundary comes from a user-authored contract and may omit device behavior."
    else:
        transaction = "not-recovered"
        transaction_limit = "The access pair does not establish a complete peripheral operation boundary."

    register = finding.register
    semantic_detail = []
    if register.read_action:
        semantic_detail.append(f"readAction={register.read_action}")
    if register.modified_write_values:
        semantic_detail.append(f"modifiedWriteValues={register.modified_write_values}")
    field_effects = [field for field in register.fields if field.modified_write_values]
    if field_effects:
        rendered_effects = [
            f"{field.name}={field.modified_write_values}" for field in field_effects[:4]
        ]
        if len(field_effects) > 4:
            rendered_effects.append(f"+{len(field_effects) - 4} fields")
        semantic_detail.append("field modifiedWriteValues=" + ", ".join(rendered_effects))
    if (finding.write_effect_relation is not None
            and finding.first.value is not None and finding.second.value is not None):
        relation_label = (
            "commuting full-width writes" if finding.write_effect_relation.final_state_transforms_commute
            else "order-dependent full-width writes"
        )
        semantic_detail.append(
            f"{relation_label}={finding.first.value:#x}/{finding.second.value:#x}"
        )
    if register.fields:
        semantic_detail.append(f"{len(register.fields)} field(s)")
    if finding.write_effect_relation is not None:
        if finding.write_effect_relation.final_state_transforms_commute:
            semantics = "modeled-commutative-write-effects"
            semantics_limit = (
                "Commutativity covers exact full-width constants under supported register-level or complete "
                "field-level SVD modifiedWriteValues semantics, or ordinary SVD default assignment when "
                "there is no field map or its writable field map is complete; intermediate "
                "observations, hardware updates between stores, undocumented, and revision-specific effects remain unknown."
            )
        else:
            semantics = "modeled-order-dependent-write-effects"
            semantics_limit = (
                "Order dependence covers exact full-width constants under supported register-level or complete "
                "field-level SVD modifiedWriteValues semantics, or ordinary SVD default assignment when "
                "there is no field map or its writable field map is complete; execution, interrupt "
                "timing, intermediate observations, hardware evolution, and revision-specific effects remain unknown."
            )
    else:
        semantics = "described-by-svd" if semantic_detail else "register-described-by-svd"
        semantics_limit = (
            "Device semantics are imported descriptions and have not been checked against the target device revision."
        )

    witness = finding.witness
    if witness and witness.foreground_resume and witness.block_path:
        feasibility = "cfg-path-recovered"
        feasibility_limit = (
            "The path uses only constant CBZ/CBNZ plus common CMP/CMN/ADDS/SUBS flag conditions and TST/TEQ zero/sign conditions with operands resolved by the bounded constant resolver, including supported shifted-register forms; "
            "other predicates and runtime reachability are not proven."
        )
    elif witness:
        feasibility = "cross-context-pair-only"
        feasibility_limit = "No foreground resume path is present in this witness."
    else:
        feasibility = "no-witness"
        feasibility_limit = "Only the finding's paired accesses are available; no interleaving path was recovered."

    return [
        {"dimension": "address", "tier": address,
         "evidence": ", ".join(address_evidence) or "register mapping",
         "limit": "SVD address aliases remain unresolved." if aliases else "Address recovery does not prove the runtime pointer history."},
        {"dimension": "context", "tier": "cross-function-access-pair",
         "evidence": f"{finding.first.function_name} ↔ {finding.second.function_name}",
         "limit": "Function identity does not prove the vector table or runtime call reachability."},
        {"dimension": "preemption", "tier": preemption,
         "evidence": preemption_evidence, "limit": preemption_limit},
        {"dimension": "transaction", "tier": transaction,
         "evidence": finding.protocol_name or "no explicit transaction contract",
         "limit": transaction_limit},
        {"dimension": "semantics", "tier": semantics,
         "evidence": ", ".join(semantic_detail) or "register address and width from SVD",
         "limit": semantics_limit},
        {"dimension": "feasibility", "tier": feasibility,
         "evidence": witness.status if witness else "no witness",
         "limit": feasibility_limit},
    ]
