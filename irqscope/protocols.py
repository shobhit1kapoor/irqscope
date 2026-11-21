"""Analyst-authored peripheral transaction contracts and bounded matching."""

from dataclasses import dataclass, replace
from collections import defaultdict
import hashlib
import json
from typing import Mapping, Optional, Sequence, Tuple

from .analysis import _build_interleaving_witness, _shortest_block_path
from .model import (
    AnalysisCancelled, CFGBlock, DeviceModel, Finding, InterruptConfigEvent, MMIOAccess,
)


PROTOCOL_FORMAT = "irqscope-protocol-v1"
MAX_PROTOCOL_BYTES = 1 * 1024 * 1024
MAX_TRANSACTIONS = 256
MAX_EVENTS_PER_TRANSACTION = 32
MAX_CANDIDATE_SEQUENCES = 128
MAX_PROTOCOL_FINDINGS = 10_000
MAX_DRAFT_INTERFERENCE_EVENTS = 32


def build_protocol_draft(proposal, interrupt_accesses: Sequence[MMIOAccess]):
    """Create an editable protocol contract draft from observed event evidence.

    The output is importable but deliberately does not assert that either the
    foreground sequence or handler accesses describe a true device protocol.
    """
    if not proposal.events or len(proposal.events) < 2:
        raise ValueError("A protocol draft requires at least two foreground events")
    if len(proposal.events) > MAX_EVENTS_PER_TRANSACTION:
        raise ValueError("The selected sequence exceeds the protocol step limit")
    interference: list[dict[str, object]] = []
    seen = set()
    ordered_accesses = sorted(interrupt_accesses, key=lambda item: (item.ea, item.function_ea))
    interference_truncated = False
    for index, access in enumerate(ordered_accesses):
        if access.register.peripheral != proposal.peripheral:
            continue
        exact_write_value = (
            access.value
            if access.operation == "write" and access.value is not None
            and access.width_bits == access.register.size_bits else None
        )
        pattern = (access.register.display_name, access.operation, exact_write_value)
        if pattern in seen:
            continue
        seen.add(pattern)
        interference_event: dict[str, object] = {
            "register": access.register.display_name,
            "operation": access.operation,
            "reason": (
                f"Observed in {access.function_name} at 0x{access.ea:X}; "
                "review handler path and device semantics before relying on this pattern."
            ),
        }
        if exact_write_value is not None:
            interference_event["value"] = exact_write_value
        interference.append(interference_event)
        if len(interference) >= MAX_DRAFT_INTERFERENCE_EVENTS:
            interference_truncated = any(
                (following.register.display_name, following.operation,
                 following.value if following.operation == "write"
                 and following.value is not None
                 and following.width_bits == following.register.size_bits else None) not in seen
                and following.register.peripheral == proposal.peripheral
                for following in ordered_accesses[index + 1:]
            )
            break
    if not interference:
        raise ValueError(
            f"No mapped interrupt-handler MMIO events were observed for {proposal.peripheral}"
        )
    proposal_id = proposal.proposal_id[:16]
    description = (
        f"Editable draft from heuristic sequence proposal {proposal.proposal_id}. "
        "Confirm the transaction boundary, event order, branch feasibility, and "
        "device semantics against source and the reference manual before analysis. "
        "Exact write values are included only when static analysis recovered a full-width constant; "
        "edit them if they should not constrain the contract."
    )
    if interference_truncated:
        description += (
            f" The interference list is capped at {MAX_DRAFT_INTERFERENCE_EVENTS} "
            "unique observed handler patterns; additional patterns may be omitted."
        )
    return {
        "format": PROTOCOL_FORMAT,
        "name": f"IRQScope draft {proposal_id}",
        "transactions": [{
            "name": f"candidate-{proposal_id}",
            "peripheral": proposal.peripheral,
            "description": description,
            "interference_mode": "any",
            "steps": [
                {
                    "register": event.register.display_name,
                    "operation": event.operation,
                    **({"value": event.value}
                       if event.operation == "write" and event.value is not None
                       and event.width_bits == event.register.size_bits else {}),
                }
                for event in proposal.events
            ],
            "interference": interference,
        }],
    }


@dataclass(frozen=True)
class ProtocolEvent:
    register: str
    operation: str
    reason: str = ""
    value: Optional[int] = None
    value_mask: Optional[int] = None
    value_label: Optional[str] = None


@dataclass(frozen=True)
class TransactionProtocol:
    name: str
    peripheral: str
    steps: Tuple[ProtocolEvent, ...]
    interference: Tuple[ProtocolEvent, ...]
    description: str = ""
    interference_mode: str = "any"


@dataclass(frozen=True)
class ProtocolModel:
    name: str
    source: str
    source_sha256: str
    transactions: Tuple[TransactionProtocol, ...]


@dataclass(frozen=True)
class ProtocolAnalysisResult:
    findings: Tuple[Finding, ...]
    truncation_reasons: Tuple[str, ...] = ()


def _event(value, device: DeviceModel, peripheral: str, context: str) -> ProtocolEvent:
    if not isinstance(value, dict):
        raise ValueError(f"{context} must be an object")
    register = value.get("register")
    operation = value.get("operation")
    reason = value.get("reason", "")
    expected_value = value.get("value")
    expected_mask = value.get("value_mask")
    field_name = value.get("field")
    enumeration_name = value.get("enumeration")
    if not isinstance(register, str) or not register.strip():
        raise ValueError(f"{context}.register must be a non-empty register name")
    if operation not in ("read", "write"):
        raise ValueError(f"{context}.operation must be 'read' or 'write'")
    if not isinstance(reason, str) or len(reason) > 2000:
        raise ValueError(f"{context}.reason must be text up to 2000 characters")
    value = register.strip()
    matches = [reg for reg in device.all_registers()
               if reg.peripheral == peripheral and (reg.display_name == value or reg.name == value)]
    distinct = {reg.display_name for reg in matches}
    if not matches:
        raise ValueError(f"{context} references unknown register {value!r} in {peripheral}")
    if len(distinct) != 1:
        raise ValueError(f"{context} register {value!r} is ambiguous in {peripheral}")
    register_name = next(iter(distinct))
    matching_registers = [register for register in matches
                          if register.display_name == register_name]
    widths = {register.size_bits for register in matching_registers}
    if len(widths) != 1:
        raise ValueError(f"{context} register {value!r} has ambiguous widths")
    width = next(iter(widths))
    width_mask = (1 << width) - 1
    value_label = None
    if field_name is not None or enumeration_name is not None:
        if (operation != "write" or not isinstance(field_name, str) or not field_name.strip()
                or not isinstance(enumeration_name, str) or not enumeration_name.strip()
                or expected_value is not None or expected_mask is not None):
            raise ValueError(
                f"{context}.field and .enumeration must identify a write enum and cannot be combined with value/value_mask"
            )
        enum_resolutions = set()
        for register in matching_registers:
            register_matches = set()
            for field in register.fields:
                if field.name != field_name.strip():
                    continue
                if (not isinstance(field.access, str)
                        or field.access.lower() not in {"write-only", "read-write"}):
                    continue
                for value_set in field.enumerated_values:
                    if value_set.usage not in {"write", "read-write"}:
                        continue
                    for enum_value in value_set.values:
                        if (enum_value.name == enumeration_name.strip()
                                and not enum_value.is_default
                                and isinstance(enum_value.value, int)
                                and isinstance(enum_value.mask, int)):
                            field_mask = (1 << field.bit_width) - 1
                            if (field.bit_offset < 0 or field.bit_width <= 0
                                    or enum_value.value & ~field_mask
                                    or enum_value.mask <= 0
                                    or enum_value.mask & ~field_mask
                                    or enum_value.value & ~enum_value.mask):
                                continue
                            register_matches.add((
                                (enum_value.value << field.bit_offset),
                                (enum_value.mask << field.bit_offset),
                            ))
            if len(register_matches) != 1:
                raise ValueError(
                    f"{context} SVD enumeration {field_name.strip()}={enumeration_name.strip()} "
                    "is missing or ambiguous in a same-name register description"
                )
            enum_resolutions.update(register_matches)
        resolved_values = enum_resolutions
        if len(resolved_values) != 1:
            raise ValueError(
                f"{context} SVD enumeration {field_name.strip()}={enumeration_name.strip()} is ambiguous"
            )
        expected_value, expected_mask = next(iter(resolved_values))
        value_label = f"{field_name.strip()}={enumeration_name.strip()}"
        if expected_mask & ~width_mask:
            raise ValueError(f"{context} SVD enumeration mask exceeds its register width")
    if expected_value is not None:
        if (operation != "write" or isinstance(expected_value, bool)
                or not isinstance(expected_value, int)
                or expected_value < 0 or expected_value & ~width_mask):
            raise ValueError(
                f"{context}.value must be a non-negative write value that fits the {width}-bit register"
            )
    if expected_mask is not None:
        if (expected_value is None or isinstance(expected_mask, bool)
                or not isinstance(expected_mask, int) or expected_mask <= 0
                or expected_mask & ~width_mask
                or expected_value & ~expected_mask):
            raise ValueError(
                f"{context}.value_mask requires value and must select non-zero in-range bits"
            )
    return ProtocolEvent(
        register_name, operation, reason.strip(), expected_value, expected_mask,
        value_label,
    )


def parse_protocol(path: str, device: DeviceModel) -> ProtocolModel:
    """Load and validate a versioned protocol contract against an SVD model."""
    try:
        with open(path, "rb") as source:
            raw = source.read(MAX_PROTOCOL_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Cannot read protocol contract: {exc}") from exc
    if not raw or len(raw) > MAX_PROTOCOL_BYTES:
        raise ValueError(f"Protocol file must be between 1 byte and {MAX_PROTOCOL_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"Invalid protocol JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != PROTOCOL_FORMAT:
        raise ValueError(f"Protocol format must be {PROTOCOL_FORMAT!r}")
    name = data.get("name")
    transactions = data.get("transactions")
    if not isinstance(name, str) or not name.strip() or len(name) > 200:
        raise ValueError("Protocol name must be non-empty text up to 200 characters")
    if not isinstance(transactions, list) or not transactions or len(transactions) > MAX_TRANSACTIONS:
        raise ValueError(f"transactions must contain 1 to {MAX_TRANSACTIONS} entries")
    parsed = []
    seen = set()
    for index, item in enumerate(transactions):
        context = f"transactions[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{context} must be an object")
        tx_name = item.get("name")
        peripheral = item.get("peripheral")
        steps = item.get("steps")
        interference = item.get("interference")
        interference_mode = item.get("interference_mode", "any")
        description = item.get("description", "")
        if not isinstance(tx_name, str) or not tx_name.strip() or len(tx_name) > 200:
            raise ValueError(f"{context}.name must be non-empty text up to 200 characters")
        if tx_name in seen:
            raise ValueError(f"Duplicate transaction name {tx_name!r}")
        seen.add(tx_name)
        if not isinstance(peripheral, str) or not peripheral.strip():
            raise ValueError(f"{context}.peripheral must be non-empty text")
        if not isinstance(description, str) or len(description) > 4000:
            raise ValueError(f"{context}.description must be text up to 4000 characters")
        if not isinstance(steps, list) or len(steps) < 2 or len(steps) > MAX_EVENTS_PER_TRANSACTION:
            raise ValueError(f"{context}.steps must contain 2 to {MAX_EVENTS_PER_TRANSACTION} events")
        if not isinstance(interference, list) or not interference or len(interference) > MAX_EVENTS_PER_TRANSACTION:
            raise ValueError(f"{context}.interference must contain 1 to {MAX_EVENTS_PER_TRANSACTION} events")
        if interference_mode not in ("any", "sequence"):
            raise ValueError(f"{context}.interference_mode must be 'any' or 'sequence'")
        parsed.append(TransactionProtocol(
            name=tx_name.strip(), peripheral=peripheral.strip(),
            steps=tuple(_event(event, device, peripheral.strip(), f"{context}.steps[{i}]")
                        for i, event in enumerate(steps)),
            interference=tuple(_event(event, device, peripheral.strip(), f"{context}.interference[{i}]")
                               for i, event in enumerate(interference)),
            interference_mode=interference_mode,
            description=description.strip(),
        ))
    return ProtocolModel(name.strip(), path, hashlib.sha256(raw).hexdigest(), tuple(parsed))


def _matches(access: MMIOAccess, event: ProtocolEvent) -> bool:
    if access.operation != event.operation:
        return False
    registers = (access.register,) + tuple(access.register_aliases)
    matching_register = next(
        (register for register in registers if register.display_name == event.register),
        None,
    )
    if matching_register is None:
        return False
    if event.value is None:
        return True
    if access.value is None:
        return False
    mask = event.value_mask or ((1 << matching_register.size_bits) - 1)
    if mask & ~((1 << access.width_bits) - 1):
        return False
    return (access.value & mask) == (event.value & mask)


def _transaction_sequences(events: Sequence[MMIOAccess], transaction: TransactionProtocol,
                           cfg: Mapping[int, CFGBlock], progress=None):
    by_step = [[access for access in events if _matches(access, event)]
               for event in transaction.steps]
    if any(not choices for choices in by_step):
        return [], False
    sequences: list[tuple[Tuple[MMIOAccess, ...], Tuple[Tuple[int, ...], ...]]] = []
    truncated = [False]
    explored = [0]

    def walk(step_index: int, chain: Tuple[MMIOAccess, ...], paths: Tuple[Tuple[int, ...], ...]):
        if len(sequences) >= MAX_CANDIDATE_SEQUENCES:
            truncated[0] = True
            return
        if step_index == len(by_step):
            sequences.append((chain, paths))
            return
        previous = chain[-1]
        for access in by_step[step_index]:
            explored[0] += 1
            if (explored[0] % 128 == 0 and progress is not None
                    and progress(f"Matching protocol {transaction.name} ({explored[0]} event extensions)")):
                raise AnalysisCancelled("protocol sequence matching")
            if access.function_ea != previous.function_ea:
                continue
            path = _shortest_block_path(previous, access, cfg)
            if path is not None:
                walk(step_index + 1, chain + (access,), paths + (path,))

    for first_index, first in enumerate(by_step[0]):
        walk(1, (first,), ())
        if len(sequences) >= MAX_CANDIDATE_SEQUENCES:
            if first_index + 1 < len(by_step[0]):
                truncated[0] = True
            break
    return sequences, truncated[0]


def build_protocol_findings(protocol: ProtocolModel, device: DeviceModel,
                            accesses: Sequence[MMIOAccess], interrupt_functions: Mapping[int, int],
                            cfg_by_function: Mapping[int, Mapping[int, CFGBlock]],
                            interrupt_configuration=(), progress=None) -> ProtocolAnalysisResult:
    """Find CFG-reachable declared transactions with matching ISR interference."""
    unique: dict[tuple[object, ...], Finding] = {}
    truncation_reasons = []
    configuration_by_irq: dict[int, list[InterruptConfigEvent]] = {}
    for event in interrupt_configuration:
        configuration_by_irq.setdefault(event.irq_number, []).append(event)
    accesses_by_function_peripheral = defaultdict(list)
    foreground_functions_by_peripheral = defaultdict(set)
    for access_index, access in enumerate(accesses, 1):
        if access_index % 512 == 0 and progress is not None and progress(
            f"Indexing protocol evidence ({access_index}/{len(accesses)} accesses)",
        ):
            raise AnalysisCancelled("protocol evidence indexing")
        key = (access.function_ea, access.register.peripheral)
        accesses_by_function_peripheral[key].append(access)
        if access.function_ea not in interrupt_functions:
            foreground_functions_by_peripheral[access.register.peripheral].add(access.function_ea)
    for transaction_index, transaction in enumerate(protocol.transactions, 1):
        if progress is not None and progress(
            f"Matching protocol contracts ({transaction_index}/{len(protocol.transactions)})",
        ):
            raise AnalysisCancelled("protocol contract matching")
        functions = sorted(foreground_functions_by_peripheral.get(transaction.peripheral, ()))
        for function_index, function_ea in enumerate(functions, 1):
            if progress is not None and progress(
                f"Checking foreground paths for {transaction.name} ({function_index}/{len(functions)})",
            ):
                raise AnalysisCancelled("protocol foreground matching")
            function_events = accesses_by_function_peripheral.get(
                (function_ea, transaction.peripheral), []
            )
            sequences, sequence_search_truncated = _transaction_sequences(
                function_events, transaction, cfg_by_function.get(function_ea, {}), progress
            )
            if sequence_search_truncated:
                truncation_reasons.append(
                    f"Protocol {transaction.name!r} reached the {MAX_CANDIDATE_SEQUENCES}-sequence per-function search cap; additional candidates may be omitted."
                )
            if not sequences:
                continue
            interrupt_chains = []
            handlers = sorted(interrupt_functions)
            for handler_index, handler_ea in enumerate(handlers, 1):
                if progress is not None and progress(
                    f"Checking handler interference for {transaction.name} ({handler_index}/{len(handlers)})",
                ):
                    raise AnalysisCancelled("protocol handler matching")
                handler_events = accesses_by_function_peripheral.get(
                    (handler_ea, transaction.peripheral), []
                )
                if transaction.interference_mode == "sequence":
                    interrupt_transaction = replace(transaction, steps=transaction.interference)
                    chains, truncated = _transaction_sequences(
                        handler_events, interrupt_transaction,
                        cfg_by_function.get(handler_ea, {}), progress,
                    )
                    if truncated:
                        truncation_reasons.append(
                            f"Protocol {transaction.name!r} reached the {MAX_CANDIDATE_SEQUENCES}-sequence per-handler interference search cap; additional candidates may be omitted."
                        )
                    interrupt_chains.extend(chains)
                else:
                    interrupt_chains.extend(
                        ((access,), ()) for access in handler_events
                        if any(_matches(access, event) for event in transaction.interference)
                    )
            matched_pairs = 0
            for chain, paths in sequences:
                start = chain[0]
                insertion_options = []
                for insertion_index, access in enumerate(chain[:-1]):
                    if access.primask == 1 or access.faultmask == 1:
                        preemption_state = "blocked-at-foreground-access"
                        rank = 2
                    elif (access.primask == 0 and access.faultmask == 0
                          and access.basepri == 0):
                        preemption_state = "mask-registers-permit-configurable-irq"
                        rank = 0
                    elif access.basepri not in (None, 0):
                        preemption_state = "basepri-priority-relation-unknown"
                        rank = 1
                    else:
                        preemption_state = "mask-state-unknown"
                        rank = 1
                    insertion_options.append((rank, insertion_index, preemption_state))
                _, insertion_index, preemption_state = min(insertion_options)
                insertion = chain[insertion_index]
                resume = chain[insertion_index + 1]
                for interrupt_chain, interrupt_paths in interrupt_chains:
                    matched_pairs += 1
                    if (matched_pairs % 128 == 0 and progress is not None
                            and progress(f"Building protocol witnesses for {transaction.name} ({matched_pairs} pairs)")):
                        raise AnalysisCancelled("protocol witness construction")
                    interrupt = interrupt_chain[0]
                    witness = _build_interleaving_witness(
                        insertion, interrupt, accesses, cfg_by_function, preemption_state
                    )
                    witness = replace(witness, foreground_resume=resume,
                                      block_path=paths[insertion_index])
                    matched_events = (
                        transaction.interference if transaction.interference_mode == "sequence"
                        else tuple(event for event in transaction.interference
                                   if _matches(interrupt, event))
                    )
                    rationale = " ".join(
                        f"Declared interference: {event.reason}"
                        for event in matched_events if event.reason
                    )
                    enum_constraints = [
                        f"{event.register}.{event.value_label}"
                        for event in transaction.steps + matched_events
                        if event.value_label
                    ]
                    if enum_constraints:
                        rationale += (
                            " SVD command constraints matched: "
                            + ", ".join(enum_constraints) + "."
                        )
                    rationale = f" {rationale}" if rationale else ""
                    assumptions: tuple[str, ...] = (
                        f"Transaction contract {protocol.name!r} is analyst-authored and may not capture all device behavior.",
                        f"The foreground sequence {transaction.name!r} is CFG-reachable in recovered blocks; branch predicates are not checked.",
                        "The candidate insertion gap is selected using the mask snapshot at its preceding observed access; mask changes inside the gap are not proven.",
                        "IRQ enable, priority, active masks across the full transaction, and hardware state evolution are not proven.",
                    )
                    if transaction.description:
                        assumptions += (f"Contract description: {transaction.description}",)
                    finding = Finding(
                        rule_id="IRQSCOPE.PROTOCOL_INTERLEAVING",
                        title=f"Protocol interleaving: {transaction.name}",
                        severity="medium",
                        confidence="analyst-contract-candidate",
                        address=interrupt.register.address,
                        register=interrupt.register,
                        first=start,
                        second=interrupt,
                        explanation=(
                            f"{protocol.name} declares a {transaction.name} transaction in "
                            f"{transaction.peripheral} with {len(chain)} foreground events. "
                            f"{interrupt.function_name} performs {len(interrupt_chain)} declared "
                            "ISR interference event(s) in CFG-reachable order."
                            f"{rationale} {witness.explanation}"
                        ),
                        assumptions=assumptions,
                        preemption_state=preemption_state,
                        witness=witness,
                        protocol_name=transaction.name,
                        protocol_identity=protocol.source_sha256,
                        protocol_interference_mode=transaction.interference_mode,
                        protocol_events=chain,
                        protocol_foreground_paths=paths,
                        protocol_insertion_index=insertion_index,
                        protocol_interrupt_events=interrupt_chain,
                        protocol_interrupt_paths=interrupt_paths,
                        interrupt_configuration=tuple(sorted(
                            configuration_by_irq.get(interrupt_functions[interrupt.function_ea] - 16, ()),
                            key=lambda event: event.ea,
                        )),
                    )
                    finding_key = (finding.protocol_name, finding.first.function_ea, finding.first.ea,
                                   finding.second.function_ea, finding.second.ea,
                                   tuple(item.ea for item in finding.protocol_interrupt_events))
                    unique.setdefault(finding_key, finding)
                    if len(unique) >= MAX_PROTOCOL_FINDINGS:
                        truncation_reasons.append(
                            f"Protocol analysis reached the {MAX_PROTOCOL_FINDINGS}-finding output cap; additional candidates may be omitted."
                        )
                        return ProtocolAnalysisResult(
                            tuple(sorted(unique.values(), key=lambda item: (item.address, item.first.ea, item.second.ea))),
                            tuple(dict.fromkeys(truncation_reasons)),
                        )
    return ProtocolAnalysisResult(
        tuple(sorted(unique.values(), key=lambda item: (item.address, item.first.ea, item.second.ea))),
        tuple(dict.fromkeys(truncation_reasons)),
    )
