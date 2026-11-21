"""IDA Pro entry point for IRQScope."""

import json
import hashlib
import os
import platform
import sys
import time
from pathlib import Path

import ida_idaapi
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_netnode
import idc

from irqscope.analysis import build_candidate_findings
from irqscope.ida_adapter import detect_vector_tables, read_vector_table, scan_mmio_with_cfg
from irqscope.model import AnalysisCancelled, AnalysisResult
from irqscope.svd import SVDParseError, parse_svd
from irqscope.ui import show_rows
from irqscope.reviews import ReviewLedger, finding_key
from irqscope.protocols import build_protocol_draft, build_protocol_findings, parse_protocol
from irqscope.confidence import confidence_vector
from irqscope.transaction_mining import mine_transaction_proposals
from irqscope.timeline import build_candidate_timeline
from irqscope import __version__ as IRQSCOPE_VERSION


ACTION_IMPORT = "irqscope:import_svd"
ACTION_DETECT = "irqscope:detect_vectors"
ACTION_ANALYZE = "irqscope:analyze"
ACTION_ACCESS = "irqscope:show_accesses"
ACTION_EXPORT = "irqscope:export"
ACTION_DASHBOARD = "irqscope:dashboard"
ACTION_PROTOCOL = "irqscope:import_protocol"
REVIEWS_NODE_NAME = "$ irqscope.review.v1"
REVIEWS_BLOB_TAG = ord("R")

_device = None
_vector_entries = []
_results = AnalysisResult()
_registered = []
_dashboard = None
_reviews = ReviewLedger()
_protocol = None


def _input_identity():
    digest = ida_nalt.retrieve_input_file_sha256()
    if digest:
        return bytes(digest).hex(), "ida-recorded-input-sha256"
    input_path = idc.get_input_file_path()
    if input_path and os.path.isfile(input_path):
        hasher = hashlib.sha256()
        try:
            with open(input_path, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    hasher.update(chunk)
            return hasher.hexdigest(), "input-file-content"
        except OSError:
            pass
    fallback = idc.get_root_filename() or "unknown-input"
    return hashlib.sha256(fallback.encode("utf-8", errors="replace")).hexdigest(), "root-filename-fallback"


def _input_sha256():
    return _input_identity()[0]


def _plugin_source_sha256():
    root = Path(__file__).resolve().parent
    sources = [Path(__file__), *sorted((root / "irqscope").glob("*.py"))]
    digest = hashlib.sha256()
    try:
        for source in sources:
            relative = source.relative_to(root).as_posix().encode("utf-8")
            content = source.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
    except OSError:
        return "unavailable"
    return digest.hexdigest()


def _export_provenance():
    input_sha256, input_hash_basis = _input_identity()
    context = {
        "irqscope_version": IRQSCOPE_VERSION,
        "plugin_source_sha256": _plugin_source_sha256(),
        "ida_kernel_version": ida_kernwin.get_kernel_version() or "unknown",
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "input_sha256": input_sha256,
        "input_hash_basis": input_hash_basis,
        "svd_sha256": _device.source_sha256 if _device else "unknown-svd",
        "protocol_sha256": _protocol.source_sha256 if _protocol else None,
        "vector_mapping": [
            {
                "slot": entry.slot,
                "address": f"0x{entry.address:X}",
                "function_ea": f"0x{entry.function_ea:X}" if entry.function_ea is not None else None,
            }
            for entry in _vector_entries
        ],
    }
    return context


def _review_id(finding):
    return finding_key(_input_sha256(), _device.source_sha256 if _device else "", finding)


def _review_for_finding(finding):
    return _reviews.get(_review_id(finding))


def _proposal_review_id(proposal):
    identity = json.dumps({
        "schema": "irqscope-sequence-proposal-review-v1",
        "input_sha256": _input_sha256(),
        "svd_sha256": _device.source_sha256 if _device else "unknown-svd",
        "proposal_id": proposal.proposal_id,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(identity).hexdigest()


def _review_for_proposal(proposal):
    return _reviews.get(_proposal_review_id(proposal))


def _review_node():
    node = ida_netnode.netnode()
    if not node.create(REVIEWS_NODE_NAME):
        raise RuntimeError("Could not open IRQScope's IDB review netnode")
    return node


def _load_reviews():
    global _reviews
    node = _review_node()
    payload = node.getblob(0, REVIEWS_BLOB_TAG)
    _reviews = ReviewLedger.from_json(payload) if payload else ReviewLedger()


def _persist_reviews(ledger):
    payload = ledger.to_json().encode("utf-8")
    if not _review_node().setblob(payload, 0, REVIEWS_BLOB_TAG):
        raise RuntimeError("IDA could not store the IRQScope review ledger")


def _save_review(index, status, note):
    global _reviews
    if index < 0 or index >= len(_results.findings):
        return
    updated = ReviewLedger.from_json(_reviews.to_json())
    finding = _results.findings[index]
    try:
        updated.set(_review_id(finding), status, note)
        _persist_reviews(updated)
    except (ValueError, RuntimeError, OSError) as exc:
        ida_kernwin.warning(f"IRQScope could not save this review in the IDB:\n{exc}")
        return
    _reviews = updated
    _refresh_dashboard()
    ida_kernwin.msg(f"[IRQScope] Saved {status} review for {finding.title}.\n")


def _save_proposal_review(proposal, status, note):
    global _reviews
    updated = ReviewLedger.from_json(_reviews.to_json())
    try:
        updated.set(_proposal_review_id(proposal), status, note)
        _persist_reviews(updated)
    except (ValueError, RuntimeError, OSError) as exc:
        ida_kernwin.warning(f"IRQScope could not save this sequence review in the IDB:\n{exc}")
        return
    _reviews = updated
    _refresh_dashboard()
    ida_kernwin.msg(f"[IRQScope] Saved {status} sequence review for {proposal.proposal_id}.\n")


def _save_protocol_draft(proposal):
    if _device is None:
        ida_kernwin.warning("Import an SVD before creating a protocol draft.")
        return
    mapped_handlers = {
        entry.function_ea for entry in _vector_entries
        if entry.function_ea is not None and entry.slot >= 16
    }
    handler_accesses = [
        access for access in _results.accesses
        if access.function_ea in mapped_handlers
        and access.function_ea != proposal.function_ea
        and access.register.peripheral == proposal.peripheral
    ]
    try:
        draft = build_protocol_draft(proposal, handler_accesses)
    except ValueError as exc:
        ida_kernwin.warning(f"IRQScope could not create a protocol draft:\n{exc}")
        return
    path = ida_kernwin.ask_file(
        True, "*.json", f"Save protocol contract draft for {proposal.proposal_id}"
    )
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as target:
            json.dump(draft, target, indent=2, sort_keys=True)
            target.write("\n")
    except OSError as exc:
        ida_kernwin.warning(f"IRQScope could not write this protocol draft:\n{exc}")
        return
    ida_kernwin.msg(
        f"[IRQScope] Saved editable protocol draft to {path}. "
        "Verify its sequence and interference assumptions before importing it.\n"
    )


def _jump(ea):
    ida_kernwin.jumpto(ea)


def _dashboard_state():
    return _device, list(_vector_entries), _results


def _refresh_dashboard():
    if _dashboard is not None:
        try:
            _dashboard.refresh()
        except Exception as exc:
            ida_kernwin.msg(f"[IRQScope] Dashboard refresh failed: {exc}\n")


def _open_dashboard():
    global _dashboard
    if _dashboard is None:
        try:
            from irqscope.dashboard import IRQScopeDashboard
            _dashboard = IRQScopeDashboard(
                _dashboard_state,
                {"import": _import_svd, "vectors": _detect_vectors,
                 "analyze": _analyze, "export": _export,
                 "protocol": _import_protocol,
                 "protocol_provider": lambda: _protocol,
                 "review": _save_review, "review_provider": _review_for_finding,
                 "proposal_review": _save_proposal_review,
                 "proposal_review_provider": _review_for_proposal,
                 "protocol_draft": _save_protocol_draft},
                _jump,
            )
        except Exception as exc:
            ida_kernwin.warning(f"IRQScope could not initialize its dockable dashboard:\n{exc}")
            return
    try:
        _dashboard.Show("IRQScope", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        _refresh_dashboard()
    except Exception as exc:
        ida_kernwin.warning(f"IRQScope could not open its dockable dashboard:\n{exc}")


class _Action(ida_kernwin.action_handler_t):
    def __init__(self, callback):
        ida_kernwin.action_handler_t.__init__(self)
        self.callback = callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def _register_action(name, label, callback, tooltip):
    desc = ida_kernwin.action_desc_t(
        name,
        label,
        _Action(callback),
        None,
        tooltip,
        -1,
    )
    if ida_kernwin.register_action(desc):
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", name, ida_kernwin.SETMENU_APP)
        _registered.append(name)


def _import_svd():
    global _device, _results, _protocol
    path = ida_kernwin.ask_file(False, "*.svd", "Import a local CMSIS-SVD device description")
    if not path:
        return
    try:
        model = parse_svd(path)
    except SVDParseError as exc:
        ida_kernwin.warning(f"IRQScope could not import this SVD:\n{exc}")
        return
    _device = model
    _protocol = None
    # Findings are tied to the imported device contract. Do not leave stale
    # analysis rows visible after the analyst switches SVDs.
    _results = AnalysisResult()
    _results.vectors = list(_vector_entries)
    _refresh_dashboard()
    ida_kernwin.msg(f"[IRQScope] Loaded {model.name}: {model.register_count} registers from {model.source}\n")
    rows = []
    for reg in sorted(model.all_registers(), key=lambda item: (item.address, item.display_name)):
        field_names = ", ".join(field.name for field in reg.fields) or "—"
        reset_summary = (
            f"0x{reg.reset_value:X} / "
            f"{f'0x{reg.reset_mask:X}' if reg.reset_mask is not None else 'mask unspecified'}"
            if reg.reset_value is not None else
            (f"mask 0x{reg.reset_mask:X}; value unspecified"
             if reg.reset_mask is not None else "—")
        )
        write_constraint = (
            f"range 0x{reg.write_constraint.minimum:X}..0x{reg.write_constraint.maximum:X}"
            if reg.write_constraint is not None and reg.write_constraint.kind == "range" else
            (reg.write_constraint.kind if reg.write_constraint is not None else "—")
        )
        rows.append((f"0x{reg.address:08X}", reg.display_name, f"{reg.size_bits}", reg.access,
                     reset_summary, write_constraint, field_names,
                     reg.read_action or "—", reg.modified_write_values or "—"))
    show_rows("IRQScope — Device Register Map", [
        ["Address", 12], ["Peripheral.Register", 32], ["Bits", 6], ["Access", 12],
        ["Reset value / known mask", 24], ["Write constraint", 24], ["Fields", 30],
        ["Read side effect", 18], ["Write side effect", 22]
    ], rows)


def _detect_vectors():
    global _vector_entries
    candidates = detect_vector_tables()
    if not candidates:
        ida_kernwin.warning("IRQScope did not find a plausible Cortex-M vector table. You can still analyze MMIO with an SVD.")
        return
    rows = []
    for candidate in candidates:
        rows.append((f"0x{candidate.address:08X}", f"0x{candidate.initial_sp:08X}",
                     f"0x{candidate.reset_handler:08X}", str(candidate.mapped_handlers),
                     f"{candidate.score:.2f}"))
    def choose(index):
        global _vector_entries
        candidate = candidates[index]
        entries = read_vector_table(candidate.address)
        missing = [entry for entry in entries if entry.slot > 1 and entry.function_ea is None]
        created = 0
        if missing and ida_kernwin.ask_yn(
            ida_kernwin.ASKBTN_YES,
            f"{len(missing)} vector targets are not IDA functions. Create function boundaries at these confirmed handler entries?",
        ) == ida_kernwin.ASKBTN_YES:
            for entry in missing:
                if ida_funcs.add_func(entry.address):
                    created += 1
        _vector_entries = read_vector_table(candidate.address)
        _results.vectors = list(_vector_entries)
        _refresh_dashboard()
        mapped = [entry for entry in _vector_entries if entry.function_ea is not None]
        vector_rows = [(str(entry.slot), entry.name, f"0x{entry.address:08X}",
                        idc.get_func_name(entry.function_ea) if entry.function_ea is not None else "unmapped")
                       for entry in _vector_entries]
        ida_kernwin.msg(
            f"[IRQScope] Selected vector table at 0x{candidate.address:X}; "
            f"{len(mapped)} entries map to IDA functions; {created} function boundaries created.\n"
        )
        show_rows("IRQScope — Confirmed Vector Entries", [
            ["Slot", 6], ["Exception", 24], ["Handler EA", 14], ["IDA function", 32]
        ], vector_rows, on_select=lambda row: _jump(_vector_entries[row].address))
    show_rows("IRQScope — Cortex-M Vector Table Candidates", [
        ["Table", 14], ["Initial SP", 14], ["Reset handler", 16], ["Mapped", 8], ["Rank", 8]
    ], rows, on_select=choose)


def _analyze():
    global _results
    if _device is None:
        ida_kernwin.warning("Import a CMSIS-SVD file first. Without a device model IRQScope cannot name register accesses.")
        return False
    working = AnalysisResult()
    working.vectors = list(_vector_entries)
    isrs = {entry.function_ea: entry.slot for entry in _vector_entries if entry.function_ea is not None}
    last_progress = [0.0]

    def report_progress(message):
        now = time.monotonic()
        if now - last_progress[0] >= 0.2:
            ida_kernwin.replace_wait_box(f"IRQScope analysis\n{message}\nPress Cancel to stop.")
            last_progress[0] = now
        return bool(ida_kernwin.user_cancelled())

    ida_kernwin.show_wait_box("IRQScope analysis\nPreparing firmware scan...\nPress Cancel to stop.")
    try:
        (working.accesses, working.cfg_by_function,
         working.interrupt_config, scan_warnings) = scan_mmio_with_cfg(
            _device, progress=report_progress
        )
        working.warnings = list(scan_warnings)
        working.findings = build_candidate_findings(
            working.accesses, isrs, working.cfg_by_function, working.interrupt_config,
            progress=report_progress,
            nvic_priority_bits=_device.nvic_priority_bits,
        )
        (working.transaction_proposals, mining_warnings) = mine_transaction_proposals(
            working.accesses, isrs, working.cfg_by_function, progress=report_progress
        )
        working.warnings.extend(mining_warnings)
        working.notes = [
            "SVD peripheral, cluster, register, field, and named enumerated-value-set inheritance is resolved. Validated alternate peripheral, cluster, and register relationships are retained; full schema validation and shared-address alias selection remain outside the current model.",
            "MMIO recovery tracks exact absolute operands and simple constant-base register flows; indexed pointers and generic helper summaries remain unresolved. A narrow constant-base NVIC wrapper summary may label a callsite as heuristic evidence.",
            "PRIMASK/BASEPRI/FAULTMASK snapshots cover recognized in-function instructions and intrinsics, not all platform-specific mask logic.",
            "Static NVIC API callsites with constant IRQ arguments and narrow store-summary callsites are indexed. A SVD-width-aware BASEPRI comparison may be shown as conditional evidence, but callsite reachability, effective enable state, priority grouping, and actual preemption are not proven. CFG paths support candidate sketches, not transaction feasibility.",
            "Transaction sequence proposals are heuristic, pairwise CFG-reachable MMIO chains ranked with SVD side-effect cues and repeated patterns; limited constant branch edges are pruned, but they do not establish protocol boundaries or complete path feasibility.",
            "A finding is a review candidate, not a confirmed race or hardware defect.",
        ]
        working.notes.extend(scan_warnings)
        if _protocol is not None:
            protocol_result = build_protocol_findings(
                _protocol, _device, working.accesses, isrs, working.cfg_by_function,
                working.interrupt_config, progress=report_progress,
            )
            working.findings.extend(protocol_result.findings)
            working.notes.extend(protocol_result.truncation_reasons)
            working.notes.append(
                f"Analyst protocol contract {_protocol.name!r} ({_protocol.source_sha256}) was applied. "
                "Its declared transaction and interference behavior is not independently validated; "
                "only constant CBZ/CBNZ, common flag conditions immediately after CMP/CMN/ADDS/SUBS, and zero/sign conditions after TST/TEQ with known unshifted operands are filtered; other branch feasibility and complete interrupt eligibility remain unknown."
            )
    except AnalysisCancelled:
        ida_kernwin.msg("[IRQScope] Analysis cancelled; the last completed result set was kept.\n")
        return False
    finally:
        ida_kernwin.hide_wait_box()

    _results = working
    _refresh_dashboard()
    rows = []
    for finding in _results.findings:
        foreground = finding.first if finding.first.function_ea not in isrs else finding.second
        mask = (f"P={foreground.primask if foreground.primask is not None else '?'} "
                f"B={foreground.basepri if foreground.basepri is not None else '?'} "
                f"F={foreground.faultmask if foreground.faultmask is not None else '?'}")
        rows.append((finding.severity.upper(), finding.title, finding.register.display_name,
                     f"0x{finding.first.ea:X}", f"0x{finding.second.ea:X}", mask,
                     finding.preemption_state,
                     finding.priority_assessment.status if finding.priority_assessment else "unknown",
                     finding.witness.status if finding.witness else "no witness",
                     finding.confidence))
    ida_kernwin.msg(
        f"[IRQScope] Found {len(_results.accesses)} SVD-matched accesses, "
        f"{len(_results.interrupt_config)} interrupt-configuration callsites, and "
        f"{len(_results.findings)} cross-context candidates plus "
        f"{len(_results.transaction_proposals)} review-only sequence proposals.\n"
    )
    show_rows("IRQScope — Cross-Context Candidates", [
        ["Severity", 10], ["Candidate", 42], ["Register", 24], ["Access A", 14], ["Access B", 14], ["Mask at foreground", 18], ["Mask assessment", 30], ["Priority hint", 30], ["Witness", 34], ["Evidence", 12]
    ], rows, on_select=_show_finding_witness)
    return True


def _show_finding_witness(index):
    finding = _results.findings[index]
    witness = finding.witness
    if witness is None:
        _jump(finding.first.ea)
        return
    rows = [("Assessment", witness.status, "—", witness.explanation)]
    locations = [None]
    start = witness.foreground_start
    rows.append(("Foreground", f"{start.operation.upper()} {start.register.display_name}",
                 f"0x{start.ea:X}",
                 f"PRIMASK={start.primask if start.primask is not None else '?'}; "
                 f"BASEPRI={start.basepri if start.basepri is not None else '?'}"))
    locations.append(start.ea)
    if finding.priority_assessment is not None:
        assessment = finding.priority_assessment
        rows.append(("BASEPRI priority", assessment.status, "—", assessment.detail))
        locations.append(None)
    interrupt = witness.interrupt_event
    rows.append(("Interrupt", f"{interrupt.operation.upper()} {interrupt.register.display_name}",
                 f"0x{interrupt.ea:X}", witness.status))
    locations.append(interrupt.ea)
    if witness.foreground_resume is not None:
        resume = witness.foreground_resume
        rows.append(("Resume", f"{resume.operation.upper()} {resume.register.display_name}",
                     f"0x{resume.ea:X}", "Shortest observed same-peripheral continuation"))
        locations.append(resume.ea)
    for block_ea in witness.block_path:
        rows.append(("CFG", "Foreground basic block", f"0x{block_ea:X}", "Reachability evidence"))
        locations.append(block_ea)
    for event in witness.interrupt_prefix:
        rows.append(("ISR prefix", f"{event.operation.upper()} {event.register.display_name}",
                     f"0x{event.ea:X}", "Observed along shortest handler CFG path"))
        locations.append(event.ea)
    for block_ea in witness.interrupt_block_path:
        rows.append(("ISR CFG", "Handler basic block", f"0x{block_ea:X}", "Reachability evidence"))
        locations.append(block_ea)
    ida_kernwin.msg(f"[IRQScope] {witness.status}: {witness.explanation}\n")
    show_rows("IRQScope — Candidate Interleaving Witness", [
        ["Context", 16], ["Observed event", 36], ["Instruction EA", 16], ["Interpretation", 46]
    ], rows, on_select=lambda row: _jump(locations[row]) if locations[row] is not None else None)


def _show_accesses():
    if not _results.accesses:
        ida_kernwin.warning("Run IRQScope: Analyze MMIO… first to build the access index.")
        return
    rows = []
    for access in _results.accesses:
        masks = f"P={access.primask if access.primask is not None else '?'} " \
                f"B={access.basepri if access.basepri is not None else '?'} " \
                f"F={access.faultmask if access.faultmask is not None else '?'}"
        rows.append((f"0x{access.ea:X}", access.function_name, access.operation.upper(),
                     access.register.display_name,
                     (f"0x{access.value:X}" if access.value is not None else "—"),
                     "; ".join(
                         f"{check.scope}: {check.status} — {check.detail}"
                         for check in getattr(access, "write_constraint_checks", ())
                     ) or "—",
                     ", ".join(alias.display_name for alias in access.register_aliases) or "—",
                     f"0x{access.register.address:08X}",
                     access.evidence, masks))
    show_rows("IRQScope — MMIO Access Index", [
        ["Instruction", 14], ["Function", 28], ["Op", 8], ["Register", 26],
        ["Value", 14], ["SVD write checks", 42], ["SVD aliases", 28], ["Address", 14],
        ["Address evidence", 26], ["Mask state", 22]
    ], rows, on_select=lambda row: _jump(_results.accesses[row].ea))


def _json_access(value):
    return {
        "ea": f"0x{value.ea:X}", "function": value.function_name,
        "function_ea": f"0x{value.function_ea:X}", "operation": value.operation,
        "width_bits": value.width_bits, "evidence": value.evidence,
        "value": f"0x{value.value:X}" if value.value is not None else None,
        "value_evidence": value.value_evidence,
        "register": value.register.display_name,
        "register_aliases": [item.display_name for item in value.register_aliases],
        "basic_block": f"0x{value.block_start_ea:X}" if value.block_start_ea is not None else None,
        "interrupt_masks": {"primask": value.primask, "basepri": value.basepri, "faultmask": value.faultmask},
        "write_constraint_checks": [
            {
                "scope": check.scope,
                "kind": check.kind,
                "status": check.status,
                "value": f"0x{check.value:X}" if check.value is not None else None,
                "detail": check.detail,
            }
            for check in getattr(value, "write_constraint_checks", ())
        ],
    }


def _json_register(value):
    return {
        "peripheral": value.peripheral,
        "name": value.name,
        "display_name": value.display_name,
        "address": f"0x{value.address:X}",
        "size_bits": value.size_bits,
        "access": value.access,
        "read_action": value.read_action or None,
        "modified_write_values": value.modified_write_values or None,
        "reset_value": f"0x{value.reset_value:X}" if value.reset_value is not None else None,
        "reset_mask": f"0x{value.reset_mask:X}" if value.reset_mask is not None else None,
        "write_constraint": _json_write_constraint(value.write_constraint),
        "description": value.description,
        "fields": [
            {
                "name": field.name,
                "bit_offset": field.bit_offset,
                "bit_width": field.bit_width,
                "access": field.access,
                "read_action": field.read_action or None,
                "modified_write_values": field.modified_write_values or None,
                "write_constraint": _json_write_constraint(field.write_constraint),
                "write_constraint_source": field.write_constraint_source,
                "enumerated_values": [
                    {
                        "name": enumeration.name or None,
                        "header_enum_name": enumeration.header_enum_name or None,
                        "usage": enumeration.usage,
                        "values": [
                            {
                                "name": value.name or None,
                                "value": f"0x{value.value:X}" if value.value is not None else None,
                                "mask": f"0x{value.mask:X}" if value.mask is not None else None,
                                "pattern": value.pattern or None,
                                "description": value.description or None,
                                "is_default": value.is_default,
                            }
                            for value in enumeration.values
                        ],
                    }
                    for enumeration in field.enumerated_values
                ],
            }
            for field in value.fields
        ],
    }


def _json_write_constraint(value):
    if value is None:
        return None
    return {
        "kind": value.kind,
        "minimum": f"0x{value.minimum:X}" if value.minimum is not None else None,
        "maximum": f"0x{value.maximum:X}" if value.maximum is not None else None,
    }


def _json_transaction_proposal(proposal):
    return {
        "id": proposal.proposal_id,
        "peripheral": proposal.peripheral,
        "function": proposal.function_name,
        "function_ea": f"0x{proposal.function_ea:X}",
        "events": [_json_access(event) for event in proposal.events],
        "cfg_paths": [[f"0x{ea:X}" for ea in path] for path in proposal.paths],
        "supporting_function_eas": [f"0x{ea:X}" for ea in proposal.supporting_function_eas],
        "supporting_functions": list(proposal.supporting_functions),
        "rationale": list(proposal.rationale),
        "limitations": list(proposal.limitations),
        "review_identity": _proposal_review_id(proposal),
        "review": _review_for_proposal(proposal),
        "interpretation": "Heuristic transaction-sequence proposal for analyst review; not a confirmed protocol.",
    }


def _json_protocol(value):
    if value is None:
        return None
    return {
        "format": "irqscope-protocol-v1",
        "name": value.name,
        "source": os.path.basename(value.source),
        "sha256": value.source_sha256,
        "transactions": [
            {
                "name": transaction.name,
                "peripheral": transaction.peripheral,
                "description": transaction.description,
                "interference_mode": transaction.interference_mode,
                "steps": [
                    {"register": event.register, "operation": event.operation}
                    for event in transaction.steps
                ],
                "interference": [
                    {"register": event.register, "operation": event.operation,
                     "reason": event.reason}
                    for event in transaction.interference
                ],
            }
            for transaction in value.transactions
        ],
    }


def _json_value(finding):
    review = _review_for_finding(finding)
    timeline = build_candidate_timeline(finding)
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "evidence_profile": confidence_vector(finding),
        "write_effect_relation": ({
            "scope": finding.write_effect_relation.scope,
            "width_bits": finding.write_effect_relation.width_bits,
            "interrupt_operations_by_bit_lsb_first": list(
                finding.write_effect_relation.interrupt_operations_by_bit
            ),
            "interrupt_active_mask": f"0x{finding.write_effect_relation.interrupt_active_mask:X}",
            "foreground_operations_by_bit_lsb_first": list(
                finding.write_effect_relation.foreground_operations_by_bit
            ),
            "foreground_active_mask": f"0x{finding.write_effect_relation.foreground_active_mask:X}",
            "overlap_mask": f"0x{finding.write_effect_relation.overlap_mask:X}",
            "conflict_mask": f"0x{finding.write_effect_relation.conflict_mask:X}",
            "final_state_transforms_commute": finding.write_effect_relation.final_state_transforms_commute,
        } if finding.write_effect_relation else None),
        "preemption_state": finding.preemption_state,
        "priority_assessment": ({
            "status": finding.priority_assessment.status,
            "irq_number": finding.priority_assessment.irq_number,
            "priority_bits": finding.priority_assessment.priority_bits,
            "logical_priority": finding.priority_assessment.logical_priority,
            "encoded_priority": (
                f"0x{finding.priority_assessment.encoded_priority:02X}"
                if finding.priority_assessment.encoded_priority is not None else None
            ),
            "basepri_threshold": (
                f"0x{finding.priority_assessment.basepri_threshold:02X}"
                if finding.priority_assessment.basepri_threshold is not None else None
            ),
            "priority_callsite_addresses": [
                f"0x{ea:X}" for ea in finding.priority_assessment.callsite_eas
            ],
            "detail": finding.priority_assessment.detail,
        } if finding.priority_assessment else None),
        "address": f"0x{finding.address:X}",
        "register": finding.register.display_name,
        "explanation": finding.explanation,
        "assumptions": list(finding.assumptions),
        "protocol_name": finding.protocol_name,
        "protocol_identity": finding.protocol_identity,
        "protocol_interference_mode": finding.protocol_interference_mode,
        "protocol_events": [_json_access(item) for item in finding.protocol_events],
        "protocol_foreground_paths": [
            [f"0x{ea:X}" for ea in path] for path in finding.protocol_foreground_paths
        ],
        "protocol_insertion_index": finding.protocol_insertion_index,
        "protocol_interrupt_events": [
            _json_access(item) for item in finding.protocol_interrupt_events
        ],
        "protocol_interrupt_paths": [
            [f"0x{ea:X}" for ea in path] for path in finding.protocol_interrupt_paths
        ],
        "candidate_timeline": ({
            "status": timeline["status"],
            "insertion_gap": timeline["insertion_gap"],
            "mask_snapshot": timeline["mask_snapshot"],
            "steps": [
                {
                    "order": step["order"],
                    "context": step["context"],
                    "event_index": step["event_index"],
                    "access": _json_access(step["event"]),
                    "cfg_path": [f"0x{ea:X}" for ea in step["cfg_path"]],
                    "path_scope": step["path_scope"],
                }
                for step in timeline["steps"]
            ],
            "limitations": list(timeline["limitations"]),
        } if timeline is not None else None),
        "interrupt_configuration": [
            {
                "ea": f"0x{event.ea:X}",
                "function": event.function_name,
                "operation": event.operation,
                "irq_number": event.irq_number,
                "vector_slot": event.vector_slot,
                "priority_argument": event.priority,
                "evidence_basis": event.evidence_basis,
                "interpretation": "Static callsite only; it does not establish runtime reachability or effective NVIC state.",
            }
            for event in finding.interrupt_configuration
        ],
        "review": {"status": review["status"], "note": review["note"]},
        "accesses": [_json_access(finding.first), _json_access(finding.second)],
        "witness": {
            "status": finding.witness.status,
            "explanation": finding.witness.explanation,
            "foreground_start": _json_access(finding.witness.foreground_start),
            "interrupt_event": _json_access(finding.witness.interrupt_event),
            "foreground_resume": _json_access(finding.witness.foreground_resume) if finding.witness.foreground_resume else None,
            "cfg_block_path": [f"0x{ea:X}" for ea in finding.witness.block_path],
            "interrupt_block_path": [f"0x{ea:X}" for ea in finding.witness.interrupt_block_path],
            "interrupt_prefix": [_json_access(item) for item in finding.witness.interrupt_prefix],
        } if finding.witness else None,
    }


def _export():
    if _device is None:
        ida_kernwin.warning("Nothing to export yet. Import an SVD and run Analyze.")
        return
    path = ida_kernwin.ask_file(True, "*.json", "Export IRQScope evidence as JSON")
    if not path:
        return
    payload = {
        "format": "irqscope-evidence-v25",
        "provenance": _export_provenance(),
        "warnings": list(_results.warnings),
        "device": _device.name,
        "svd_endianness": _device.endianness,
        "address_unit_bits": _device.address_unit_bits,
        "nvic_priority_bits": _device.nvic_priority_bits,
        "svd_source": os.path.basename(_device.source),
        "svd_sha256": _device.source_sha256,
        "protocol": _json_protocol(_protocol),
        "ida_input": idc.get_input_file_path(),
        "generated_unix_time": int(time.time()),
        "register_map": [
            {
                "address": f"0x{address:X}",
                "descriptions": [_json_register(item) for item in _device.get_registers(address)],
            }
            for address in sorted(_device.registers)
        ],
        "alternate_peripherals": [
            {"name": alternate, "alternate_of": primary}
            for alternate, primary in sorted(_device.alternate_peripherals.items())
        ],
        "alternate_registers": [
            {"name": alternate, "alternate_of": primary}
            for alternate, primary in sorted(_device.alternate_registers.items())
        ],
        "alternate_clusters": [
            {"name": alternate, "alternate_of": primary}
            for alternate, primary in sorted(_device.alternate_clusters.items())
        ],
        "vectors": [{"slot": row.slot, "name": row.name, "address": f"0x{row.address:X}",
                     "function_ea": f"0x{row.function_ea:X}" if row.function_ea is not None else None}
                    for row in _vector_entries],
        "interrupt_configuration_events": [
            {
                "ea": f"0x{event.ea:X}",
                "function": event.function_name,
                "function_ea": f"0x{event.function_ea:X}",
                "operation": event.operation,
                "irq_number": event.irq_number,
                "vector_slot": event.vector_slot,
                "mapped_handler": next((entry.name for entry in _vector_entries
                                         if entry.slot == event.vector_slot), None),
                "priority_argument": event.priority,
                "evidence_basis": event.evidence_basis,
                "interpretation": "Static API callsite only; runtime reachability and active NVIC state are not established.",
            }
            for event in _results.interrupt_config
        ],
        "access_count": len(_results.accesses),
        "accesses": [_json_access(item) for item in _results.accesses],
        "findings": [_json_value(item) for item in _results.findings],
        "transaction_proposals": [
            _json_transaction_proposal(proposal)
            for proposal in _results.transaction_proposals
        ],
        "limitations": _results.notes,
    }
    identity_payload = dict(payload)
    identity_payload.pop("generated_unix_time", None)
    payload["provenance"]["analysis_id"] = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    try:
        with open(path, "w", encoding="utf-8") as target:
            json.dump(payload, target, indent=2, sort_keys=True)
            target.write("\n")
    except OSError as exc:
        ida_kernwin.warning(f"IRQScope export failed:\n{exc}")
        return
    ida_kernwin.msg(f"[IRQScope] Exported evidence to {path}\n")


def _import_protocol():
    global _protocol
    if _device is None:
        ida_kernwin.warning("Import a CMSIS-SVD device model before importing a protocol contract.")
        return
    path = ida_kernwin.ask_file(False, "*.json", "Import an IRQScope protocol contract")
    if not path:
        return
    try:
        protocol = parse_protocol(path, _device)
    except ValueError as exc:
        ida_kernwin.warning(f"IRQScope could not import this protocol contract:\n{exc}")
        return
    previous_protocol = _protocol
    _protocol = protocol
    if _results.accesses:
        if not _analyze():
            _protocol = previous_protocol
            _refresh_dashboard()
            ida_kernwin.msg("[IRQScope] Protocol import was not applied because analysis was cancelled.\n")
            return
    else:
        _refresh_dashboard()
    ida_kernwin.msg(
        f"[IRQScope] Loaded protocol {protocol.name}: "
        f"{len(protocol.transactions)} transaction contract(s).\n"
    )


class IRQScopePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Interrupt-aware peripheral analysis workbench"
    help = "Import SVD, inspect Cortex-M vectors, and review cross-context MMIO candidates"
    wanted_name = "IRQScope"
    wanted_hotkey = ""

    def init(self):
        global _device, _vector_entries, _results, _reviews, _protocol
        # IDA may load the same PLUGIN_KEEP instance for successive IDBs.
        # Reset session state before binding the ledger to this database.
        _device = None
        _vector_entries = []
        _results = AnalysisResult()
        _reviews = ReviewLedger()
        _protocol = None
        try:
            _load_reviews()
        except Exception as exc:
            ida_kernwin.warning(f"IRQScope review records could not be loaded from this IDB:\n{exc}")
        _register_action(ACTION_IMPORT, "IRQScope: Import CMSIS-SVD…", _import_svd,
                         "Load register names and hardware side-effect metadata from a local SVD")
        _register_action(ACTION_DETECT, "IRQScope: Detect Cortex-M vectors…", _detect_vectors,
                         "Rank possible vector tables and review mapped handlers")
        _register_action(ACTION_ANALYZE, "IRQScope: Analyze MMIO…", _analyze,
                         "Find SVD-matched accesses shared by vector handlers and foreground code")
        _register_action(ACTION_ACCESS, "IRQScope: Show MMIO Access Index…", _show_accesses,
                         "Review every recovered SVD-matched load/store and mask snapshot")
        _register_action(ACTION_EXPORT, "IRQScope: Export evidence…", _export,
                         "Export candidate findings and known limitations as JSON")
        _register_action(ACTION_PROTOCOL, "IRQScope: Import protocol contract…", _import_protocol,
                         "Add analyst-authored transaction and interference contracts")
        _register_action(ACTION_DASHBOARD, "IRQScope: Open Analysis Dashboard", _open_dashboard,
                         "Open the dockable device, access, and interleaving review surface")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        _open_dashboard()

    def term(self):
        global _dashboard, _device, _vector_entries, _results, _reviews, _protocol
        if _dashboard is not None:
            try:
                _dashboard.Close(ida_kernwin.PluginForm.WCLS_SAVE)
            except Exception:
                pass
            _dashboard = None
        for name in _registered:
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", name)
            ida_kernwin.unregister_action(name)
        _registered.clear()
        _device = None
        _vector_entries = []
        _results = AnalysisResult()
        _reviews = ReviewLedger()
        _protocol = None


def PLUGIN_ENTRY():
    return IRQScopePlugin()
