"""Bounded discovery of review-only MMIO transaction sequence proposals."""

from collections import defaultdict
import hashlib
from typing import Mapping, Sequence, Tuple

from .analysis import _shortest_block_path
from .model import AnalysisCancelled, CFGBlock, MMIOAccess, TransactionProposal


MAX_SEQUENCE_EVENTS = 5
MAX_PROPOSALS = 1000
MAX_FUNCTION_EVENTS = 5000
MAX_SEARCH_STATES = 20_000


def _signature(events: Sequence[MMIOAccess]) -> Tuple[Tuple[str, str], ...]:
    return tuple((event.register.display_name, event.operation) for event in events)


def _svd_semantic_cues(events: Sequence[MMIOAccess]) -> Tuple[str, ...]:
    """Return register-side-effect hints relevant to observed access directions.

    These are prioritization hints from imported SVD metadata, not proof that
    the binary's access has the modeled device effect at runtime.
    """
    cues = []
    seen = set()
    for event in events:
        register = event.register
        if event.operation == "read" and register.read_action:
            action = register.read_action.strip()
            cue = (
                f"SVD semantic cue: {register.display_name} declares readAction={action}; "
                "an observed read may change device state."
            )
            if cue not in seen:
                seen.add(cue)
                cues.append(cue)
        if event.operation == "write" and register.modified_write_values:
            behavior = register.modified_write_values.strip()
            cue = (
                f"SVD semantic cue: {register.display_name} declares "
                f"modifiedWriteValues={behavior}; an observed write may have "
                "bit-specific effects."
            )
            if cue not in seen:
                seen.add(cue)
                cues.append(cue)
    return tuple(cues)


def mine_transaction_proposals(
    accesses: Sequence[MMIOAccess],
    interrupt_functions: Mapping[int, int],
    cfg_by_function: Mapping[int, Mapping[int, CFGBlock]],
    progress=None,
):
    """Suggest short, pairwise CFG-reachable foreground MMIO sequences.

    The miner deliberately proposes evidence for analyst review. It does not
    label a sequence a transaction, infer protocol invariants, or test branch
    predicates. Each adjacent pair in a proposed chain must have a recovered
    CFG path. CFG cycles may revisit an earlier instruction or repeat an event;
    sequence length and total search work are bounded below.
    """
    grouped = defaultdict(list)
    for access in accesses:
        if access.function_ea not in interrupt_functions:
            grouped[(access.function_ea, access.register.peripheral)].append(access)

    raw_candidates = []
    truncated_groups = []
    path_cache = {}
    search_states = 0
    search_truncated = False
    groups = sorted(grouped.items())
    for group_index, ((function_ea, peripheral), events) in enumerate(groups, 1):
        if progress is not None and progress(
            f"Mining MMIO sequences ({group_index}/{len(groups)} functions)",
        ):
            raise AnalysisCancelled("transaction mining")
        events.sort(key=lambda item: (item.ea, item.register.display_name, item.operation))
        if len(events) > MAX_FUNCTION_EVENTS:
            truncated_groups.append((function_ea, peripheral, len(events)))
            events = events[:MAX_FUNCTION_EVENTS]
        cfg = cfg_by_function.get(function_ea, {})
        for first in events:
            def extend(chain, paths):
                nonlocal search_states, search_truncated
                if len(chain) >= 2:
                    raw_candidates.append((function_ea, peripheral, tuple(chain), tuple(paths)))
                if len(chain) >= MAX_SEQUENCE_EVENTS:
                    return
                for following in events:
                    search_states += 1
                    if search_states % 128 == 0 and progress is not None and progress(
                        f"Exploring CFG-reachable MMIO sequences ({search_states}/{MAX_SEARCH_STATES} extensions)",
                    ):
                        raise AnalysisCancelled("transaction mining")
                    if search_states > MAX_SEARCH_STATES:
                        search_truncated = True
                        return
                    key = (chain[-1].ea, following.ea)
                    if key not in path_cache:
                        path_cache[key] = _shortest_block_path(chain[-1], following, cfg)
                    path = path_cache[key]
                    if path is not None:
                        extend(chain + (following,), paths + (path,))
                    if search_truncated:
                        return

            extend((first,), ())
            if search_truncated:
                break
        if search_truncated:
            break

    support = defaultdict(set)
    for function_ea, peripheral, chain, _ in raw_candidates:
        support[(peripheral, _signature(chain))].add(function_ea)
    function_names = {}
    for access in accesses:
        function_names.setdefault(access.function_ea, access.function_name)

    proposals = []
    for function_ea, peripheral, chain, paths in raw_candidates:
        signature = _signature(chain)
        supporting_eas = sorted(support[(peripheral, signature)])
        supporting_names = tuple(function_names.get(ea, f"sub_{ea:X}") for ea in supporting_eas)
        path_kinds = {len(path) for path in paths}
        rationale = [
            f"{len(chain)} ordered MMIO observations span {len({event.register.display_name for event in chain})} distinct register(s).",
            f"Every adjacent event pair has a recovered CFG path; {sum(1 for path in paths if len(path) == 1)} pair(s) share one basic block.",
        ]
        semantic_cues = _svd_semantic_cues(chain)
        rationale.extend(semantic_cues)
        if len(supporting_eas) > 1:
            rationale.append(
                f"The same register/operation pattern appears in {len(supporting_eas)} foreground functions."
            )
        if len(path_kinds) > 1:
            rationale.append("The candidate crosses both intra-block and inter-block paths.")
        digest_input = f"{function_ea:X}|{peripheral}|" + ",".join(
            f"{event.ea:X}:{event.register.display_name}:{event.operation}" for event in chain
        )
        proposal_id = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        proposals.append(TransactionProposal(
            proposal_id=proposal_id,
            function_ea=function_ea,
            function_name=chain[0].function_name,
            peripheral=peripheral,
            events=chain,
            paths=paths,
            supporting_function_eas=tuple(supporting_eas),
            supporting_functions=supporting_names,
            rationale=tuple(rationale),
            limitations=(
                "This is a sequence proposal, not a proven transaction boundary or device protocol.",
                "Event order follows recovered CFG reachability and may revisit instructions through loops; branch predicates and mutually exclusive paths are not resolved.",
                "Pairwise CFG reachability does not establish runtime execution, interrupt state, or a semantic conflict.",
            ),
        ))

    proposals.sort(key=lambda item: (
        -sum(1 for reason in item.rationale if reason.startswith("SVD semantic cue:")),
        -len(item.supporting_function_eas), -len(item.events),
        -len({event.register.display_name for event in item.events}),
        item.function_ea, item.events[0].ea,
    ))
    warnings = []
    if len(proposals) > MAX_PROPOSALS:
        proposals = proposals[:MAX_PROPOSALS]
        warnings.append(
            f"Transaction mining reached its {MAX_PROPOSALS}-proposal output bound after semantic and pattern ranking; lower-ranked candidates may be omitted."
        )
    if search_truncated:
        warnings.append(
            f"Transaction mining reached its {MAX_SEARCH_STATES}-extension search bound; additional candidates may be omitted."
        )
    for function_ea, peripheral, count in truncated_groups:
        warnings.append(
            f"Transaction mining limited {count} {peripheral} events in function 0x{function_ea:X} to {MAX_FUNCTION_EVENTS}."
        )
    return tuple(proposals), tuple(warnings)
