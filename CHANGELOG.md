# Changelog

## 0.1.0 — 2026-11-21

Initial contest prototype for Cortex-M peripheral-concurrency triage in IDA.

- Import CMSIS-SVD peripheral/register semantics, inheritance, arrays, and address aliases.
- Preserve read/write field encodings and resolve named SVD enumerated-value-set inheritance.
- Rank vector-table candidates and review mapped interrupt handlers.
- Recover bounded MMIO, mask, CFG, and static NVIC setup evidence.
- Review cross-context and analyst-authored protocol-interference candidates in a dockable dashboard.
- Explain candidate evidence across six dimensions, with evidence sources and explicit limits in the witness inspector and JSON export.
- Persist analyst verdicts and notes in the IDB, and export versioned evidence JSON.
- Include a synthetic Cortex-M firmware/SVD fixture, deterministic source-package tool, and 16:9 plugin artwork.
- Add a reproducible Clang/LLD demo firmware build and clean-build verification command for symbolized and stripped ELFs.
- Validate a generated sample-metadata release archive with HCLI 0.28.0; lint returned no recommendations.
- Surface CFG propagation iteration-limit warnings in the dashboard and JSON evidence instead of silently presenting partial facts as complete.
- Link findings to same-IRQ static enable/disable/priority callsites in the witness inspector and export, while keeping runtime reachability and effective NVIC state explicitly unknown.
- Recover stripped NVIC wrapper summaries when the store uses an indexed operand but IDA's rendered expression identifies a propagated constant NVIC base; keep index bounds and helper ABI explicitly heuristic.
- Resolve constant base-plus-index-times-LSL MMIO operands and abstain on dynamic or unsupported indexed forms rather than mislabeling the base address as the effective register.
- Match optional ordered ISR interference sequences against CFG-reachable handler MMIO events; preserve the complete event chain and inter-event paths in the dashboard, review identity, and versioned evidence export.
- Choose a protocol witness insertion gap from the available foreground event windows, preferring known mask-permitted snapshots over unknown or blocked snapshots; label the selected gap and record the mask-snapshot limitation.
- Preserve validated CMSIS-SVD `alternatePeripheral` links in the device model, register map, dashboard, and evidence-v11 export; reject unresolved, self-referential, or spec-order-invalid links.
- Preserve CMSIS-SVD `alternateRegister` references separately from address collisions, require a unique earlier same-peripheral register at the same address, and surface the relation in the UI and evidence-v12 export.
- Preserve CMSIS-SVD `alternateCluster` links, requiring an earlier cluster at the same base address; expose cluster and register ancestry in the dashboard and evidence-v13 export.
- Mine bounded CFG-traversed foreground MMIO sequence proposals, including loop-backs and repeated instruction events; expose repeated-pattern support, navigable path details, explicit limits, and the evidence-v14 export field.
- Add proposal-specific confirmed/dismissed/open status and analyst notes, persisted in the IDB review ledger under input/SVD/proposal-scoped identities and included in evidence exports.
- Compute a content hash for proposal and finding review identity when IDA does not supply the input SHA-256, avoiding filename-only review collisions when the input file is readable.
- Save a selected sequence proposal as an editable, SVD-validatable protocol contract draft populated with observed mapped-handler event patterns; require handler evidence and disclose the 32-pattern cap and unverified assumptions.
- Prioritize bounded sequence proposals that touch SVD-declared read or write side effects, surface those semantics in the exported rationale, and apply the output cap only after ranking so early enumeration order does not crowd out higher-value candidates.
- Add an IDA 9.5 host-validation checklist with the required ARM/IDAPython edition capabilities, symbolized/stripped fixture steps, IDB persistence review, no-decompiler check, and a results record.
- Add cancellable progress reporting for NVIC wrapper indexing, CFG/MMIO scanning, cross-context pair analysis, sequence mining, and protocol matching; pre-index protocol accesses by function/peripheral, keep previous results intact when a rerun is cancelled, and roll back a protocol import that did not finish analysis.
- Add evidence-v15 reproducibility provenance for firmware content identity and hash basis, exact plugin-source/SVD/protocol hashes, IDA/Python/platform versions, selected vector mapping, and a content-stable export identity; document the identity calculation.

Runtime behavior and presentation have not yet been verified in an IDA installation.

- Add constant MMIO write-value recovery for immediate and locally constant-propagated single-register stores; surface values and matching SVD write enumerations in the dashboard, legacy access chooser, and evidence-v16 JSON. This is static evidence and does not prove execution.

- Extend bounded ARM constant propagation through unshifted immediate/register AND, ORR, EOR, and BIC forms; reject rendered shifted-register forms instead of treating them as unshifted constants.

- Add a conservative SVD-aware write-pair classification for exact full-width constants under write-capable access policies and register-level or complete non-overlapping field-level one/zero-to-clear, set, and toggle semantics; commuting final-state transforms receive a low-severity review result with explicit temporal and hardware-model limits.

- Add structured per-bit SVD write-effect evidence to findings and exports, including scope, operation vectors, active masks, overlap mask, and the modeled commutativity result; bump the evidence format to v17.
- Extend the structured relation to distinguish order-dependent overlapping SVD write effects from commuting effects; export a conflict mask and bump the evidence format to v18.
- Add conservative CBZ/CBNZ edge pruning for known registers; resolve common ARM flag conditions after CMP/CMN/ADDS/SUBS and zero/sign conditions after TST/TEQ when unshifted operands are known. Retain decisions in scan warnings and fall back to conservative CFG propagation on non-convergence.
- Extend bounded ARM constant propagation through shifted MOV/MOVS, RSB/NEG, register-form MVN, ORN, UBFX/SBFX/BFI/BFC, standalone LSL/LSR/ASR/ROR operations, and rendered shifted-register operands in arithmetic/bitwise instructions; abstain on unsupported forms and ambiguous ROR encodings that depend on carry.
- Resolve supported shifted-register operands when pruning constant comparison branches, and conservatively abstain when an `ADDS`/`SUBS` destination aliases a register needed to reconstruct a shifted operand.
- Report mask-state disagreements at CFG joins with the predecessor block addresses and incoming PRIMASK/BASEPRI/FAULTMASK values while continuing to merge uncertain state to unknown.
- Compare exact full-width writes to explicitly writable registers using ordinary SVD default assignment semantics when no field map exists or writable fields cover the word; demonstrate conflicting configuration writes and disjoint commuting W1C writes in the rebuilt synthetic firmware fixture.
- Add optional exact and masked constant-write constraints to protocol events, plus SVD `field`/`enumeration` names that resolve to bit masks; preserve full-width constant values in editable protocol drafts and demonstrate value-specific foreground/ISR matching in the synthetic UART contract.
- Add a shifted-comparison firmware fixture with constant MMIO stores on both branch edges; the static build guard preserves the intended CMP/LSL/BNE shape for future IDA path-feasibility validation.
- Make dashboard evidence tables sortable with numeric address/count ordering and severity ranking, while keeping finding/proposal callbacks bound to original result identities after Qt reorders rows.
- Import inherited CMSIS-SVD reset values and known-bit masks, decode fully known reset fields using read/read-write enums, import and display register/field range, enum-only, and write-as-read constraints, check recovered full-width writes with explicit pass/violate/unknown outcomes, and retain the evidence in v21 exports. Add an invalid-mode write to the synthetic firmware fixture.

- Propagate register-level CMSIS-SVD write constraints to fields as defaults, let explicit field declarations override or clear those defaults, expose constraint provenance in the dashboard and evidence-v22 export, and exercise inherited range plus field enum override behavior in the CONFIG fixture.

- Map supported byte and halfword MMIO stores into field constraints using the SVD CPU endian and address-unit metadata; retain unknown outcomes for configurable or missing byte-lane metadata and partial field coverage, and export the device mapping properties in evidence-v23.

- Compare observed BASEPRI snapshots with a unique static CMSIS priority setup hint using SVD `nvicPrioBits`; label the result conditional, preserve unknown outcomes for missing or conflicting evidence, and expose it in the dashboard and evidence-v24 format.
- Match the dockable dashboard to IDA's host light/dark palette, with a readable light variant and a dark fallback when palette detection is unavailable.
- Add a read-only GitHub Actions validation workflow for Python tests, deterministic firmware checks, sample-metadata packaging, and HCLI archive lint.
- Assemble matched foreground and ordered ISR contract events into a conditional synchronized candidate timeline with CFG links, an explicit insertion gap, and limitations; bump the evidence schema to v25.
- Preserve each recovered effective MMIO address in findings, dashboard rows, and evidence exports; map byte-addressed partial accesses to one unambiguous containing SVD register and abstain on overlapping or crossing ranges.
- Compare constrained partial protocol writes in register-relative bit lanes using fixed SVD endianness and byte address units; abstain when the lane cannot be established.
- Extend the reproducible Cortex-M demo with a byte-lane CONFIG write and verify that `MODE=FAST` matches through the imported SVD and protocol contract.

The current source tree has focused unit coverage for these additions, but none of the new behavior has been exercised inside IDA.
