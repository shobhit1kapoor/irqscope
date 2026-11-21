# IRQScope Implementation Roadmap

## Contest-critical slice

The 2026 contest deadline is November 30, 2026. As of November 21, only nine calendar days remain, and Hex-Rays says plugin-repository publication generally takes about 24 hours. A realistic submission needs a deliberately bounded, installable core and a publication buffer; the full research vision in `architecture.md` cannot responsibly be claimed complete in that time.

## Current prototype limits

- No IDA runtime validation has been performed.
- HCLI 0.28.0 lint passed with no recommendations for a temporary package built using sample author/repository metadata; no project-identity release archive or clean IDA install has been validated.
- The manifest uses the submitter-provided author name/email and targets `https://github.com/shobhit1kapoor/irqscope`; the public repository now exists and its initial validation workflow passed.
- SVD peripheral, cluster, register, field, and named enumerated-value-set `derivedFrom` resolution plus peripheral, cluster, register, and field array expansion are implemented in the local parser. CPU endianness, address units, and `nvicPrioBits` are retained for conservative byte-lane and conditional priority evidence. Validated `alternatePeripheral`, `alternateCluster`, and `alternateRegister` links are retained and shown separately from generic address aliases. Full schema validation and selection among shared-address SVD descriptions remain incomplete; address collisions are retained as aliases and surfaced as ambiguity.
- Inherited CMSIS-SVD `resetValue` and `resetMask` metadata is now retained, width-checked, shown in the register maps, and exported in evidence-v25. Reset metadata is descriptive only; the analyzer does not initialize a modeled hardware state from it.
- CMSIS-SVD `writeConstraint` ranges, enum-only rules, and write-as-read restrictions are retained at declared scopes; register constraints propagate to fields as defaults and explicit field constraints override or clear them. The source of each effective field constraint is shown in the map and exported in evidence-v25. Supported byte, halfword, and full-width stores check fully covered fields when SVD declares a fixed endian and 8-bit address units; partial field coverage, ambiguous SVD aliases, register-level enum composition, and write-as-read history remain unknown.
- Analyst-authored protocol JSON can declare a CFG-reachable foreground register sequence and ISR interference events, including cross-register interactions and optional exact/masked constant write-value or SVD field-enumeration constraints. A separate bounded miner proposes short foreground MMIO chains by following CFG event reachability, including loop-backs and repeated instruction events. CFG recovery filters constant CBZ/CBNZ, common flag conditions after CMP/CMN/ADDS/SUBS, and zero/sign conditions after TST/TEQ when operands are known, including supported constant shifted-register operands; other predicates remain unchecked. Proposals and contracts are analyst-review evidence, not proven device protocols. Transaction-boundary validation and state-machine reachability remain future work.
- MMIO scanning recognizes exact absolute-memory operands, base-plus-displacement accesses, and indexed LSL addresses when both base and index are constant and IDA renders the register expression. Bounded 32-bit propagation handles moves, literals, add/subtract/reverse-subtract/negate, MVN, bitwise operations with known rendered operands, UBFX/SBFX/BFI/BFC, and standalone LSL/LSR/ASR/ROR operations with known operands. Conditional branches are pruned only for constant CBZ/CBNZ, common CMP/CMN/ADDS/SUBS flag conditions, and TST/TEQ zero/sign conditions with known operands, including supported shifted-register operands; predicated compares and Thumb IT blocks are conservatively left unresolved, with register/mask facts dropped for the remainder of the basic block after an IT instruction. Other predicates, carry-dependent RRX, dynamic indices, unsupported forms, full pointer arithmetic, and generic MMIO helper summaries remain unresolved. A separate narrow pass recognizes direct and indexed stores through a rendered constant Cortex-M NVIC base in wrapper functions; index bounds and helper ABI are not proven.
- Recognized mask instructions and explicit CMSIS global mask intrinsics produce per-access PRIMASK/BASEPRI/FAULTMASK snapshots. When reachable CFG predecessors disagree on a mask value, the merged value becomes unknown and an analysis warning identifies the merge block and incoming values. Constant-argument NVIC API callsites are indexed and linked to vector slots. When SVD declares `nvicPrioBits`, a static CMSIS `NVIC_SetPriority` callsite and an observed BASEPRI value can produce a conditional threshold comparison; it does not prove callsite execution, effective enable state, or nested preemption. This is not a complete interrupt model and is not validated on target firmware.
- Vector-table detection is heuristic. A selected table should be manually checked against the image and device.
- The witness sketch follows CFG reachability to one later same-peripheral foreground MMIO event and shows observed same-peripheral accesses on the shortest handler path to the selected ISR event. The sequence miner proposes short multi-register foreground chains, but does not establish transaction boundaries; optional analyst-authored contracts can define a sequence and ISR interference. Only constant CBZ/CBNZ, common CMP/CMN/ADDS/SUBS flag conditions, and TST/TEQ zero/sign conditions with known supported operands are filtered; all other branch predicates remain unchecked. The analyzer also does not model interrupt priorities, enable state, RTOS tasks, DMA, or hardware evolution. It labels an external IRQ as blocked at a foreground instruction where PRIMASK or FAULTMASK is known set; that point snapshot does not establish whole-operation protection.
- Current findings must be described as triage candidates, not demonstrated races or confirmed defects.
- An authored synthetic firmware fixture, matching SVD, symbolized ELF, and stripped ELF are present. It includes destructive reads, masked/unmasked paths, W1C and ordinary assignment semantics, and a shifted-comparison branch with two constant MMIO stores. Their analysis output has not been verified in IDA; there is still no measured fixture matrix, screenshot/demo, release ZIP, official plugin listing, or contest submission.

### P0 — Prototype status

- [x] Add an IDA 9.5-targeted Python plugin entry point and manifest scaffold. Submitter-provided author metadata and the selected repository URL are recorded. Target-host compatibility remains unverified.
- [x] Parse local SVD arrays, fields, read/write side effects, and enumeration values (including named enumerated-value-set references); resolve peripheral, cluster, register, and field inheritance; preserve shared-address aliases; validate and retain ordered `alternatePeripheral`, `alternateCluster`, and `alternateRegister` references. Full schema validation and alias selection remain open.
- [x] Rank Cortex-M vector-table candidates, review entries, and offer to create missing handler function boundaries after confirmation.
- [x] Index absolute, base-plus-displacement, and constant-index LSL MMIO operands with CFG constant propagation, including bounded arithmetic, logical, bitfield, and shift operations; dynamic indexing, unsupported operand forms, full pointer arithmetic, and generic helper summaries remain open.
- [x] Prune CBZ/CBNZ with a known register, common CMP/CMN/ADDS/SUBS flag conditions, and TST/TEQ zero/sign conditions with known supported operands, including constant shifted-register forms; export each decision as an analysis warning and fall back to all-edge propagation if the bounded edge-sensitive pass does not converge.
- [x] Capture constant values for supported single-register MMIO stores and display them with matching SVD field encodings in the dashboard and evidence export; this is static evidence, not proof of execution.
- [x] Compare exact full-width cross-context constants under supported write-capable access policies and register-level or complete non-overlapping field-level SVD `modifiedWriteValues` rules, plus ordinary default assignments when no field map exists or writable fields cover the word; identify commuting final-state transforms and order-dependent bits with structured masks. Intermediate observations, hardware updates, partial writes, and alias ambiguity remain outside the model.
- [x] Infer bounded enable/disable/priority summaries for direct or indexed constant-base NVIC wrapper stores and expose their evidence basis in the dashboard and export. Indexed range/argument semantics remain heuristic.
- [x] Track recognized mask instructions, emit per-access mask snapshots, and report mask-state disagreement at CFG joins; this is not a complete priority or transaction-coverage proof.
- [x] Index constant-argument NVIC enable, disable, pending, and priority API callsites and map IRQn values to vector slots. This does not prove runtime reachability or current NVIC state.
- [x] Link each finding to recovered setup callsites for its handler IRQ and expose the static evidence in the witness inspector and JSON export; effective runtime state remains unknown.
- [x] Show register and access tables, candidate findings, IDA navigation, and JSON evidence export.
- [x] Add a dockable dashboard with device/access/finding overview, register and access tabs, candidate table, linked evidence view, navigation callbacks, filterable/sortable evidence tables, and stable row identity across sorting. Runtime and visual validation remain open.
- [x] Persist analyst verdicts and notes in a versioned IDB netnode and include them with the current finding set in JSON evidence exports. IDA save/reopen behavior still needs runtime validation.
- [x] Import analyst-authored peripheral transaction/interference contracts, validate register references against the SVD, support optional exact/masked constant write constraints, and report bounded CFG-reachable cross-register ISR candidates; branch feasibility and hardware state are not proven.
- [x] Support ordered ISR interference sequences in analyst-authored contracts, preserving matched handler events and inter-event CFG paths in the inspector and versioned export; branch predicates and runtime scheduling remain unresolved.
- [x] Select and display a candidate interrupt insertion gap between foreground contract events using the strongest available point mask snapshot; mask changes within the gap remain unproven.
- [x] Assemble matched analyst-contract foreground and ISR event chains into a conditional synchronized timeline in the witness inspector and evidence-v25 export, including context-local CFG paths, the selected insertion gap, its mask snapshot, and explicit limitations. This is not a multi-context scheduler proof.
- [x] Mine bounded CFG-traversed foreground MMIO chains with pairwise paths, loop/repeated-instruction candidates, repeated-pattern support, rationale, and limits; surface navigable proposals in the dashboard and evidence-v25 JSON. This does not prove transaction boundaries or branch feasibility.
- [x] Surface SVD-declared read and modified-write side-effect cues in sequence rationale and rank those proposals before pattern-only leads when applying the bounded output cap. This is SVD-informed triage, not runtime semantic proof.
- [x] Record proposal-specific analyst status and notes in the IDB review ledger, preserve them across reanalysis for the same input/SVD/proposal, and include them with proposal evidence in JSON export.
- [x] Convert a selected sequence proposal into an editable protocol-contract draft using observed mapped-handler patterns, with SVD import validation and explicit evidence/cap caveats.
- [x] Author and build symbolized plus stripped Cortex-M demo ELFs with a matching synthetic SVD.
- [x] Add a cross-platform clean-build check that compares both ELFs' functional sections and symbol tables with a clean build while allowing host-specific debug and ARM ABI metadata to differ.
- [ ] Load the plugin in a clean current IDA and confirm its UI/API behavior.
- [ ] Record the host edition, OS, embedded Python/Qt, decompiler availability, screenshots, and observed results using `docs/ida-validation.md`.
- [ ] Analyze both demo ELFs in IDA and record the observed results and misses.
- [x] Add a shortest CFG path and candidate single-event insertion sketch to each finding. It is not a complete event schedule or protocol violation proof.
- [x] Show the observed same-peripheral ISR MMIO prefix and its shortest recovered handler CFG path leading to the selected interrupt event. Branch feasibility and side effects between accesses remain unresolved.
- [ ] Add full path-predicate-aware multi-context schedule search, validated transaction boundaries, and assumption-level triage. The contract-backed candidate timeline is a selected-gap sketch, not a full synchronized scheduler or protocol-violation proof.
- [ ] Create the measured fixture matrix, screenshot/demo, release archive, and official plugin listing.

### P1 — Strong technical differentiator

- Microcode-backed constant propagation and def-use for MMIO addresses.
- Path-sensitive mask windows and function summaries for PRIMASK/BASEPRI/FAULTMASK.
- Handler priority/enable and nested preemption relation.
- Full handler-path and transaction-aware interleaving witness generation with bounded search.
- [x] Bounded review-only mining of status/data/control sequence proposals; full path-sensitive transaction recovery remains open.
- [x] Add a six-dimension evidence profile to the witness inspector and JSON export, with per-dimension evidence and limits. The profile is categorical and does not claim calibrated probabilities.
- [x] Make CFG propagation iteration-limit failures visible in the dashboard and evidence export; do not silently imply convergence.
- [x] Add cancellable progress reporting across IDA scans, cross-context candidate generation, bounded sequence mining, and protocol matching; preserve the last completed analysis on cancellation. Runtime behavior still needs host validation.

### P2 — Research extensions

- RTOS tasks and scheduler/critical-section models.
- DMA ownership and completion event semantics.
- User-authored peripheral automata and SVD-to-protocol dependency modeling.
- Trace import for corroboration (document source format and synchronization assumptions).
- Symbolic execution or emulation as optional witness validation, never a required dependency.
- Cross-version firmware model comparison and shared analyst annotation bundles.

## Exit gates

Before calling the plugin contest-ready:

- Install from the packaged archive in a clean IDA 9.5 environment with ARM disassembly and IDAPython (IDA Home with ARM selected, IDA Pro, or eligible IDA Classroom).
- Confirm the plugin loads without Hex-Rays installed; verify microcode features degrade gracefully.
- Run the full fixture corpus and publish expected-versus-observed results.
- Verify IDB save/reopen preserves manual models and verdicts.
- [x] Build and validate the project-metadata release archive with HCLI 0.28.0; lint returns no recommendations.
- [ ] Install the package in a clean IDA 9.5 environment with ARM disassembly and IDAPython.
- Ensure README clearly distinguishes implemented features from roadmap items.
- Publish the official plugin listing early enough for repository propagation, then submit the contest form before the deadline.

These are proposed gates, not checks performed in this workspace. The prototype now includes the local SVD and protocol-contract workflows, CFG-based MMIO and mask recovery, interrupt setup evidence, candidate review, IDB verdict persistence, JSON export, and authored Cortex-M fixtures. The public GitHub source and HCLI-linted project-metadata archive are ready for review, but no IDA runtime validation, official plugin listing, or contest submission has been completed.
