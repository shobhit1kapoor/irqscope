# Evidence JSON v25

IRQScope exports `irqscope-evidence-v25`. The existing analysis records remain available alongside a `provenance` object for reproducibility. MMIO access records also include an optional constant write value and its recovery basis, plus per-write constraint check results. Findings may include a structured `write_effect_relation` when exact stores and SVD semantics support a commuting or order-dependent final-state classification. The SVD register map now preserves reset values/masks and declared register/field write constraints. Top-level `svd_endianness`, `address_unit_bits`, and `nvic_priority_bits` record device properties used in lane mapping and conditional priority analysis.

## Register reset evidence

Each register description includes `reset_value` and `reset_mask` as hexadecimal strings or `null` when not specified after CMSIS-SVD inheritance. A reset mask bit of one identifies a bit with a defined reset value; zero means that bit's reset state is unspecified. `reset_value` is retained as described, and analysts should use `reset_value & reset_mask` when interpreting only known reset bits. IRQScope displays the value and known mask separately and may decode a fully known field using its SVD read or read-write enumeration; write-only command names are not presented as current reset states. Missing reset metadata is not treated as zero or as proof that all bits are defined.

## Declared write constraints

Register and field descriptions include an optional `write_constraint` object with `kind` set to `range`, `enumerated-values-only`, or `write-as-read`. Range constraints include hexadecimal `minimum` and `maximum`; other kinds use `null` endpoints. Field descriptions include `write_constraint_source` (`field`, `register-default`, or `null`) so consumers can distinguish explicit overrides from inherited constraints; an explicit field-level false declaration clears the register default. MMIO access records include `write_constraint_checks`: each check has a register/field `scope`, `kind`, `status` (`satisfied`, `violated`, or `unknown`), checked `value`, and `detail`. Supported byte and halfword writes are mapped to register lanes using the SVD-declared fixed CPU endianness and 8-bit address units; a field is checked only when the store covers that entire field. Partially covered fields, ambiguous SVD aliases, register-level enum composition, and write-as-read history remain unknown. Checks are static and do not prove the instruction executes.

## MMIO write values

Each access contains `value` and `value_evidence`. `value` is a hexadecimal string when IRQScope proves a constant source for a supported single-register store, otherwise `null`. `value_evidence` identifies `immediate-operand` or `constant-propagated-register`; it is `null` when no value was recovered. Register-field enumerations are decoded in the dashboard when the SVD declares matching write or read-write encodings. This is static value propagation and does not establish that a store executes at runtime.

## Conditional BASEPRI priority assessment

Findings include `priority_assessment` when the SVD and static setup evidence allow a result. The object contains `status`, IRQ number, `priority_bits`, the raw CMSIS `logical_priority`, its encoded eight-bit value, the implemented-bit-masked `basepri_threshold`, priority callsite addresses, and a `detail` explanation. Status can be `conditional-basepri-block`, `conditional-basepri-permit`, `basepri-clear`, or `unknown`. CMSIS priority arguments are encoded using `nvic_priority_bits`; `BASEPRI` is compared only across implemented priority bits. A conditional result does not prove the setup call executes, that no later setting overrides it, that the IRQ is enabled, or that the interrupt preempts at the candidate access. Missing or conflicting priority callsites and missing SVD priority width remain unknown.

## Conditional synchronized candidate timeline

Protocol findings include `candidate_timeline` when the matched foreground sequence, matched ISR interference sequence, and selected insertion gap are all available. Its status is `conditional-synchronized-insertion-candidate`. `insertion_gap` names the zero-based foreground event immediately before and after the proposed ISR insertion. `mask_snapshot` records the state used to rank that point. `steps` is an ordered list with a zero-based `order`, `context` (`foreground` or `interrupt`), context-local `event_index`, serialized `access`, optional `cfg_path`, and `path_scope`. Paths connect successive events within one context; the first event has no predecessor path. `limitations` accompanies the sequence so consumers do not mistake the cross-context ordering sketch for a verified schedule. This timeline is derived from an analyst-authored contract and one selected point snapshot; it does not establish runtime IRQ eligibility, complete path predicates, or hardware state evolution. Other finding types and protocol findings without a valid insertion gap use `null`.

## SVD write-effect relation

`write_effect_relation` is `null` unless both cross-context writes have exact full-width constant values, writable access policies, and supported semantics. These are complete register-level or non-overlapping field-level `modifiedWriteValues` rules, or ordinary full-word assignment semantics when no field map exists or the writable field map covers the word. When present, `scope` is `register`, `fields`, or `register-default`; `*_operations_by_bit_lsb_first` lists each bit's modeled clear/set/toggle/assignment operation starting at bit 0; `*_active_mask` marks the bits each store affects; `overlap_mask` marks bits affected by both stores; and `conflict_mask` marks overlapping bits where the modeled transformations differ, including bits assigned different constant values. `final_state_transforms_commute` records whether the modeled transformations commute. This result covers final state under imported SVD semantics only; it does not model observations between stores, hardware updates, or undocumented device effects.

The top-level `warnings` list includes edges pruned for constant CBZ/CBNZ and supported flag conditions immediately following CMP/CMN/ADDS/SUBS or zero/sign conditions following TST/TEQ when operands resolve through the bounded constant resolver, including supported shifted-register forms. These arithmetic flag sources support EQ/NE, MI/PL, VS/VC, CS/HS, CC/LO, HI/LS, and signed GE/LT/GT/LE; TST/TEQ support EQ/NE and MI/PL because carry/overflow may depend on preserved prior flags. Predicated comparisons and instructions inside Thumb IT blocks are left unresolved. Warnings also include conflicting mask states at CFG joins, propagation fallbacks, and convergence limits. Unsupported compare/flag branches are not evaluated.

## Provenance fields

| Field | Meaning |
|---|---|
| `analysis_id` | SHA-256 over canonical JSON for the complete export, excluding `generated_unix_time` and `provenance.analysis_id` itself. Different findings or annotations therefore produce a different ID even when the input firmware and settings are unchanged. |
| `irqscope_version` | Version from `irqscope.__version__`. |
| `plugin_source_sha256` | SHA-256 over `irqscope_plugin.py` and all `irqscope/*.py` files in sorted path order, with relative paths and content lengths included. `unavailable` means a source file could not be read. |
| `ida_kernel_version` | Value reported by `ida_kernwin.get_kernel_version()`, or `unknown`. |
| `python_version` / `platform` | Python runtime version and Python's platform description. |
| `input_sha256` | Hash associated with the open firmware input. |
| `input_hash_basis` | `ida-recorded-input-sha256`, `input-file-content`, or `root-filename-fallback`. The last case identifies only a name and is not binary integrity evidence. |
| `svd_sha256` / `protocol_sha256` | Hashes of the imported device description and optional protocol contract. A missing protocol is `null`. |
| `vector_mapping` | Selected vector slots, handler addresses, and any mapped IDA function addresses. |

`generated_unix_time` is excluded from the identity, so exporting byte-for-byte identical evidence again does not change its `analysis_id`. The top-level `ida_input` path is included as part of the export content. Hashes identify inputs and exported evidence; they do not prove that the SVD or analyst-authored protocol accurately models the hardware.
