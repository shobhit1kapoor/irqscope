# IRQScope Contest Playbook

## Contest strategy

Hex-Rays describes plugins it likes using examples—automation, visualization/navigation/collaboration, integrations, architecture/format support, and advanced/AI techniques—but does not publish a weighted numeric scorecard. Treat those examples as a design fit, not promises about judging.

| What judges can assess | IRQScope evidence to show |
|---|---|
| Technical depth | Binary-first interrupt-context recovery, SVD semantics, a bounded interleaving witness with a concrete path |
| Immediate usefulness | The reviewer can jump from finding to the two disassembly locations and inspect the assumed hardware behavior |
| IDA fit | Results use IDA functions, EAs, xrefs, pseudocode, and an IDB-local review workflow |
| Originality | Explain PASan and IEmu as prior art, then show the narrower contribution: evidence-linked review of stripped binaries directly in IDA |
| Product quality | Clean installation, usable empty states, defensible confidence labels, fast analysis, visible limitations |
| Communication | One short demo reproducer, sample binary, README walkthrough, architecture note, and fixture results |

Avoid presenting “AI-powered” as the innovation. IRQScope's differentiator is the analysis object: a concrete, reviewable candidate execution schedule with a device contract and provenance.

## Suggested four-minute demonstration

1. **Orient (20 seconds):** open a tiny stripped Cortex-M image; show IRQScope has no server, no network transfer, and no required vendor symbols.
2. **Load device knowledge (30 seconds):** import the authored SVD; show register names, field positions, read/write enum values, and a read-to-clear status field with its source.
3. **Recover contexts (35 seconds):** select the ranked vector-table candidate, inspect mapped handler slots, and show which slots remain unresolved. In the symbolized demo, use **Interrupt setup** to show the NVIC API callsites and constant IRQ arguments, then open a candidate to inspect only the setup calls for its IRQ; state clearly that these callsites do not prove runtime enable state.
4. **Surface the scenario (35 seconds):** run analysis; filter to one peripheral and one cross-context candidate; open its evidence panel.
5. **Show the core idea (75 seconds):** display the conditional synchronized candidate timeline around the selected foreground gap; click each event/block to jump to its IDA EA; show mask state and the still-unknown priority/contract assumptions. Explain that the timeline orders contract-matched CFG events but does not prove runtime scheduling.
6. **Prove the tool can abstain (30 seconds):** switch to a safe fixture where the critical section or non-destructive register behavior removes the semantic conflict. Show “no witness under this model,” not “the firmware is safe.”
7. **Close (15 seconds):** export evidence JSON and point to the reproducible fixture and limitation section.

The authored fixture now pairs an ordinary full-word assignment conflict (`SIMUART.CONFIG`) with disjoint W1C acknowledgements (`SIMUART.EVENTS`) alongside its destructive-status and interrupt-masking examples. IRQScope's source model compares exact full-width constant writes for both cases. This expected story has not been confirmed by running the plugin in IDA; safe-versus-unsafe proof comparison remains unimplemented. The demo must be updated to match shipped code; never animate an unimplemented feature as if it ran.

The [local evaluation matrix](evaluation.md) tracks measured checks separately from IDA-only claims. It deliberately records no firmware recall or false-positive metric until the actual IDA fixture matrix has been run.

## Benchmark that signals serious engineering

The fixture suite should be a compact adversarial ladder, not a pile of unrelated vulnerable snippets:

| Fixture pair | Unsafe case | Safe/lookalike control |
|---|---|---|
| Read side effect | Handler reads a status field that clears state during foreground poll | Same access on a non-destructive status field |
| W1C semantics | Handler clears a pending bit while foreground updates a neighboring control bit | Disjoint field masks proven to commute |
| Interrupt masking | Relevant configurable IRQ can preempt in the window | Mask held across the whole operation and restored correctly |
| Priority edge | Lower-priority handler cannot preempt active context | Higher-priority handler remains eligible under BASEPRI |
| Path feasibility | Apparent event sequence lies on mutually exclusive branches | Feasible sequence reaches both accesses |
| Helper indirection | MMIO address passed through a small helper | Similar constant is only logged as data, not dereferenced |
| DMA ownership | Completion interrupt races with buffer reuse under a declared DMA contract | Ownership transfers after completion acknowledgement |
| Bad metadata | Incorrect SVD side effect would create a false finding | UI exposes the SVD assumption and override |

Each fixture needs an expected analysis tier, assumptions, and acceptable abstention result. Publish both false positives and missed cases. The most persuasive result is a measured reduction in analyst effort while preserving traceability, not a high raw alert count.

## Submission release checklist

The official contest page currently requires an official plugin-repository entry with a GitHub source link, a README with an overview, installation/use instructions, and preferred author credit, plus `ida-plugin.json`, followed by the contest form. HCLI documents ZIP packaging and `hcli plugin lint`. Build these before spending time on visual polish:

1. Confirm the public repository exists, keep the submitter-provided author metadata in the manifest, and verify the MIT license.
2. Pin supported IDA versions to those actually exercised, including the current latest version.
3. Build the deterministic source package with `python tools/package_release.py --github-repository <url> --author <name> --author-email <email>` and validate the archive with `hcli plugin lint`.
4. Install it into a clean supported IDA build, analyze both fixtures, record misses and environment versions, and capture the actual UI.
5. Create a semantic version tag and GitHub release using the validated archive.
6. Verify the plugin appears in the official repository after indexing.
7. Submit the contest form only after the listing is public.

The contest deadline is November 30, 2026; as of November 21, publication lead time makes this an unusually tight release window. A credible limited plugin is stronger than a video claiming the full roadmap is implemented.

## Sources

- [IDA Plugin Contest requirements and examples](https://hex-rays.com/plugin-contest)
- [HCLI packaging format and manifest requirements](https://hcli.docs.hex-rays.com/reference/plugin-packaging-and-format/)
- [PASan research](https://www.usenix.org/system/files/sec21fall-kim.pdf)
- [IEmu research](https://www.sciencedirect.com/science/article/pii/S1383762124001747)
