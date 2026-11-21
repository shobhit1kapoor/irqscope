# IDA 9.5 host validation

Use this checklist to turn the synthetic fixture into runtime evidence before release. The current workspace has not completed these steps.

## Host requirements

Use IDA 9.5 with an ARM disassembler and IDAPython enabled. IDA Home with ARM selected, IDA Pro, or an eligible IDA Classroom installation can provide the needed capabilities. IDA Free is not a valid host for this project: Hex-Rays lists it as x86-only and without the IDAPython development kit ([edition comparison](https://hex-rays.com/ida-free)). IRQScope itself does not require the Hex-Rays decompiler; include a run without a decompiler to confirm graceful behavior.

## Load and analyze the fixtures

1. Start with a clean IDA 9.5 user configuration and record the edition, operating system, Python version, and whether a decompiler is available.
2. Install the source tree by copying `irqscope_plugin.py` and the `irqscope` package directory into the IDA user plugins directory. Restart IDA and open **Edit → Plugins → IRQScope: Open Analysis Dashboard**. Record plugin load errors and a screenshot of the initial dashboard. Where the host supports both appearances, check the dashboard in light and dark themes, including the witness evidence labels and tables.
3. Open `demo/irqscope_demo.elf` as ARM Cortex-M firmware. Select the vector table at `0x08000000`, import `demo/demo.svd`, optionally import `demo/uart-protocol.json`, and analyze. Save the IDB.
4. Record observed results for `transfer_unsafe`, `transfer_masked`, `configure_and_acknowledge_foreground`, `invalid_config_mode_write_fixture`, `branch_shifted_constant_fixture`, both mapped handlers, and the external IRQ 0/1 setup callsites. Inspect the MMIO, mask, CFG path, witness, SVD semantics, write-constraint check, protocol, and candidate review panes. Compare each observation with the [fixture specification](../demo/README.md); do not treat an expected result as observed until it appears in IDA.
5. Check the adversarial cases explicitly: the shifted `CMP r0, r1, LSL #2` should make `BNE` infeasible and retain only the CONFIG=`0x3` store; CONFIG=`0x3` versus timer CONFIG=`0x1` should yield an order-dependent mask of `0x2`; foreground EVENTS=`0x1` versus USART EVENTS=`0x2` should be modeled as disjoint W1C effects; the `MODE=FAST` contract filter should match the foreground CONFIG store but not the timer value; and the `CONFIG=0x7` fixture should show a violated enum-only constraint for MODE=`3`. Check that the evidence-v25 candidate timeline orders the foreground contract around its selected ISR insertion and retains CFG paths and limitations. Record the actual result, any missing evidence, and the rendered operand spelling if branch pruning abstains.
6. Close and reopen the IDB. Check that finding and proposal review notes/status persist and that evidence export contains the same reviewed records.
7. Repeat with `demo/irqscope_demo_stripped.elf`. Record which name-based detections disappear, which address/CFG recovery still works, and any false or missing results.
8. Repeat analysis with Hex-Rays unavailable, then capture startup, import, analysis, export, and any failure dialogs. Confirm unsupported optional features degrade without preventing the base workflow.

## Results record

For each host run, record:

| Field | Value |
|---|---|
| IDA build and edition | |
| OS / Python / Qt binding | |
| Hex-Rays decompiler available | |
| Fixture and SHA-256 | |
| Analysis duration | |
| Vector table selected | |
| MMIO accesses recovered | |
| Findings by function and rule | |
| Branches pruned and reason | |
| Recovered write values / semantic masks | |
| Protocol value or enum constraints matched | |
| Expected results missed | |
| Unexpected candidates | |
| Review persistence after reopen | |
| Export path and schema version | |
| Load/runtime errors | |
| Screenshot paths | |

Keep this record with the release artifacts. A successful HCLI manifest lint is package validation only; it does not replace any host steps above.
