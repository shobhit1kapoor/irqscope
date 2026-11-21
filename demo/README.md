# IRQScope synthetic Cortex-M demo

This authored fixture creates a small Cortex-M4 ELF with a vector table, ISRs, an unmasked foreground transaction, and a PRIMASK-protected counterpart. `demo.svd` describes a deliberately synthetic UART-like device whose `STATUS` read is destructive. It also includes device-level reset value/mask defaults inherited by each register, an ordinary full-word `CONFIG` register for order-dependent constant-write analysis, and a W1C `EVENTS` register for disjoint, commuting acknowledgements. The reset metadata is synthetic and pedagogical, not a claim about a commercial MCU.

[`alternate-peripheral.svd`](alternate-peripheral.svd) is a separate import fixture for CMSIS-SVD `alternatePeripheral`, `alternateCluster`, and `alternateRegister`. It shows `PORTA_ANALOG` as a mode-specific view of the `PORTA` address block, `PORTA.DATA_ANALOG` as a same-peripheral alias of `PORTA.DATA`, and `PORTA.PIN_ANALOG` as an alternate cluster of `PORTA.PIN`. Loading it in the dashboard should show all three relationships and retain descriptions at shared addresses. It is not used for firmware ELF analysis.

## Build and verify

With Clang, LLD, `llvm-strip`, and `llvm-objdump` installed, regenerate both artifacts with:

```sh
python tools/build_demo.py
```

Check that the checked-in symbolized ELF and stripped ELF exactly match clean builds without changing either file. The check also inspects the section table and disassembly for the vector table, masked/unmasked transaction shapes, ISR, indexed NVIC store case, constant-write functions, and shifted-comparison branch fixture:

```sh
python tools/build_demo.py --check
```

The symbolized ELF contains the Cortex-M4 vector table, MOVW/MOVT peripheral-base construction, register-offset loads/stores, `MRS PRIMASK`, `CPSID i`, `MSR PRIMASK`, and named CMSIS-shaped `NVIC_EnableIRQ`, `NVIC_DisableIRQ`, and `NVIC_SetPriority` setup calls. The stripped ELF retains vector and executable sections but removes those names. The compiler-generated NVIC wrappers use indexed addressing; IRQScope now has a narrow fallback that resolves the rendered base register and recognizes NVIC-range stores. This summary path has mocked adapter coverage but has not been exercised in IDA, and the computed index/argument semantics remain heuristic.

Open the ELF in IDA as an ARM Cortex-M image. Import `demo/demo.svd`, optionally import `demo/uart-protocol.json` from the dashboard's **Protocol** action, review the vector-table candidate at `0x08000000`, and analyze. The intended comparison is `transfer_unsafe` versus `transfer_masked`; the second function saves/restores PRIMASK around the operation.

## Expected analysis story

- MOVW/MOVT-constructed peripheral base plus register offset resolves to `SIMUART.STATUS`, `DATA`, and `CONTROL`.
- The Device Map shows the `READY` read encodings (`NOT_READY`, `READY`), including `READY=NOT_READY` at the declared synthetic reset state, and the `START` write commands (`IDLE`, `BEGIN_TRANSFER`) from the synthetic SVD.
- `CONFIG.MODE` declares that writes must use one of its SVD enumerated values. IRQScope checks supported full-width recovered constants against this restriction; partial-width stores and other unsupported forms remain unknown.
- `invalid_config_mode_write_fixture` writes `CONFIG=0x7`, which encodes the unlisted `MODE=3`; a full-width constant recovery should report the declared enum-only constraint as violated. This is a static instruction result, not proof that firmware executes the function.
- The device-level reset default (`0x0`, known mask `0xFFFFFFFF`) should appear on each register after SVD inheritance; these synthetic reset bits are descriptive evidence and are not used to initialize the analysis state.
- `USART_IRQHandler` maps from external vector slot 16.
- The unsafe function has no recognized mask around its accesses.
- The protected function should show PRIMASK set at its MMIO instructions; the MVP still reports any shared access as a candidate and explains that a point snapshot is not whole-operation proof.
- `configure_and_acknowledge_foreground` writes `SIMUART.CONFIG=0x3` then `SIMUART.EVENTS=0x1`; `TIMER_IRQHandler` writes CONFIG=`0x1`, so the ordinary full-word assignments are order-dependent on bits `0x2`.
- `USART_IRQHandler` writes EVENTS=`0x2`; the SVD marks that register W1C, so its clear mask is disjoint from the foreground's `0x1` and the modeled final transforms commute.
- `branch_shifted_constant_fixture` compares `8` with `2 << 2`, then has CONFIG=`0x3` and CONFIG=`0x1` stores on opposite edges. The expected feasible edge keeps only the first store; the emitted disassembly retains the CMP/LSL/BNE and both stores for CFG analysis.
- In the symbolized image, the **Interrupt setup** dashboard tab should list calls for external IRQs 0 and 1, their vector slots, priority arguments, and mapped handlers. This remains static callsite evidence, not effective runtime NVIC state. Those API names are absent from the stripped image.
- The SVD read-to-clear metadata raises the `STATUS` interaction for analyst review.
- The candidate details should show the foreground `STATUS` access, one shortest CFG block path to a later same-peripheral access, and the ISR access as an insertion sketch. This is not a proof of an actual hardware schedule.
- With `uart-protocol.json` loaded, IRQScope can additionally match the declared `STATUS → DATA → CONTROL → STATUS → DATA` foreground sequence against the handler's declared `STATUS` read, `DATA` read, and `CONTROL` write interference. This contract is intentionally synthetic and its sequence/path feasibility must be confirmed in IDA; no observed run is claimed here.
- The second contract uses the SVD name `MODE=FAST` plus the exact EVENTS write value to match the foreground `CONFIG=3 → EVENTS=1` transaction, then matches handler writes `CONFIG=1` and `EVENTS=2`. The enum mask distinguishes the order-dependent configuration assignment from the disjoint W1C acknowledgement.

This is a fixture specification, not a verified plugin result. The plugin has not been run in IDA, so the expected findings and current prototype coverage remain unconfirmed.
