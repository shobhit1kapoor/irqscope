# IRQScope protocol contracts

Protocol contracts let an analyst describe a multi-register device operation that is not encoded as one function or one register access. IRQScope validates every register name against the currently imported CMSIS-SVD, then compares the declared foreground sequence with MMIO events in functions mapped from the selected vector table.

## Format

```json
{
  "format": "irqscope-protocol-v1",
  "name": "Device operation model",
  "transactions": [
    {
      "name": "poll-submit-wait-read",
      "peripheral": "SIMUART",
      "interference_mode": "sequence",
      "description": "Optional analyst explanation.",
      "steps": [
        { "register": "STATUS", "operation": "read" },
        { "register": "DATA", "operation": "write" },
        { "register": "CONTROL", "operation": "write", "value": 1, "value_mask": 1 }
      ],
      "interference": [
        {
          "register": "STATUS",
          "operation": "read",
          "reason": "Optional reason this handler event may disturb the transaction."
        }
      ]
    }
  ]
}
```

`register` accepts a name within the declared peripheral (`STATUS`) or its full `Peripheral.Register` name. `operation` must be `read` or `write`. Optional `value` is a non-negative JSON integer that must fit the register width and is allowed only for writes. Without `value_mask`, it requires an exact full-register constant. With `value_mask`, the mask must be a non-zero in-range integer and the contract compares only selected bits; `value` may not set bits outside the mask. As an alternative, a write event may provide both `field` and `enumeration` to name a writable SVD field encoding. IRQScope resolves exact numeric enum values and wildcard bit patterns into a register-level value/mask comparison; default or non-numeric entries are rejected. Enum constraints cannot be combined with `value` or `value_mask`. A constrained event does not match when the static write value is unknown or when the store is too narrow to cover the requested mask. For a partial-width store, IRQScope shifts the observed value into register-relative bit positions only when the effective MMIO address, fixed SVD endianness, byte address units, and access width establish its lane. It abstains from value matching when any of that metadata is missing or inconsistent. Accesses are currently associated with a register through the adapter's exact SVD address lookup; a store to an interior address is not automatically assigned to a register. These fields are additive and optional in `irqscope-protocol-v1`, so existing contracts remain valid. A transaction needs at least two ordered foreground steps and one or more interference events. `interference_mode` accepts `any` or `sequence` and defaults to `any` for older contracts. `any` reports each matching handler access independently; `sequence` requires the listed ISR events in order along recovered CFG paths and reports the complete event chain. `reason` and `description` are optional and appear in the candidate explanation or assumptions.

The Sequence Mining dashboard can save a selected proposal as an editable draft in this format. Its foreground steps are copied from the proposal, and its interference list is populated from distinct observed MMIO patterns in mapped handlers for the same peripheral (up to 32). Recovered full-width constant writes are preserved as optional exact-value filters; edit them if those values should not constrain the draft. The saved description identifies the proposal as heuristic and asks for manual validation. IRQScope does not assert that the handler accesses conflict with the foreground operation. Review the resulting JSON, then import it to validate register identities against the selected SVD.

The importer rejects unknown or ambiguous register names. It accepts at most 1 MiB, 256 transactions, and 32 events in each step/interference list. Analysis retains at most 128 foreground sequences per function and 10,000 protocol findings; if a search cap is reached, the evidence export reports possible truncation.

## How matching works

For each non-handler function, IRQScope searches for a sequence of recovered MMIO accesses matching the declared steps in order, including any exact or masked write-value constraints. Consecutive events must have a recovered CFG path between their blocks; accesses in one block must appear in increasing address order. It then finds mapped vector-handler accesses matching the declared interference patterns. In `sequence` mode the same ordered path check is applied inside one handler function. The finding and evidence export retain every matched foreground and ISR event, including each recovered MMIO effective address, the recovered CFG paths, protocol content, and protocol SHA-256.

For a protocol finding, IRQScope chooses one candidate insertion gap between matched foreground events. It prefers a gap whose preceding access has a known mask snapshot that permits configurable IRQ delivery; unknown snapshots rank below that, and observed blocked snapshots rank last. The inspector labels that gap and reports its saved snapshot. Mask changes between the preceding access and the next transaction event are not reconstructed, so this is a review aid rather than an exact scheduling proof.

## Interpretation limits

A match is a review candidate, not a proof of a device protocol violation. The analyst supplied the transaction semantics. Numeric and SVD-enumeration write constraints only match statically recovered constants; they do not prove execution or account for runtime values. CFG pruning handles constant CBZ/CBNZ, common ARM conditions after CMP/CMN/ADDS/SUBS, and zero/sign conditions after TST/TEQ when operands resolve through the bounded constant resolver, including supported shifted-register forms; other branch predicates remain unchecked. The matcher does not prove that an interrupt is enabled, can preempt at that exact point, or changes the hardware state as described. It does not model transaction guards, loop counts, field-value predicates beyond the declared write filter, priorities, nested scheduling, or hardware evolution. A blocked mask snapshot at the first foreground access does not prove the entire transaction is protected. Review every candidate against the device reference manual and firmware context.

The synthetic example is [`../demo/uart-protocol.json`](../demo/uart-protocol.json), paired with [`../demo/demo.svd`](../demo/demo.svd).
