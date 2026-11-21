import json
import os
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

from irqscope.model import (
    CFGBlock, DeviceModel, InterruptConfigEvent, MMIOAccess, Register, TransactionProposal,
)
from irqscope.protocols import build_protocol_draft, build_protocol_findings, parse_protocol
from irqscope.timeline import build_candidate_timeline


class ProtocolAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.device = DeviceModel("Fixture", registers={
            0x40000000: Register("UART", "STATUS", 0x40000000, 32),
            0x40000004: Register("UART", "CONTROL", 0x40000004, 32),
            0x40000008: Register("UART", "DATA", 0x40000008, 32),
            0x4000000C: Register("UART", "CONFIG", 0x4000000C, 32),
        })

    def parse_contract(self, contract):
        handle, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as target:
                json.dump(contract, target)
            return parse_protocol(path, self.device)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def make_access(self, ea, function, name, operation, block,
                    primask=None, basepri=None, faultmask=None):
        register = self.device.get_register({
            "STATUS": 0x40000000, "CONTROL": 0x40000004, "DATA": 0x40000008,
            "CONFIG": 0x4000000C,
        }[name])
        return MMIOAccess(ea, function, f"fn_{function:X}", register, operation, 32,
                          "fixture", primask=primask, basepri=basepri,
                          faultmask=faultmask, block_start_ea=block)

    def test_sequence_produces_valid_editable_protocol_draft(self):
        first = self.make_access(0x110, 0x100, "STATUS", "read", 0x100)
        second = self.make_access(0x120, 0x100, "CONTROL", "write", 0x100)
        handler_status = self.make_access(0x210, 0x200, "STATUS", "read", 0x200)
        handler_data = self.make_access(0x220, 0x200, "DATA", "write", 0x220)
        proposal = TransactionProposal(
            proposal_id="0123456789abcdef",
            function_ea=0x100,
            function_name="transfer",
            peripheral="UART",
            events=(first, second),
            paths=((0x100,),),
        )

        draft = build_protocol_draft(
            proposal, [handler_status, handler_data, handler_status]
        )
        parsed = self.parse_contract(draft)

        self.assertEqual(draft["format"], "irqscope-protocol-v1")
        self.assertEqual(parsed.transactions[0].name, "candidate-0123456789abcdef")
        self.assertEqual([item.register for item in parsed.transactions[0].steps],
                         ["UART.STATUS", "UART.CONTROL"])
        self.assertEqual([item.register for item in parsed.transactions[0].interference],
                         ["UART.STATUS", "UART.DATA"])
        self.assertEqual(parsed.transactions[0].interference_mode, "any")
        self.assertIn("Confirm the transaction boundary", parsed.transactions[0].description)

    def test_protocol_draft_requires_handler_evidence(self):
        first = self.make_access(0x110, 0x100, "STATUS", "read", 0x100)
        second = self.make_access(0x120, 0x100, "CONTROL", "write", 0x100)
        proposal = TransactionProposal(
            "abcdef0123456789", 0x100, "transfer", "UART", (first, second), ((0x100,),)
        )
        with self.assertRaisesRegex(ValueError, "No mapped interrupt-handler"):
            build_protocol_draft(proposal, [])

    def test_protocol_draft_reports_interference_cap(self):
        first = self.make_access(0x110, 0x100, "STATUS", "read", 0x100)
        second = self.make_access(0x120, 0x100, "CONTROL", "write", 0x100)
        proposal = TransactionProposal(
            "abcdef0123456789", 0x100, "transfer", "UART", (first, second), ((0x100,),)
        )
        accesses = []
        for index in range(33):
            register = Register("UART", f"REG{index}", 0x40001000 + index * 4, 32)
            self.device.registers[register.address] = register
            accesses.append(MMIOAccess(
                0x200 + index, 0x200, "IRQHandler", register, "write", 32, "fixture"
            ))

        draft = build_protocol_draft(proposal, accesses)
        transaction = draft["transactions"][0]

        self.assertEqual(len(transaction["interference"]), 32)
        self.assertIn("capped at 32", transaction["description"])

    def test_contract_finds_cross_register_interference(self):
        protocol = self.parse_contract({
            "format": "irqscope-protocol-v1",
            "name": "UART transaction model",
            "transactions": [{
                "name": "poll then arm",
                "peripheral": "UART",
                "description": "Read status before arming the transfer.",
                "steps": [
                    {"register": "STATUS", "operation": "read"},
                    {"register": "CONTROL", "operation": "write"},
                ],
                "interference": [{
                    "register": "DATA", "operation": "write",
                    "reason": "The handler consumes or replaces the pending word.",
                }],
            }],
        })
        accesses = [
            self.make_access(0x110, 0x100, "STATUS", "read", 0x100),
            self.make_access(0x120, 0x100, "CONTROL", "write", 0x100),
            self.make_access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x130)},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }
        setup = (
            InterruptConfigEvent(0x300, 0x100, "configure", 0, "enable"),
            InterruptConfigEvent(0x308, 0x100, "configure", 1, "disable"),
        )
        findings = build_protocol_findings(
            protocol, self.device, accesses, {0x200: 16}, cfg, setup
        ).findings

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "IRQSCOPE.PROTOCOL_INTERLEAVING")
        self.assertEqual(finding.protocol_name, "poll then arm")
        self.assertEqual([event.register.name for event in finding.protocol_events], ["STATUS", "CONTROL"])
        self.assertEqual(finding.witness.foreground_resume.ea, 0x120)
        self.assertEqual(finding.confidence, "analyst-contract-candidate")
        self.assertEqual([(event.irq_number, event.operation)
                          for event in finding.interrupt_configuration], [(0, "enable")])

    def test_partial_write_value_matching_uses_endian_register_lanes(self):
        contract = {
            "format": "irqscope-protocol-v1",
            "name": "endian-aware UART model",
            "transactions": [{
                "name": "configure then arm",
                "peripheral": "UART",
                "steps": [
                    {"register": "STATUS", "operation": "read"},
                    {"register": "CONFIG", "operation": "write",
                     "value": 0xAB000000, "value_mask": 0xFF000000},
                ],
                "interference": [{"register": "DATA", "operation": "write"}],
            }],
        }
        protocol = self.parse_contract(contract)
        config = self.device.get_register(0x4000000C)
        accesses = [
            self.make_access(0x110, 0x100, "STATUS", "read", 0x100),
            replace(
                self.make_access(0x120, 0x100, "CONFIG", "write", 0x100),
                width_bits=8, value=0xAB, access_address=config.address,
            ),
            self.make_access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x130)},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }

        self.device.endianness = "big"
        self.device.address_unit_bits = 8
        big_endian = build_protocol_findings(
            protocol, self.device, accesses, {0x200: 16}, cfg
        )
        self.assertEqual(len(big_endian.findings), 1)

        self.device.endianness = "little"
        little_endian = build_protocol_findings(
            protocol, self.device, accesses, {0x200: 16}, cfg
        )
        self.assertEqual(little_endian.findings, ())

        self.device.endianness = "big"
        missing_address = [accesses[0], replace(accesses[1], access_address=None), accesses[2]]
        unknown_lane = build_protocol_findings(
            protocol, self.device, missing_address, {0x200: 16}, cfg
        )
        self.assertEqual(unknown_lane.findings, ())

    def test_ordered_interference_chain_and_best_insertion_gap_are_preserved(self):
        protocol = self.parse_contract({
            "format": "irqscope-protocol-v1",
            "name": "ordered UART model",
            "transactions": [{
                "name": "read arm consume",
                "peripheral": "UART",
                "interference_mode": "sequence",
                "steps": [
                    {"register": "STATUS", "operation": "read"},
                    {"register": "CONTROL", "operation": "write"},
                    {"register": "DATA", "operation": "read"},
                ],
                "interference": [
                    {"register": "STATUS", "operation": "read"},
                    {"register": "DATA", "operation": "write"},
                ],
            }],
        })
        accesses = [
            self.make_access(0x110, 0x100, "STATUS", "read", 0x100,
                             primask=1, basepri=0, faultmask=0),
            self.make_access(0x120, 0x100, "CONTROL", "write", 0x120,
                             primask=0, basepri=0, faultmask=0),
            self.make_access(0x130, 0x100, "DATA", "read", 0x130,
                             primask=0, basepri=0, faultmask=0),
            self.make_access(0x210, 0x200, "STATUS", "read", 0x200),
            self.make_access(0x220, 0x200, "DATA", "write", 0x220),
        ]
        cfg = {
            0x100: {
                0x100: CFGBlock(0x100, 0x118, (0x120,)),
                0x120: CFGBlock(0x120, 0x128, (0x130,)),
                0x130: CFGBlock(0x130, 0x140),
            },
            0x200: {
                0x200: CFGBlock(0x200, 0x218, (0x220,)),
                0x220: CFGBlock(0x220, 0x230),
            },
        }

        result = build_protocol_findings(
            protocol, self.device, accesses, {0x200: 16}, cfg
        )
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual([event.ea for event in finding.protocol_interrupt_events],
                         [0x210, 0x220])
        self.assertEqual(finding.protocol_interrupt_paths, ((0x200, 0x220),))
        self.assertEqual(finding.protocol_insertion_index, 1)
        self.assertEqual(finding.preemption_state,
                         "mask-registers-permit-configurable-irq")
        self.assertEqual(finding.witness.foreground_start.ea, 0x120)
        self.assertEqual(finding.witness.foreground_resume.ea, 0x130)
        self.assertEqual(finding.witness.block_path, (0x120, 0x130))
        timeline = build_candidate_timeline(finding)
        self.assertEqual(timeline["status"], "conditional-synchronized-insertion-candidate")
        self.assertEqual(timeline["insertion_gap"], {
            "after_foreground_event_index": 1,
            "before_foreground_event_index": 2,
        })
        self.assertEqual(
            [(step["context"], step["event"].ea) for step in timeline["steps"]],
            [("foreground", 0x110), ("foreground", 0x120),
             ("interrupt", 0x210), ("interrupt", 0x220),
             ("foreground", 0x130)],
        )
        self.assertEqual(timeline["steps"][3]["cfg_path"], (0x200, 0x220))
        self.assertIn("not a verified schedule", timeline["limitations"][2])
        self.assertIsNone(build_candidate_timeline(
            replace(finding, protocol_insertion_index=None)
        ))
        self.assertIsNone(build_candidate_timeline(
            replace(finding, protocol_insertion_index=9)
        ))

    def test_contract_rejects_unknown_or_ambiguous_registers(self):
        contract = {
            "format": "irqscope-protocol-v1", "name": "bad model",
            "transactions": [{
                "name": "bad", "peripheral": "UART",
                "steps": [{"register": "MISSING", "operation": "read"},
                          {"register": "DATA", "operation": "write"}],
                "interference": [{"register": "DATA", "operation": "read"}],
            }],
        }
        with self.assertRaisesRegex(ValueError, "unknown register"):
            self.parse_contract(contract)

    def test_deeply_nested_contract_fails_with_validation_error(self):
        nested = "[" * 1100 + "0" + "]" * 1100
        handle, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as target:
                target.write('{"format":"irqscope-protocol-v1","name":"x","transactions":' + nested + "}")
            with self.assertRaisesRegex(ValueError, "Invalid protocol JSON"):
                parse_protocol(path, self.device)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_unreachable_sequence_does_not_generate_candidate(self):
        protocol = self.parse_contract({
            "format": "irqscope-protocol-v1", "name": "model",
            "transactions": [{
                "name": "poll then arm", "peripheral": "UART",
                "steps": [{"register": "STATUS", "operation": "read"},
                          {"register": "CONTROL", "operation": "write"}],
                "interference": [{"register": "DATA", "operation": "write"}],
            }],
        })
        accesses = [
            self.make_access(0x110, 0x100, "STATUS", "read", 0x100),
            self.make_access(0x120, 0x100, "CONTROL", "write", 0x120),
            self.make_access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x118), 0x120: CFGBlock(0x120, 0x130)},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }
        findings = build_protocol_findings(protocol, self.device, accesses, {0x200: 16}, cfg).findings
        self.assertEqual(findings, ())

    def test_authored_demo_contract_matches_its_svd(self):
        root = os.path.dirname(os.path.dirname(__file__))
        from irqscope.svd import parse_svd

        device = parse_svd(os.path.join(root, "demo", "demo.svd"))
        protocol = parse_protocol(os.path.join(root, "demo", "uart-protocol.json"), device)
        self.assertEqual(protocol.name, "Synthetic UART transaction model")
        self.assertEqual(protocol.transactions[0].peripheral, "SIMUART")
        self.assertEqual(len(protocol.transactions[0].steps), 5)
        self.assertEqual(len(protocol.transactions[0].interference), 3)

    def test_sequence_cap_is_reported_as_truncation(self):
        protocol = self.parse_contract({
            "format": "irqscope-protocol-v1", "name": "model",
            "transactions": [{
                "name": "read then arm", "peripheral": "UART",
                "steps": [{"register": "STATUS", "operation": "read"},
                          {"register": "CONTROL", "operation": "write"}],
                "interference": [{"register": "DATA", "operation": "write"}],
            }],
        })
        accesses = [
            self.make_access(0x110, 0x100, "STATUS", "read", 0x100),
            self.make_access(0x114, 0x100, "STATUS", "read", 0x100),
            self.make_access(0x120, 0x100, "CONTROL", "write", 0x100),
            self.make_access(0x124, 0x100, "CONTROL", "write", 0x100),
            self.make_access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x130)},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }
        with patch("irqscope.protocols.MAX_CANDIDATE_SEQUENCES", 1):
            result = build_protocol_findings(protocol, self.device, accesses, {0x200: 16}, cfg)
        self.assertTrue(any("sequence per-function search cap" in item
                            for item in result.truncation_reasons))

    def test_polling_loop_can_match_repeated_instruction(self):
        protocol = self.parse_contract({
            "format": "irqscope-protocol-v1", "name": "poll model",
            "transactions": [{
                "name": "two status observations", "peripheral": "UART",
                "steps": [{"register": "STATUS", "operation": "read"},
                          {"register": "STATUS", "operation": "read"}],
                "interference": [{"register": "DATA", "operation": "write"}],
            }],
        })
        accesses = [
            self.make_access(0x110, 0x100, "STATUS", "read", 0x100),
            self.make_access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x120, (0x100,))},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }
        result = build_protocol_findings(protocol, self.device, accesses, {0x200: 16}, cfg)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual([event.ea for event in result.findings[0].protocol_events], [0x110, 0x110])
        self.assertEqual(result.findings[0].witness.block_path, (0x100, 0x100))


if __name__ == "__main__":
    unittest.main()
