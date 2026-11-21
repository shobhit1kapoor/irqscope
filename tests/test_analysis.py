import unittest

from irqscope.analysis import build_candidate_findings
from irqscope.model import CFGBlock, InterruptConfigEvent, MMIOAccess, Register


class InterleavingEvidenceTests(unittest.TestCase):
    def test_same_instruction_repeat_requires_cfg_cycle(self):
        from irqscope.analysis import _shortest_block_path

        access_a = self.access(0x110, 0x100, self.status, "read", block=0x100)
        access_b = self.access(0x110, 0x100, self.status, "read", block=0x100)
        self.assertIsNone(_shortest_block_path(access_a, access_b, {
            0x100: CFGBlock(0x100, 0x120),
        }))
        self.assertEqual(_shortest_block_path(access_a, access_b, {
            0x100: CFGBlock(0x100, 0x120, (0x100,)),
        }), (0x100, 0x100))

    def setUp(self):
        self.status = Register("UART", "STATUS", 0x40000000, 32, read_action="clear")
        self.data = Register("UART", "DATA", 0x40000004, 32)

    def access(self, ea, function, register, operation="read", block=None,
               primask=0, basepri=0, faultmask=0, aliases=()):
        return MMIOAccess(
            ea=ea,
            function_ea=function,
            function_name=f"sub_{function:X}",
            register=register,
            operation=operation,
            width_bits=32,
            evidence="fixture",
            primask=primask,
            basepri=basepri,
            faultmask=faultmask,
            block_start_ea=block if block is not None else function,
            register_aliases=aliases,
        )

    def analyze(self, foreground_masks=(0, 0, 0), aliases=(), interrupt_configuration=(),
                priority_bits=None):
        foreground = self.access(0x100, 0x100, self.status, primask=foreground_masks[0],
                                 basepri=foreground_masks[1], faultmask=foreground_masks[2])
        continuation = self.access(0x108, 0x100, self.data, "write")
        handler_prefix = self.access(0x200, 0x200, self.data, "write")
        interrupt_event = self.access(0x210, 0x200, self.status, block=0x208, aliases=aliases)
        accesses = [foreground, continuation, handler_prefix, interrupt_event]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x10C)},
            0x200: {
                0x200: CFGBlock(0x200, 0x208, (0x208,)),
                0x208: CFGBlock(0x208, 0x214),
            },
        }
        return build_candidate_findings(
            accesses, {0x200: 16}, cfg, interrupt_configuration,
            nvic_priority_bits=priority_bits,
        )[0]

    def test_finding_contains_foreground_and_handler_paths(self):
        finding = self.analyze()

        self.assertEqual(finding.witness.status, "candidate-insertion-sketch")
        self.assertEqual(finding.witness.foreground_resume.ea, 0x108)
        self.assertEqual(finding.witness.block_path, (0x100,))
        self.assertEqual(finding.witness.interrupt_block_path, (0x200, 0x208))
        self.assertEqual([event.ea for event in finding.witness.interrupt_prefix], [0x200])
        self.assertIn("handler prefix contains 1", finding.witness.explanation)

    def test_point_mask_is_labeled_as_blocked_without_claiming_whole_operation(self):
        finding = self.analyze(foreground_masks=(1, 0, 0))

        self.assertEqual(finding.witness.status, "blocked-at-observed-insertion-point")
        self.assertEqual(finding.severity, "low")
        self.assertIn("does not prove", finding.explanation)

    def test_shared_address_alias_downgrades_semantic_confidence(self):
        alias = Register("UART_ALT", "STATUS_VIEW", 0x40000000, 32)

        finding = self.analyze(aliases=(alias,))

        self.assertEqual(finding.severity, "medium")
        self.assertIn("SVD aliases are ambiguous", finding.title)
        self.assertTrue(any("active peripheral/register alias" in item for item in finding.assumptions))

    def test_finding_links_only_static_setup_for_its_external_irq(self):
        setup = (
            InterruptConfigEvent(0x300, 0x100, "configure", 0, "enable"),
            InterruptConfigEvent(0x308, 0x100, "configure", 1, "set-priority", 3),
            InterruptConfigEvent(0x304, 0x100, "configure", 0, "set-priority", 2),
        )
        finding = self.analyze(interrupt_configuration=setup)

        self.assertEqual(
            [(event.irq_number, event.operation, event.ea)
             for event in finding.interrupt_configuration],
            [(0, "enable", 0x300), (0, "set-priority", 0x304)],
        )
        from irqscope.confidence import confidence_vector
        preemption = next(item for item in confidence_vector(finding)
                          if item["dimension"] == "preemption")
        self.assertIn("2 static NVIC setup callsite(s)", preemption["evidence"])
        self.assertIn("effective", preemption["limit"])

    def test_basepri_priority_hint_is_linked_but_kept_conditional(self):
        setup = (InterruptConfigEvent(0x304, 0x100, "configure", 0, "set-priority", 2),)
        finding = self.analyze(foreground_masks=(0, 0x40, 0),
                               interrupt_configuration=setup, priority_bits=3)

        self.assertEqual(finding.preemption_state, "basepri-priority-relation-unknown")
        self.assertEqual(finding.priority_assessment.status, "conditional-basepri-block")
        self.assertEqual(finding.priority_assessment.encoded_priority, 0x40)
        self.assertIn("runtime NVIC state is unproven", finding.priority_assessment.detail)
        self.assertTrue(any("conditional rather than" in item for item in finding.assumptions))


if __name__ == "__main__":
    unittest.main()
