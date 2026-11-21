import unittest

from irqscope.analysis import build_candidate_findings
from irqscope.confidence import confidence_vector
from irqscope.model import CFGBlock, MMIOAccess, Register


class ConfidenceVectorTests(unittest.TestCase):
    def make_finding(self, evidence="absolute-memory-operand", aliases=()):
        status = Register("UART", "STATUS", 0x40000000, 32, read_action="clear")
        control = Register("UART", "CONTROL", 0x40000004, 32)
        accesses = [
            MMIOAccess(0x110, 0x100, "foreground", status, "read", 32, evidence,
                       block_start_ea=0x100),
            MMIOAccess(0x210, 0x200, "USART1_IRQHandler", status, "write", 32, evidence,
                       block_start_ea=0x200, register_aliases=aliases),
            MMIOAccess(0x120, 0x100, "foreground", control, "write", 32, evidence,
                       block_start_ea=0x100),
        ]
        findings = build_candidate_findings(accesses, {0x200: 37}, {
            0x100: {0x100: CFGBlock(0x100, 0x130)},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        })
        return findings[0]

    def test_vector_uses_evidence_tiers_and_limits_without_probability(self):
        vector = confidence_vector(self.make_finding())
        self.assertEqual([item["dimension"] for item in vector], [
            "address", "context", "preemption", "transaction", "semantics", "feasibility",
        ])
        self.assertEqual(vector[0]["tier"], "direct")
        self.assertEqual(vector[3]["tier"], "not-recovered")
        self.assertEqual(vector[4]["tier"], "described-by-svd")
        self.assertIn("not proven", vector[5]["limit"])
        self.assertTrue(all("limit" in item and "evidence" in item for item in vector))

    def test_constant_propagation_and_aliases_are_reported(self):
        primary = Register("UART", "STATUS", 0x40000000, 32)
        alias = Register("GPIO", "STATUS", 0x40000000, 32)
        vector = confidence_vector(self.make_finding("constant-base-register", (primary, alias)))
        self.assertEqual(vector[0]["tier"], "ambiguous")
        self.assertIn("constant-base-register", vector[0]["evidence"])


if __name__ == "__main__":
    unittest.main()
