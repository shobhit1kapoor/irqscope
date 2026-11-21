import unittest
from dataclasses import replace

from irqscope.model import Finding, MMIOAccess, Register
from irqscope.reviews import ReviewLedger, finding_key


class ReviewLedgerTests(unittest.TestCase):
    def setUp(self):
        register = Register("UART", "STATUS", 0x40000000, 32)
        first = MMIOAccess(0x100, 0x100, "foreground", register, "read", 32, "fixture")
        second = MMIOAccess(0x200, 0x200, "handler", register, "read", 32, "fixture")
        self.finding = Finding(
            "IRQSCOPE.DESTRUCTIVE_READ_CROSS_CONTEXT", "Read review", "medium", "candidate",
            register.address, register, first, second, "candidate evidence",
        )

    def test_key_stays_stable_for_pair_order_and_changes_with_input(self):
        key = finding_key("a" * 64, "b" * 64, self.finding)
        swapped = replace(self.finding, first=self.finding.second, second=self.finding.first)

        self.assertEqual(key, finding_key("a" * 64, "b" * 64, swapped))
        self.assertNotEqual(key, finding_key("c" * 64, "b" * 64, swapped))

    def test_protocol_reviews_are_scoped_to_contract_and_matched_sequence(self):
        protocol_finding = replace(
            self.finding,
            rule_id="IRQSCOPE.PROTOCOL_INTERLEAVING",
            protocol_name="poll then arm",
            protocol_identity="c" * 64,
            protocol_events=(self.finding.first, self.finding.second),
        )
        changed_contract = replace(protocol_finding, protocol_identity="d" * 64)
        changed_sequence = replace(protocol_finding, protocol_events=(self.finding.first,))
        reversed_sequence = replace(protocol_finding,
                                    protocol_events=(self.finding.second, self.finding.first))
        key = finding_key("a" * 64, "b" * 64, protocol_finding)

        self.assertNotEqual(key, finding_key("a" * 64, "b" * 64, changed_contract))
        self.assertNotEqual(key, finding_key("a" * 64, "b" * 64, changed_sequence))
        self.assertNotEqual(key, finding_key("a" * 64, "b" * 64, reversed_sequence))

    def test_review_round_trips_and_defaults_to_open(self):
        key = finding_key("a" * 64, "b" * 64, self.finding)
        ledger = ReviewLedger()
        self.assertEqual(ledger.get(key)["status"], "open")
        ledger.set(key, "confirmed", "Reviewed against the device reference manual.")

        loaded = ReviewLedger.from_json(ledger.to_json())
        self.assertEqual(loaded.get(key)["status"], "confirmed")
        self.assertEqual(loaded.get(key)["note"], "Reviewed against the device reference manual.")

    def test_invalid_status_and_schema_are_rejected(self):
        ledger = ReviewLedger()
        with self.assertRaises(ValueError):
            ledger.set("a" * 64, "probably")
        with self.assertRaises(ValueError):
            ReviewLedger.from_json('{"format":"unknown","schema_version":1,"records":{}}')


if __name__ == "__main__":
    unittest.main()
