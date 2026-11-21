import unittest
from unittest.mock import patch

from irqscope.model import CFGBlock, DeviceModel, MMIOAccess, Register
from irqscope.transaction_mining import mine_transaction_proposals


class TransactionMiningTests(unittest.TestCase):
    def setUp(self):
        self.device = DeviceModel("Fixture", registers={
            0x40000000: Register("UART", "STATUS", 0x40000000, 32),
            0x40000004: Register("UART", "CONTROL", 0x40000004, 32),
            0x40000008: Register("UART", "DATA", 0x40000008, 32),
        })

    def access(self, ea, function, name, operation, block):
        register = self.device.get_register({
            "STATUS": 0x40000000, "CONTROL": 0x40000004, "DATA": 0x40000008,
        }[name])
        return MMIOAccess(ea, function, f"fn_{function:X}", register, operation,
                          32, "fixture", block_start_ea=block)

    def test_suggests_ordered_cfg_reachable_foreground_chain(self):
        accesses = [
            self.access(0x110, 0x100, "STATUS", "read", 0x100),
            self.access(0x120, 0x100, "CONTROL", "write", 0x120),
            self.access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {
                0x100: CFGBlock(0x100, 0x118, (0x120,)),
                0x120: CFGBlock(0x120, 0x130),
            },
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }

        proposals, warnings = mine_transaction_proposals(accesses, {0x200: 16}, cfg)

        self.assertEqual(warnings, ())
        proposal = next(item for item in proposals if len(item.events) == 2)
        self.assertEqual(proposal.function_name, "fn_100")
        self.assertEqual([event.register.name for event in proposal.events], ["STATUS", "CONTROL"])
        self.assertEqual(proposal.paths, ((0x100, 0x120),))
        self.assertTrue(any("not a proven transaction boundary" in item for item in proposal.limitations))

    def test_unreachable_and_handler_events_are_not_proposed(self):
        accesses = [
            self.access(0x110, 0x100, "STATUS", "read", 0x100),
            self.access(0x120, 0x100, "CONTROL", "write", 0x120),
            self.access(0x210, 0x200, "DATA", "write", 0x200),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x118), 0x120: CFGBlock(0x120, 0x130)},
            0x200: {0x200: CFGBlock(0x200, 0x220)},
        }

        proposals, _ = mine_transaction_proposals(accesses, {0x200: 16}, cfg)

        self.assertEqual(proposals, ())

    def test_unreachable_intermediate_event_does_not_hide_later_reachable_event(self):
        accesses = [
            self.access(0x110, 0x100, "STATUS", "read", 0x100),
            self.access(0x120, 0x100, "CONTROL", "write", 0x120),
            self.access(0x130, 0x100, "DATA", "read", 0x130),
        ]
        cfg = {
            0x100: {
                0x100: CFGBlock(0x100, 0x118, (0x130,)),
                0x120: CFGBlock(0x120, 0x128),
                0x130: CFGBlock(0x130, 0x138),
            },
        }

        proposals, _ = mine_transaction_proposals(accesses, {}, cfg)
        chains = [[event.register.name for event in item.events] for item in proposals]

        self.assertIn(["STATUS", "DATA"], chains)
        self.assertNotIn(["STATUS", "CONTROL"], chains)

    def test_cfg_loop_can_revisit_lower_address_event(self):
        accesses = [
            self.access(0x110, 0x100, "STATUS", "read", 0x110),
            self.access(0x120, 0x100, "CONTROL", "write", 0x120),
        ]
        cfg = {
            0x100: {
                0x110: CFGBlock(0x110, 0x118, (0x120,)),
                0x120: CFGBlock(0x120, 0x128, (0x110,)),
            },
        }

        proposals, _ = mine_transaction_proposals(accesses, {}, cfg)
        chains = [[event.register.name for event in item.events] for item in proposals]

        self.assertIn(["CONTROL", "STATUS"], chains)

    def test_single_event_loop_can_propose_a_repeated_iteration(self):
        accesses = [self.access(0x110, 0x100, "STATUS", "read", 0x100)]
        cfg = {0x100: {0x100: CFGBlock(0x100, 0x120, (0x100,))}}

        proposals, _ = mine_transaction_proposals(accesses, {}, cfg)
        repeated = next(item for item in proposals if len(item.events) == 2)

        self.assertEqual([event.ea for event in repeated.events], [0x110, 0x110])
        self.assertEqual(repeated.paths, ((0x100, 0x100),))

    def test_repeated_sequence_pattern_surfaces_supporting_functions(self):
        accesses = [
            self.access(0x110, 0x100, "STATUS", "read", 0x100),
            self.access(0x120, 0x100, "CONTROL", "write", 0x100),
            self.access(0x310, 0x300, "STATUS", "read", 0x300),
            self.access(0x320, 0x300, "CONTROL", "write", 0x300),
        ]
        cfg = {
            0x100: {0x100: CFGBlock(0x100, 0x130)},
            0x300: {0x300: CFGBlock(0x300, 0x330)},
        }

        proposals, _ = mine_transaction_proposals(accesses, {}, cfg)
        matching = [item for item in proposals
                    if len(item.events) == 2 and item.events[0].register.name == "STATUS"
                    and item.events[1].register.name == "CONTROL"]

        self.assertEqual(len(matching), 2)
        self.assertTrue(all(len(item.supporting_functions) == 2 for item in matching))

    def test_candidate_bound_is_reported(self):
        accesses = [
            self.access(0x110 + index * 4, 0x100, "STATUS", "read", 0x100)
            for index in range(8)
        ]
        cfg = {0x100: {0x100: CFGBlock(0x100, 0x180)}}

        with patch("irqscope.transaction_mining.MAX_PROPOSALS", 2):
            proposals, warnings = mine_transaction_proposals(accesses, {}, cfg)

        self.assertEqual(len(proposals), 2)
        self.assertTrue(any("reached its 2-proposal output bound" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
