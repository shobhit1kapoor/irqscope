import unittest

from irqscope.interrupts import (
    assess_basepri_priority,
    mask_effect_for_call,
    normalize_mask_value,
    nvic_event_for_call,
    nvic_operation_for_store,
)
from irqscope.model import InterruptConfigEvent


class InterruptCallSemanticsTests(unittest.TestCase):
    def test_basepri_comparison_uses_svd_priority_width_and_cmsis_arguments(self):
        event = InterruptConfigEvent(
            0x100, 0x80, "configure", 4, "set-priority", 3,
        )
        blocked = assess_basepri_priority(4, 0x40, 3, (event,))
        self.assertEqual(blocked.status, "conditional-basepri-block")
        self.assertEqual((blocked.logical_priority, blocked.encoded_priority,
                          blocked.basepri_threshold), (3, 0x60, 0x40))
        self.assertEqual(blocked.callsite_eas, (0x100,))

        permitted = assess_basepri_priority(
            4, 0x40, 3,
            (InterruptConfigEvent(0x104, 0x80, "configure", 4, "set-priority", 1),),
        )
        self.assertEqual(permitted.status, "conditional-basepri-permit")
        self.assertEqual(permitted.encoded_priority, 0x20)

    def test_basepri_priority_analysis_abstains_on_missing_or_conflicting_evidence(self):
        priority = InterruptConfigEvent(0x100, 0x80, "configure", 4, "set-priority", 3)
        self.assertEqual(assess_basepri_priority(4, 0x40, None, (priority,)).status, "unknown")
        self.assertEqual(assess_basepri_priority(4, 0x40, 3, ()).status, "unknown")
        conflicting = (
            priority,
            InterruptConfigEvent(0x104, 0x84, "configure", 4, "set-priority", 2),
        )
        self.assertEqual(assess_basepri_priority(4, 0x40, 3, conflicting).status, "unknown")
        self.assertEqual(assess_basepri_priority(4, 0x07, 3, (priority,)).status, "basepri-clear")

    def test_cmsis_global_mask_intrinsics(self):
        self.assertEqual(mask_effect_for_call("__disable_irq"), ("set", "primask"))
        self.assertEqual(mask_effect_for_call("__enable_irq"), ("clear", "primask"))
        self.assertEqual(mask_effect_for_call("__disable_fault_irq"), ("set", "faultmask"))
        self.assertEqual(mask_effect_for_call("__enable_fault_irq"), ("clear", "faultmask"))
        self.assertEqual(mask_effect_for_call("__set_BASEPRI"), ("assign", "basepri"))

    def test_nvic_calls_do_not_change_global_masks(self):
        for name in (
            "NVIC_EnableIRQ", "NVIC_DisableIRQ", "__NVIC_EnableIRQ",
            "HAL_NVIC_DisableIRQ", "device::NVIC_SetPriority",
        ):
            with self.subTest(name=name):
                self.assertEqual(mask_effect_for_call(name), ("per-irq", ""))

    def test_unknown_helpers_remain_unknown(self):
        self.assertIsNone(mask_effect_for_call("disable_irq"))
        self.assertIsNone(mask_effect_for_call("my_irq_enable_wrapper"))

    def test_nvic_callsite_operations(self):
        expected = {
            "NVIC_EnableIRQ": "enable",
            "NVIC_DisableIRQ": "disable",
            "__NVIC_SetPriority": "set-priority",
            "NVIC_SetPendingIRQ": "set-pending",
            "NVIC_ClearPendingIRQ": "clear-pending",
            "HAL_NVIC_SetPriority": "set-priority",
        }
        for name, operation in expected.items():
            with self.subTest(name=name):
                self.assertEqual(nvic_event_for_call(name), operation)

    def test_mask_values_are_narrowed_to_architectural_width(self):
        self.assertEqual(normalize_mask_value("primask", 0xFFFFFFFF), 1)
        self.assertEqual(normalize_mask_value("faultmask", 2), 0)
        self.assertEqual(normalize_mask_value("basepri", 0x1234), 0x34)

    def test_nvic_register_store_ranges_and_widths(self):
        self.assertEqual(nvic_operation_for_store(0xE000E100, 32), "enable")
        self.assertEqual(nvic_operation_for_store(0xE000E17C, 32), "enable")
        self.assertEqual(nvic_operation_for_store(0xE000E180, 32), "disable")
        self.assertEqual(nvic_operation_for_store(0xE000E400, 8), "set-priority")
        self.assertIsNone(nvic_operation_for_store(0xE000E100, 8))
        self.assertIsNone(nvic_operation_for_store(0xE000E200, 32))


if __name__ == "__main__":
    unittest.main()
