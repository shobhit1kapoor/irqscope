import importlib
import hashlib
import os
import sys
import tempfile
import types
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch


class PluginBootstrapTests(unittest.TestCase):
    def test_plugin_bootstrap_and_dashboard_theme_without_hexrays_ui_creation(self):
        registered = []

        class FakeNetnode:
            def create(self, name):
                self.name = name
                return True

            def getblob(self, start, tag):
                return None

            def setblob(self, payload, start, tag):
                return True

        class FakePluginBase:
            pass

        class FakeActionHandler:
            pass

        class FakeChooser:
            pass

        kernwin = types.ModuleType("ida_kernwin")
        kernwin.action_handler_t = FakeActionHandler
        kernwin.Choose = FakeChooser
        kernwin.PluginForm = type("PluginForm", (), {"WCLS_SAVE": 0})
        kernwin.AST_ENABLE_ALWAYS = 1
        kernwin.SETMENU_APP = 0
        kernwin.action_desc_t = lambda *args: args
        kernwin.register_action = lambda desc: registered.append(desc[0]) or True
        kernwin.attach_action_to_menu = lambda *args: True
        kernwin.detach_action_from_menu = lambda *args: True
        kernwin.unregister_action = lambda *args: True
        kernwin.warning = lambda *args: None
        kernwin.msg = lambda *args: None
        kernwin.ask_file = lambda *args: None
        kernwin.show_wait_box = lambda *args: None
        kernwin.replace_wait_box = lambda *args: None
        kernwin.hide_wait_box = lambda *args: None
        kernwin.user_cancelled = lambda *args: False

        idaapi = types.ModuleType("ida_idaapi")
        idaapi.plugin_t = FakePluginBase
        idaapi.PLUGIN_KEEP = 1

        idp = types.ModuleType("ida_idp")
        idp.CF_CALL = 1

        callee_name = ["NVIC_DisableIRQ"]
        idc = types.ModuleType("idc")
        idc.get_operand_value = lambda *args: 0
        idc.get_name = lambda *args: callee_name[0]
        idc.print_operand = lambda *args: ""
        idc.print_insn_mnem = lambda *args: "bl"
        idc.generate_disasm_line = lambda *args: "bl"
        class FakeInstruction:
            ops = []

            def get_canon_feature(self):
                return 1

        instruction = FakeInstruction()
        ua = types.ModuleType("ida_ua")
        ua.o_void = -1
        ua.insn_t = lambda: instruction
        ua.decode_insn = lambda *args: 1
        byte_api = types.ModuleType("ida_bytes")
        byte_api.get_flags = lambda *args: 0
        byte_api.is_code = lambda *args: True
        utilities = types.ModuleType("idautils")
        utilities.Heads = lambda *args: [0x100]

        netnode = types.ModuleType("ida_netnode")
        netnode.netnode = FakeNetnode

        functions = types.ModuleType("ida_funcs")
        functions.get_func = lambda ea: None
        modules = {
            "ida_idaapi": idaapi,
            "ida_kernwin": kernwin,
            "ida_netnode": netnode,
            "ida_nalt": types.ModuleType("ida_nalt"),
            "ida_funcs": functions,
            "ida_bytes": byte_api,
            "ida_gdl": types.ModuleType("ida_gdl"),
            "ida_idp": idp,
            "ida_lines": types.ModuleType("ida_lines"),
            "ida_segment": types.ModuleType("ida_segment"),
            "ida_ua": ua,
            "idautils": utilities,
            "idc": idc,
        }
        modules["ida_lines"].tag_remove = lambda text: text
        purge = ("irqscope_plugin", "irqscope.ida_adapter", "irqscope.ui")
        previous = {name: sys.modules.pop(name) for name in purge if name in sys.modules}
        try:
            with patch.dict(sys.modules, modules):
                plugin_module = importlib.import_module("irqscope_plugin")
                plugin = plugin_module.PLUGIN_ENTRY()
                self.assertEqual(plugin.init(), idaapi.PLUGIN_KEEP)
                self.assertIn("irqscope:import_protocol", registered)
                self.assertIn("irqscope:dashboard", registered)
                with tempfile.TemporaryDirectory() as input_directory:
                    input_path = os.path.join(input_directory, "fixture.bin")
                    with open(input_path, "wb") as input_file:
                        input_file.write(b"firmware input identity")
                    modules["ida_nalt"].retrieve_input_file_sha256 = lambda: None
                    idc.get_input_file_path = lambda: input_path
                    idc.get_root_filename = lambda: "fixture.bin"
                    self.assertEqual(
                        plugin_module._input_sha256(),
                        hashlib.sha256(b"firmware input identity").hexdigest(),
                    )

                from irqscope import ida_adapter

                class FlowBlock:
                    def __init__(self, block_id, predecessors=()):
                        self.id = block_id
                        self._predecessors = predecessors

                    def preds(self):
                        return self._predecessors

                entry_block = FlowBlock(0)
                following_block = FlowBlock(1, (entry_block,))
                def identity_transfer(block, state):
                    return dict(state[0]), dict(state[1]), dict(state[2])

                _, _, converged, iterations = ida_adapter._propagate_cfg_states(
                    [entry_block, following_block], 0, identity_transfer, iteration_limit=4
                )
                self.assertTrue(converged)
                self.assertEqual(iterations, 2)
                _, _, converged, iterations = ida_adapter._propagate_cfg_states(
                    [entry_block, following_block], 0, identity_transfer, iteration_limit=1
                )
                self.assertFalse(converged)
                self.assertEqual(iterations, 1)

                instruction = SimpleNamespace(ops=[], get_canon_feature=lambda: 1)
                state = ({}, {"primask": 0, "basepri": 0, "faultmask": 0}, {})
                _, masks, _ = ida_adapter._mask_instruction(0x100, instruction, "bl", state)
                self.assertEqual(masks["primask"], 0)
                callee_name[0] = "__disable_irq"
                _, masks, _ = ida_adapter._mask_instruction(0x104, instruction, "bl", state)
                self.assertEqual(masks["primask"], 1)
                callee_name[0] = "__set_PRIMASK"
                _, masks, _ = ida_adapter._mask_instruction(
                    0x108, instruction, "bl", state, call_argument_regs={0: 1}
                )
                self.assertEqual(masks["primask"], 1)
                callee_name[0] = "NVIC_SetPriority"
                block = SimpleNamespace(start_ea=0x100, end_ea=0x104)
                _, _, _, _, events = ida_adapter._transfer_block(
                    block,
                    ({0: 7, 1: 3}, {"primask": 0, "basepri": 0, "faultmask": 0}, {}),
                    None, 0x100, "configure", collect=True,
                )
                self.assertEqual(len(events), 1)
                self.assertEqual((events[0].irq_number, events[0].operation, events[0].priority),
                                 (7, "set-priority", 3))
                self.assertEqual(events[0].evidence_basis, "recognized-api-name")

                # Exercise the IDA adapter's stripped-wrapper summary against
                # realistic MOVW/MOVT + STR operands. The second function keeps
                # the NVIC constant in the value register while its store base
                # is unknown; it must not be summarized as an NVIC access.
                adapter = ida_adapter
                adapter.ida_ua.o_reg = 1
                adapter.ida_ua.o_imm = 2
                adapter.ida_ua.o_displ = 3
                adapter.ida_ua.o_phrase = 4
                adapter.ida_ua.dt_byte = 1
                adapter.ida_ua.dt_word = 2
                adapter.ida_ua.dt_dword = 3
                adapter.ida_ua.dt_qword = 4
                adapter.ida_idp.str2reg = lambda name: (
                    int(name[1:]) if name.lower().startswith("r") else -1
                )
                adapter.ida_ua.o_mem = 2
                adapter.ida_ua.o_void = -1
                void_operand = SimpleNamespace(type=-1)
                indexed_instruction = SimpleNamespace(ops=[
                    SimpleNamespace(type=1),
                    SimpleNamespace(type=4, phrase=7, addr=0),
                    *([void_operand] * 6),
                ])
                adapter.idc.print_operand = lambda ea, operand: (
                    "[r2, r3, lsl #2]" if ea == 0x400 and operand == 1 else
                    "[r2, r4, lsl #2]" if ea == 0x404 and operand == 1 else
                    "[r2, #0x10]" if ea == 0x408 and operand == 1 else ""
                )
                base_registers = {2: 0x40010000, 3: 2}
                self.assertEqual(adapter._memory_operand_addresses(
                    0x400, indexed_instruction,
                    (base_registers, {}, {}),
                ), [(0x40010008, 1, "constant-index-register")])
                self.assertEqual(adapter._memory_operand_addresses(
                    0x404, indexed_instruction,
                    (base_registers, {}, {}),
                ), [])
                displaced_instruction = SimpleNamespace(ops=[
                    SimpleNamespace(type=1),
                    SimpleNamespace(type=3, phrase=7, addr=0x10),
                    *([void_operand] * 6),
                ])
                self.assertEqual(adapter._memory_operand_addresses(
                    0x408, displaced_instruction,
                    (base_registers, {}, {}),
                ), [(0x40010010, 1, "constant-base-register")])
                negative_displacement = SimpleNamespace(ops=[
                    SimpleNamespace(type=1),
                    SimpleNamespace(type=3, phrase=7, addr=0xFFFFFFFC),
                    *([void_operand] * 6),
                ])
                adapter.idc.print_operand = lambda ea, operand: (
                    "[r2, #-4]" if ea == 0x40C and operand == 1 else ""
                )
                self.assertEqual(adapter._memory_operand_addresses(
                    0x40C, negative_displacement,
                    (base_registers, {}, {}),
                ), [(0x4000FFFC, 1, "constant-base-register")])
                functions.get_func = lambda ea: SimpleNamespace(start_ea=ea)
                utilities.Functions = lambda: [0x200, 0x300]
                function_items = {
                    0x200: [0x200, 0x204, 0x208],
                    0x300: [0x300, 0x304, 0x308],
                }
                utilities.FuncItems = lambda start: function_items[start]
                instruction_specs = {
                    0x200: ("movw", [SimpleNamespace(type=1, reg=2), SimpleNamespace(type=2, value=0xE100)]),
                    0x204: ("movt", [SimpleNamespace(type=1, reg=2), SimpleNamespace(type=2, value=0xE000)]),
                    0x208: ("str", [SimpleNamespace(type=1, reg=1, dtype=3),
                                     SimpleNamespace(type=3, phrase=7, addr=0)]),
                    0x300: ("movw", [SimpleNamespace(type=1, reg=1), SimpleNamespace(type=2, value=0xE100)]),
                    0x304: ("movt", [SimpleNamespace(type=1, reg=1), SimpleNamespace(type=2, value=0xE000)]),
                    0x308: ("str", [SimpleNamespace(type=1, reg=1, dtype=3),
                                     SimpleNamespace(type=3, phrase=1, addr=0)]),
                    0x410: ("ldr", [SimpleNamespace(type=1, reg=0, dtype=3),
                                     SimpleNamespace(type=4, phrase=7, addr=0, dtype=3),
                                     SimpleNamespace(type=-1)]),
                }
                adapter.ida_bytes.get_flags = lambda ea: 1
                adapter.ida_ua.insn_t = lambda: SimpleNamespace(ops=[], get_canon_feature=lambda: 0)
                adapter.ida_ua.decode_insn = lambda insn, ea: (
                    setattr(
                        insn, "ops",
                        instruction_specs[ea][1]
                        + [void_operand] * (8 - len(instruction_specs[ea][1])),
                    ) or True
                )
                adapter.idc.print_insn_mnem = lambda ea: instruction_specs[ea][0]
                adapter.idc.print_operand = lambda ea, operand: (
                    "[r2, r0, lsl #2]" if ea == 0x208 and operand == 1 else
                    "[r3, r0, lsl #2]" if ea == 0x308 and operand == 1 else ""
                )
                self.assertEqual(adapter._nvic_helper_summaries(), {0x200: "enable"})
                adapter.idc.print_operand = lambda ea, operand: (
                    "[r2, r3, lsl #2]" if ea == 0x410 and operand == 1 else ""
                )
                utilities.Heads = lambda start, end: [0x410]
                utilities.DataRefsFrom = lambda ea: []
                from irqscope.model import DeviceModel, Register
                indexed_register = Register("UART", "DATA1", 0x40010004, 32)
                _, _, _, indexed_accesses, _ = adapter._transfer_block(
                    SimpleNamespace(start_ea=0x410, end_ea=0x414),
                    ({2: 0x40010000, 3: 1},
                     {"primask": None, "basepri": None, "faultmask": None}, {}),
                    DeviceModel("Fixture", registers={indexed_register.address: indexed_register}),
                    0x400, "indexed_reader", collect=True,
                )
                self.assertEqual(len(indexed_accesses), 1)
                self.assertEqual(indexed_accesses[0].register.name, "DATA1")
                self.assertEqual(indexed_accesses[0].evidence, "constant-index-register")

                # Exercise the instruction transfer end-to-end: a literal is
                # shifted and combined before the constant store reaches MMIO.
                instruction_specs.update({
                    0x420: ("mov", [
                        SimpleNamespace(type=1, reg=0),
                        SimpleNamespace(type=2, value=3),
                        void_operand,
                    ]),
                    0x424: ("lsl", [
                        SimpleNamespace(type=1, reg=0),
                        SimpleNamespace(type=2, value=2),
                        void_operand,
                    ]),
                    0x428: ("orr", [
                        SimpleNamespace(type=1, reg=0),
                        SimpleNamespace(type=2, value=1),
                        void_operand,
                    ]),
                    0x42C: ("str", [
                        SimpleNamespace(type=1, reg=0, dtype=3),
                        SimpleNamespace(type=3, phrase=2, addr=0, dtype=3),
                        void_operand,
                    ]),
                })
                adapter.idc.print_operand = lambda ea, operand: (
                    "[r2]" if ea == 0x42C and operand == 1 else
                    "r0" if ea in {0x420, 0x424, 0x428} and operand == 0 else ""
                )
                utilities.Heads = lambda start, end: [0x420, 0x424, 0x428, 0x42C]
                config_register = Register(
                    "UART", "CONFIG", 0x40010000, 32, access="read-write"
                )
                _, _, _, constant_writes, _ = adapter._transfer_block(
                    SimpleNamespace(start_ea=0x420, end_ea=0x430),
                    ({2: config_register.address},
                     {"primask": 0, "basepri": 0, "faultmask": 0}, {}),
                    DeviceModel("Fixture", registers={config_register.address: config_register}),
                    0x400, "constant_writer", collect=True,
                )
                self.assertEqual(len(constant_writes), 1)
                self.assertEqual(constant_writes[0].value, 13)
                self.assertEqual(
                    constant_writes[0].value_evidence,
                    "constant-propagated-register",
                )
                instruction_specs.update({
                    0x430: ("add", [
                        SimpleNamespace(type=1, reg=0),
                        SimpleNamespace(type=1, reg=0),
                        SimpleNamespace(type=1, reg=1),
                        void_operand,
                    ]),
                    0x434: ("str", [
                        SimpleNamespace(type=1, reg=0, dtype=3),
                        SimpleNamespace(type=3, phrase=2, addr=0, dtype=3),
                        void_operand,
                    ]),
                })
                adapter.idc.print_operand = lambda ea, operand: (
                    "[r2]" if ea == 0x434 and operand == 1 else
                    "r1, lsl #2" if ea == 0x430 and operand == 2 else ""
                )
                utilities.Heads = lambda start, end: [0x430, 0x434]
                _, _, _, shifted_writes, _ = adapter._transfer_block(
                    SimpleNamespace(start_ea=0x430, end_ea=0x438),
                    ({0: 5, 1: 2, 2: config_register.address},
                     {"primask": 0, "basepri": 0, "faultmask": 0}, {}),
                    DeviceModel("Fixture", registers={config_register.address: config_register}),
                    0x400, "shifted_writer", collect=True,
                )
                self.assertEqual([access.value for access in shifted_writes], [13])

                from irqscope.model import EnumeratedValue, EnumeratedValues, RegisterField
                exported_register = plugin_module._json_register(Register(
                    peripheral="BASE",
                    name="CTRL",
                    address=0x40000000,
                    size_bits=32,
                    fields=(RegisterField(
                        name="MODE",
                        bit_offset=0,
                        bit_width=2,
                        enumerated_values=(EnumeratedValues(
                            name="ModeSet",
                            usage="read",
                            values=(EnumeratedValue(
                                name="Active", value=1, mask=3,
                                pattern="0b01", description="Active state",
                            ),),
                        ),),
                    ),),
                ))
                enum_export = exported_register["fields"][0]["enumerated_values"][0]
                self.assertEqual(enum_export["usage"], "read")
                self.assertEqual(enum_export["values"][0]["value"], "0x1")
                self.assertEqual(enum_export["values"][0]["mask"], "0x3")
                from irqscope.dashboard import IRQScopeDashboard
                display_field = RegisterField(
                    name="MODE", bit_offset=0, bit_width=2,
                    enumerated_values=(EnumeratedValues(
                        name="ModeSet", usage="read",
                        values=(EnumeratedValue(name="Active", value=1, mask=3),),
                    ),),
                )
                field_summary = IRQScopeDashboard._field_summary(None, display_field)
                self.assertEqual(field_summary, "MODE [READ: Active=0x1]")

                class FakeColor:
                    def __init__(self, lightness):
                        self._lightness = lightness

                    def lightness(self):
                        return self._lightness

                class FakeRoot:
                    def __init__(self, lightness):
                        self._lightness = lightness

                    def palette(self):
                        return SimpleNamespace(color=lambda role: FakeColor(self._lightness))

                    def backgroundRole(self):
                        return 0

                dashboard = IRQScopeDashboard.__new__(IRQScopeDashboard)
                dashboard.root = FakeRoot(240)
                light_stylesheet = dashboard._stylesheet()
                self.assertTrue(dashboard.light_theme)
                self.assertIn("#F3F6FA", light_stylesheet)
                dashboard.root = FakeRoot(20)
                dark_stylesheet = dashboard._stylesheet()
                self.assertFalse(dashboard.light_theme)
                self.assertIn("#101722", dark_stylesheet)
                dashboard.root = object()
                fallback_stylesheet = dashboard._stylesheet()
                self.assertFalse(dashboard.light_theme)
                self.assertIn("#101722", fallback_stylesheet)

                from irqscope.analysis import build_candidate_findings
                from irqscope.model import (
                    CFGBlock, DeviceModel, InterruptConfigEvent, MMIOAccess,
                )
                status = Register("UART", "STATUS", 0x40000000, 32, read_action="clear")
                data = Register("UART", "DATA", 0x40000004, 32)
                foreground = MMIOAccess(
                    0x110, 0x100, "transfer", status, "read", 32,
                    "absolute-memory-operand", block_start_ea=0x100,
                    access_address=status.address,
                )
                resume = MMIOAccess(
                    0x120, 0x100, "transfer", data, "write", 32,
                    "absolute-memory-operand", block_start_ea=0x100,
                )
                handler = MMIOAccess(
                    0x210, 0x200, "USART_IRQHandler", status, "read", 32,
                    "absolute-memory-operand", block_start_ea=0x200,
                )
                setup_event = InterruptConfigEvent(
                    0x308, 0x300, "configure", 0, "set-priority", 2,
                )
                device = DeviceModel(
                    "Fixture", registers={status.address: status, data.address: data},
                    source_sha256="svd-sha256",
                )
                finding = build_candidate_findings(
                    [foreground, resume, handler], {0x200: 16}, {
                        0x100: {0x100: CFGBlock(0x100, 0x130)},
                        0x200: {0x200: CFGBlock(0x200, 0x220)},
                    }, [setup_event],
                )[0]
                plugin_module._device = device
                plugin_module._input_sha256 = lambda: "input-sha256"
                self.assertEqual(
                    plugin_module._json_access(foreground)["access_address"],
                    "0x40000000",
                )
                serialized_finding = plugin_module._json_value(finding)
                self.assertIsNone(serialized_finding["candidate_timeline"])
                protocol_finding = replace(
                    finding,
                    protocol_events=(foreground, resume),
                    protocol_foreground_paths=((0x100, 0x100),),
                    protocol_insertion_index=0,
                    protocol_interrupt_events=(handler,),
                    protocol_interrupt_paths=(),
                )
                serialized_timeline = plugin_module._json_value(protocol_finding)[
                    "candidate_timeline"
                ]
                self.assertEqual(
                    [(step["context"], step["access"]["ea"])
                     for step in serialized_timeline["steps"]],
                    [("foreground", "0x110"), ("interrupt", "0x210"),
                     ("foreground", "0x120")],
                )
                self.assertEqual(
                    serialized_timeline["steps"][0]["cfg_path"], ["0x100", "0x100"]
                )
                self.assertEqual(serialized_timeline["insertion_gap"], {
                    "after_foreground_event_index": 0,
                    "before_foreground_event_index": 1,
                })
                rendered_timeline = []
                dashboard.findings = [protocol_finding]
                dashboard._row_identity = lambda table, row: 0
                dashboard._access_event_label = lambda event: (
                    f"{event.function_name}:{event.register.name}:{event.operation}"
                )
                dashboard._escape = lambda value: str(value)
                dashboard.witness_view = SimpleNamespace(
                    setHtml=rendered_timeline.append,
                )
                dashboard._jump_finding(None, 0)
                rendered = rendered_timeline[0]
                self.assertIn("Conditional synchronized candidate timeline", rendered)
                self.assertLess(rendered.index("<b>FOREGROUND</b>"),
                                rendered.index("<b>ISR</b>"))
                self.assertIn("Candidate IRQ gap", rendered)
                self.assertIn("does not establish runtime scheduling", rendered)
                self.assertEqual(serialized_finding["interrupt_configuration"], [{
                    "ea": "0x308", "function": "configure", "operation": "set-priority",
                    "irq_number": 0, "vector_slot": 16, "priority_argument": 2,
                    "evidence_basis": "recognized-api-name",
                    "interpretation": "Static callsite only; it does not establish runtime reachability or effective NVIC state.",
                }])
                self.assertIn("static NVIC setup callsite(s)", next(
                    item["evidence"] for item in serialized_finding["evidence_profile"]
                    if item["dimension"] == "preemption"
                ))
                plugin_module._device = device
                plugin_module._vector_entries = [SimpleNamespace(function_ea=0x200, slot=16)]
                with patch.object(plugin_module, "scan_mmio_with_cfg", return_value=(
                    [foreground, resume, handler],
                    {
                        0x100: {0x100: CFGBlock(0x100, 0x130)},
                        0x200: {0x200: CFGBlock(0x200, 0x220)},
                    },
                    [setup_event], [],
                )), patch.object(plugin_module, "_refresh_dashboard"), \
                        patch.object(plugin_module, "show_rows"):
                    plugin_module._analyze()
                proposals = plugin_module._results.transaction_proposals
                self.assertEqual(len(proposals), 1)
                self.assertEqual(
                    [event.register.name for event in proposals[0].events], ["STATUS", "DATA"]
                )
                self.assertEqual(proposals[0].function_ea, foreground.function_ea)
                proposal_review_id = plugin_module._proposal_review_id(proposals[0])
                with patch.object(plugin_module, "_persist_reviews"), \
                        patch.object(plugin_module, "_refresh_dashboard"):
                    plugin_module._save_proposal_review(
                        proposals[0], "confirmed", "Repeated in the DMA setup path."
                    )
                self.assertEqual(
                    plugin_module._review_for_proposal(proposals[0])["status"], "confirmed",
                )
                self.assertEqual(plugin_module._review_for_proposal(proposals[0])["note"],
                                 "Repeated in the DMA setup path.")
                original_input_hash = plugin_module._input_sha256
                plugin_module._input_sha256 = lambda: "different-input"
                self.assertNotEqual(
                    proposal_review_id, plugin_module._proposal_review_id(proposals[0])
                )
                plugin_module._input_sha256 = original_input_hash
                original_svd_hash = plugin_module._device.source_sha256
                plugin_module._device.source_sha256 = "different-svd"
                self.assertNotEqual(
                    proposal_review_id, plugin_module._proposal_review_id(proposals[0])
                )
                plugin_module._device.source_sha256 = original_svd_hash
                with patch.object(plugin_module, "scan_mmio_with_cfg", return_value=(
                    [foreground, resume, handler],
                    {
                        0x100: {0x100: CFGBlock(0x100, 0x130)},
                        0x200: {0x200: CFGBlock(0x200, 0x220)},
                    },
                    [setup_event], [],
                )), patch.object(plugin_module, "_refresh_dashboard"), \
                        patch.object(plugin_module, "show_rows"):
                    plugin_module._analyze()
                self.assertEqual(
                    plugin_module._review_for_proposal(
                        plugin_module._results.transaction_proposals[0]
                    )["status"], "confirmed",
                )
                with tempfile.TemporaryDirectory() as draft_directory:
                    draft_path = os.path.join(draft_directory, "protocol-draft.json")
                    with patch.object(plugin_module.ida_kernwin, "ask_file", return_value=draft_path):
                        plugin_module._save_protocol_draft(
                            plugin_module._results.transaction_proposals[0]
                        )
                    generated_draft = plugin_module.parse_protocol(draft_path, device)
                    self.assertEqual(generated_draft.transactions[0].peripheral, "UART")
                    self.assertEqual(
                        [event.register for event in generated_draft.transactions[0].steps],
                        ["UART.STATUS", "UART.DATA"],
                    )
                    self.assertEqual(
                        [event.register for event in generated_draft.transactions[0].interference],
                        ["UART.STATUS"],
                    )
                serialized_proposal = plugin_module._json_transaction_proposal(proposals[0])
                self.assertEqual(serialized_proposal["cfg_paths"], [["0x100"]])
                self.assertEqual(serialized_proposal["supporting_function_eas"], ["0x100"])
                self.assertIn("not a confirmed protocol", serialized_proposal["interpretation"])
                self.assertEqual(serialized_proposal["review"]["status"], "confirmed")
                plugin_module._device = object()
                plugin_module._vector_entries = [object()]
                plugin.term()
                self.assertIsNone(plugin_module._device)
                self.assertEqual(plugin_module._vector_entries, [])
        finally:
            for name in purge:
                sys.modules.pop(name, None)
            sys.modules.update(previous)


if __name__ == "__main__":
    unittest.main()
