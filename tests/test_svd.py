import os
import tempfile
import unittest
from unittest.mock import patch

from irqscope.model import Register, RegisterField, WriteConstraint
from irqscope.svd import SVDParseError, check_write_constraints, parse_svd


SVD = """<?xml version="1.0"?>
<device schemaVersion="1.3">
  <name>IRQScopeInheritanceFixture</name>
  <size>32</size>
  <access>read-write</access>
  <peripherals>
    <peripheral>
      <name>BASE</name>
      <baseAddress>0x40000000</baseAddress>
      <registers>
        <register>
          <name>CTRL</name><description>source control</description>
          <addressOffset>0x0</addressOffset><readAction>clear</readAction>
          <fields><field>
            <name>ENABLE</name><description>source field</description>
            <bitOffset>3</bitOffset><bitWidth>1</bitWidth><access>read-only</access>
          </field><field>
            <name>MODE%s</name><description>field array</description>
            <bitOffset>8</bitOffset><bitWidth>1</bitWidth>
            <dim>3</dim><dimIncrement>1</dimIncrement><dimIndex>A-C</dimIndex>
          </field></fields>
        </register>
        <register derivedFrom="CTRL">
          <name>CTRL_COPY</name><description>same peripheral copy</description>
          <addressOffset>0x4</addressOffset>
          <fields><field derivedFrom="BASE.CTRL.ENABLE">
            <name>ENABLE_COPY</name><description>cross-register field copy</description>
          </field></fields>
        </register>
        <cluster>
          <name>PORT</name><addressOffset>0x100</addressOffset>
          <register><name>DATA</name><addressOffset>0x4</addressOffset></register>
        </cluster>
        <cluster derivedFrom="BASE.PORT">
          <name>PORT_COPY</name><addressOffset>0x200</addressOffset>
        </cluster>
        <cluster>
          <name>BANK[%s]</name><addressOffset>0x300</addressOffset>
          <dim>2</dim><dimIncrement>0x10</dimIncrement><dimIndex>0,1</dimIndex>
          <register><name>DATA</name><addressOffset>0x0</addressOffset></register>
        </cluster>
      </registers>
    </peripheral>
    <peripheral derivedFrom="BASE">
      <name>BASE2</name><baseAddress>0x50000000</baseAddress>
      <registers><register derivedFrom="BASE.CTRL">
        <name>CTRL2</name><description>cross-peripheral copy</description>
        <addressOffset>0x8</addressOffset>
      </register></registers>
    </peripheral>
    <peripheral>
      <name>ALIAS</name><baseAddress>0x40000000</baseAddress>
      <registers><register>
        <name>CTRL_VIEW</name><addressOffset>0x0</addressOffset>
      </register></registers>
    </peripheral>
    <peripheral>
      <name>UART%s</name><baseAddress>0x60000000</baseAddress>
      <dim>2</dim><dimIncrement>0x100</dimIncrement><dimIndex>0,1</dimIndex>
      <registers><register><name>RX</name><addressOffset>0x10</addressOffset></register></registers>
    </peripheral>
  </peripherals>
</device>
"""


class SVDInheritanceTests(unittest.TestCase):
    def parse_text(self, content):
        handle, path = tempfile.mkstemp(suffix=".svd")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as target:
                target.write(content)
            return parse_svd(path)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_resolves_peripheral_register_cluster_and_field_inheritance(self):
        model = self.parse_text(SVD)

        self.assertEqual(model.get_register(0x40000000).display_name, "BASE.CTRL")
        self.assertEqual(model.get_register(0x40000004).read_action, "clear")
        self.assertEqual(model.get_register(0x40000104).display_name, "BASE.PORT.DATA")
        self.assertEqual(model.get_register(0x40000204).display_name, "BASE.PORT_COPY.DATA")
        self.assertEqual(model.get_register(0x40000300).display_name, "BASE.BANK[0].DATA")
        self.assertEqual(model.get_register(0x40000310).display_name, "BASE.BANK[1].DATA")
        self.assertEqual(model.get_register(0x50000000).display_name, "BASE2.CTRL")
        self.assertEqual(model.get_register(0x50000008).read_action, "clear")
        self.assertEqual(model.get_register(0x60000010).display_name, "UART0.RX")
        self.assertEqual(model.get_register(0x60000110).display_name, "UART1.RX")
        inherited_field = model.get_register(0x40000004).fields[0]
        self.assertEqual((inherited_field.name, inherited_field.bit_offset, inherited_field.access),
                         ("ENABLE", 3, "read-only"))
        derived_field = next(field for field in model.get_register(0x40000004).fields
                             if field.name == "ENABLE_COPY")
        self.assertEqual((derived_field.name, derived_field.bit_offset, derived_field.access),
                         ("ENABLE_COPY", 3, "read-only"))
        mode_fields = [field for field in model.get_register(0x40000000).fields
                       if field.name.startswith("MODE")]
        self.assertEqual([(field.name, field.bit_offset) for field in mode_fields],
                         [("MODEA", 8), ("MODEB", 9), ("MODEC", 10)])

    def test_parses_the_authored_demo_svd(self):
        path = os.path.join(os.path.dirname(__file__), "..", "demo", "demo.svd")
        model = parse_svd(path)

        self.assertEqual(model.name, "IRQScopeDemoM4")
        self.assertEqual(model.get_register(0x40013000).read_action, "clear")
        self.assertEqual(model.get_register(0x40013004).fields[0].name, "VALUE")
        ready = model.get_register(0x40013000).fields[0].enumerated_values[0]
        start = model.get_register(0x40013008).fields[0].enumerated_values[0]
        self.assertEqual((ready.usage, [value.name for value in ready.values]),
                         ("read", ["NOT_READY", "READY"]))
        self.assertEqual((start.usage, [value.name for value in start.values]),
                         ("write", ["IDLE", "BEGIN_TRANSFER"]))
        self.assertEqual((model.endianness, model.address_unit_bits, model.nvic_priority_bits),
                         ("little", 8, 3))

    def test_register_write_constraint_defaults_to_fields_and_explicit_field_overrides(self):
        content = """<device><name>ConstraintFixture</name><addressUnitBits>8</addressUnitBits>
          <cpu><endian>little</endian></cpu><size>32</size><peripherals>
          <peripheral><name>P</name><baseAddress>0x40000000</baseAddress><registers>
            <register><name>R</name><addressOffset>0</addressOffset>
              <writeConstraint><range><minimum>0</minimum><maximum>3</maximum></range></writeConstraint>
              <fields>
                <field><name>DEFAULTED</name><bitOffset>0</bitOffset><bitWidth>2</bitWidth></field>
                <field><name>OVERRIDE</name><bitOffset>2</bitOffset><bitWidth>2</bitWidth>
                  <enumeratedValues><usage>write</usage>
                    <enumeratedValue><name>ONE</name><value>1</value></enumeratedValue>
                  </enumeratedValues>
                  <writeConstraint><useEnumeratedValues>true</useEnumeratedValues></writeConstraint>
                </field>
                <field><name>CLEARED</name><bitOffset>4</bitOffset><bitWidth>2</bitWidth>
                  <writeConstraint><useEnumeratedValues>false</useEnumeratedValues></writeConstraint>
                </field>
              </fields>
            </register>
          </registers></peripheral></peripherals></device>"""
        register = self.parse_text(content).get_register(0x40000000)
        defaulted, override, cleared = register.fields
        self.assertEqual((defaulted.write_constraint, defaulted.write_constraint_source),
                         (WriteConstraint("range", 0, 3), "register-default"))
        self.assertEqual((override.write_constraint, override.write_constraint_source),
                         (WriteConstraint("enumerated-values-only"), "field"))
        self.assertEqual((cleared.write_constraint, cleared.write_constraint_source),
                         (None, "field"))
        passed = check_write_constraints(register, 0x4, 32, access_address=0x40000000,
                                         endianness="little", address_unit_bits=8)
        failed = check_write_constraints(register, 0x8, 32, access_address=0x40000000,
                                         endianness="little", address_unit_bits=8)
        self.assertEqual([check.status for check in passed], ["satisfied", "satisfied"])
        self.assertEqual([check.status for check in failed], ["satisfied", "violated"])

    def test_partial_store_checks_only_complete_fields_using_declared_endianness(self):
        register = Register(
            "P", "R", 0x40000000, 32, fields=(
                RegisterField("LOW", 0, 8,
                              enumerated_values=(self._write_enum("LOW", 0x34),),
                              write_constraint=WriteConstraint("enumerated-values-only")),
                RegisterField("CROSS", 4, 8,
                              write_constraint=WriteConstraint("range", 0, 3)),
                RegisterField("MIDDLE", 8, 8,
                              write_constraint=WriteConstraint("range", 0, 20)),
                RegisterField("HIGH", 24, 8,
                              enumerated_values=(self._write_enum("HIGH", 0x12),),
                              write_constraint=WriteConstraint("enumerated-values-only")),
            ),
        )
        little = check_write_constraints(
            register, 0x34, 8, access_address=0x40000000,
            endianness="little", address_unit_bits=8,
        )
        self.assertEqual([(check.scope, check.status) for check in little],
                         [("LOW", "satisfied"), ("CROSS", "unknown")])
        second_lane = check_write_constraints(
            register, 21, 8, access_address=0x40000001,
            endianness="little", address_unit_bits=8,
        )
        self.assertEqual([(check.scope, check.status) for check in second_lane],
                         [("CROSS", "unknown"), ("MIDDLE", "violated")])
        big = check_write_constraints(
            register, 0x12, 8, access_address=0x40000000,
            endianness="big", address_unit_bits=8,
        )
        self.assertEqual([(check.scope, check.status) for check in big],
                         [("HIGH", "satisfied")])
        uncertain = check_write_constraints(
            register, 0x34, 8, access_address=0x40000000,
            endianness="selectable", address_unit_bits=8,
        )
        self.assertEqual(uncertain[0].status, "unknown")
        self.assertIn("endianness", uncertain[0].detail)

    @staticmethod
    def _write_enum(name, value):
        from irqscope.model import EnumeratedValue, EnumeratedValues
        return EnumeratedValues(
            name=name,
            usage="write",
            values=(EnumeratedValue(name=f"V{value:X}", value=value),),
        )

    def test_preserves_peripheral_cluster_and_register_alternate_relationships(self):
        path = os.path.join(os.path.dirname(__file__), "..", "demo", "alternate-peripheral.svd")
        model = parse_svd(path)

        self.assertEqual(model.alternate_peripherals, {"PORTA_ANALOG": "PORTA"})
        self.assertEqual(model.alternate_clusters, {"PORTA.PIN_ANALOG": "PORTA.PIN"})
        self.assertEqual(model.alternate_registers, {"PORTA.DATA_ANALOG": "PORTA.DATA"})
        self.assertEqual(
            [item.display_name for item in model.get_registers(0x40020000)],
            ["PORTA.DATA", "PORTA.DATA_ANALOG", "PORTA_ANALOG.SAMPLE"],
        )
        self.assertEqual(
            [item.display_name for item in model.get_registers(0x40020010)],
            ["PORTA.PIN.CONTROL", "PORTA.PIN_ANALOG.SAMPLE_CONTROL"],
        )

    def test_alternate_peripheral_references_must_name_an_earlier_peripheral(self):
        def source(peripherals):
            return f"""<device><name>AlternateFixture</name><size>32</size><peripherals>
              {peripherals}
            </peripherals></device>"""

        primary = '<peripheral><name>BASE</name><baseAddress>0x40000000</baseAddress><registers><register><name>R</name><addressOffset>0</addressOffset></register></registers></peripheral>'
        valid_alternate = '<peripheral><name>ALT</name><alternatePeripheral>BASE</alternatePeripheral><baseAddress>0x40000000</baseAddress><registers><register><name>R2</name><addressOffset>0</addressOffset></register></registers></peripheral>'
        model = self.parse_text(source(primary + valid_alternate))
        self.assertEqual(model.alternate_peripherals, {"ALT": "BASE"})

        invalid = (
            primary + valid_alternate.replace("BASE</alternatePeripheral>", "MISSING</alternatePeripheral>"),
            primary + valid_alternate.replace("<name>ALT</name>", "<name>SELF</name>").replace(
                "BASE</alternatePeripheral>", "SELF</alternatePeripheral>"
            ),
            valid_alternate + primary,
        )
        for peripherals in invalid:
            with self.subTest(peripherals=peripherals):
                with self.assertRaises(SVDParseError):
                    self.parse_text(source(peripherals))

    def test_alternate_register_references_must_be_prior_unique_and_same_address(self):
        def source(registers):
            return f"""<device><name>AlternateFixture</name><size>32</size><peripherals>
              <peripheral><name>P</name><baseAddress>0x40000000</baseAddress>
                <registers>{registers}</registers>
              </peripheral></peripherals></device>"""

        primary = '<register><name>DATA</name><addressOffset>0</addressOffset></register>'
        alternate = '<register><name>DATA_ALT</name><alternateRegister>DATA</alternateRegister><addressOffset>{offset}</addressOffset></register>'
        model = self.parse_text(source(primary + alternate.format(offset="0")))
        self.assertEqual(model.alternate_registers, {"P.DATA_ALT": "P.DATA"})

        ambiguous = (
            primary + alternate.format(offset="4"),
            alternate.format(offset="0") + primary,
            primary + '<register><name>OTHER</name><addressOffset>4</addressOffset></register>'
            + alternate.replace("</alternateRegister>", "_MISSING</alternateRegister>").format(offset="0"),
            '<cluster><name>A</name><addressOffset>0</addressOffset><register><name>DATA</name><addressOffset>0</addressOffset></register></cluster>'
            '<cluster><name>B</name><addressOffset>0</addressOffset><register><name>DATA</name><addressOffset>0</addressOffset></register></cluster>'
            + alternate.format(offset="0"),
        )
        for registers in ambiguous:
            with self.subTest(registers=registers):
                with self.assertRaises(SVDParseError):
                    self.parse_text(source(registers))

    def test_alternate_cluster_requires_an_earlier_cluster_at_same_base(self):
        def source(clusters):
            return f"""<device><name>AlternateFixture</name><size>32</size><peripherals>
              <peripheral><name>P</name><baseAddress>0x40000000</baseAddress>
                <registers>{clusters}</registers>
              </peripheral></peripherals></device>"""

        primary = '<cluster><name>PORT</name><addressOffset>0x10</addressOffset><register><name>DATA</name><addressOffset>0</addressOffset></register></cluster>'
        alternate = '<cluster><name>PORT_ALT</name><alternateCluster>PORT</alternateCluster><addressOffset>{offset}</addressOffset><register><name>SAMPLE</name><addressOffset>0</addressOffset></register></cluster>'
        model = self.parse_text(source(primary + alternate.format(offset="0x10")))
        self.assertEqual(model.alternate_clusters, {"P.PORT_ALT": "P.PORT"})

        invalid = (
            alternate.format(offset="0x10"),
            alternate.format(offset="0x10") + primary,
            primary + alternate.format(offset="0x20"),
        )
        for clusters in invalid:
            with self.subTest(clusters=clusters):
                with self.assertRaises(SVDParseError):
                    self.parse_text(source(clusters))

    def test_parses_enumerated_values_patterns_and_inheritance(self):
        content = """<device><name>EnumFixture</name><size>32</size><peripherals>
          <peripheral><name>BASE</name><baseAddress>0x40000000</baseAddress><registers>
            <register><name>CTRL</name><addressOffset>0x0</addressOffset><fields>
              <field><name>MODE</name><bitOffset>0</bitOffset><bitWidth>4</bitWidth>
                <enumeratedValues><name>ModeSet</name><usage>read</usage>
                  <enumeratedValue><name>Idle</name><value>0</value><description>Stopped</description></enumeratedValue>
                  <enumeratedValue><name>Pattern</name><value>#10x1</value></enumeratedValue>
                  <enumeratedValue><name>Reserved</name><isDefault>true</isDefault></enumeratedValue>
                </enumeratedValues>
                <enumeratedValues><name>ModeCommands</name><usage>write</usage>
                  <enumeratedValue><name>Reset</name><value>0b0010</value></enumeratedValue>
                </enumeratedValues>
              </field>
              <field derivedFrom="BASE.CTRL.MODE"><name>MODE_COPY</name><description>copy</description></field>
              <field><name>MODE_ALIAS</name><bitOffset>4</bitOffset><bitWidth>4</bitWidth>
                <enumeratedValues derivedFrom="BASE.CTRL.MODE.ModeSet"/>
              </field>
            </fields></register>
          </registers></peripheral></peripherals></device>"""
        model = self.parse_text(content)
        fields = {field.name: field for field in model.get_register(0x40000000).fields}

        mode = fields["MODE"]
        self.assertEqual([item.usage for item in mode.enumerated_values], ["read", "write"])
        read_values = mode.enumerated_values[0].values
        self.assertEqual((read_values[0].name, read_values[0].value, read_values[0].mask),
                         ("Idle", 0, 0xF))
        self.assertEqual((read_values[1].name, read_values[1].value, read_values[1].mask,
                          read_values[1].pattern), ("Pattern", 0b1001, 0b1101, "#10x1"))
        self.assertTrue(read_values[2].is_default)
        self.assertEqual(fields["MODE_COPY"].enumerated_values, mode.enumerated_values)
        self.assertEqual(fields["MODE_ALIAS"].enumerated_values[0].values, read_values)
        with patch("irqscope.svd.MAX_ENUMERATED_VALUES", 3):
            with self.assertRaisesRegex(SVDParseError, "more than 3 enumerated values"):
                self.parse_text(content)

    def test_enumerated_value_references_fail_closed_when_missing_ambiguous_or_cyclic(self):
        template = """<device><name>EnumFixture</name><size>32</size><peripherals>
          <peripheral><name>BASE</name><baseAddress>0x40000000</baseAddress><registers>
            <register><name>CTRL</name><addressOffset>0x0</addressOffset><fields>{fields}</fields></register>
          </registers></peripheral></peripherals></device>"""
        valid = lambda name: (
            f'<field><name>{name}</name><bitOffset>0</bitOffset><bitWidth>2</bitWidth>'
            f'<enumeratedValues><name>Shared</name><enumeratedValue><name>Off</name>'
            f'<value>0</value></enumeratedValue></enumeratedValues></field>'
        )
        unresolved = valid("A") + (
            '<field><name>B</name><bitOffset>2</bitOffset><bitWidth>2</bitWidth>'
            '<enumeratedValues derivedFrom="Missing"/></field>'
        )
        with self.assertRaisesRegex(SVDParseError, "Unresolved enumeratedValues"):
            self.parse_text(template.format(fields=unresolved))

        ambiguous = valid("A") + valid("B") + (
            '<field><name>C</name><bitOffset>4</bitOffset><bitWidth>2</bitWidth>'
            '<enumeratedValues derivedFrom="Shared"/></field>'
        )
        with self.assertRaisesRegex(SVDParseError, "Ambiguous enumeratedValues"):
            self.parse_text(template.format(fields=ambiguous))

        cyclic = (
            '<field><name>A</name><bitOffset>0</bitOffset><bitWidth>2</bitWidth>'
            '<enumeratedValues derivedFrom="BSet"><name>ASet</name></enumeratedValues>'
            '<enumeratedValues derivedFrom="ASet"><name>BSet</name></enumeratedValues></field>'
        )
        with self.assertRaisesRegex(SVDParseError, "Cyclic enumeratedValues"):
            self.parse_text(template.format(fields=cyclic))

    def test_field_inheritance_overrides_enum_set_by_usage_not_position(self):
        content = """<device><name>EnumFixture</name><size>32</size><peripherals>
          <peripheral><name>BASE</name><baseAddress>0x40000000</baseAddress><registers>
            <register><name>CTRL</name><addressOffset>0x0</addressOffset><fields>
              <field><name>MODE</name><bitOffset>0</bitOffset><bitWidth>2</bitWidth>
                <enumeratedValues><name>ReadMode</name><usage>read</usage>
                  <enumeratedValue><name>Old</name><value>0</value></enumeratedValue></enumeratedValues>
                <enumeratedValues><name>WriteMode</name><usage>write</usage>
                  <enumeratedValue><name>Command</name><value>1</value></enumeratedValue></enumeratedValues>
              </field>
              <field derivedFrom="BASE.CTRL.MODE"><name>COPY</name><description>copy</description>
                <enumeratedValues><name>NewReadMode</name><usage>read</usage>
                  <enumeratedValue><name>New</name><value>2</value></enumeratedValue></enumeratedValues>
              </field>
            </fields></register></registers></peripheral></peripherals></device>"""
        model = self.parse_text(content)
        copied = next(field for field in model.get_register(0x40000000).fields if field.name == "COPY")
        self.assertEqual([(item.name, item.usage, [value.name for value in item.values])
                          for item in copied.enumerated_values],
                         [("NewReadMode", "read", ["New"]),
                          ("WriteMode", "write", ["Command"])])

    def test_rejects_overlapping_or_excess_enumeration_usages(self):
        sets = "".join(
            f'<enumeratedValues><usage>{usage}</usage><enumeratedValue>'
            f'<name>V{index}</name><value>{index}</value></enumeratedValue></enumeratedValues>'
            for index, usage in enumerate(("read", "write", "read-write"))
        )
        content = f"""<device><name>EnumFixture</name><size>32</size><peripherals>
          <peripheral><name>BASE</name><baseAddress>0x40000000</baseAddress><registers>
            <register><name>CTRL</name><addressOffset>0x0</addressOffset><fields>
              <field><name>MODE</name><bitOffset>0</bitOffset><bitWidth>2</bitWidth>{sets}</field>
            </fields></register></registers></peripheral></peripherals></device>"""
        with self.assertRaisesRegex(SVDParseError, "at most two"):
            self.parse_text(content)

    def test_preserves_multiple_descriptions_at_one_address(self):
        model = self.parse_text(SVD)

        aliases = model.get_registers(0x40000000)
        self.assertEqual([item.display_name for item in aliases], ["BASE.CTRL", "ALIAS.CTRL_VIEW"])
        self.assertEqual(model.register_count, len(model.all_registers()))

    def test_unresolved_and_cyclic_references_fail_closed(self):
        unresolved = SVD.replace('derivedFrom="BASE.CTRL"', 'derivedFrom="BASE.MISSING"', 1)
        with self.assertRaisesRegex(SVDParseError, "Unresolved register"):
            self.parse_text(unresolved)

        cyclic = SVD.replace('derivedFrom="CTRL"', 'derivedFrom="CTRL_COPY"', 1)
        with self.assertRaisesRegex(SVDParseError, "Cyclic register"):
            self.parse_text(cyclic)

    def test_field_limit_applies_after_register_array_expansion(self):
        with patch("irqscope.svd.MAX_EXPANDED_FIELDS", 10):
            with self.assertRaisesRegex(SVDParseError, "expands to more than 10 fields"):
                self.parse_text(SVD)


if __name__ == "__main__":
    unittest.main()
