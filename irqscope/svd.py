"""Small, dependency-free CMSIS-SVD reader for register-level evidence.

This reader intentionally preserves the register-level evidence used by the
prototype. It resolves common SVD inheritance scopes, expands register arrays
and field ranges, and fails closed on malformed or unresolved input.
"""

import copy
import hashlib
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from .model import (
    DeviceModel, EnumeratedValue, EnumeratedValues, Register, RegisterField,
    WriteConstraint, WriteConstraintCheck,
)


MAX_SVD_BYTES = 32 * 1024 * 1024
MAX_SVD_NODES = 500_000
MAX_SVD_DEPTH = 128
MAX_DERIVATION_DEPTH = 256
MAX_EXPANDED_REGISTERS = 250_000
MAX_EXPANDED_FIELDS = 1_000_000
MAX_ENUMERATED_VALUES = 1_000_000
MAX_ARRAY_ELEMENTS = 65_536
REGISTER_PROPERTIES = ("size", "access", "resetValue", "resetMask")


class SVDParseError(ValueError):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(node: ET.Element, name: str) -> Optional[ET.Element]:
    for item in node:
        if _local(item.tag) == name:
            return item
    return None


def _text(node: Optional[ET.Element], default: str = "") -> str:
    if node is None or node.text is None:
        return default
    return node.text.strip()


def _register_children(parent: ET.Element) -> List[ET.Element]:
    container = _child(parent, "registers")
    if container is not None:
        return list(container)
    if _local(parent.tag) == "cluster":
        return list(parent)
    return []


def _merge_svd_node(source: ET.Element, override: ET.Element) -> ET.Element:
    """Copy an SVD node and apply explicitly provided values from an override."""
    merged = copy.deepcopy(source)
    for child in list(merged):
        if _local(child.tag) in {"alternatePeripheral", "alternateCluster", "alternateRegister"}:
            merged.remove(child)
    for key, value in override.attrib.items():
        merged.set(key, value)

    for child in override:
        child_name = _text(_child(child, "name"))
        match = None
        for candidate in merged:
            if _local(candidate.tag) != _local(child.tag):
                continue
            candidate_name = _text(_child(candidate, "name"))
            if child_name:
                if candidate_name == child_name:
                    match = candidate
                    break
                if (_local(child.tag) == "enumeratedValues"
                        and _text(_child(child, "usage"), "read-write").lower()
                        == _text(_child(candidate, "usage"), "read-write").lower()):
                    match = candidate
                    break
            elif _local(child.tag) == "enumeratedValues":
                child_usage = _text(_child(child, "usage"), "read-write").lower()
                candidate_usage = _text(_child(candidate, "usage"), "read-write").lower()
                if child_usage == candidate_usage:
                    match = candidate
                    break
            elif not candidate_name:
                match = candidate
                break
        if match is None:
            merged.append(copy.deepcopy(child))
        else:
            replace_enumeration = (
                _local(child.tag) == "enumeratedValues"
                and (child.attrib.get("derivedFrom")
                     or child_name != _text(_child(match, "name")))
            )
            replacement = copy.deepcopy(child) if replace_enumeration else _merge_svd_node(match, child)
            position = list(merged).index(match)
            merged.remove(match)
            merged.insert(position, replacement)
    merged.text = override.text if override.text and override.text.strip() else merged.text
    return merged


def _replace_svd_node(target: ET.Element, replacement: ET.Element) -> None:
    target.clear()
    target.tag = replacement.tag
    target.attrib.update(replacement.attrib)
    target.text = replacement.text
    target.tail = replacement.tail
    for child in replacement:
        target.append(copy.deepcopy(child))


def _validate_tree_complexity(root: ET.Element) -> None:
    stack = [(root, 1)]
    node_count = 0
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if depth > MAX_SVD_DEPTH:
            raise SVDParseError(f"SVD XML nesting exceeds {MAX_SVD_DEPTH} levels")
        if node_count > MAX_SVD_NODES:
            raise SVDParseError(f"SVD XML contains more than {MAX_SVD_NODES} elements")
        stack.extend((child, depth + 1) for child in node)


def _resolve_inheritance(nodes: Dict[str, ET.Element], scopes: Dict[str, str], label: str) -> None:
    """Resolve one named SVD scope, preserving inherited children and overrides."""
    resolved: Dict[str, ET.Element] = {}
    active = set()

    def resolve(key: str) -> ET.Element:
        if key in resolved:
            return resolved[key]
        if key in active:
            raise SVDParseError(f"Cyclic {label} inheritance at {key}")
        if len(active) >= MAX_DERIVATION_DEPTH:
            raise SVDParseError(f"{label.capitalize()} inheritance exceeds {MAX_DERIVATION_DEPTH} levels")
        node = nodes[key]
        reference = node.attrib.get("derivedFrom", "").strip()
        if not reference:
            result = copy.deepcopy(node)
        else:
            source_key = reference if reference in nodes else f"{scopes[key]}.{reference}"
            if source_key not in nodes:
                raise SVDParseError(f"Unresolved {label} derivedFrom {reference!r} at {key}")
            active.add(key)
            result = _merge_svd_node(resolve(source_key), node)
            active.remove(key)
        result.attrib.pop("derivedFrom", None)
        resolved[key] = result
        return result

    for key in nodes:
        resolve(key)
    for key, node in nodes.items():
        _replace_svd_node(node, resolved[key])


def _collect_peripheral_nodes(peripherals: List[ET.Element], kind: str):
    nodes: Dict[str, ET.Element] = {}
    scopes: Dict[str, str] = {}

    def visit(parent: ET.Element, scope: str) -> None:
        for item in _register_children(parent):
            item_kind = _local(item.tag)
            if item_kind not in ("register", "cluster"):
                continue
            name = _text(_child(item, "name"), "unnamed")
            key = f"{scope}.{name}"
            if item_kind == kind:
                if key in nodes:
                    raise SVDParseError(f"Duplicate {kind} path in SVD: {key}")
                nodes[key] = item
                scopes[key] = scope
            if item_kind == "cluster":
                visit(item, key)

    for peripheral in peripherals:
        visit(peripheral, _text(_child(peripheral, "name"), "unnamed"))
    return nodes, scopes


def _resolve_register_tree(peripherals: List[ET.Element]) -> None:
    while True:
        clusters, scopes = _collect_peripheral_nodes(peripherals, "cluster")
        pending = any(node.attrib.get("derivedFrom") for node in clusters.values())
        if not pending:
            break
        _resolve_inheritance(clusters, scopes, "cluster")

    registers, scopes = _collect_peripheral_nodes(peripherals, "register")
    _resolve_inheritance(registers, scopes, "register")

    fields: Dict[str, ET.Element] = {}
    field_scopes: Dict[str, str] = {}
    for register_key, register in registers.items():
        field_container = _child(register, "fields")
        if field_container is None:
            continue
        for field_node in field_container:
            if _local(field_node.tag) != "field":
                continue
            field_name = _text(_child(field_node, "name"), "unnamed")
            field_key = f"{register_key}.{field_name}"
            if field_key in fields:
                raise SVDParseError(f"Duplicate field path in SVD: {field_key}")
            fields[field_key] = field_node
            field_scopes[field_key] = register_key
    _resolve_inheritance(fields, field_scopes, "field")
    _resolve_enumerated_value_sets(fields)


def _resolve_enumerated_value_sets(fields: Dict[str, ET.Element]) -> None:
    """Resolve named enumeratedValues references after field inheritance."""
    nodes = {}
    names = {}
    scopes = {}
    for field_key, field_node in fields.items():
        ordinal_by_usage = {}
        for enum_node in field_node:
            if _local(enum_node.tag) != "enumeratedValues":
                continue
            name = _text(_child(enum_node, "name"))
            usage = _text(_child(enum_node, "usage"), "read-write").lower()
            ordinal = ordinal_by_usage.get(usage, 0)
            ordinal_by_usage[usage] = ordinal + 1
            key = f"{field_key}.{name}" if name else f"{field_key}.@{usage}:{ordinal}"
            if key in nodes:
                raise SVDParseError(f"Duplicate enumeratedValues set at {field_key}: {name or usage}")
            nodes[key] = enum_node
            scopes[key] = field_key
            if name:
                names.setdefault(name, []).append(key)

    resolved = {}
    active = set()
    resolved_value_count = [0]

    def resolve_key(key: str) -> ET.Element:
        if key in resolved:
            return resolved[key]
        if key in active:
            raise SVDParseError(f"Cyclic enumeratedValues inheritance at {key}")
        if len(active) >= MAX_DERIVATION_DEPTH:
            raise SVDParseError(
                f"EnumeratedValues inheritance exceeds {MAX_DERIVATION_DEPTH} levels"
            )
        node = nodes[key]
        reference = node.attrib.get("derivedFrom", "").strip()
        if not reference:
            result = copy.deepcopy(node)
        else:
            candidates = []
            if reference in nodes:
                candidates = [reference]
            else:
                local_key = f"{scopes[key]}.{reference}"
                if local_key in nodes:
                    candidates = [local_key]
                else:
                    candidates = [candidate for candidate in nodes
                                  if candidate.endswith(f".{reference}")]
                    if not candidates:
                        candidates = names.get(reference, [])
            candidates = sorted(set(candidates))
            if not candidates:
                raise SVDParseError(
                    f"Unresolved enumeratedValues derivedFrom {reference!r} at {key}"
                )
            if len(candidates) != 1:
                raise SVDParseError(
                    f"Ambiguous enumeratedValues derivedFrom {reference!r} at {key}"
                )
            active.add(key)
            source = resolve_key(candidates[0])
            active.remove(key)
            forbidden = [child for child in node
                          if _local(child.tag) not in ("name", "headerEnumName")]
            if forbidden:
                raise SVDParseError(
                    f"enumeratedValues derivedFrom cannot override entries or usage at {key}"
                )
            result = copy.deepcopy(source)
            for tag_name in ("name", "headerEnumName"):
                override_child = _child(node, tag_name)
                if override_child is not None:
                    current = _child(result, tag_name)
                    if current is None:
                        result.append(copy.deepcopy(override_child))
                    else:
                        current.text = override_child.text
        result.attrib.pop("derivedFrom", None)
        value_count = sum(1 for child in result if _local(child.tag) == "enumeratedValue")
        resolved_value_count[0] += value_count
        if resolved_value_count[0] > MAX_ENUMERATED_VALUES:
            raise SVDParseError(
                f"SVD expands to more than {MAX_ENUMERATED_VALUES} enumerated values"
            )
        resolved[key] = result
        return result

    for key, node in nodes.items():
        _replace_svd_node(node, resolve_key(key))


def _int(value: str, label: str) -> int:
    try:
        normalized = value.strip().replace("_", "")
        if normalized.startswith("#"):
            return int(normalized[1:], 2)
        return int(normalized, 0)
    except (AttributeError, ValueError) as exc:
        raise SVDParseError(f"Invalid integer for {label}: {value!r}") from exc


def _dim_indices(register: ET.Element, count: int) -> List[str]:
    raw = _text(_child(register, "dimIndex"))
    if raw:
        pieces = [part.strip() for part in raw.split(",") if part.strip()]
        if len(pieces) == count:
            return pieces
        match = re.fullmatch(r"(-?\d+)\s*-\s*(-?\d+)", raw)
        if match:
            lo, hi = map(int, match.groups())
            step = 1 if hi >= lo else -1
            values = [str(x) for x in range(lo, hi + step, step)]
            if len(values) == count:
                return values
        match = re.fullmatch(r"([A-Za-z])\s*-\s*([A-Za-z])", raw)
        if match:
            lo, hi = (ord(item) for item in match.groups())
            step = 1 if hi >= lo else -1
            values = [chr(value) for value in range(lo, hi + step, step)]
            if len(values) == count:
                return values
    return [str(index) for index in range(count)]


def _expand_peripheral_arrays(peripherals: List[ET.Element]) -> List[ET.Element]:
    expanded = []
    total = 0
    for node in peripherals:
        dim = _child(node, "dim")
        if dim is None:
            expanded.append(node)
            total += 1
            continue
        count = _int(_text(dim), "peripheral.dim")
        if count < 1 or count > MAX_ARRAY_ELEMENTS:
            raise SVDParseError(f"Unreasonable peripheral array size: {count}")
        increment = _int(_text(_child(node, "dimIncrement"), "0"), "peripheral.dimIncrement")
        labels = _dim_indices(node, count)
        name_node = _child(node, "name")
        base_node = _child(node, "baseAddress")
        if name_node is None or base_node is None:
            raise SVDParseError("Peripheral arrays require name and baseAddress elements")
        base = _int(_text(base_node), "peripheral.baseAddress")
        for index, label in enumerate(labels):
            clone = copy.deepcopy(node)
            clone_name = _child(clone, "name")
            clone_name.text = (
                _text(clone_name).replace("%s", label)
                if "%s" in _text(clone_name)
                else f"{_text(clone_name)}{label}"
            )
            alternate_node = _child(clone, "alternatePeripheral")
            if alternate_node is not None and "%s" in _text(alternate_node):
                alternate_node.text = _text(alternate_node).replace("%s", label)
            _child(clone, "baseAddress").text = f"0x{base + index * increment:X}"
            for dimension_tag in ("dim", "dimIncrement", "dimIndex", "dimArrayIndex"):
                dimension_node = _child(clone, dimension_tag)
                if dimension_node is not None:
                    clone.remove(dimension_node)
            expanded.append(clone)
            total += 1
            if total > MAX_EXPANDED_REGISTERS:
                raise SVDParseError("SVD expands to too many peripherals")
    return expanded


def _parse_enumerated_value(node: ET.Element, width: int) -> EnumeratedValue:
    name = _text(_child(node, "name"))
    description = _text(_child(node, "description"))
    value_node = _child(node, "value")
    default_text = _text(_child(node, "isDefault")).lower()
    if default_text not in ("", "true", "false", "1", "0"):
        raise SVDParseError(f"Invalid isDefault value for enumerated value {name!r}")
    is_default = default_text in ("true", "1")
    if value_node is not None and is_default:
        raise SVDParseError(f"Enumerated value {name!r} cannot define both value and isDefault")
    if value_node is None:
        if not is_default:
            raise SVDParseError(f"Enumerated value {name!r} requires a value or isDefault")
        return EnumeratedValue(name=name, description=description, is_default=True)

    pattern = _text(value_node).replace("_", "")
    base2 = pattern.startswith("#") or pattern.lower().startswith("0b")
    bits = pattern[1:] if pattern.startswith("#") else pattern[2:] if pattern.lower().startswith("0b") else ""
    if base2 and re.fullmatch(r"[01xX]+", bits):
        if len(bits) > width:
            raise SVDParseError(f"Enumerated pattern {pattern!r} exceeds its {width}-bit field")
        padded = bits.rjust(width, "0").lower()
        value = int(padded.replace("x", "0"), 2)
        mask = int("".join("0" if bit == "x" else "1" for bit in padded), 2)
    else:
        value = _int(pattern, f"enumeratedValue {name or '<unnamed>'}")
        if value < 0 or value >= (1 << width):
            raise SVDParseError(f"Enumerated value {pattern!r} exceeds its {width}-bit field")
        mask = (1 << width) - 1
    return EnumeratedValue(
        name=name,
        value=value,
        mask=mask,
        pattern=pattern,
        description=description,
    )


def _parse_enumerated_values(field_node: ET.Element, width: int):
    parsed = []
    usages = set()
    for node in field_node:
        if _local(node.tag) != "enumeratedValues":
            continue
        usage = _text(_child(node, "usage"), "read-write").lower()
        if usage not in {"read", "write", "read-write"}:
            raise SVDParseError(f"Invalid enumeratedValues usage: {usage!r}")
        if usage in usages:
            raise SVDParseError(f"Duplicate enumeratedValues usage {usage!r} on field {_text(_child(field_node, 'name'))!r}")
        if len(usages) >= 2 or (usages and usage == "read-write") or "read-write" in usages:
            raise SVDParseError("A field may define at most two non-overlapping enumeratedValues usages")
        usages.add(usage)
        values = tuple(
            _parse_enumerated_value(value_node, width)
            for value_node in node
            if _local(value_node.tag) == "enumeratedValue"
        )
        defaults = sum(item.is_default for item in values)
        if defaults > 1:
            raise SVDParseError("An enumeratedValues set may have at most one default entry")
        if not values:
            raise SVDParseError("An enumeratedValues set must contain at least one entry")
        parsed.append(EnumeratedValues(
            name=_text(_child(node, "name")),
            header_enum_name=_text(_child(node, "headerEnumName")),
            usage=usage,
            values=values,
        ))
    return tuple(parsed)


def _parse_write_constraint(node: ET.Element, width: int, label: str):
    constraint = _child(node, "writeConstraint")
    if constraint is None:
        return None
    options = [child for child in constraint
               if _local(child.tag) in {"writeAsRead", "useEnumeratedValues", "range"}]
    if len(options) != 1:
        raise SVDParseError(f"{label} must specify exactly one writeConstraint option")
    option = options[0]
    option_name = _local(option.tag)
    if option_name in {"writeAsRead", "useEnumeratedValues"}:
        raw = _text(option).lower()
        if raw not in {"true", "false", "1", "0"}:
            raise SVDParseError(f"Invalid boolean in {label}.writeConstraint: {raw!r}")
        if raw in {"false", "0"}:
            return None
        kind = "write-as-read" if option_name == "writeAsRead" else "enumerated-values-only"
        return WriteConstraint(kind)
    minimum_node = _child(option, "minimum")
    maximum_node = _child(option, "maximum")
    if minimum_node is None or maximum_node is None:
        raise SVDParseError(f"{label}.writeConstraint.range requires minimum and maximum")
    minimum = _int(_text(minimum_node), f"{label}.writeConstraint.minimum")
    maximum = _int(_text(maximum_node), f"{label}.writeConstraint.maximum")
    width_maximum = (1 << width) - 1
    if minimum < 0 or maximum < minimum or maximum > width_maximum:
        raise SVDParseError(f"Invalid writeConstraint range for {label}: {minimum}..{maximum}")
    return WriteConstraint("range", minimum, maximum)


def _enumerated_write_check(field: RegisterField, value: int):
    value_sets = [value_set for value_set in field.enumerated_values
                  if value_set.usage in {"write", "read-write"}]
    entries = [entry for value_set in value_sets for entry in value_set.values]
    explicit = [entry for entry in entries if not entry.is_default]
    if not explicit:
        return "unknown", "no explicit writable enumerated values are available"
    for entry in explicit:
        if entry.value is not None:
            mask = entry.mask if entry.mask is not None else (1 << field.bit_width) - 1
            if (value & mask) == (entry.value & mask):
                return "satisfied", f"value 0x{value:X} matches enum {entry.name}"
            continue
        pattern = (entry.pattern or "").lower().replace("0b", "").replace("#", "")
        pattern = pattern.replace("_", "").replace(" ", "")
        if not pattern or len(pattern) > field.bit_width:
            continue
        padded = pattern.rjust(field.bit_width, "x")
        if all(bit in ("x", "?") or (bit in ("0", "1")
                                      and ((value >> (field.bit_width - index - 1)) & 1) == int(bit))
               for index, bit in enumerate(padded)):
            return "satisfied", f"value 0x{value:X} matches enum pattern for {entry.name}"
    if any(entry.is_default for entry in entries):
        return "unknown", f"value 0x{value:X} may be accepted by a default enum"
    return "violated", f"value 0x{value:X} matches no writable enumerated value"


def _write_lane_unknown_reason(register: Register, access_width: int,
                               access_address: Optional[int], endianness: str,
                               address_unit_bits: Optional[int]) -> str:
    if access_address is None:
        return "partial store address is unavailable for field-lane mapping"
    byte_offset = access_address - register.address
    if byte_offset < 0 or byte_offset * 8 + access_width > register.size_bits:
        return "store address or width extends outside the declared register"
    if address_unit_bits != 8:
        return "field-lane mapping requires 8-bit SVD address units"
    if register.size_bits % 8 != 0 or access_width % 8 != 0:
        return "field-lane mapping requires byte-aligned register and store widths"
    if endianness not in {"little", "big"}:
        return "partial store lane is unknown because SVD CPU endianness is missing or configurable"
    return "store lane cannot be mapped to the declared register"


def check_write_constraints(register: Register, value: Optional[int], access_width: int,
                            aliases=(), access_address: Optional[int] = None,
                            endianness: str = "unknown", address_unit_bits: Optional[int] = 8):
    """Check a recovered store against supported SVD constraints, preserving uncertainty."""
    checks = []
    if aliases:
        detail = "address has multiple SVD descriptions; select the applicable register alias"
        for description in (register, *aliases):
            if description.write_constraint is not None and not description.fields:
                checks.append(WriteConstraintCheck(
                    description.display_name, description.write_constraint.kind,
                    "unknown", value, detail,
                ))
            for field in description.fields:
                if field.write_constraint is not None:
                    checks.append(WriteConstraintCheck(
                        f"{description.display_name}.{field.name}",
                        field.write_constraint.kind, "unknown", value, detail,
                    ))
        return tuple(checks)
    lane_start = None
    if (access_width == register.size_bits
            and (access_address is None or access_address == register.address)):
        lane_start = 0
    elif access_address is not None and access_width > 0 and address_unit_bits == 8:
        byte_offset = access_address - register.address
        if byte_offset >= 0 and byte_offset * 8 + access_width <= register.size_bits:
            if byte_offset == 0 and access_width == register.size_bits:
                lane_start = 0
            elif (endianness == "little" and register.size_bits % 8 == 0
                  and access_width % 8 == 0):
                lane_start = byte_offset * 8
            elif (endianness == "big" and register.size_bits % 8 == 0
                  and access_width % 8 == 0):
                lane_start = register.size_bits - (byte_offset * 8 + access_width)
    lane_end = lane_start + access_width if lane_start is not None else None
    full_width = lane_start == 0 and access_width == register.size_bits
    # A register-level constraint is a default for each declared field. Only
    # apply it to the whole stored value when the SVD has no field layout.
    if register.write_constraint is not None and not register.fields:
        constraint = register.write_constraint
        if value is None:
            status, detail = "unknown", "store value was not recovered"
        elif constraint.kind == "range" and full_width:
            status = "satisfied" if constraint.minimum <= value <= constraint.maximum else "violated"
            detail = (
                f"0x{value:X} is within 0x{constraint.minimum:X}..0x{constraint.maximum:X}"
                if status == "satisfied" else
                f"0x{value:X} is outside 0x{constraint.minimum:X}..0x{constraint.maximum:X}"
            )
        elif constraint.kind == "enumerated-values-only" and full_width:
            full_register_field = next((field for field in register.fields
                                        if field.bit_offset == 0
                                        and field.bit_width == register.size_bits), None)
            if full_register_field is None:
                status, detail = "unknown", "register enum constraint cannot be checked from its field layout"
            else:
                status, detail = _enumerated_write_check(full_register_field, value)
        elif constraint.kind == "write-as-read":
            status, detail = "unknown", "checking write-as-read requires the prior runtime read value"
        elif not full_width:
            status, detail = "unknown", _write_lane_unknown_reason(
                register, access_width, access_address, endianness, address_unit_bits
            )
        else:
            status, detail = "unknown", "full-register constraint has no complete register value"
        checks.append(WriteConstraintCheck("register", constraint.kind, status, value, detail))

    for field in register.fields:
        constraint = field.write_constraint
        if constraint is None:
            continue
        if (field.bit_offset < 0 or field.bit_width <= 0
              or field.bit_offset + field.bit_width > register.size_bits):
            status, detail = "unknown", "field bit layout is outside the declared register width"
        elif lane_start is None or lane_end is None:
            status, detail = "unknown", _write_lane_unknown_reason(
                register, access_width, access_address, endianness, address_unit_bits
            )
        elif lane_start >= field.bit_offset + field.bit_width or lane_end <= field.bit_offset:
            continue
        elif lane_start > field.bit_offset or lane_end < field.bit_offset + field.bit_width:
            status, detail = "unknown", "store covers only part of this constrained field"
        elif value is None:
            status, detail = "unknown", "store value was not recovered"
        elif constraint.kind == "range":
            field_value = (value >> (field.bit_offset - lane_start)) & ((1 << field.bit_width) - 1)
            status = "satisfied" if constraint.minimum <= field_value <= constraint.maximum else "violated"
            detail = (
                f"field value 0x{field_value:X} is within 0x{constraint.minimum:X}..0x{constraint.maximum:X}"
                if status == "satisfied" else
                f"field value 0x{field_value:X} is outside 0x{constraint.minimum:X}..0x{constraint.maximum:X}"
            )
        elif constraint.kind == "enumerated-values-only":
            field_value = (value >> (field.bit_offset - lane_start)) & ((1 << field.bit_width) - 1)
            status, detail = _enumerated_write_check(field, field_value)
        elif constraint.kind == "write-as-read":
            status, detail = "unknown", "checking write-as-read requires the prior runtime field value"
        else:
            status, detail = "unknown", "constraint kind is not supported by the checker"
        checks.append(WriteConstraintCheck(field.name, constraint.kind, status, value, detail))
    return tuple(checks)


def _parse_fields(register: ET.Element, inherited_access: str,
                  inherited_read_action: str, inherited_write_action: str,
                  inherited_write_constraint: Optional[WriteConstraint] = None,
                  expanded_field_count: Optional[List[int]] = None,
                  expanded_enumerated_count: Optional[List[int]] = None):
    if expanded_field_count is None:
        expanded_field_count = [0]
    if expanded_enumerated_count is None:
        expanded_enumerated_count = [0]
    container = _child(register, "fields")
    if container is None:
        return ()
    fields = []
    for node in container:
        if _local(node.tag) != "field":
            continue
        name = _text(_child(node, "name"), "unnamed")
        dim = _child(node, "dim")
        count = _int(_text(dim, "1"), f"{name}.dim") if dim is not None else 1
        increment = _int(_text(_child(node, "dimIncrement"), "0"),
                         f"{name}.dimIncrement")
        if count < 1 or count > MAX_ARRAY_ELEMENTS:
            raise SVDParseError(f"Unreasonable field array size for {name}: {count}")
        offset_node = _child(node, "bitOffset")
        width_node = _child(node, "bitWidth")
        if offset_node is not None and width_node is not None:
            offset = _int(_text(offset_node), f"{name}.bitOffset")
            width = _int(_text(width_node), f"{name}.bitWidth")
        else:
            range_node = _child(node, "bitRange")
            match = re.fullmatch(r"\[\s*(\d+)\s*:\s*(\d+)\s*\]", _text(range_node))
            if match:
                high, low = map(int, match.groups())
                offset, width = low, high - low + 1
            else:
                lsb = _child(node, "lsb")
                msb = _child(node, "msb")
                if lsb is None or msb is None:
                    continue
                low = _int(_text(lsb), f"{name}.lsb")
                high = _int(_text(msb), f"{name}.msb")
                offset, width = low, high - low + 1
        if offset < 0 or width < 1 or width > 128:
            continue
        access = _text(_child(node, "access"), inherited_access)
        read_action = _text(_child(node, "readAction"), inherited_read_action)
        modified_write = _text(_child(node, "modifiedWriteValues"), inherited_write_action)
        enumerated_values = _parse_enumerated_values(node, width)
        has_field_constraint = _child(node, "writeConstraint") is not None
        write_constraint = (
            _parse_write_constraint(node, width, name)
            if has_field_constraint else inherited_write_constraint
        )
        write_constraint_source = (
            "field" if has_field_constraint else
            ("register-default" if inherited_write_constraint is not None else None)
        )
        expanded_enumerated_count[0] += count * sum(len(item.values) for item in enumerated_values)
        if expanded_enumerated_count[0] > MAX_ENUMERATED_VALUES:
            raise SVDParseError(
                f"SVD expands to more than {MAX_ENUMERATED_VALUES} enumerated values"
            )
        for index, label in enumerate(_dim_indices(node, count)):
            expanded_name = name.replace("%s", label) if "%s" in name else (
                f"{name}{label}" if count > 1 else name
            )
            fields.append(RegisterField(
                name=expanded_name,
                bit_offset=offset + index * increment,
                bit_width=width,
                access=access,
                read_action=read_action,
                modified_write_values=modified_write,
                enumerated_values=enumerated_values,
                write_constraint=write_constraint,
                write_constraint_source=write_constraint_source,
            ))
            expanded_field_count[0] += 1
            if expanded_field_count[0] > MAX_EXPANDED_FIELDS:
                raise SVDParseError(f"SVD expands to more than {MAX_EXPANDED_FIELDS} fields")
    return tuple(fields)


def _expand_registers(parent: ET.Element, peripheral_name: str,
                      base_address: int, inherited: Dict[str, str],
                      registers: Dict[int, List[Register]], prefix: str = "",
                      alternate_registers: Optional[Dict[str, str]] = None,
                      alternate_clusters: Optional[Dict[str, str]] = None,
                      cluster_bases: Optional[Dict[str, int]] = None,
                      expanded_count: Optional[List[int]] = None,
                      expanded_field_count: Optional[List[int]] = None,
                      expanded_enumerated_count: Optional[List[int]] = None) -> None:
    if expanded_count is None:
        expanded_count = [0]
    if alternate_registers is None:
        alternate_registers = {}
    if alternate_clusters is None:
        alternate_clusters = {}
    if cluster_bases is None:
        cluster_bases = {}
    if expanded_field_count is None:
        expanded_field_count = [0]
    if expanded_enumerated_count is None:
        expanded_enumerated_count = [0]
    for item in _register_children(parent):
        kind = _local(item.tag)
        if kind not in ("register", "cluster"):
            continue
        name = _text(_child(item, "name"), "unnamed")
        full_name = f"{prefix}{name}" if prefix else name
        offset = _int(_text(_child(item, "addressOffset"), "0"), f"{full_name}.addressOffset")
        if kind == "cluster":
            cluster_defaults = dict(inherited)
            for property_name in REGISTER_PROPERTIES:
                value = _text(_child(item, property_name))
                if value:
                    cluster_defaults[property_name] = value
            dim = _child(item, "dim")
            count = _int(_text(dim, "1"), f"{full_name}.dim") if dim is not None else 1
            increment = _int(_text(_child(item, "dimIncrement"), "0"),
                             f"{full_name}.dimIncrement")
            if count < 1 or count > MAX_ARRAY_ELEMENTS:
                raise SVDParseError(f"Unreasonable cluster array size for {full_name}: {count}")
            for index, label in enumerate(_dim_indices(item, count)):
                cluster_name = full_name.replace("%s", label) if "%s" in full_name else (
                    f"{full_name}{label}" if count > 1 else full_name
                )
                cluster_base = base_address + offset + index * increment
                alternate_node = _child(item, "alternateCluster")
                if alternate_node is not None:
                    reference = _text(alternate_node).replace("%s", label)
                    candidates = [
                        name for name in cluster_bases
                        if name.startswith(peripheral_name + ".")
                        and (name == reference or name.endswith("." + reference))
                    ]
                    if not candidates:
                        raise SVDParseError(
                            f"alternateCluster {reference!r} at {peripheral_name}.{cluster_name} "
                            "does not reference an earlier cluster"
                        )
                    if len(candidates) != 1:
                        raise SVDParseError(
                            f"alternateCluster {reference!r} at {peripheral_name}.{cluster_name} is ambiguous"
                        )
                    primary_name = candidates[0]
                    alternate_name = f"{peripheral_name}.{cluster_name}"
                    if primary_name == alternate_name:
                        raise SVDParseError(f"Cluster {alternate_name} cannot be its own alternate")
                    if cluster_bases[primary_name] != cluster_base:
                        raise SVDParseError(
                            f"alternateCluster {reference!r} at {alternate_name} "
                            "does not share the referenced cluster base address"
                        )
                    alternate_clusters[alternate_name] = primary_name
                _expand_registers(item, peripheral_name, cluster_base,
                                  cluster_defaults, registers, prefix=cluster_name + ".",
                                  alternate_registers=alternate_registers,
                                  alternate_clusters=alternate_clusters,
                                  cluster_bases=cluster_bases,
                                  expanded_count=expanded_count,
                                  expanded_field_count=expanded_field_count,
                                  expanded_enumerated_count=expanded_enumerated_count)
                cluster_bases[f"{peripheral_name}.{cluster_name}"] = cluster_base
            continue

        dim = _child(item, "dim")
        count = _int(_text(dim, "1"), f"{full_name}.dim") if dim is not None else 1
        increment_node = _child(item, "dimIncrement")
        increment = _int(_text(increment_node, "0"), f"{full_name}.dimIncrement") if increment_node is not None else 0
        if count < 1 or count > MAX_ARRAY_ELEMENTS:
            raise SVDParseError(f"Unreasonable register array size for {full_name}: {count}")
        labels = _dim_indices(item, count)
        size_text = _text(_child(item, "size"), inherited.get("size", "32"))
        access = _text(_child(item, "access"), inherited.get("access", "unknown"))
        read_action = _text(_child(item, "readAction"), inherited.get("readAction", ""))
        modified_write = _text(
            _child(item, "modifiedWriteValues"), inherited.get("modifiedWriteValues", "")
        )
        description = _text(_child(item, "description"))
        size_bits = _int(size_text, f"{full_name}.size")
        if size_bits < 1 or size_bits > 128:
            raise SVDParseError(f"Unsupported register width for {full_name}: {size_bits}")
        write_constraint = _parse_write_constraint(item, size_bits, full_name)
        fields = _parse_fields(item, access, read_action, modified_write,
                               write_constraint,
                               expanded_field_count, expanded_enumerated_count)
        width_mask = (1 << size_bits) - 1
        reset_value_text = _text(_child(item, "resetValue"), inherited.get("resetValue", ""))
        reset_mask_text = _text(_child(item, "resetMask"), inherited.get("resetMask", ""))
        reset_value = _int(reset_value_text, f"{full_name}.resetValue") if reset_value_text else None
        reset_mask = _int(reset_mask_text, f"{full_name}.resetMask") if reset_mask_text else None
        if reset_value is not None and (reset_value < 0 or reset_value & ~width_mask):
            raise SVDParseError(f"Reset value does not fit the {size_bits}-bit register {full_name}")
        if reset_mask is not None and (reset_mask < 0 or reset_mask & ~width_mask):
            raise SVDParseError(f"Reset mask does not fit the {size_bits}-bit register {full_name}")

        for index, label in enumerate(labels):
            expanded_name = full_name.replace("%s", label) if "%s" in full_name else (
                f"{full_name}{label}" if count > 1 else full_name
            )
            address = base_address + offset + index * increment
            register = Register(
                peripheral=peripheral_name,
                name=expanded_name,
                address=address,
                size_bits=size_bits,
                access=access,
                read_action=read_action,
                modified_write_values=modified_write,
                description=description,
                fields=fields,
                reset_value=reset_value,
                reset_mask=reset_mask,
                write_constraint=write_constraint,
            )
            alternate_node = _child(item, "alternateRegister")
            if alternate_node is not None:
                reference = _text(alternate_node).replace("%s", label)
                prior_registers = [
                    prior
                    for group in registers.values()
                    for prior in group
                    if prior.peripheral == peripheral_name
                    and (prior.name == reference
                         or prior.display_name == reference
                         or prior.name.endswith("." + reference))
                ]
                if not prior_registers:
                    raise SVDParseError(
                        f"alternateRegister {reference!r} at {register.display_name} "
                        "does not reference an earlier register in the same peripheral"
                    )
                if len(prior_registers) != 1:
                    raise SVDParseError(
                        f"alternateRegister {reference!r} at {register.display_name} is ambiguous"
                    )
                primary = prior_registers[0]
                if primary.display_name == register.display_name:
                    raise SVDParseError(
                        f"alternateRegister at {register.display_name} must use a unique register name"
                    )
                if primary.address != address:
                    raise SVDParseError(
                        f"alternateRegister {reference!r} at {register.display_name} "
                        "does not share the referenced register address"
                    )
                alternate_registers[register.display_name] = primary.display_name
            group = registers.setdefault(address, [])
            same_name = next((index for index, prior in enumerate(group)
                              if prior.display_name == register.display_name), None)
            if same_name is None:
                group.append(register)
                expanded_count[0] += 1
                if expanded_count[0] > MAX_EXPANDED_REGISTERS:
                    raise SVDParseError(
                        f"SVD expands to more than {MAX_EXPANDED_REGISTERS} registers"
                    )
            else:
                group[same_name] = register


def parse_svd(path: str) -> DeviceModel:
    """Parse a local CMSIS-SVD file into an address-indexed device model."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SVDParseError(f"Cannot read SVD file: {exc}") from exc
    if size <= 0 or size > MAX_SVD_BYTES:
        raise SVDParseError(f"SVD size must be between 1 byte and {MAX_SVD_BYTES} bytes")
    try:
        with open(path, "rb") as source:
            content = source.read(MAX_SVD_BYTES + 1)
        upper = content.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise SVDParseError("DTD/entity declarations are not accepted in SVD input")
        root = ET.fromstring(content)
        _validate_tree_complexity(root)
    except ET.ParseError as exc:
        raise SVDParseError(f"Malformed SVD XML: {exc}") from exc
    except OSError as exc:
        raise SVDParseError(f"Cannot read SVD file: {exc}") from exc

    device = _child(root, "device") if _local(root.tag) != "device" else root
    if device is None:
        device = root
    name = _text(_child(device, "name"), "Unknown device")
    cpu = _child(device, "cpu")
    endianness = _text(_child(cpu, "endian") if cpu is not None else None, "unknown").lower()
    if endianness not in {"little", "big", "selectable", "other"}:
        endianness = "unknown"
    address_unit_text = _text(_child(device, "addressUnitBits"))
    address_unit_bits = (
        _int(address_unit_text, "device.addressUnitBits") if address_unit_text else None
    )
    priority_bits_text = (
        _text(_child(cpu, "nvicPrioBits")) if cpu is not None else ""
    )
    nvic_priority_bits = (
        _int(priority_bits_text, "device.cpu.nvicPrioBits") if priority_bits_text else None
    )
    if nvic_priority_bits is not None and not 1 <= nvic_priority_bits <= 8:
        raise SVDParseError("device.cpu.nvicPrioBits must be between 1 and 8")
    device_defaults = {key: _text(_child(device, key)) for key in REGISTER_PROPERTIES}
    device_defaults["size"] = device_defaults["size"] or "32"
    device_defaults["access"] = device_defaults["access"] or "unknown"
    container = _child(device, "peripherals")
    if container is None:
        raise SVDParseError("SVD has no peripherals section")

    peripheral_nodes = _expand_peripheral_arrays(
        [node for node in container if _local(node.tag) == "peripheral"]
    )
    by_name = {}
    for node in peripheral_nodes:
        peripheral_name = _text(_child(node, "name"))
        if not peripheral_name:
            raise SVDParseError("Peripheral is missing its required name")
        if peripheral_name in by_name:
            raise SVDParseError(f"Duplicate peripheral name in SVD: {peripheral_name}")
        by_name[peripheral_name] = node
    peripheral_order = {name: index for index, name in enumerate(by_name)}
    alternate_peripherals = {}
    for alternate_name, node in by_name.items():
        primary_name = _text(_child(node, "alternatePeripheral"))
        if not primary_name:
            continue
        if primary_name not in by_name:
            raise SVDParseError(
                f"alternatePeripheral {primary_name!r} at {alternate_name} does not name a peripheral"
            )
        if primary_name == alternate_name:
            raise SVDParseError(f"Peripheral {alternate_name} cannot be its own alternate")
        if peripheral_order[primary_name] >= peripheral_order[alternate_name]:
            raise SVDParseError(
                f"alternatePeripheral {primary_name!r} must be defined before {alternate_name}"
            )
        alternate_peripherals[alternate_name] = primary_name
    register_groups: Dict[int, List[Register]] = {}
    resolved_peripherals: Dict[str, ET.Element] = {}
    resolving = set()

    def resolve_peripheral(node: ET.Element) -> ET.Element:
        pname = _text(_child(node, "name"), "unnamed")
        if pname in resolved_peripherals:
            return resolved_peripherals[pname]
        if pname in resolving:
            raise SVDParseError(f"Cyclic peripheral inheritance at {pname}")
        if len(resolving) >= MAX_DERIVATION_DEPTH:
            raise SVDParseError(f"Peripheral inheritance exceeds {MAX_DERIVATION_DEPTH} levels")
        resolving.add(pname)
        reference = node.attrib.get("derivedFrom", "").strip()
        if reference:
            parent_name = reference
            if parent_name not in by_name:
                raise SVDParseError(f"Unresolved peripheral derivedFrom {reference!r} at {pname}")
            source = resolve_peripheral(by_name[parent_name])
            merged = _merge_svd_node(source, node)
        else:
            merged = copy.deepcopy(node)
        merged.attrib.pop("derivedFrom", None)
        if not _text(_child(merged, "baseAddress")):
            raise SVDParseError(f"Peripheral {pname} has no baseAddress")
        _replace_svd_node(node, merged)
        resolved_peripherals[pname] = node
        resolving.remove(pname)
        return node

    for node in peripheral_nodes:
        resolve_peripheral(node)
    _resolve_register_tree(peripheral_nodes)
    expanded_count = [0]
    expanded_field_count = [0]
    expanded_enumerated_count = [0]
    alternate_registers = {}
    alternate_clusters = {}
    cluster_bases = {}
    for node in peripheral_nodes:
        pname = _text(_child(node, "name"), "unnamed")
        base = _int(_text(_child(node, "baseAddress")), f"{pname}.baseAddress")
        inherited = {
            key: _text(_child(node, key), device_defaults.get(key, ""))
            for key in REGISTER_PROPERTIES
        }
        _expand_registers(node, pname, base, inherited, register_groups,
                          alternate_registers=alternate_registers,
                          alternate_clusters=alternate_clusters,
                          cluster_bases=cluster_bases,
                          expanded_count=expanded_count,
                          expanded_field_count=expanded_field_count,
                          expanded_enumerated_count=expanded_enumerated_count)
    if not register_groups:
        raise SVDParseError("No registers were found in the SVD")
    # Template parsing counts field declarations, but array expansion can
    # multiply those declarations across registers and peripherals. Enforce
    # the limit on the concrete model that will be retained in memory.
    concrete_field_count = 0
    for group in register_groups.values():
        for register in group:
            concrete_field_count += len(register.fields)
            if concrete_field_count > MAX_EXPANDED_FIELDS:
                raise SVDParseError(
                    f"SVD expands to more than {MAX_EXPANDED_FIELDS} fields"
                )
    registers = {address: group[0] for address, group in register_groups.items()}
    aliases = {address: tuple(group) for address, group in register_groups.items() if len(group) > 1}
    return DeviceModel(
        name=name,
        registers=registers,
        source=os.path.abspath(path),
        source_sha256=hashlib.sha256(content).hexdigest(),
        endianness=endianness,
        address_unit_bits=address_unit_bits,
        nvic_priority_bits=nvic_priority_bits,
        register_aliases=aliases,
        alternate_peripherals=alternate_peripherals,
        alternate_registers=alternate_registers,
        alternate_clusters=alternate_clusters,
    )
