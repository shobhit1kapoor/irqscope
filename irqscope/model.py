"""IDA-independent data structures used by IRQScope."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class AnalysisCancelled(Exception):
    """Raised when an analyst cancels a bounded IDA analysis pass."""


@dataclass(frozen=True)
class EnumeratedValue:
    name: str
    value: Optional[int] = None
    mask: Optional[int] = None
    pattern: str = ""
    description: str = ""
    is_default: bool = False


@dataclass(frozen=True)
class EnumeratedValues:
    name: str = ""
    header_enum_name: str = ""
    usage: str = "read-write"
    values: Tuple[EnumeratedValue, ...] = ()


@dataclass(frozen=True)
class WriteConstraint:
    kind: str
    minimum: Optional[int] = None
    maximum: Optional[int] = None


@dataclass(frozen=True)
class WriteConstraintCheck:
    scope: str
    kind: str
    status: str
    value: Optional[int]
    detail: str


@dataclass(frozen=True)
class RegisterField:
    name: str
    bit_offset: int
    bit_width: int
    access: str = "unknown"
    read_action: str = ""
    modified_write_values: str = ""
    enumerated_values: Tuple[EnumeratedValues, ...] = ()
    write_constraint: Optional[WriteConstraint] = None
    write_constraint_source: Optional[str] = None


@dataclass(frozen=True)
class Register:
    peripheral: str
    name: str
    address: int
    size_bits: int
    access: str = "unknown"
    read_action: str = ""
    modified_write_values: str = ""
    description: str = ""
    fields: Tuple[RegisterField, ...] = ()
    reset_value: Optional[int] = None
    reset_mask: Optional[int] = None
    write_constraint: Optional[WriteConstraint] = None

    @property
    def display_name(self) -> str:
        return f"{self.peripheral}.{self.name}"


@dataclass
class DeviceModel:
    name: str
    registers: Dict[int, Register] = field(default_factory=dict)
    source: str = ""
    source_sha256: str = ""
    endianness: str = "unknown"
    address_unit_bits: Optional[int] = None
    nvic_priority_bits: Optional[int] = None
    register_aliases: Dict[int, Tuple[Register, ...]] = field(default_factory=dict)
    alternate_peripherals: Dict[str, str] = field(default_factory=dict)
    alternate_registers: Dict[str, str] = field(default_factory=dict)
    alternate_clusters: Dict[str, str] = field(default_factory=dict)

    def get_register(self, address: int) -> Optional[Register]:
        return self.registers.get(address)

    def get_registers(self, address: int) -> Tuple[Register, ...]:
        primary = self.registers.get(address)
        if primary is None:
            return ()
        return self.register_aliases.get(address, (primary,))

    def all_registers(self) -> List[Register]:
        result: List[Register] = []
        for address, register in self.registers.items():
            result.extend(self.register_aliases.get(address, (register,)))
        return result

    @property
    def register_count(self) -> int:
        return sum(len(self.register_aliases.get(address, (register,)))
                   for address, register in self.registers.items())


@dataclass(frozen=True)
class VectorTableCandidate:
    address: int
    initial_sp: int
    reset_handler: int
    mapped_handlers: int
    score: float


@dataclass(frozen=True)
class VectorEntry:
    slot: int
    address: int
    function_ea: Optional[int]
    name: str


@dataclass(frozen=True)
class InterruptConfigEvent:
    ea: int
    function_ea: int
    function_name: str
    irq_number: int
    operation: str
    priority: Optional[int] = None
    evidence_basis: str = "recognized-api-name"

    @property
    def vector_slot(self) -> int:
        return self.irq_number + 16


@dataclass(frozen=True)
class PriorityAssessment:
    status: str
    irq_number: int
    priority_bits: Optional[int] = None
    logical_priority: Optional[int] = None
    encoded_priority: Optional[int] = None
    basepri_threshold: Optional[int] = None
    callsite_eas: Tuple[int, ...] = ()
    detail: str = ""


@dataclass(frozen=True)
class MMIOAccess:
    ea: int
    function_ea: int
    function_name: str
    register: Register
    operation: str
    width_bits: int
    evidence: str
    primask: Optional[int] = None
    basepri: Optional[int] = None
    faultmask: Optional[int] = None
    block_start_ea: Optional[int] = None
    register_aliases: Tuple[Register, ...] = ()
    value: Optional[int] = None
    value_evidence: Optional[str] = None
    write_constraint_checks: Tuple[WriteConstraintCheck, ...] = ()


@dataclass(frozen=True)
class WriteEffectRelation:
    scope: str
    width_bits: int
    interrupt_operations_by_bit: Tuple[str, ...]
    interrupt_active_mask: int
    foreground_operations_by_bit: Tuple[str, ...]
    foreground_active_mask: int
    overlap_mask: int
    conflict_mask: int
    final_state_transforms_commute: bool


@dataclass(frozen=True)
class TransactionProposal:
    proposal_id: str
    function_ea: int
    function_name: str
    peripheral: str
    events: Tuple[MMIOAccess, ...]
    paths: Tuple[Tuple[int, ...], ...]
    supporting_function_eas: Tuple[int, ...] = ()
    supporting_functions: Tuple[str, ...] = ()
    rationale: Tuple[str, ...] = ()
    limitations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class CFGBlock:
    start_ea: int
    end_ea: int
    successors: Tuple[int, ...] = ()


@dataclass(frozen=True)
class InterleavingWitness:
    status: str
    foreground_start: MMIOAccess
    interrupt_event: MMIOAccess
    foreground_resume: Optional[MMIOAccess]
    block_path: Tuple[int, ...] = ()
    interrupt_block_path: Tuple[int, ...] = ()
    interrupt_prefix: Tuple[MMIOAccess, ...] = ()
    explanation: str = ""


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    address: int
    register: Register
    first: MMIOAccess
    second: MMIOAccess
    explanation: str
    assumptions: Tuple[str, ...] = ()
    preemption_state: str = "unknown"
    witness: Optional[InterleavingWitness] = None
    protocol_name: Optional[str] = None
    protocol_identity: Optional[str] = None
    interrupt_configuration: Tuple[InterruptConfigEvent, ...] = ()
    priority_assessment: Optional[PriorityAssessment] = None
    protocol_interference_mode: str = "any"
    protocol_events: Tuple[MMIOAccess, ...] = ()
    protocol_foreground_paths: Tuple[Tuple[int, ...], ...] = ()
    protocol_insertion_index: Optional[int] = None
    protocol_interrupt_events: Tuple[MMIOAccess, ...] = ()
    protocol_interrupt_paths: Tuple[Tuple[int, ...], ...] = ()
    write_effect_relation: Optional[WriteEffectRelation] = None


@dataclass
class AnalysisResult:
    accesses: List[MMIOAccess] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    vectors: List[VectorEntry] = field(default_factory=list)
    interrupt_config: List[InterruptConfigEvent] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    cfg_by_function: Dict[int, Dict[int, CFGBlock]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    transaction_proposals: List[TransactionProposal] = field(default_factory=list)
