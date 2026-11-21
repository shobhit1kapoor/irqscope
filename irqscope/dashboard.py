"""Theme-aware dockable review surface for IRQScope."""

import re

import ida_kernwin
from .confidence import confidence_vector
from .timeline import build_candidate_timeline


def _qt_binding():
    try:
        from PySide6 import QtCore, QtWidgets
        return "pyside", QtCore, QtWidgets
    except ImportError:
        pass
    try:
        from PySide2 import QtCore, QtWidgets
        return "pyside", QtCore, QtWidgets
    except ImportError:
        pass
    from PyQt5 import QtCore, QtWidgets
    return "pyqt", QtCore, QtWidgets


def _table_sort_key(value):
    text = str(value).strip()
    normalized = text.casefold()
    severity = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if normalized in severity:
        return (0, severity[normalized])
    if re.fullmatch(r"0x[0-9a-f]+", normalized):
        return (1, int(normalized, 16))
    if re.fullmatch(r"[+-]?\d+", normalized):
        return (1, int(normalized, 10))
    if normalized in {"", "—", "?", "unknown", "unmapped", "no witness"}:
        return (3, "")
    return (2, normalized)


def _sortable_table_item_type(base_item):
    """Build a Qt item with numeric address/count and severity-aware ordering."""
    class SortableTableItem(base_item):
        def __lt__(self, other):
            return _table_sort_key(self.text()) < _table_sort_key(other.text())

    return SortableTableItem


class IRQScopeDashboard(ida_kernwin.PluginForm):
    def __init__(self, state_provider, actions, jump):
        ida_kernwin.PluginForm.__init__(self)
        self.state_provider = state_provider
        self.actions = actions
        self.jump = jump
        self.qt_kind = None
        self.QtCore = None
        self.QtWidgets = None
        self.table_item_type = None
        self.root = None
        self.target_label = None
        self.analysis_warning_label = None
        self.metric_labels = {}
        self.register_table = None
        self.access_table = None
        self.interrupt_config_table = None
        self.finding_table = None
        self.transaction_table = None
        self.transaction_view = None
        self.transaction_proposals = []
        self.transaction_review_status = None
        self.transaction_review_note = None
        self.save_transaction_review_button = None
        self.create_protocol_draft_button = None
        self.witness_view = None
        self.review_status = None
        self.review_note = None
        self.save_review_button = None
        self.selected_finding_index = None
        self.filter_inputs = []
        self.light_theme = False

    def OnCreate(self, form):
        self.qt_kind, self.QtCore, self.QtWidgets = _qt_binding()
        self.table_item_type = _sortable_table_item_type(self.QtWidgets.QTableWidgetItem)
        if self.qt_kind == "pyside":
            parent = self.FormToPySideWidget(form)
        else:
            parent = self.FormToPyQtWidget(form)
        self.root = self.QtWidgets.QWidget(parent)
        self.root.setObjectName("IRQScopeRoot")
        outer = self.QtWidgets.QVBoxLayout(self.root)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(12)

        header = self.QtWidgets.QFrame()
        header.setObjectName("HeaderCard")
        header_layout = self.QtWidgets.QHBoxLayout(header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        title_box = self.QtWidgets.QVBoxLayout()
        title = self.QtWidgets.QLabel("IRQScope")
        title.setObjectName("Title")
        self.target_label = self.QtWidgets.QLabel("Load a device description, optional protocol contract, and vector table to begin")
        self.target_label.setObjectName("Subtitle")
        title_box.addWidget(title)
        title_box.addWidget(self.target_label)
        header_layout.addLayout(title_box, 1)
        for label, callback, primary in (
            ("Import SVD", self.actions.get("import"), False),
            ("Protocol", self.actions.get("protocol"), False),
            ("Vectors", self.actions.get("vectors"), False),
            ("Analyze", self.actions.get("analyze"), True),
            ("Export", self.actions.get("export"), False),
        ):
            if callback is None:
                continue
            button = self.QtWidgets.QPushButton(label)
            button.setObjectName("PrimaryButton" if primary else "ActionButton")
            button.clicked.connect(lambda checked=False, fn=callback: fn())
            header_layout.addWidget(button)
        outer.addWidget(header)

        metrics = self.QtWidgets.QHBoxLayout()
        metrics.setSpacing(10)
        for key, label in (("registers", "DEVICE REGISTERS"), ("vectors", "MAPPED VECTORS"),
                           ("accesses", "MMIO EVENTS"), ("findings", "REVIEW CANDIDATES"),
                           ("sequences", "SEQUENCE LEADS")):
            card = self.QtWidgets.QFrame()
            card.setObjectName("MetricCard")
            card_layout = self.QtWidgets.QVBoxLayout(card)
            card_layout.setContentsMargins(12, 9, 12, 9)
            number = self.QtWidgets.QLabel("—")
            number.setObjectName("MetricNumber")
            caption = self.QtWidgets.QLabel(label)
            caption.setObjectName("MetricCaption")
            card_layout.addWidget(number)
            card_layout.addWidget(caption)
            metrics.addWidget(card, 1)
            self.metric_labels[key] = number
        outer.addLayout(metrics)

        self.analysis_warning_label = self.QtWidgets.QLabel()
        self.analysis_warning_label.setObjectName("AnalysisWarning")
        self.analysis_warning_label.setWordWrap(True)
        self.analysis_warning_label.hide()
        outer.addWidget(self.analysis_warning_label)

        tabs = self.QtWidgets.QTabWidget()
        tabs.setObjectName("MainTabs")
        outer.addWidget(tabs, 1)

        overview = self.QtWidgets.QWidget()
        overview_layout = self.QtWidgets.QVBoxLayout(overview)
        overview_layout.setContentsMargins(0, 10, 0, 0)
        splitter = self.QtWidgets.QSplitter(self.QtCore.Qt.Orientation.Horizontal if hasattr(self.QtCore.Qt, "Orientation") else self.QtCore.Qt.Horizontal)
        left = self.QtWidgets.QWidget()
        left_layout = self.QtWidgets.QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(self._section_label("Cross-context candidates"))
        self.finding_table = self._table(
            ["Severity", "Register", "Mask state", "Priority hint", "Witness", "Verdict"],
            self._jump_finding,
        )
        left_layout.addWidget(self._filter_box(self.finding_table, "Filter candidates…"))
        self.finding_table.currentCellChanged.connect(
            lambda row, column, previous_row, previous_column: self._select_finding(row)
        )
        left_layout.addWidget(self.finding_table, 1)
        right = self.QtWidgets.QWidget()
        right_layout = self.QtWidgets.QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(self._section_label("Interleaving evidence"))
        self.witness_view = self.QtWidgets.QTextBrowser()
        self.witness_view.setObjectName("WitnessView")
        self.witness_view.setOpenExternalLinks(False)
        self.witness_view.anchorClicked.connect(self._follow_ea_link)
        right_layout.addWidget(self.witness_view, 1)
        review_row = self.QtWidgets.QHBoxLayout()
        review_row.addWidget(self._section_label("Analyst verdict"))
        self.review_status = self.QtWidgets.QComboBox()
        for label, value in (("Open", "open"), ("Confirmed", "confirmed"), ("Dismissed", "dismissed")):
            self.review_status.addItem(label, value)
        review_row.addWidget(self.review_status, 1)
        self.save_review_button = self.QtWidgets.QPushButton("Save to IDB")
        self.save_review_button.setObjectName("PrimaryButton")
        self.save_review_button.clicked.connect(lambda checked=False: self._save_current_review())
        review_row.addWidget(self.save_review_button)
        right_layout.addLayout(review_row)
        self.review_note = self.QtWidgets.QPlainTextEdit()
        self.review_note.setPlaceholderText("Analyst note: device manual reference, reproduced trace, rejected assumption…")
        self.review_note.setMaximumHeight(84)
        right_layout.addWidget(self.review_note)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        overview_layout.addWidget(splitter)
        tabs.addTab(overview, "Overview")

        register_page = self.QtWidgets.QWidget()
        register_layout = self.QtWidgets.QVBoxLayout(register_page)
        register_layout.setContentsMargins(0, 10, 0, 0)
        self.register_table = self._table([
            "Address", "Register", "Bits", "Access", "Reset value / known mask",
            "Reset field values", "Write constraint", "Fields", "Read", "Write",
            "SVD relationship",
        ])
        register_layout.addWidget(self._filter_box(self.register_table, "Filter peripheral, register, field, address…"))
        register_layout.addWidget(self.register_table)
        tabs.addTab(register_page, "Device map")

        access_page = self.QtWidgets.QWidget()
        access_layout = self.QtWidgets.QVBoxLayout(access_page)
        access_layout.setContentsMargins(0, 10, 0, 0)
        self.access_table = self._table([
            "Instruction", "Function", "Op", "Register", "Value / fields", "SVD write checks",
            "SVD aliases", "Evidence", "PRIMASK", "BASEPRI", "FAULTMASK",
        ], self._jump_access)
        access_layout.addWidget(self._filter_box(self.access_table, "Filter function, register, value, field, operation…"))
        access_layout.addWidget(self.access_table)
        tabs.addTab(access_page, "MMIO access")

        interrupt_page = self.QtWidgets.QWidget()
        interrupt_layout = self.QtWidgets.QVBoxLayout(interrupt_page)
        interrupt_layout.setContentsMargins(0, 10, 0, 0)
        self.interrupt_config_table = self._table([
            "Callsite", "Operation", "IRQn", "Vector slot", "Mapped handler", "Priority arg", "Evidence basis", "Function"
        ], self._jump_access)
        interrupt_layout.addWidget(self._filter_box(
            self.interrupt_config_table, "Filter IRQn, handler, operation, callsite…"
        ))
        interrupt_layout.addWidget(self.interrupt_config_table)
        tabs.addTab(interrupt_page, "Interrupt setup")

        transaction_page = self.QtWidgets.QWidget()
        transaction_layout = self.QtWidgets.QVBoxLayout(transaction_page)
        transaction_layout.setContentsMargins(0, 10, 0, 0)
        transaction_layout.addWidget(self._section_label("Sequence proposals · heuristic evidence for analyst review"))
        self.transaction_table = self._table(
            ["Peripheral", "Function", "Observed sequence", "Function support", "Review", "Proposal ID"],
            self._jump_proposal,
        )
        self.transaction_table.currentCellChanged.connect(
            lambda row, column, previous_row, previous_column: self._select_proposal(row)
        )
        transaction_layout.addWidget(self._filter_box(
            self.transaction_table, "Filter peripheral, function, register, operation…"
        ))
        transaction_layout.addWidget(self.transaction_table, 3)
        self.transaction_view = self.QtWidgets.QTextBrowser()
        self.transaction_view.setOpenExternalLinks(False)
        self.transaction_view.anchorClicked.connect(self._follow_ea_link)
        transaction_layout.addWidget(self.transaction_view, 2)
        proposal_review_row = self.QtWidgets.QHBoxLayout()
        proposal_review_row.addWidget(self._section_label("Sequence review"))
        self.transaction_review_status = self.QtWidgets.QComboBox()
        for label, value in (("Open", "open"), ("Confirmed pattern", "confirmed"),
                             ("Dismissed", "dismissed")):
            self.transaction_review_status.addItem(label, value)
        proposal_review_row.addWidget(self.transaction_review_status, 1)
        self.save_transaction_review_button = self.QtWidgets.QPushButton("Save sequence review to IDB")
        self.save_transaction_review_button.setObjectName("PrimaryButton")
        self.save_transaction_review_button.clicked.connect(
            lambda checked=False: self._save_current_proposal_review()
        )
        proposal_review_row.addWidget(self.save_transaction_review_button)
        self.create_protocol_draft_button = self.QtWidgets.QPushButton("Save contract draft…")
        self.create_protocol_draft_button.clicked.connect(
            lambda checked=False: self._create_current_protocol_draft()
        )
        proposal_review_row.addWidget(self.create_protocol_draft_button)
        transaction_layout.addLayout(proposal_review_row)
        self.transaction_review_note = self.QtWidgets.QPlainTextEdit()
        self.transaction_review_note.setPlaceholderText(
            "Review note: manual reference, observed usage, or reason this sequence is not a transaction…"
        )
        self.transaction_review_note.setMaximumHeight(72)
        transaction_layout.addWidget(self.transaction_review_note)
        self._set_proposal_review_controls_enabled(False)
        tabs.addTab(transaction_page, "Sequence mining")

        self.root.setStyleSheet(self._stylesheet())
        outer.addWidget(self._footer_label())
        container_layout = self.QtWidgets.QVBoxLayout(parent)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.addWidget(self.root)
        self.refresh()

    def OnClose(self, form):
        self.root = None
        self.analysis_warning_label = None
        self.filter_inputs = []
        self.metric_labels = {}
        self.register_table = None
        self.access_table = None
        self.interrupt_config_table = None
        self.finding_table = None
        self.transaction_table = None
        self.transaction_view = None
        self.transaction_proposals = []
        self.transaction_review_status = None
        self.transaction_review_note = None
        self.save_transaction_review_button = None
        self.create_protocol_draft_button = None
        self.witness_view = None
        self.review_status = None
        self.review_note = None
        self.save_review_button = None
        self.selected_finding_index = None

    def _section_label(self, text):
        label = self.QtWidgets.QLabel(text)
        label.setObjectName("SectionTitle")
        return label

    def _filter_box(self, table, placeholder):
        field = self.QtWidgets.QLineEdit()
        field.setPlaceholderText(placeholder)
        field.setClearButtonEnabled(True)
        field.textChanged.connect(lambda text, grid=table: self._apply_filter(grid, text))
        self.filter_inputs.append((table, field))
        return field

    def _apply_filter(self, table, query):
        needle = str(query).strip().casefold()
        for row in range(table.rowCount()):
            values = []
            for column in range(table.columnCount()):
                item = table.item(row, column)
                if item is not None:
                    values.append(item.text())
            table.setRowHidden(row, bool(needle) and needle not in " ".join(values).casefold())
        if table is self.finding_table and table.currentRow() >= 0 and table.isRowHidden(table.currentRow()):
            visible = next((row for row in range(table.rowCount()) if not table.isRowHidden(row)), None)
            if visible is None:
                self.selected_finding_index = None
                self.witness_view.setPlainText("No candidates match this filter.")
                self._set_review_controls_enabled(False)
            else:
                table.selectRow(visible)
                self._select_finding(visible)

    def _set_review_controls_enabled(self, enabled):
        for control in (self.review_status, self.review_note, self.save_review_button):
            if control is not None:
                control.setEnabled(enabled)

    def _set_proposal_review_controls_enabled(self, enabled):
        for control in (self.transaction_review_status, self.transaction_review_note,
                        self.save_transaction_review_button, self.create_protocol_draft_button):
            if control is not None:
                control.setEnabled(enabled)

    def _footer_label(self):
        label = self.QtWidgets.QLabel(
            "Candidate evidence only · IRQ enable/priority and complete peripheral contracts may be unknown"
        )
        label.setObjectName("Footer")
        return label

    def _table(self, headers, jump_callback=None):
        table = self.QtWidgets.QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        header_help = {
            "Instruction": "Double-click an address to navigate to the instruction in IDA.",
            "Evidence": "Static evidence attached to this access; it is not a runtime trace.",
            "Preemption": "Conservative preemption classification derived from available mask and priority evidence.",
            "Witness": "Interleaving status and explanation for the candidate finding.",
            "Verdict": "Analyst review state stored in the current IDB.",
            "SVD relationship": "Relationship to the imported CMSIS-SVD register model.",
            "PRIMASK": "Saved PRIMASK value, when this analysis path establishes it; ? means unknown.",
            "BASEPRI": "Saved BASEPRI value, when this analysis path establishes it; ? means unknown.",
            "FAULTMASK": "Saved FAULTMASK value, when this analysis path establishes it; ? means unknown.",
        }
        for column, header in enumerate(headers):
            if header in header_help:
                table.horizontalHeaderItem(column).setToolTip(header_help[header])
        table.horizontalHeader().setToolTip(
            "Click a column heading to sort. Filtering and row actions stay attached to the original evidence record."
        )
        table.setAlternatingRowColors(True)
        table.setSortingEnabled(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(True)
        table.setSelectionBehavior(self.QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
                                   if hasattr(self.QtWidgets.QAbstractItemView, "SelectionBehavior")
                                   else self.QtWidgets.QAbstractItemView.SelectRows)
        table.setEditTriggers(self.QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
                              if hasattr(self.QtWidgets.QAbstractItemView, "EditTrigger")
                              else self.QtWidgets.QAbstractItemView.NoEditTriggers)
        if jump_callback is not None:
            table.cellDoubleClicked.connect(lambda row, column, fn=jump_callback, grid=table: fn(grid, row))
        return table

    def _set_rows(self, table, rows):
        if table is None:
            return
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        user_role = (
            self.QtCore.Qt.ItemDataRole.UserRole
            if hasattr(self.QtCore.Qt, "ItemDataRole") else self.QtCore.Qt.UserRole
        )
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                item = self.table_item_type(str(value))
                if column == 0:
                    # Qt may reorder visible rows when a header is clicked. Keep
                    # the source index attached so review and navigation actions
                    # still target the underlying finding/proposal.
                    item.setData(user_role, row_index)
                table.setItem(row_index, column, item)
        table.resizeColumnsToContents()
        table.setSortingEnabled(True)

    def _row_identity(self, table, row):
        if table is None or row < 0 or row >= table.rowCount():
            return None
        item = table.item(row, 0)
        if item is None:
            return None
        user_role = (
            self.QtCore.Qt.ItemDataRole.UserRole
            if hasattr(self.QtCore.Qt, "ItemDataRole") else self.QtCore.Qt.UserRole
        )
        value = item.data(user_role)
        return value if isinstance(value, int) else None

    def _row_for_identity(self, table, identity):
        if identity is None or table is None:
            return None
        return next(
            (row for row in range(table.rowCount())
             if self._row_identity(table, row) == identity),
            None,
        )

    def _jump_cell(self, table, row, column=0):
        item = table.item(row, column)
        if item is None:
            return
        try:
            self.jump(int(item.text(), 16))
        except ValueError:
            return

    def _jump_finding(self, table, row):
        if row < 0:
            return
        finding_index = self._row_identity(table, row)
        if finding_index is None:
            finding_index = row
        if finding_index >= len(self.findings):
            return
        finding = self.findings[finding_index]
        if finding.witness is None:
            self.jump(finding.first.ea)
            return
        witness = finding.witness
        emphasis_color = "#087F8C" if self.light_theme else "#70D6B4"
        muted_color = "#52677B" if self.light_theme else "#9BAFC3"
        parts = [
            f"<b>{self._escape(witness.status)}</b>",
            self._escape(witness.explanation),
            "",
            f"{'Foreground insertion anchor' if finding.protocol_events else 'Foreground'}: "
            f"{self._escape(self._access_event_label(witness.foreground_start))} at "
            f"<a href='ea:{witness.foreground_start.ea:X}'>0x{witness.foreground_start.ea:X}</a>",
        ]
        if finding.protocol_events:
            parts.extend(["", f"Declared foreground transaction: {self._escape(finding.protocol_name or 'protocol candidate')}"])
            for index, event in enumerate(finding.protocol_events):
                parts.append(
                    f"{self._escape(self._access_event_label(event))} at "
                    f"<a href='ea:{event.ea:X}'>0x{event.ea:X}</a>"
                )
                if index == finding.protocol_insertion_index:
                    next_event = finding.protocol_events[index + 1]
                    parts.append(
                        f"<b style='color:{emphasis_color}'>Candidate IRQ insertion window:</b> "
                        f"after this access, before "
                        f"{self._escape(self._access_event_label(next_event))} "
                        f"(mask snapshot: {self._escape(finding.preemption_state)})"
                    )
                if index < len(finding.protocol_foreground_paths):
                    path = finding.protocol_foreground_paths[index]
                    if path:
                        parts.append("&nbsp;&nbsp;CFG path: " + " → ".join(
                            f"<a href='ea:{ea:X}'>0x{ea:X}</a>" for ea in path
                        ))
        if finding.protocol_interrupt_events:
            interference_title = (
                "Declared ISR interference sequence:"
                if finding.protocol_interference_mode == "sequence"
                else "Matching declared ISR interference event:"
            )
            parts.extend(["", interference_title])
            for index, event in enumerate(finding.protocol_interrupt_events, 1):
                parts.append(
                    f"{index}. {self._escape(self._access_event_label(event))} at "
                    f"<a href='ea:{event.ea:X}'>0x{event.ea:X}</a>"
                )
                path_index = index - 2
                if path_index >= 0 and path_index < len(finding.protocol_interrupt_paths):
                    path = finding.protocol_interrupt_paths[path_index]
                    if path:
                        parts.append("&nbsp;&nbsp;CFG path: " + " → ".join(
                            f"<a href='ea:{ea:X}'>0x{ea:X}</a>" for ea in path
                        ))
        timeline = build_candidate_timeline(finding)
        if timeline is not None:
            parts.extend(["", "Conditional synchronized candidate timeline:"])
            for step in timeline["steps"]:
                actor = "FOREGROUND" if step["context"] == "foreground" else "ISR"
                event = step["event"]
                parts.append(
                    f"{step['order'] + 1}. <b>{actor}</b> — "
                    f"{self._escape(self._access_event_label(event))} at "
                    f"<a href='ea:{event.ea:X}'>0x{event.ea:X}</a>"
                )
                if step["cfg_path"]:
                    parts.append(
                        "&nbsp;&nbsp;CFG edge: " + " → ".join(
                            f"<a href='ea:{ea:X}'>0x{ea:X}</a>"
                            for ea in step["cfg_path"]
                        )
                    )
                gap = timeline["insertion_gap"]
                if (step["context"] == "foreground"
                        and step["event_index"] == gap["after_foreground_event_index"]):
                    parts.append(
                        f"<b style='color:{emphasis_color}'>↳ Candidate IRQ gap · "
                        f"mask snapshot: {self._escape(timeline['mask_snapshot'])}</b>"
                    )
            parts.append(
                "<i>Candidate ordering only; this timeline does not establish runtime scheduling.</i>"
            )
        if witness.interrupt_prefix:
            parts.extend(["", "Observed handler prefix:"])
            for event in witness.interrupt_prefix:
                parts.append(
                    f"{self._escape(self._access_event_label(event))} at "
                    f"<a href='ea:{event.ea:X}'>0x{event.ea:X}</a>"
                )
        if not finding.protocol_interrupt_events:
            parts.append(
                f"Interrupt event: {self._escape(self._access_event_label(witness.interrupt_event))} at "
                f"<a href='ea:{witness.interrupt_event.ea:X}'>0x{witness.interrupt_event.ea:X}</a>"
            )
        if finding.interrupt_configuration:
            irq_number = finding.interrupt_configuration[0].irq_number
            parts.extend([
                "",
                f"Static NVIC callsites for IRQ {irq_number} (callsite evidence; effective runtime state is unknown):",
            ])
            for event in finding.interrupt_configuration:
                priority = (f", priority argument {event.priority}"
                            if event.priority is not None else "")
                parts.append(
                    f"{self._escape(event.operation)} at "
                    f"<a href='ea:{event.ea:X}'>0x{event.ea:X}</a>{priority} "
                    f"({self._escape(event.evidence_basis)})"
                )
        else:
            parts.extend([
                "",
                "No constant-argument NVIC setup callsite was recovered for this external IRQ.",
            ])
        if finding.priority_assessment is not None:
            assessment = finding.priority_assessment
            parts.extend([
                "",
                f"Conditional BASEPRI comparison ({self._escape(assessment.status)}): "
                f"{self._escape(assessment.detail)}",
            ])
        if witness.interrupt_block_path:
            handler_blocks = " → ".join(f"0x{ea:X}" for ea in witness.interrupt_block_path)
            parts.extend(["", f"Shortest handler block path: {handler_blocks}"])
        if witness.foreground_resume is not None:
            resume = witness.foreground_resume
            parts.append(
                f"Resume: {self._escape(self._access_event_label(resume))} at "
                f"<a href='ea:{resume.ea:X}'>0x{resume.ea:X}</a>"
            )
        if witness.block_path:
            blocks = " → ".join(f"0x{ea:X}" for ea in witness.block_path)
            parts.extend(["", f"Shortest block path: {blocks}"])
        parts.extend(["", "Evidence profile:"])
        for item in confidence_vector(finding):
            parts.append(
                f"<b>{self._escape(item['dimension'].title())}: "
                f"{self._escape(item['tier'])}</b> — {self._escape(item['evidence'])}<br>"
                f"<span style='color:{muted_color}'>{self._escape(item['limit'])}</span>"
            )
        relation = finding.write_effect_relation
        if relation is not None:
            interrupt_name = witness.interrupt_event.function_name
            foreground_name = witness.foreground_start.function_name
            parts.extend(["", "Modeled write-semantics comparison:"])
            parts.append(
                f"{self._escape(relation.scope.title())}-scope, {relation.width_bits}-bit store; "
                + ("final-state transforms commute." if relation.final_state_transforms_commute
                   else "final state depends on write order under this SVD model.")
            )
            parts.append(
                f"ISR {self._escape(interrupt_name)}: "
                f"{self._escape(self._write_operation_masks(relation.interrupt_operations_by_bit, relation.interrupt_active_mask))}"
            )
            parts.append(
                f"Foreground {self._escape(foreground_name)}: "
                f"{self._escape(self._write_operation_masks(relation.foreground_operations_by_bit, relation.foreground_active_mask))}"
            )
            parts.append(f"Affected-bit overlap: 0x{relation.overlap_mask:X}")
            if relation.conflict_mask:
                parts.append(f"Conflicting-bit mask: 0x{relation.conflict_mask:X}")
        parts.extend(["", "Assumptions:"])
        parts.extend(f"• {self._escape(item)}" for item in finding.assumptions)
        self.witness_view.setHtml("<br>".join(parts))

    def _select_finding(self, row):
        finding_index = self._row_identity(self.finding_table, row)
        if finding_index is None:
            finding_index = row
        if row < 0 or finding_index < 0 or finding_index >= len(self.findings):
            return
        self.selected_finding_index = finding_index
        self._set_review_controls_enabled(True)
        finding = self.findings[finding_index]
        self._jump_finding(self.finding_table, row)
        provider = self.actions.get("review_provider")
        review = provider(finding) if provider is not None else {"status": "open", "note": ""}
        status_index = self.review_status.findData(review.get("status", "open"))
        self.review_status.setCurrentIndex(max(status_index, 0))
        self.review_note.setPlainText(review.get("note", ""))

    def _save_current_review(self):
        if self.selected_finding_index is None:
            return
        callback = self.actions.get("review")
        if callback is None:
            return
        callback(self.selected_finding_index, self.review_status.currentData(),
                 self.review_note.toPlainText())

    def _follow_ea_link(self, url):
        value = url.toString()
        if not value.startswith("ea:"):
            return
        try:
            self.jump(int(value[3:], 16))
        except ValueError:
            return

    def _jump_access(self, table, row):
        self._jump_cell(table, row)

    def _jump_proposal(self, table, row):
        proposal_index = self._row_identity(table, row)
        if proposal_index is None:
            proposal_index = row
        if 0 <= proposal_index < len(self.transaction_proposals):
            proposal = self.transaction_proposals[proposal_index]
            if proposal.events:
                self.jump(proposal.events[0].ea)

    def _select_proposal(self, row):
        if self.transaction_view is None:
            return
        proposal_index = self._row_identity(self.transaction_table, row)
        if proposal_index is None:
            proposal_index = row
        if row < 0 or proposal_index < 0 or proposal_index >= len(self.transaction_proposals):
            self.transaction_view.setPlainText("No sequence proposal is selected.")
            self._set_proposal_review_controls_enabled(False)
            return
        proposal = self.transaction_proposals[proposal_index]
        self._set_proposal_review_controls_enabled(True)
        provider = self.actions.get("proposal_review_provider")
        review = provider(proposal) if provider is not None else {"status": "open", "note": ""}
        status_index = self.transaction_review_status.findData(review.get("status", "open"))
        self.transaction_review_status.setCurrentIndex(max(status_index, 0))
        self.transaction_review_note.setPlainText(review.get("note", ""))
        parts = [
            f"<b>Heuristic sequence proposal · {self._escape(proposal.peripheral)}</b>",
            f"Function: {self._escape(proposal.function_name)} "
            f"(<a href='ea:{proposal.function_ea:X}'>0x{proposal.function_ea:X}</a>)",
            "This is a review lead. IRQScope has not inferred a confirmed transaction boundary or device invariant.",
            "<br><b>Observed events</b>",
        ]
        for index, event in enumerate(proposal.events):
            parts.append(
                f"{index + 1}. {self._escape(self._access_event_label(event))} at "
                f"<a href='ea:{event.ea:X}'>0x{event.ea:X}</a>"
            )
            if index < len(proposal.paths):
                path = proposal.paths[index]
                parts.append("&nbsp;&nbsp;CFG path: " + " → ".join(
                    f"<a href='ea:{ea:X}'>0x{ea:X}</a>" for ea in path
                ))
        parts.extend(["<br><b>Why it was surfaced</b>"])
        parts.extend(self._escape(reason) for reason in proposal.rationale)
        if proposal.supporting_functions:
            parts.extend(["<br><b>Matching foreground functions</b>"])
            for function_ea, name in zip(proposal.supporting_function_eas, proposal.supporting_functions):
                parts.append(
                    f"{self._escape(name)} "
                    f"(<a href='ea:{function_ea:X}'>0x{function_ea:X}</a>)"
                )
        parts.extend(["<br><b>Limits</b>"])
        parts.extend(self._escape(limit) for limit in proposal.limitations)
        self.transaction_view.setHtml("<br>".join(parts))

    def _save_current_proposal_review(self):
        row = self.transaction_table.currentRow() if self.transaction_table is not None else -1
        if row < 0 or row >= len(self.transaction_proposals):
            return
        callback = self.actions.get("proposal_review")
        if callback is not None:
            callback(self.transaction_proposals[row],
                     self.transaction_review_status.currentData(),
                     self.transaction_review_note.toPlainText())

    def _create_current_protocol_draft(self):
        row = self.transaction_table.currentRow() if self.transaction_table is not None else -1
        if row < 0 or row >= len(self.transaction_proposals):
            return
        callback = self.actions.get("protocol_draft")
        if callback is not None:
            callback(self.transaction_proposals[row])

    def _escape(self, value):
        return (str(value).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    def _access_event_label(self, event):
        label = f"{event.operation.upper()} {event.register.display_name}"
        if event.operation == "write" and event.value is not None:
            label += f" = 0x{event.value:X}"
        return label

    def _write_operation_masks(self, operations_by_bit, active_mask):
        masks = {}
        for bit, operation in enumerate(operations_by_bit):
            if active_mask & (1 << bit):
                masks[operation] = masks.get(operation, 0) | (1 << bit)
        if not masks:
            return "no bits affected"
        return ", ".join(f"{operation}=0x{mask:X}"
                          for operation, mask in sorted(masks.items()))

    def _field_summary(self, field):
        summaries = []
        for enumeration in field.enumerated_values:
            entries = []
            for value in enumeration.values[:3]:
                label = value.name or "value"
                if value.is_default:
                    entries.append(f"{label}=default")
                elif value.pattern and ("x" in value.pattern.lower()):
                    entries.append(f"{label}={value.pattern}")
                elif value.value is not None:
                    entries.append(f"{label}={value.value:#x}")
            remaining = len(enumeration.values) - min(3, len(enumeration.values))
            if remaining:
                entries.append(f"+{remaining}")
            usage = enumeration.usage.upper()
            summaries.append(f"{usage}: {', '.join(entries)}")
        if not summaries:
            rendered = field.name
        else:
            rendered = f"{field.name} [{'; '.join(summaries)}]"
        if field.write_constraint is not None:
            source = " (register default)" if field.write_constraint_source == "register-default" else ""
            rendered += f" · write: {self._write_constraint_summary(field.write_constraint)}{source}"
        elif field.write_constraint_source == "field":
            rendered += " · write: clears register default"
        return rendered

    def _write_constraint_summary(self, constraint):
        if constraint is None:
            return "—"
        if constraint.kind == "range":
            return f"range 0x{constraint.minimum:X}..0x{constraint.maximum:X}"
        if constraint.kind == "enumerated-values-only":
            return "enumerated values only"
        if constraint.kind == "write-as-read":
            return "must match last read"
        return f"unknown constraint ({constraint.kind})"

    def _reset_field_summary(self, register):
        if register.reset_value is None or register.reset_mask is None:
            return "—"
        decoded = []
        for field in register.fields:
            if (field.bit_offset < 0 or field.bit_width <= 0
                    or field.bit_offset + field.bit_width > register.size_bits):
                continue
            field_mask = ((1 << field.bit_width) - 1) << field.bit_offset
            if (register.reset_mask & field_mask) != field_mask:
                continue
            value = (register.reset_value >> field.bit_offset) & ((1 << field.bit_width) - 1)
            labels = set()
            for value_set in field.enumerated_values:
                if value_set.usage.lower() not in {"read", "read-write"}:
                    continue
                for entry in value_set.values:
                    if (entry.name and not entry.is_default
                            and self._enumerated_value_matches(value, field.bit_width, entry)):
                        labels.add(entry.name)
            label = next(iter(labels)) if len(labels) == 1 else f"0x{value:X}"
            if len(labels) > 1:
                label += " (ambiguous enum)"
            decoded.append(f"{field.name}={label}")
        return ", ".join(decoded) if decoded else "No fully known fields"

    def _access_value_summary(self, access):
        if access.value is None:
            return "—"
        width = max(1, min(access.width_bits, 128))
        value = access.value & ((1 << width) - 1)
        decoded = []
        for field in access.register.fields:
            if field.bit_offset < 0 or field.bit_width <= 0 or field.bit_offset + field.bit_width > width:
                continue
            field_value = (value >> field.bit_offset) & ((1 << field.bit_width) - 1)
            for enumeration in field.enumerated_values:
                if enumeration.usage.lower() not in ("write", "read-write"):
                    continue
                match = next((entry for entry in enumeration.values
                              if self._enumerated_value_matches(field_value, field.bit_width, entry)), None)
                if match is not None:
                    decoded.append(f"{field.name}={match.name}")
                    break
        summary = f"0x{value:X}"
        if decoded:
            summary += " · " + ", ".join(decoded)
        if access.value_evidence:
            summary += f" ({access.value_evidence})"
        return summary

    def _access_constraint_summary(self, access):
        checks = getattr(access, "write_constraint_checks", ())
        if not checks:
            return "—"
        return "; ".join(
            f"{check.scope}: {check.status} — {check.detail}"
            for check in checks
        )

    def _enumerated_value_matches(self, value, width, entry):
        if entry.value is not None:
            mask = entry.mask if entry.mask is not None else (1 << width) - 1
            return (value & mask) == (entry.value & mask)
        pattern = (entry.pattern or "").lower().replace("0b", "").replace("_", "").replace(" ", "")
        if not pattern or len(pattern) > width:
            return False
        padded = pattern.rjust(width, "x")
        for index, bit in enumerate(padded):
            if bit in ("x", "?"):
                continue
            if bit not in ("0", "1"):
                return False
            shift = width - index - 1
            if ((value >> shift) & 1) != int(bit):
                return False
        return True

    def _register_svd_relationship(self, device, register):
        relationships = []
        alternate_peripheral = device.alternate_peripherals.get(register.peripheral)
        if alternate_peripheral:
            relationships.append(f"peripheral alternate of {alternate_peripheral}")
        else:
            primary_alternates = sorted(
                name for name, primary in device.alternate_peripherals.items()
                if primary == register.peripheral
            )
            if primary_alternates:
                relationships.append(f"peripheral primary for {', '.join(primary_alternates)}")

        def register_is_in_cluster(cluster_display_name):
            prefix = register.peripheral + "."
            if not cluster_display_name.startswith(prefix):
                return False
            cluster_path = cluster_display_name[len(prefix):]
            return register.name.startswith(cluster_path + ".")

        alternate_clusters = [
            (name, primary) for name, primary in device.alternate_clusters.items()
            if register_is_in_cluster(name)
        ]
        if alternate_clusters:
            name, primary = max(alternate_clusters, key=lambda item: len(item[0]))
            relationships.append(f"cluster alternate of {primary}")
        else:
            primary_clusters = [
                name for name, primary in device.alternate_clusters.items()
                if register_is_in_cluster(primary)
            ]
            if primary_clusters:
                relationships.append(f"cluster primary for {', '.join(sorted(primary_clusters))}")

        alternate_register = device.alternate_registers.get(register.display_name)
        if alternate_register:
            relationships.append(f"register alternate of {alternate_register}")
        else:
            register_alternates = sorted(
                name for name, primary in device.alternate_registers.items()
                if primary == register.display_name
            )
            if register_alternates:
                relationships.append(f"register primary for {', '.join(register_alternates)}")
        return " · ".join(relationships) or "—"

    def refresh(self):
        if self.root is None:
            return
        previous_selection = self._row_identity(
            self.finding_table, self.finding_table.currentRow()
        )
        previous_proposal_selection = (
            self._row_identity(self.transaction_table, self.transaction_table.currentRow())
            if self.transaction_table is not None else None
        )
        device, vectors, result = self.state_provider()
        protocol_provider = self.actions.get("protocol_provider")
        protocol = protocol_provider() if protocol_provider is not None else None
        mapped = sum(1 for item in vectors if item.function_ea is not None)
        self.target_label.setText(
            f"{device.name if device else 'No SVD loaded'}  ·  "
            f"{(device.endianness + ' endian · ' + str(device.address_unit_bits or '?') + '-bit address units') if device else 'endianness unknown'}  ·  "
            f"NVIC priority bits: {device.nvic_priority_bits if device and device.nvic_priority_bits is not None else '?'}  ·  "
            f"{mapped} vector entries mapped  ·  "
            f"{len(device.alternate_peripherals) if device else 0} alternate peripheral links  ·  "
            f"{len(device.alternate_clusters) if device else 0} alternate cluster links  ·  "
            f"{len(device.alternate_registers) if device else 0} alternate register links  ·  "
            f"{('Protocol: ' + protocol.name + '  ·  ') if protocol else ''}"
            "Evidence stays in this IDB"
        )
        self.metric_labels["registers"].setText(str(device.register_count if device else 0))
        self.metric_labels["vectors"].setText(str(mapped))
        self.metric_labels["accesses"].setText(str(len(result.accesses)))
        self.metric_labels["findings"].setText(str(len(result.findings)))
        self.metric_labels["sequences"].setText(str(len(result.transaction_proposals)))
        warnings = list(getattr(result, "warnings", ()))
        if warnings:
            self.analysis_warning_label.setText(
                "Analysis may be incomplete\n" + "\n".join(warnings)
            )
            self.analysis_warning_label.show()
        else:
            self.analysis_warning_label.hide()
        self.findings = list(result.findings)
        self.transaction_proposals = list(result.transaction_proposals)
        self._set_rows(self.register_table, [
            (f"0x{reg.address:08X}", reg.display_name, reg.size_bits, reg.access,
             (f"0x{reg.reset_value:X} / "
              f"{f'0x{reg.reset_mask:X}' if reg.reset_mask is not None else 'mask unspecified'}"
              if reg.reset_value is not None else
              (f"mask 0x{reg.reset_mask:X}; value unspecified"
               if reg.reset_mask is not None else "—")),
             self._reset_field_summary(reg),
             self._write_constraint_summary(reg.write_constraint),
             "; ".join(self._field_summary(field) for field in reg.fields) or "—",
             reg.read_action or "—", reg.modified_write_values or "—",
             self._register_svd_relationship(device, reg))
            for reg in sorted(device.all_registers(), key=lambda value: (value.address, value.display_name))
        ] if device else [])
        self._set_rows(self.access_table, [
            (f"0x{item.ea:X}", item.function_name, item.operation.upper(), item.register.display_name,
             self._access_value_summary(item),
             self._access_constraint_summary(item),
             ", ".join(alias.display_name for alias in item.register_aliases) or "—",
             item.evidence, item.primask if item.primask is not None else "?",
             item.basepri if item.basepri is not None else "?",
             item.faultmask if item.faultmask is not None else "?")
            for item in result.accesses
        ])
        vectors_by_slot = {item.slot: item for item in vectors}
        self._set_rows(self.interrupt_config_table, [
            (f"0x{event.ea:X}", event.operation, event.irq_number,
             event.vector_slot,
             (vectors_by_slot[event.vector_slot].name
              if event.vector_slot in vectors_by_slot else "unmapped"),
             event.priority if event.priority is not None else "—",
             event.evidence_basis,
             event.function_name)
            for event in result.interrupt_config
        ])
        self._set_rows(self.transaction_table, [
            (proposal.peripheral, proposal.function_name,
             " → ".join(self._access_event_label(event) for event in proposal.events),
             len(proposal.supporting_function_eas),
             self.actions.get("proposal_review_provider", lambda value: {"status": "open"})(proposal).get("status", "open"),
             proposal.proposal_id)
            for proposal in self.transaction_proposals
        ])
        if self.transaction_proposals:
            selected_proposal = self._row_for_identity(
                self.transaction_table, previous_proposal_selection
            )
            if selected_proposal is None:
                selected_proposal = 0
            self.transaction_table.selectRow(selected_proposal)
            self._select_proposal(selected_proposal)
        elif self.transaction_view is not None:
            self.transaction_view.setPlainText(
                "No pairwise CFG-reachable foreground MMIO sequences were recovered. "
                "This can indicate missing SVD coverage, incomplete disassembly, or a quiet firmware path."
            )
            self._set_proposal_review_controls_enabled(False)
        self._set_rows(self.finding_table, [
            (item.severity.upper(), item.register.display_name, item.preemption_state,
             item.priority_assessment.status if item.priority_assessment else "unknown",
             item.witness.status if item.witness else "no witness",
             self.actions.get("review_provider", lambda value: {"status": "open"})(item).get("status", "open"))
            for item in result.findings
        ])
        for table, field in self.filter_inputs:
            self._apply_filter(table, field.text())
        selected = self._row_for_identity(self.finding_table, previous_selection)
        if selected is not None and self.finding_table.isRowHidden(selected):
            selected = None
        first_visible = next(
            (row for row in range(self.finding_table.rowCount())
             if not self.finding_table.isRowHidden(row)),
            None,
        )
        if first_visible is not None:
            if selected is None:
                selected = first_visible
            self.finding_table.selectRow(selected)
            self._select_finding(selected)
        elif result.findings:
            self.selected_finding_index = None
            self._set_review_controls_enabled(False)
            self.witness_view.setPlainText("No candidates match this filter.")
        else:
            self.selected_finding_index = None
            self._set_review_controls_enabled(False)
            self.witness_view.setPlainText(
                "No review candidates yet. Import an SVD, confirm the vector table, and run analysis."
            )

    def _stylesheet(self):
        try:
            background = self.root.palette().color(self.root.backgroundRole())
            light_theme = background.lightness() >= 128
        except (AttributeError, RuntimeError, TypeError):
            # Keep the established dark presentation if the host binding does
            # not expose a usable palette through this dock widget.
            light_theme = False
        self.light_theme = light_theme
        if light_theme:
            return """
            QWidget#IRQScopeRoot { background: #F3F6FA; color: #1B2A3A; font-size: 12px; }
            QFrame#HeaderCard, QFrame#MetricCard { background: #FFFFFF; border: 1px solid #D8E1EA; border-radius: 9px; }
            QLabel#Title { color: #13263A; font-size: 22px; font-weight: 700; }
            QLabel#Subtitle { color: #52677B; font-size: 11px; }
            QLabel#MetricNumber { color: #087F8C; font-size: 22px; font-weight: 700; }
            QLabel#MetricCaption, QLabel#Footer { color: #5D7184; font-size: 10px; letter-spacing: 1px; }
            QLabel#AnalysisWarning { background: #FFF4D8; color: #63470B; border: 1px solid #E6C66E; border-radius: 6px; padding: 8px 11px; }
            QLabel#SectionTitle { color: #263D53; font-size: 14px; font-weight: 650; padding: 3px; }
            QPushButton { color: #263D53; background: #EAF0F5; border: 1px solid #C9D5E0; border-radius: 6px; padding: 7px 12px; }
            QPushButton:hover { background: #DDE8EF; border-color: #83A6B8; }
            QPushButton#PrimaryButton { color: #FFFFFF; background: #087F8C; border-color: #087F8C; font-weight: 700; }
            QPushButton#PrimaryButton:hover { background: #066A75; }
            QTabWidget::pane { border: 1px solid #D8E1EA; border-radius: 7px; top: -1px; }
            QTabBar::tab { background: #EAF0F5; color: #52677B; padding: 8px 14px; border: 1px solid #D8E1EA; }
            QTabBar::tab:selected { color: #1B2A3A; background: #FFFFFF; border-bottom: 2px solid #087F8C; }
            QTableWidget, QTextBrowser { background: #FFFFFF; alternate-background-color: #F4F7FA; color: #26384A; gridline-color: #E1E8EF; border: 1px solid #D8E1EA; border-radius: 5px; }
            QHeaderView::section { background: #EAF0F5; color: #41586E; padding: 7px; border: none; border-bottom: 1px solid #D0DAE4; }
            QTableWidget::item:selected { background: #D4EFEB; color: #123D3B; }
            QSplitter::handle { background: #D5DFE8; width: 4px; }
            """
        return """
        QWidget#IRQScopeRoot { background: #101722; color: #E8EEF5; font-size: 12px; }
        QFrame#HeaderCard, QFrame#MetricCard { background: #172230; border: 1px solid #2B3A4C; border-radius: 9px; }
        QLabel#Title { color: #F4F7FB; font-size: 22px; font-weight: 700; }
        QLabel#Subtitle { color: #9DAFC1; font-size: 11px; }
        QLabel#MetricNumber { color: #56D7C5; font-size: 22px; font-weight: 700; }
        QLabel#MetricCaption, QLabel#Footer { color: #9DAFC1; font-size: 10px; letter-spacing: 1px; }
        QLabel#AnalysisWarning { background: #3B2D19; color: #FFE0A6; border: 1px solid #8A632A; border-radius: 6px; padding: 8px 11px; }
        QLabel#SectionTitle { color: #D9E6F2; font-size: 14px; font-weight: 650; padding: 3px; }
        QPushButton { color: #DDE7F0; background: #202E3E; border: 1px solid #34475B; border-radius: 6px; padding: 7px 12px; }
        QPushButton:hover { background: #2A3B4E; border-color: #4B718A; }
        QPushButton#PrimaryButton { color: #081B1B; background: #56D7C5; border-color: #56D7C5; font-weight: 700; }
        QPushButton#PrimaryButton:hover { background: #79E4D5; }
        QTabWidget::pane { border: 1px solid #2B3A4C; border-radius: 7px; top: -1px; }
        QTabBar::tab { background: #172230; color: #9DAFC1; padding: 8px 14px; border: 1px solid #263648; }
        QTabBar::tab:selected { color: #E8EEF5; background: #202E3E; border-bottom: 2px solid #56D7C5; }
        QTableWidget, QTextBrowser { background: #121C28; alternate-background-color: #172331; color: #DBE5EF; gridline-color: #293848; border: 1px solid #293848; border-radius: 5px; }
        QHeaderView::section { background: #1B2938; color: #AFC0D1; padding: 7px; border: none; border-bottom: 1px solid #314356; }
        QTableWidget::item:selected { background: #23414A; color: #F0FAFA; }
        QSplitter::handle { background: #263648; width: 4px; }
        """
