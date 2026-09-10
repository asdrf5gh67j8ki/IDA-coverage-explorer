"""Compact coverage table. Uses IDA's Qt theme without application styling."""
from dataclasses import replace
from .qt import C, G, W, Qt, Signal, ui_font
from .core import CoverageError, VERSION, evaluate, parse_trace, basename, number


def label(text):
    widget = W.QLabel(text)
    widget.setTextFormat(Qt.PlainText)
    return widget


class Worker(C.QThread):
    done = Signal(object)
    failed = Signal(str)
    def __init__(self, operation, parent):
        super().__init__(parent)
        self.operation = operation
    def run(self):
        try: self.done.emit(self.operation())
        except Exception as error: self.failed.emit(str(error))


class FunctionModel(C.QAbstractTableModel):
    headers = ('Function', 'Address', 'Coverage', 'Instructions', 'Blocks touched')
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows, self.base = [], 0
    def rowCount(self, parent=C.QModelIndex()): return 0 if parent.isValid() else len(self.rows)
    def columnCount(self, parent=C.QModelIndex()): return len(self.headers)
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole: return self.headers[section]
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid(): return None
        f, hit, blocks = self.rows[index.row()]
        total, column = len(f.instructions), index.column()
        ratio = hit / total if total else 0.0
        address = self.base + f.start
        if role == Qt.DisplayRole:
            return (f.name, f'{address:08X}', f'{ratio:.1%}', f'{hit:,} / {total:,}',
                    f'{blocks:,} / {len(f.blocks):,}')[column]
        if role == Qt.UserRole:
            return (f.name.casefold(), address, ratio, hit, blocks)[column]
        if role == Qt.ToolTipRole:
            return (f'{f.name}\nAddress 0x{address:X} / RVA 0x{f.start:X}\n'
                    f'{hit:,} of {total:,} indexed instructions observed.\n'
                    'Blocks touched = blocks with at least one observed instruction.')
        if role == Qt.FontRole and column == 1: return ui_font(fixed=True)
        if role == Qt.TextAlignmentRole:
            return int(Qt.AlignVCenter | (Qt.AlignLeft if column < 2 else Qt.AlignRight))
    def update(self, rows, base):
        self.beginResetModel()
        self.rows, self.base = rows, base
        self.endResetModel()


class FilterModel(C.QSortFilterProxyModel):
    def __init__(self, parent):
        super().__init__(parent)
        self.query, self.mode = '', 'Observed'
        self.setSortRole(Qt.UserRole)
    def filterAcceptsRow(self, row, parent):
        model = self.sourceModel()
        f, hit, _ = model.rows[row]
        query = self.query.removeprefix('0x')
        if (self.query and self.query not in f.name.casefold()
                and query not in f'{model.base + f.start:x}' and query not in f'{f.start:x}'):
            return False
        return (self.mode == 'All functions' or self.mode == 'Observed' and hit > 0
                or self.mode == 'Not observed' and hit == 0
                or self.mode == 'Partial' and 0 < hit < len(f.instructions))


class CoveragePanel(W.QWidget):
    """Navigation uses RVAs; address columns use the current IDA image base."""
    def __init__(self, workspace, navigate=None, paint=None, refresh=None, parent=None,
                 highlighted=True, keep_highlight=False):
        super().__init__(parent)
        self.workspace = workspace
        self.navigate = navigate or (lambda rva: self.message(f'Navigate to 0x{workspace.index.base + rva:X} (preview).'))
        self.paint = paint or (lambda hits, enabled: None)
        self.refresh_callback = refresh
        self.keep_highlight = keep_highlight
        self.workers = set()
        self.index_stale, self.closing = False, False
        self.hits, self.active = frozenset(), None
        self._pending = []
        self._build()
        self.highlight.setEnabled(paint is not None)
        self.highlight.setChecked(highlighted and paint is not None)
        self.rebuild_runs()
        self.recalculate()

    def _action(self, menu, text, callback):
        action = menu.addAction(text)
        action.triggered.connect(lambda checked=False: callback())
        return action

    def _build(self):
        layout = W.QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        top = W.QHBoxLayout()
        top.setSpacing(4)
        self.import_button = W.QPushButton('Import…')
        self.import_button.clicked.connect(self.import_dialog)
        self.import_button.setToolTip('Import one or more coverage files (Ctrl+O)')
        top.addWidget(self.import_button)
        self.run_combo = W.QComboBox()
        self.run_combo.setEditable(True)
        self.run_combo.setInsertPolicy(W.QComboBox.NoInsert)
        self.run_combo.setMinimumWidth(100)
        self.run_combo.setSizePolicy(W.QSizePolicy.Expanding, W.QSizePolicy.Fixed)
        self.run_combo.setCompleter(None)
        self.expression = self.run_combo.lineEdit()
        self.expression.setPlaceholderText('Select a run or type B - A, then Enter')
        self.expression.setToolTip('Select a run, or type an expression: A | B, A & B, B - A, A ^ B')
        self.expression.returnPressed.connect(self.expression_changed)
        self.run_combo.activated.connect(self.run_selected)
        top.addWidget(self.run_combo, 1)
        self.highlight = W.QCheckBox('Highlight')
        self.highlight.setToolTip('Show selected coverage in IDA disassembly')
        self.highlight.toggled.connect(self.apply_paint)
        top.addWidget(self.highlight)
        self.more_button = W.QToolButton()
        self.more_button.setText('More')
        self.more_button.clicked.connect(self.show_more)
        top.addWidget(self.more_button)
        layout.addLayout(top)
        filters = W.QHBoxLayout()
        filters.setSpacing(4)
        self.search = W.QLineEdit()
        self.search.setPlaceholderText('Filter functions or addresses (Ctrl+F)')
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.filter_rows)
        filters.addWidget(self.search, 1)
        self.mode = W.QComboBox()
        self.mode.addItems(['Observed', 'Partial', 'Not observed', 'All functions'])
        self.mode.currentTextChanged.connect(self.filter_rows)
        filters.addWidget(self.mode)
        layout.addLayout(filters)
        self.model = FunctionModel(self)
        self.proxy = FilterModel(self)
        self.proxy.setSourceModel(self.model)
        self.table = W.QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(W.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(W.QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(W.QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(self.fontMetrics().height() + 6)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(0, W.QHeaderView.Stretch)
        for column, width in ((1, 138), (2, 80), (3, 100), (4, 108)):
            header_width = self.fontMetrics().horizontalAdvance(self.model.headers[column]) + 24
            self.table.setColumnWidth(column, max(width, header_width))
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(2, Qt.DescendingOrder)
        self.table.doubleClicked.connect(lambda _: self.jump_function())
        self.table.selectionModel().currentRowChanged.connect(self.selected_function)
        self.table.selectionModel().selectionChanged.connect(self.selected_function)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.table_menu)
        self.table.installEventFilter(self)
        layout.addWidget(self.table, 1)
        self.status = label('')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        shortcut_class = getattr(G, 'QShortcut', None) or W.QShortcut
        self.shortcuts = []
        for sequence, callback in (('Ctrl+F', self.focus_search), ('Ctrl+O', self.import_dialog)):
            shortcut = shortcut_class(G.QKeySequence(sequence), self)
            shortcut.setContext(Qt.WidgetWithChildrenShortcut)
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)
        self.setMinimumSize(400, 220)
        self.resize(820, 450)

    def show_more(self):
        # Keep every menu wrapper alive through exec(), then discard the tree.
        # Imports and session updates must never depend on a cached QMenu:
        # IDA's embedded PySide6 can invalidate its native object independently.
        menus = [W.QMenu(self)]
        menu = menus[0]
        def submenu(parent, title):
            child = W.QMenu(title, parent)
            menus.append(child)
            parent.addMenu(child)
            return child
        self._action(menu, 'Open session…', self.open_session)
        self._action(menu, 'Save session…', self.save_session)
        self._action(menu, 'Export JSON…', self.export)
        menu.addSeparator()
        runs = submenu(menu, 'Runs')
        runs.setEnabled(bool(self.workspace.runs))
        for key, run in self.workspace.runs.items():
            actions = submenu(runs, f'{key}: {run.label.replace("&", "&&")}')
            self._action(actions, 'Select', lambda k=key: self.select_expression(k))
            self._action(actions, 'Details…', lambda k=key: self.run_details(k))
            self._action(actions, 'Rename…', lambda k=key: self.rename_run(k))
            self._action(actions, 'Remove', lambda k=key: self.remove_run(k))
        menu.addSeparator()
        refresh = self._action(menu, 'Refresh index', self.refresh_index)
        refresh.setEnabled(self.refresh_callback is not None)
        self._action(menu, 'About Coverage Explorer', self.about)
        try:
            menu.exec(self.more_button.mapToGlobal(C.QPoint(0, self.more_button.height())))
        finally:
            menu.deleteLater()

    def eventFilter(self, obj, event):
        if obj is self.table and event.type() == C.QEvent.KeyPress:
            if event.matches(G.QKeySequence.Copy):
                self.copy_rows()
                return True
            if event.key() in (Qt.Key_Return, Qt.Key_Enter):
                self.jump_function()
                return True
            if event.key() == Qt.Key_N and event.modifiers() == Qt.NoModifier:
                self.jump_instruction(False)
                return True
        return super().eventFilter(obj, event)

    def focus_search(self):
        self.search.setFocus()
        self.search.selectAll()

    def message(self, text):
        self.status.setText(text)
        self.status.setToolTip(text)

    def failure(self, text):
        self.message(text)
        W.QMessageBox.warning(self, 'Coverage Explorer', text)

    def about(self):
        W.QMessageBox.information(self, 'Coverage Explorer',
            f'Coverage Explorer {VERSION}\n\n'
            'Import recorded coverage, select a run or expression, and navigate the table.\n'
            'Enter: jump. N: next unobserved instruction. Ctrl+C: copy rows.\n'
            'Close the panel to continue working with coverage in IDA.\n\n'
            'Coverage is imported; this plugin does not record execution.')

    def busy(self, operation, completed, failed=None):
        if self.closing: return
        worker = Worker(operation, self)
        self.workers.add(worker)
        self.import_button.setEnabled(False)
        self.message('Reading and mapping coverage…')
        def deliver(value):
            if self.closing: return
            try: completed(value)
            except Exception as error: (failed or self.failure)(str(error))
        def error(text):
            if not self.closing: (failed or self.failure)(text)
        worker.done.connect(deliver, Qt.QueuedConnection)
        worker.failed.connect(error, Qt.QueuedConnection)
        def finished():
            self.workers.discard(worker)
            if not self.closing:
                self.import_button.setEnabled(not self.workers and not self.index_stale)
            worker.deleteLater()
        worker.finished.connect(finished, Qt.QueuedConnection)
        worker.start()

    def rebuild_runs(self):
        blocked = self.run_combo.blockSignals(True)
        try:
            self.run_combo.clear()
            for key, run in self.workspace.runs.items():
                self.run_combo.addItem(f'{key}: {run.label}', key)
                self.run_combo.setItemData(self.run_combo.count() - 1,
                    f'{run.source}\nModule: {run.module}\n{len(run.hits):,} instructions', Qt.ToolTipRole)
        finally:
            self.run_combo.blockSignals(blocked)
        self.sync_controls()

    def sync_controls(self):
        expression = self.workspace.expression
        self.run_combo.blockSignals(True)
        position = self.run_combo.findData(expression)
        self.run_combo.setCurrentIndex(position)
        if position < 0: self.run_combo.setEditText(expression)
        self.run_combo.blockSignals(False)

    def expression_changed(self):
        text = self.expression.text().strip()
        key = self.run_combo.currentData()
        # Enter also works when a labeled run is already selected.
        expression = key if key and text == self.run_combo.currentText() and text == self.run_combo.itemText(self.run_combo.currentIndex()) else text.upper()
        self.select_expression(expression)

    def select_expression(self, expression):
        try: evaluate(expression, self.workspace.runs)
        except CoverageError as error:
            self.message(str(error))
            return
        self.workspace.expression = expression
        self.recalculate()

    def run_selected(self, position):
        key = self.run_combo.itemData(position)
        if key: self.select_expression(key)

    def run_details(self, key):
        run = self.workspace.runs[key]
        dialog = W.QDialog(self)
        dialog.setWindowTitle(f'Coverage run {key}')
        layout = W.QVBoxLayout(dialog)
        text = W.QPlainTextEdit()
        text.setReadOnly(True)
        text.setPlainText(f'{run.label}\n{run.source}\nModule: {run.module}\n'
            f'Format: {run.format}\nTrace SHA-256: {run.digest}\n'
            f'{run.records:,} records / {run.unique:,} unique\n'
            f'{len(run.hits):,} observed instructions\n'
            f'{run.unmapped:,} records match no complete indexed instruction\n' + '\n'.join(run.notes))
        layout.addWidget(text)
        buttons = W.QDialogButtonBox(W.QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.resize(560, 270)
        dialog.exec()

    def rename_run(self, key):
        text, ok = W.QInputDialog.getText(self, 'Rename run', 'Name:', text=self.workspace.runs[key].label)
        if ok and text.strip():
            self.workspace.runs[key] = replace(self.workspace.runs[key], label=text.strip()[:160])
            self.rebuild_runs()

    def remove_run(self, key):
        self.workspace.remove(key)
        self.rebuild_runs()
        self.recalculate()

    def recalculate(self):
        previous = self.active.start if self.active else None
        self.sync_controls()
        self.hits = self.workspace.selected()
        index = self.workspace.index
        rows = [(f, sum(i in self.hits for i in f.instructions),
                 sum(any(i in self.hits for i in b.instructions) for b in f.blocks)) for f in index.functions]
        self.model.update(rows, index.base)
        self.filter_rows()
        previous_row = next((n for n, (f, _, _) in enumerate(rows) if f.start == previous), None)
        selected = self.proxy.mapFromSource(self.model.index(previous_row, 0)) if previous_row is not None else C.QModelIndex()
        if not selected.isValid() and self.proxy.rowCount(): selected = self.proxy.index(0, 0)
        if selected.isValid():
            self.table.setCurrentIndex(selected)
            self.table.selectRow(selected.row())
        else: self.active = None
        self.apply_paint()

    def filter_rows(self, *_):
        modern = hasattr(self.proxy, 'beginFilterChange') and hasattr(self.proxy, 'endFilterChange')
        if modern: self.proxy.beginFilterChange()
        self.proxy.query = self.search.text().strip().casefold()
        self.proxy.mode = self.mode.currentText()
        if modern: self.proxy.endFilterChange(C.QSortFilterProxyModel.Direction.Rows)
        else: self.proxy.invalidateFilter()
        self.selected_function()
        self.summary_status()

    def summary_status(self):
        if self.index_stale:
            self.message('Database changed. More > Refresh index to resume coverage.')
        elif not self.workspace.runs:
            self.message(f'No coverage loaded. Import a trace for {self.workspace.index.name}.')
        else:
            total = len(self.workspace.index.addresses)
            self.message(f'{len(self.hits):,} / {total:,} instructions ({len(self.hits) / max(1, total):.1%})'
                         f' | {self.proxy.rowCount():,} functions shown | {self.workspace.expression}')

    def set_stale(self, stale=True):
        self.index_stale = stale
        self.import_button.setEnabled(not stale and not self.workers)
        self.table.setEnabled(not stale)
        self.summary_status()

    def selected_function(self, *_):
        selected = self.table.selectionModel().selectedRows()
        current = self.table.currentIndex()
        self.active = None
        if selected:
            row = current if current.isValid() and self.table.selectionModel().isRowSelected(current.row(), C.QModelIndex()) else selected[0]
            self.active = self.model.rows[self.proxy.mapToSource(row).row()][0]

    def jump_function(self):
        if self.active and not self.index_stale: self.navigate(self.active.start)

    def jump_instruction(self, observed):
        if not self.active or self.index_stale: return
        candidates = [i for i in self.active.instructions if (i in self.hits) == observed]
        if not candidates:
            self.message('No ' + ('observed' if observed else 'unobserved') + ' instructions in this function.')
            return
        last = getattr(self, '_last_instruction', -1)
        selected = next((i for i in candidates if i > last), candidates[0])
        self._last_instruction = selected
        self.navigate(self.workspace.index.addresses[selected])

    def copy_rows(self):
        selected = sorted(self.table.selectionModel().selectedRows(), key=lambda index: index.row())
        if selected:
            lines = ['\t'.join(self.model.headers)]
            lines += ['\t'.join(str(self.proxy.index(index.row(), col).data())
                                 for col in range(self.model.columnCount())) for index in selected]
            W.QApplication.clipboard().setText('\n'.join(lines))

    def table_menu(self, point):
        index = self.table.indexAt(point)
        if not index.isValid(): return
        if not self.table.selectionModel().isRowSelected(index.row(), C.QModelIndex()):
            self.table.setCurrentIndex(index)
            self.table.selectRow(index.row())
        menu = W.QMenu(self)
        jump = self._action(menu, 'Jump to function', self.jump_function)
        observed = self._action(menu, 'Next observed instruction', lambda: self.jump_instruction(True))
        missing = self._action(menu, 'Next unobserved instruction (N)', lambda: self.jump_instruction(False))
        for action in (jump, observed, missing): action.setEnabled(not self.index_stale)
        menu.addSeparator()
        self._action(menu, 'Copy selected rows', self.copy_rows)
        if self.active:
            runs = menu.addMenu('Select a run that reached this function')
            for key, run in self.workspace.runs.items():
                if any(i in run.hits for i in self.active.instructions):
                    self._action(runs, f'{key}: {run.label.replace("&", "&&")}', lambda k=key: self.select_expression(k))
            runs.setEnabled(bool(runs.actions()))
        menu.exec(self.table.viewport().mapToGlobal(point))

    def apply_paint(self, *_):
        self.paint(self.hits, self.highlight.isChecked())

    def import_dialog(self):
        if self.index_stale or self.workers: return
        paths, _ = W.QFileDialog.getOpenFileNames(self, 'Import coverage', '', 'Coverage (*.log *.drcov *.modoff *.txt);;All files (*)')
        if not paths: return
        self._pending = list(paths)
        self._import_next()

    def _import_next(self):
        if self.closing or self.index_stale: return
        if not self._pending: return
        path = self._pending.pop(0)
        def failure(text):
            if text.startswith('Absolute-address traces require'):
                value, ok = W.QInputDialog.getText(self, 'Runtime image base',
                    'Enter the traced module runtime base in hexadecimal.\nUse the IDA image base only if the trace uses IDA addresses:')
                if ok:
                    try: base = number(value)
                    except CoverageError as error:
                        self.failure(str(error))
                        self._import_next()
                        return
                    self.busy(lambda: parse_trace(path, base), self.choose_module, self.import_failed)
                    return
                self._import_next()
            else: self.import_failed(text)
        self.busy(lambda: parse_trace(path), self.choose_module, failure)

    def import_failed(self, text):
        self.failure(text)
        self._import_next()

    def choose_module(self, trace):
        if self.closing or self.index_stale: return
        names = [f'{m.path}   [ID {m.key}]' for m in trace.modules]
        if not names:
            self.failure('No loadable modules in this trace.')
            self._import_next()
            return
        candidates = [i for i, m in enumerate(trace.modules) if basename(m.path) == basename(self.workspace.index.name)]
        choice, ok = W.QInputDialog.getItem(self, 'Map trace to this database',
                                           f'Select the traced module for {self.workspace.index.name}.\nFilename matching does not verify binary identity.',
                                           names, candidates[0] if len(candidates) == 1 else 0, False)
        if not ok:
            self._import_next()
            return
        module = trace.modules[names.index(choice)]
        index = self.workspace.index
        def mapped(run):
            if self.index_stale or index is not self.workspace.index:
                self.failure('Index changed during import; import the file again.')
            else:
                key, added = self.workspace.add(run)
                self.workspace.expression = key
                self.rebuild_runs()
                self.recalculate()
                self.message(f'{key}: {"Imported" if added else "Already loaded"} {run.label}. {run.unmapped:,} records matched no full indexed instruction.')
            self._import_next()
        self.busy(lambda: index.map_trace(trace, module.key), mapped, self.import_failed)

    def save_session(self):
        if self.index_stale: self.message("Refresh the index first."); return
        path, _ = W.QFileDialog.getSaveFileName(self, 'Save workspace', 'coverage-session.json', 'JSON (*.json)')
        if path:
            try: self.workspace.save(path); self.message('Workspace saved.')
            except (CoverageError, OSError) as error: self.failure(str(error))

    def open_session(self):
        if self.index_stale: self.message("Refresh the index first."); return
        if self.workers: self.message('Wait for the current import to finish.'); return
        path, _ = W.QFileDialog.getOpenFileName(self, 'Open workspace', '', 'JSON (*.json)')
        if path:
            try:
                self.workspace.load(path)
                self.rebuild_runs()
                self.recalculate()
            except (CoverageError, OSError) as error: self.failure(str(error))

    def export(self):
        if self.index_stale: self.message("Refresh the index first."); return
        path, _ = W.QFileDialog.getSaveFileName(self, 'Export selected coverage', 'coverage-result.json', 'JSON (*.json)')
        if path:
            try: self.workspace.export(path); self.message('Selected coverage exported.')
            except (CoverageError, OSError) as error: self.failure(str(error))

    def refresh_index(self):
        if self.workers: self.message('Wait for the current import to finish.'); return
        if self.refresh_callback:
            try: self.refresh_callback(self)
            except Exception as error: self.failure(str(error))

    def shutdown(self):
        if self.closing: return
        self.closing = True
        self._pending.clear()
        if not self.keep_highlight:
            self.paint(frozenset(), False)
        # Workers have immutable snapshots and never access IDA. Queued results
        # are discarded when this panel closes; loaded coverage stays in the controller.
        for worker in tuple(self.workers): worker.wait()

    def closeEvent(self, event):
        self.shutdown()
        super().closeEvent(event)
