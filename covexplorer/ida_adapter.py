"""IDA APIs stay on the main thread; coverage workers receive plain snapshots."""
from dataclasses import replace
import weakref
import ida_auto
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_kernwin
import ida_nalt
import idautils
from .core import CoverageError, Index, Workspace, MAX_INSTRUCTIONS, MAX_FUNCTIONS, filename
from .qt import C, W
from .ui import CoveragePanel

_active = None


def snapshot():
    if not ida_auto.auto_is_ok():
        raise CoverageError('Wait for IDA auto-analysis to finish, then open Coverage Explorer again.')
    base = ida_nalt.get_imagebase()
    path = ida_nalt.get_input_file_path()
    if not path:
        raise CoverageError('Open a binary database first.')
    raw_digest = ida_nalt.retrieve_input_file_sha256()
    digest = bytes(raw_digest).hex() if raw_digest else ''
    functions, count = [], 0
    ida_kernwin.show_wait_box('Indexing instructions and basic blocks…')
    try:
        for n, address in enumerate(idautils.Functions()):
            if n >= MAX_FUNCTIONS:
                raise CoverageError('Function limit reached; index was not committed.')
            if n % 100 == 0:
                if ida_kernwin.user_cancelled():
                    raise CoverageError('Indexing cancelled; previous coverage was retained.')
                ida_kernwin.replace_wait_box(f'Indexing function {n:,}…')
            function = ida_funcs.get_func(address)
            if function is None or address < base:
                continue
            blocks = []
            for block in ida_gdl.FlowChart(function, flags=ida_gdl.FC_NOEXT):
                if block.start_ea < base or block.end_ea <= block.start_ea:
                    continue
                instructions = []
                for ea in idautils.Heads(block.start_ea, block.end_ea):
                    if not ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
                        continue
                    size = ida_bytes.get_item_size(ea)
                    if 0 < size and ea + size <= block.end_ea:
                        instructions.append((ea - base, size))
                        count += 1
                    if count > MAX_INSTRUCTIONS * 2:
                        raise CoverageError('Instruction ownership limit reached.')
                if instructions:
                    blocks.append((block.start_ea - base, block.end_ea - base, instructions))
            functions.append((address - base, ida_funcs.get_func_name(address), blocks))
        result = Index(filename(path), base, digest, functions)
        if not result.addresses:
            raise CoverageError('IDA has no indexed function instructions in this database.')
        return result
    finally:
        ida_kernwin.hide_wait_box()


class Overlay(ida_kernwin.UI_Hooks):
    """Transient line overlays preserve all persistent user item/node colors."""
    def __init__(self, controller):
        super().__init__()
        self.controller = weakref.ref(controller)
        self.addresses = frozenset()
        self.broken = False

    def get_lines_rendering_info(self, out, widget, info):
        controller = self.controller()
        if (not controller or controller.stale or self.broken or not self.addresses
                or ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_DISASM):
            return
        try:
            base = ida_nalt.get_imagebase()
            for section in info.sections_lines:
                for line in section:
                    ea = line.at.toea()
                    if ea - base not in self.addresses:
                        continue
                    entry = ida_kernwin.line_rendering_output_entry_t(line)
                    # AABBGGRR: a translucent neutral overlay works with light/dark IDA themes.
                    entry.bg_color = 0x60888888
                    out.entries.push_back(entry)
                    # IDAPython's push_back transfers ownership to IDA.
        except Exception as error:
            self.broken = True
            ida_kernwin.msg('Coverage Explorer: line overlay unavailable: %s\n' % error)
            if controller.form.panel:
                controller.form.panel.message('IDA line highlighting failed; see the Output window.')

    def database_closed(self):
        controller = self.controller()
        if controller: controller.close()


class DatabaseChanges(ida_idp.IDB_Hooks):
    def __init__(self, controller):
        super().__init__()
        self.controller = weakref.ref(controller)
    def changed(self):
        controller = self.controller()
        if controller: controller.mark_stale()
        return 0
    def func_added(self, *args): return self.changed()
    def func_updated(self, *args): return self.changed()
    def deleting_func(self, *args): return self.changed()
    def set_func_start(self, *args): return self.changed()
    def set_func_end(self, *args): return self.changed()
    def renamed(self, *args): return self.changed()
    def byte_patched(self, *args): return self.changed()
    def segm_moved(self, *args): return self.changed()
    def allsegs_moved(self, *args): return self.changed()
    def make_code(self, *args): return self.changed()
    def make_data(self, *args): return self.changed()
    def destroyed_items(self, *args): return self.changed()


class Form(ida_kernwin.PluginForm):
    def __init__(self, controller):
        super().__init__()
        self.controller = weakref.ref(controller)
        self.panel = None

    def OnCreate(self, form):
        controller = self.controller()
        # The legacy name remains the official converter for PySide6 in IDA 9.2+.
        # FormToPySideWidget is an older, unrelated PySide compatibility method.
        parent = self.FormToPyQtWidget(form)
        layout = parent.layout() or W.QVBoxLayout(parent)
        layout.setContentsMargins(0, 0, 0, 0)
        self.panel = CoveragePanel(controller.workspace, controller.navigate,
                                   controller.paint, controller.refresh, parent,
                                   highlighted=controller.highlighting, keep_highlight=True)
        layout.addWidget(self.panel)
        controller.attach()
        if controller.stale:
            self.panel.set_stale()

    def OnClose(self, form):
        if self.panel:
            self.panel.shutdown()
            self.panel = None
        # Keep coverage overlays and database-change hooks alive while the
        # analyst works in IDA without the coverage table open.


class Controller:
    def __init__(self):
        self.workspace = Workspace(snapshot())
        self.stale, self.attached = False, False
        self.highlighting = True
        self.form = Form(self)
        self.overlay = Overlay(self)
        self.changes = DatabaseChanges(self)

    def attach(self):
        global _active
        _active = weakref.ref(self)
        if not self.attached:
            self.overlay.hook()
            self.changes.hook()
            self.attached = True

    def detach(self):
        global _active
        self.overlay.addresses = frozenset()
        self.stale = True
        if self.attached:
            self.overlay.unhook()
            self.changes.unhook()
            self.attached = False
        if _active and _active() is self: _active = None
        ida_kernwin.refresh_idaview_anyway()

    def show(self, prompt=False):
        self.form.Show('Coverage Explorer', options=ida_kernwin.PluginForm.WOPN_PERSIST)
        if prompt:
            def import_when_open():
                panel = self.form.panel
                if panel and not panel.closing and not self.workspace.runs:
                    panel.import_dialog()
            C.QTimer.singleShot(0, import_when_open)

    def close(self):
        if self.form.panel:
            self.form.panel.shutdown()
            self.form.Close(ida_kernwin.PluginForm.WCLS_CLOSE_LATER)
        self.detach()

    def mark_stale(self):
        self.stale = True
        self.overlay.addresses = frozenset()
        if self.form.panel:
            self.form.panel.set_stale()
        ida_kernwin.refresh_idaview_anyway()

    def require_fresh(self):
        if self.stale:
            raise CoverageError('Refresh the instruction index after IDA database changes.')

    def navigate(self, rva):
        if self.stale:
            if self.form.panel: self.form.panel.message('Refresh the index before navigating coverage.')
            return
        ida_kernwin.jumpto(ida_nalt.get_imagebase() + rva)

    def paint(self, hits, enabled):
        self.highlighting = bool(enabled)
        if self.stale or not enabled:
            self.overlay.addresses = frozenset()
        else:
            self.overlay.addresses = frozenset(self.workspace.index.addresses[i] for i in hits)
        ida_kernwin.refresh_idaview_anyway()

    def sync(self):
        if self.form.panel:
            self.form.panel.rebuild_runs()
            self.form.panel.recalculate()
        else:
            self.paint(self.workspace.selected(), self.highlighting)

    def refresh(self, panel):
        old = self.workspace.index
        updated = snapshot()
        # Remap only unchanged instruction boundaries. No execution is inferred for new code.
        runs, dropped = {}, 0
        for key, run in self.workspace.runs.items():
            hits = set()
            for i in run.hits:
                rva = old.addresses[i]
                j = updated.lookup.get(rva)
                if j is not None and updated.ends[j] == old.ends[i]:
                    hits.add(j)
                else: dropped += 1
            runs[key] = replace(run, hits=frozenset(hits))
        self.workspace.index, self.workspace.runs = updated, runs
        self.stale = False
        self.overlay.broken = False
        panel.set_stale(False)
        self.sync()
        panel.message(f'Index refreshed. {dropped:,} run observations no longer match instruction boundaries.')


def active_controller():
    controller = _active() if _active else None
    if not controller:
        raise CoverageError('Open Coverage Explorer from Edit > Plugins first.')
    controller.require_fresh()
    return controller
