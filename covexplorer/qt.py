"""Use IDA's own binding. Never load two different Qt runtimes into IDA."""
try:
    import ida_kernwin
except ImportError:
    ida_kernwin = None

if ida_kernwin is not None:
    import re
    version = re.match(r'(\d+)\.(\d+)', ida_kernwin.get_kernel_version())
    modern = bool(version and tuple(map(int, version.groups())) >= (9, 2))
else:
    modern = True

if modern:
    from PySide6 import QtCore as C, QtGui as G, QtWidgets as W
    Signal = C.Signal
else:
    from PyQt5 import QtCore as C, QtGui as G, QtWidgets as W
    Signal = C.pyqtSignal

Qt = C.Qt


def ui_font(size=None, fixed=False):
    """Resolve fonts from the running OS after QApplication exists."""
    role = G.QFontDatabase.FixedFont if fixed else G.QFontDatabase.GeneralFont
    font = G.QFontDatabase.systemFont(role)
    if size is not None:
        font.setPointSize(size)
    return font
