"""Callable through IDAPython, including an MCP client's Python-execution tool.
Call these functions on IDA's main thread; they do not start another MCP server.
"""
from .core import parse_trace, evaluate


def _controller():
    from .qt import C, W
    from .ida_adapter import active_controller
    app = W.QApplication.instance()
    if app is None or C.QThread.currentThread() != app.thread():
        raise RuntimeError('Invoke this API on the IDA main thread.')
    return active_controller()


def load(path, module_key, absolute_base=None, label=None):
    controller = _controller()
    workspace = controller.workspace
    trace = parse_trace(path, absolute_base)
    key, added = workspace.add(workspace.index.map_trace(trace, str(module_key), label))
    workspace.expression = key
    controller.sync()
    return {'run': key, 'added': added}


def select(expression):
    controller = _controller()
    evaluate(expression, controller.workspace.runs)
    controller.workspace.expression = expression
    controller.sync()
    return summary()


def summary():
    workspace = _controller().workspace
    return {'expression': workspace.expression, 'observed': len(workspace.selected()),
            'indexed': len(workspace.index.addresses),
            'runs': {key: {'name': run.label, 'observed': len(run.hits), 'unmapped_records': run.unmapped}
                     for key, run in workspace.runs.items()}}


def export(path):
    _controller().workspace.export(path)


def highlight(enabled=True):
    controller = _controller()
    panel = controller.form.panel
    if panel:
        panel.highlight.setChecked(bool(enabled))
    controller.paint(controller.workspace.selected(), enabled)
