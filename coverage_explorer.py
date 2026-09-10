"""IDA entry point. Install this file beside the covexplorer package."""
import ida_idaapi
import ida_kernwin


class CoverageModule(ida_idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self.controller = None

    def run(self, arg):
        try:
            from covexplorer.ida_adapter import Controller
            if self.controller is None:
                self.controller = Controller()
            self.controller.show(prompt=not self.controller.workspace.runs)
        except Exception as error:
            ida_kernwin.warning('Coverage Explorer: ' + str(error))

    def __del__(self):
        if self.controller is not None:
            self.controller.close()


class CoveragePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI
    comment = 'Import coverage, compare runs, and navigate observed code'
    help = 'Import drcov or module-relative traces for the open database.'
    wanted_name = 'Coverage Explorer'
    wanted_hotkey = 'Ctrl-Alt-C'

    def init(self):
        return CoverageModule()


def PLUGIN_ENTRY():
    return CoveragePlugin()
