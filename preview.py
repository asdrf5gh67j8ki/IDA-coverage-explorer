"""Run the real coverage table outside IDA with synthetic coverage."""
import argparse
import sys
from covexplorer.qt import C, W
from covexplorer.demo import workspace
from covexplorer.ui import CoveragePanel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screenshot')
    parser.add_argument('--fixtures')
    args = parser.parse_args()
    app = W.QApplication.instance() or W.QApplication(sys.argv[:1])
    window = CoveragePanel(workspace(args.fixtures))
    window.setWindowTitle('Coverage Explorer — synthetic preview')
    window.show()
    if args.screenshot:
        def capture():
            window.grab().save(args.screenshot)
            window.close()
            app.quit()
        C.QTimer.singleShot(250, capture)
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
