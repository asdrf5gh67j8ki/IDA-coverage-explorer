"""Install Coverage Explorer into IDA's user plugins directory (no dependencies)."""
import argparse
import os
from pathlib import Path
import shutil
import sys


ROOT = Path(__file__).resolve().parent


def default_plugins():
    user_roots = os.environ.get('IDAUSR', '')
    if user_roots:
        separator = ';' if sys.platform == 'win32' else ':'
        first = user_roots.split(separator, 1)[0]
        if not first:
            raise ValueError('IDAUSR starts with an empty directory. Supply --plugins explicitly.')
        root = Path(first).expanduser()
    elif sys.platform == 'win32':
        appdata = os.environ.get('APPDATA')
        if not appdata:
            raise ValueError('APPDATA is unavailable. Supply --plugins explicitly.')
        root = Path(appdata) / 'Hex-Rays' / 'IDA Pro'
    else:
        root = Path.home() / '.idapro'
    return root / 'plugins'


def install(destination):
    destination = Path(destination).expanduser().resolve()
    files = [ROOT / 'coverage_explorer.py']
    files.extend(sorted((ROOT / 'covexplorer').glob('*.py')))
    if not files[0].is_file() or not (ROOT / 'covexplorer' / '__init__.py').is_file():
        raise ValueError('Incomplete source package. Extract the entire release ZIP first.')
    # Copy only this plugin's source; preserve all other plugins and user files.
    (destination / 'covexplorer').mkdir(parents=True, exist_ok=True)
    for source in files:
        target = destination / source.relative_to(ROOT)
        if source.resolve() != target.resolve():
            shutil.copy2(source, target)
    return destination


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(errors='backslashreplace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plugins', help='Exact plugins directory; overrides IDAUSR/defaults.')
    args = parser.parse_args()
    try:
        destination = install(args.plugins if args.plugins is not None else default_plugins())
    except (OSError, ValueError) as error:
        parser.exit(1, f'Installation failed: {error}\n')
    print(f'Installed Coverage Explorer in {destination}')
    print('Restart IDA, open a binary, wait for analysis, then choose')
    print('Edit > Plugins > Coverage Explorer.')


if __name__ == '__main__':
    main()
