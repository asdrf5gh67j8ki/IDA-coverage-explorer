"""Create a source/install ZIP without caches, virtual environments, or local traces."""
import hashlib
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from covexplorer.core import VERSION


def main():
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    destination = output / f'coverage-explorer-{VERSION}.zip'
    singles = ['README.md', 'LICENSE', '.gitignore', 'coverage_explorer.py',
               'install.ps1', 'install.py', 'preview.py', 'requirements-preview.txt']
    files = [ROOT / name for name in singles]
    for directory in ('covexplorer', 'tests', 'docs', 'tools', '.github', 'examples'):
        files.extend(path for path in (ROOT / directory).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts
                     and 'traces' not in path.relative_to(ROOT).parts
                     and path.suffix in ('.py', '.md', '.png', '.ps1', '.yml', '.c', '.drcov', '.json'))
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files):
            archive.write(path, f'coverage-explorer-{VERSION}/' + path.relative_to(ROOT).as_posix())
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix('.zip.sha256').write_text(f'{digest}  {destination.name}\n', encoding='ascii')
    print(f'{destination} ({destination.stat().st_size:,} bytes)')
    print(f'SHA-256 {digest}')


if __name__ == '__main__': main()
