"""Synthetic instruction index and trace fixtures. Never presented as a malware run."""
import hashlib
from pathlib import Path
import struct
from .core import Index, Workspace, parse_bytes

NAMES = ['entry', 'initialize_runtime', 'parse_command_line', 'validate_configuration',
         'decode_strings', 'resolve_imports', 'initialize_transport', 'read_configuration',
         'check_environment', 'select_execution_mode', 'connect_endpoint', 'build_request',
         'parse_response', 'dispatch_command', 'enumerate_records', 'transform_buffer',
         'write_output', 'retry_connection', 'release_resources', 'shutdown_runtime',
         'parse_optional_header', 'resolve_module_path', 'check_cache', 'refresh_configuration',
         'handle_timeout', 'process_queue', 'serialize_record', 'validate_checksum',
         'allocate_buffer', 'initialize_worker', 'wait_for_work', 'flush_records',
         'decode_message', 'validate_message', 'copy_record', 'query_status']


def index():
    functions = []
    for n, name in enumerate(NAMES):
        start = 0x1000 + n * 0x200
        blocks = []
        for b in range(4 + n % 13):
            ea = start + b * 24
            count = 3 + (n + b) % 5
            items = [(ea + i * 3, 3) for i in range(count)]
            blocks.append((ea, ea + count * 3, items))
        functions.append((start, name, blocks))
    return Index('coverage-demo.exe', 0x140000000,
                 hashlib.sha256(b'Coverage Explorer synthetic demonstration v1').hexdigest(), functions)


def drcov(blocks, path='C:\\demo\\coverage-demo.exe', base=0x7ff600000000, version=2, table=2):
    if table == 2:
        columns = 'id, base, end, entry, checksum, timestamp, path'
        module = f'0, {base:#x}, {base + 0x20000:#x}, {base + 0x1000:#x}, 0x0, 0x0, {path}'
    else:
        columns = 'id, containing_id, start, end, entry, offset, preferred_base, checksum, timestamp, path'
        module = f'0, 0, {base:#x}, {base + 0x20000:#x}, {base + 0x1000:#x}, 0x0, 0x140000000, 0x0, 0x0, {path}'
    header = f'DRCOV VERSION: {version}\nDRCOV FLAVOR: drcov\nModule Table: version {table}, count 1\nColumns: {columns}\n{module}\nBB Table: {len(blocks)} bbs\n'
    return header.encode('utf-8') + b''.join(struct.pack('<IHH', start, size, 0) for start, size in blocks)


def workspace(output=None):
    snapshot = index()
    result = Workspace(snapshot)
    for run, title in enumerate(('baseline', 'configured', 'timeout-path')):
        blocks = []
        for n, function in enumerate(snapshot.functions):
            for b, block in enumerate(function.blocks):
                include = ((n * 7 + b * 3 + run * 5) % 11 < (5, 8, 4)[run])
                if n in (0, 1, 4, 5): include = True
                if n in (17, 24) and run != 2: include = False
                if include: blocks.append((block.start, block.end - block.start))
        data = drcov(blocks, version=3 if run else 2, table=5 if run else 2)
        source = title + '.drcov'
        if output:
            Path(output).mkdir(parents=True, exist_ok=True)
            Path(output, source).write_bytes(data)
        result.add(snapshot.map_trace(parse_bytes(data, source), '0', title))
    result.expression = 'B - A'
    if output: result.save(Path(output, 'demo-session.json'))
    return result
