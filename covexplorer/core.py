"""Coverage semantics and set algebra. No IDA or Qt dependencies."""
from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import string
import struct

VERSION = '1.1.1'
MAX_FILE = 128 * 1024 * 1024
MAX_RECORDS = 2_000_000
MAX_INSTRUCTIONS = 1_000_000
MAX_FUNCTIONS = 100_000
MAX_RUNS = 26
MAX_ADDRESS = (1 << 64) - 1


class CoverageError(ValueError):
    pass


def number(text, base=16):
    try:
        value = int(text.strip(), base)
    except (ValueError, AttributeError):
        raise CoverageError('Invalid numeric field: ' + repr(text)) from None
    if not 0 <= value <= MAX_ADDRESS:
        raise CoverageError('Address or count is outside the supported range.')
    return value


def filename(path):
    """IDA databases and traces can retain paths from a different host OS."""
    return str(path).replace('\\', '/').rsplit('/', 1)[-1]


def basename(path):
    return filename(path).casefold()


@dataclass(frozen=True)
class Module:
    key: str
    path: str
    base: int = 0
    end: int = 0
    parent: str = ''


@dataclass(frozen=True)
class Trace:
    source: str
    digest: str
    format: str
    modules: tuple
    records: tuple  # module key, RVA, length; length=0 means one observed address
    notes: tuple = ()


def read_limited(path):
    with open(path, 'rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise CoverageError('Input exceeds 128 MiB.')
    return data


def parse_trace(path, absolute_base=None):
    return parse_bytes(read_limited(path), str(path), absolute_base)


def parse_bytes(data, source='<memory>', absolute_base=None):
    if absolute_base is not None and (type(absolute_base) is not int or not 0 <= absolute_base <= MAX_ADDRESS):
        raise CoverageError('Runtime image base must be an unsigned 64-bit integer.')
    if len(data) > MAX_FILE:
        raise CoverageError('Input exceeds 128 MiB.')
    digest = hashlib.sha256(data).hexdigest()
    if data.startswith(b'DRCOV VERSION:'):
        modules, records, notes = _drcov(data)
        return Trace(source, digest, 'drcov', tuple(modules), tuple(records), tuple(notes))
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError:
        raise CoverageError('Text traces must be UTF-8; unsupported binary format.') from None
    modules, records, mode = {}, [], None
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if len(records) >= MAX_RECORDS or len(line) > 32768:
            raise CoverageError('Trace record or line-length limit reached.')
        if '+' in line:
            if mode == 'absolute':
                raise CoverageError('Do not mix absolute and module-relative records.')
            mode = 'modoff'
            path, offset = line.rsplit('+', 1)
            path = path.strip()
            if not path:
                raise CoverageError(f'Line {line_no}: module name is empty.')
            # Case-sensitive filesystems can contain both App and app. Keep
            # their observations distinct; basename matching only suggests a UI selection.
            key = path
            modules[key] = Module(key, path)
            if len(modules) > 65535:
                raise CoverageError('Trace module limit reached (65,535).')
            records.append((key, number(offset), 0))
        else:
            if mode == 'modoff':
                raise CoverageError('Do not mix absolute and module-relative records.')
            mode = 'absolute'
            if absolute_base is None:
                raise CoverageError('Absolute-address traces require an explicit runtime image base.')
            address = number(line)
            if address < absolute_base:
                raise CoverageError(f'Line {line_no}: address precedes the supplied image base.')
            modules['absolute'] = Module('absolute', 'absolute addresses', absolute_base)
            records.append(('absolute', address - absolute_base, 0))
    if not records:
        raise CoverageError('The trace contains no coverage records.')
    return Trace(source, digest, mode, tuple(modules.values()), tuple(records),
                 ('Point traces mark only exact instruction starts; no basic-block expansion.',))


def _drcov(data):
    position = 0
    def line():
        nonlocal position
        end = data.find(b'\n', position, position + 32769)
        if end < 0:
            raise CoverageError('Truncated or oversized drcov header line.')
        try:
            value = data[position:end].rstrip(b'\r').decode('utf-8')
        except UnicodeError:
            raise CoverageError('Invalid UTF-8 in drcov module table.') from None
        position = end + 1
        return value
    match = re.fullmatch(r'DRCOV VERSION: (2|3)', line())
    if not match:
        raise CoverageError('Supported drcov versions are 2 and 3.')
    version = int(match[1])
    if not re.fullmatch(r'DRCOV FLAVOR: drcov(?:-32|-64)?', line()):
        raise CoverageError('Unsupported drcov flavor.')
    match = re.fullmatch(r'Module Table: version ([2-5]), count (\d+)', line())
    if not match or int(match[2]) > 65535:
        raise CoverageError('Supported module-table versions are 2 through 5 (65,535 entries maximum).')
    table_version, count = int(match[1]), int(match[2])
    header = line()
    if not header.startswith('Columns: '):
        raise CoverageError('Missing module column header.')
    columns = [value.strip() for value in header[9:].split(',')]
    allowed = {'id', 'containing_id', 'base', 'start', 'end', 'entry', 'offset',
               'preferred_base', 'checksum', 'timestamp', 'path'}
    if (not columns or columns[-1] != 'path' or len(set(columns)) != len(columns)
            or set(columns) - allowed or not {'id', 'end', 'path'} <= set(columns)
            or not ('base' in columns or 'start' in columns)
            or ('base' in columns and 'start' in columns)
            or (table_version >= 3 and 'containing_id' not in columns)):
        raise CoverageError('Unsupported module columns or custom module fields.')
    modules = {}
    for _ in range(count):
        values = [part.strip() for part in line().split(',', len(columns) - 1)]
        if len(values) != len(columns):
            raise CoverageError('Malformed module row.')
        row = dict(zip(columns, values))
        key = str(number(row['id'], 10))
        parent = str(number(row.get('containing_id', row['id']), 10))
        base, end = number(row.get('start', row.get('base'))), number(row['end'])
        if key in modules or not row['path'] or end < base:
            raise CoverageError('Duplicate module ID, empty module path, or invalid module range.')
        # Validate all scalar fields, even those not used in address mapping.
        for field in set(columns) - {'id', 'containing_id', 'path', 'base', 'start', 'end'}:
            number(row[field])
        modules[key] = Module(key, row['path'], base, end, parent)
    for module in modules.values():
        if module.parent not in modules or modules[module.parent].parent != module.parent:
            raise CoverageError('Invalid containing-module relationship.')
        if module.base < modules[module.parent].base:
            raise CoverageError('Segment precedes its containing module.')
    match = re.fullmatch(r'BB Table: (\d+) bbs', line())
    if not match or int(match[1]) > MAX_RECORDS:
        raise CoverageError('Invalid basic-block table count or record limit reached.')
    count = int(match[1])
    payload = data[position:]
    if payload.startswith(b'module id,'):
        raise CoverageError('Text-mode drcov is unsupported; collect the default binary BB table.')
    if len(payload) != count * 8:
        raise CoverageError('Truncated basic-block table or unexpected trailing data.')
    records, missing = [], 0
    for start, size, module_id in struct.iter_unpack('<IHH', payload):
        key = str(module_id)
        if module_id == 65535:
            missing += 1
            continue
        if key not in modules or not size:
            raise CoverageError('Unknown module ID or zero-length drcov block.')
        module = modules[key]
        parent = modules[module.parent]
        address = (module.base if version == 3 else parent.base) + start
        if not module.base <= address < address + size <= module.end:
            raise CoverageError('A drcov block exceeds its module segment.')
        records.append((parent.key, address - parent.base, size))
    roots = [module for module in modules.values() if module.key == module.parent]
    notes = (f'{missing:,} records from unknown/JIT module ID 65535 were excluded.',) if missing else ()
    return roots, records, notes


@dataclass(frozen=True)
class Block:
    start: int
    end: int
    instructions: tuple


@dataclass(frozen=True)
class Function:
    start: int
    name: str
    instructions: tuple
    blocks: tuple


class Index:
    """Sorted, deduplicated instruction RVAs with per-function ownership."""
    def __init__(self, name, base, digest, functions):
        self.name, self.base, self.digest = name, base, digest
        if len(functions) > MAX_FUNCTIONS:
            raise CoverageError('Function index limit reached.')
        instructions = {}
        for start, function_name, blocks in functions:
            for begin, end, items in blocks:
                if not 0 <= begin < end <= MAX_ADDRESS:
                    raise CoverageError('Invalid indexed block range.')
                for ea, size in items:
                    if not begin <= ea < ea + size <= end:
                        raise CoverageError('Instruction exceeds its indexed block.')
                    if ea in instructions and instructions[ea] != size:
                        raise CoverageError('Conflicting instruction sizes in the index.')
                    instructions[ea] = size
                    if len(instructions) > MAX_INSTRUCTIONS:
                        raise CoverageError('Instruction index limit reached.')
        self.addresses = tuple(sorted(instructions))
        self.ends = tuple(ea + instructions[ea] for ea in self.addresses)
        if any(a < b for a, b in zip(self.addresses[1:], self.ends[:-1])):
            raise CoverageError('Overlapping instructions are unsupported.')
        self.lookup = {ea: i for i, ea in enumerate(self.addresses)}
        result = []
        for start, name, blocks in functions:
            converted = tuple(Block(begin, end, tuple(self.lookup[ea] for ea, _ in items))
                              for begin, end, items in blocks if items)
            owned = tuple(sorted({i for block in converted for i in block.instructions}))
            if owned:
                result.append(Function(start, name, owned, converted))
        self.functions = tuple(sorted(result, key=lambda f: f.start))
        h = hashlib.sha256()
        for ea, end in zip(self.addresses, self.ends):
            h.update(struct.pack('<QQ', ea, end))
        self.geometry = h.hexdigest()

    def map_trace(self, trace, module_key, label=None):
        if module_key not in {module.key for module in trace.modules}:
            raise CoverageError('Select one module present in the trace.')
        hits, unique, mapped_records, selected = set(), set(), 0, 0
        for key, start, size in trace.records:
            if key != module_key:
                continue
            selected += 1
            unique.add((start, size))
        ranges = []
        for start, size in sorted(unique):
            if not size:
                i = self.lookup.get(start)
                if i is not None:
                    hits.add(i)
                    mapped_records += 1
                continue
            begin = bisect_left(self.addresses, start)
            end = bisect_right(self.ends, start + size)
            if begin >= end:
                continue
            mapped_records += 1
            if ranges and begin <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
            else:
                ranges.append((begin, end))
        for begin, end in ranges:
            hits.update(range(begin, end))
        if not selected:
            raise CoverageError('The selected module contains no coverage records.')
        module = next(m for m in trace.modules if m.key == module_key)
        return Run(label or Path(trace.source).name, frozenset(hits), trace.source,
                   trace.digest, module.path, trace.format, selected, len(unique),
                   len(unique) - mapped_records, trace.notes)


@dataclass(frozen=True)
class Run:
    label: str
    hits: frozenset
    source: str
    digest: str
    module: str
    format: str
    records: int
    unique: int
    unmapped: int
    notes: tuple = ()


def evaluate(expression, runs):
    if len(expression) > 256:
        raise CoverageError('Expression exceeds 256 characters.')
    tokens = re.findall(r'[A-Z]|[|&^()\-]', expression)
    if ''.join(tokens) != re.sub(r'\s+', '', expression) or len(tokens) > 128:
        raise CoverageError('Use run letters, parentheses, and | & ^ - only.')
    position = 0
    precedence = {'|': 1, '^': 2, '&': 3, '-': 3}
    def parse(minimum=1, depth=0):
        nonlocal position
        if depth > 16 or position >= len(tokens):
            raise CoverageError('Incomplete or excessively nested expression.')
        token = tokens[position]
        position += 1
        if token == '(':
            left = parse(1, depth + 1)
            if position >= len(tokens) or tokens[position] != ')':
                raise CoverageError('Unbalanced parentheses.')
            position += 1
        elif token in runs:
            left = runs[token].hits
        else:
            raise CoverageError(f'Unknown run or unexpected token: {token}')
        while position < len(tokens) and precedence.get(tokens[position], 0) >= minimum:
            op = tokens[position]
            position += 1
            right = parse(precedence[op] + 1, depth + 1)
            if op == '|': left = left | right
            elif op == '&': left = left & right
            elif op == '^': left = left ^ right
            else: left = left - right
        return left
    if not tokens:
        return frozenset()
    result = parse()
    if position != len(tokens):
        raise CoverageError('Unexpected token after expression.')
    return frozenset(result)


class Workspace:
    def __init__(self, index):
        self.index, self.runs, self.expression = index, {}, ''

    def add(self, run):
        for key, existing in self.runs.items():
            if (existing.digest, existing.module, existing.hits) == (run.digest, run.module, run.hits):
                return key, False
        if len(self.runs) >= MAX_RUNS:
            raise CoverageError('A workspace supports up to 26 runs.')
        key = next(key for key in string.ascii_uppercase if key not in self.runs)
        self.runs[key] = run
        self.expression = key
        return key, True

    def remove(self, key):
        self.runs.pop(key, None)
        self.expression = next(iter(self.runs), '')

    def selected(self):
        return evaluate(self.expression, self.runs)

    def save(self, path):
        if not self.index.digest:
            raise CoverageError('Saving requires an input-file SHA-256 identity.')
        data = {'schema': 1, 'binary': self.index.digest, 'geometry': self.index.geometry,
                'expression': self.expression, 'runs': []}
        for key, run in self.runs.items():
            values = dict(vars(run))
            values['hits'] = [hex(self.index.addresses[i]) for i in sorted(run.hits)]
            data['runs'].append(dict(alias=key, **values))
        write_json(path, data)

    def load(self, path):
        try:
            data = json.loads(read_limited(path))
            if (data['schema'] != 1 or not self.index.digest or data['binary'] != self.index.digest
                    or data['geometry'] != self.index.geometry):
                raise CoverageError('Workspace belongs to a different binary or instruction layout.')
            records = data['runs']
            if not isinstance(records, list) or len(records) > MAX_RUNS:
                raise CoverageError('Invalid workspace run count.')
            runs = {}
            for entry in records:
                key = entry['alias']
                if key not in string.ascii_uppercase or len(key) != 1 or key in runs:
                    raise CoverageError('Invalid or duplicate run alias.')
                values = {field: entry[field] for field in Run.__dataclass_fields__}
                for field in ('label', 'source', 'digest', 'module', 'format'):
                    if not isinstance(values[field], str) or len(values[field]) > 32768:
                        raise CoverageError('Invalid workspace text field.')
                for field in ('records', 'unique', 'unmapped'):
                    if type(values[field]) is not int or not 0 <= values[field] <= MAX_RECORDS:
                        raise CoverageError('Invalid workspace coverage count.')
                if not values['records'] >= values['unique'] >= values['unmapped']:
                    raise CoverageError('Inconsistent workspace coverage counts.')
                if not isinstance(values['hits'], list) or len(values['hits']) > MAX_INSTRUCTIONS:
                    raise CoverageError('Invalid workspace hit count.')
                values['hits'] = frozenset(self.index.lookup[number(ea)] for ea in values['hits'])
                if not isinstance(values['notes'], list) or len(values['notes']) > 100:
                    raise CoverageError('Invalid workspace notes.')
                if any(not isinstance(note, str) or len(note) > 32768 for note in values['notes']):
                    raise CoverageError('Invalid workspace note.')
                values['notes'] = tuple(values['notes'])
                runs[key] = Run(**values)
            expression = data['expression']
            evaluate(expression, runs)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
            if isinstance(error, CoverageError): raise
            raise CoverageError('Malformed workspace: ' + str(error)) from None
        self.runs, self.expression = runs, expression

    def export(self, path):
        hits = self.selected()
        write_json(path, {'schema': 1, 'binary': self.index.digest, 'expression': self.expression,
                          'instruction_rvas': [hex(self.index.addresses[i]) for i in sorted(hits)],
                          'functions': [dict(rva=hex(f.start), name=f.name,
                                             observed=sum(i in hits for i in f.instructions),
                                             total=len(f.instructions)) for f in self.index.functions]})


def write_json(path, data):
    """Atomic replacement, including on Windows, with no half-written JSON."""
    import os
    import tempfile
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', delete=False) as stream:
            temporary = stream.name
            json.dump(data, stream, ensure_ascii=True, separators=(',', ':'))
            stream.write('\n')
            if stream.tell() > MAX_FILE:
                raise CoverageError('JSON output exceeds the 128 MiB session/input limit. Export fewer runs.')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary): os.unlink(temporary)
