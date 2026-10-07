"""Compute the macOS requirement of mandatory PyInstaller binaries."""

from pathlib import Path
import struct

from macholib.MachO import MachO
from macholib.mach_o import LC_BUILD_VERSION, LC_VERSION_MIN_MACOSX


_MACHO_MAGICS = {
    b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
    b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe',
    b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf',
    b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca',
}
_PLATFORM_MACOS = 1


def _decode_version(value: int) -> tuple[int, int, int]:
    return value >> 16, (value >> 8) & 0xFF, value & 0xFF


def minimum_macos_version(binaries, *, code_minimum: str = '12.0') -> str:
    """Return the highest deployment target, ignoring SDK versions and data.

    ``binaries`` is the Analysis.binaries TOC of (destination, source, type).
    All slices of universal binaries contribute to the result. Optional helper
    executables belong in Analysis.datas and must not be passed to this function.
    A malformed Mach-O fails the build instead of silently understating its
    requirement. PyInstaller already depends on macholib on macOS.
    """
    parts = tuple(int(part) for part in code_minimum.split('.'))
    if not 1 <= len(parts) <= 3 or any(part < 0 for part in parts):
        raise ValueError(f'Invalid macOS version: {code_minimum}')
    minimum = parts + (0,) * (3 - len(parts))
    seen = set()

    for _, source, kind in binaries:
        if kind not in ('BINARY', 'EXTENSION'):
            continue
        path = Path(source)
        if path in seen:
            continue
        seen.add(path)
        with path.open('rb') as handle:
            if handle.read(4) not in _MACHO_MAGICS:
                continue
        try:
            binary = MachO(str(path))
            for header in binary.headers:
                for command, data, _ in header.commands:
                    if command.cmd == LC_BUILD_VERSION and data.platform == _PLATFORM_MACOS:
                        minimum = max(minimum, _decode_version(data.minos))
                    elif command.cmd == LC_VERSION_MIN_MACOSX:
                        minimum = max(minimum, _decode_version(data.version))
        except (ValueError, OSError, EOFError, struct.error) as exc:
            raise ValueError(f'Cannot read macOS deployment target: {path}') from exc

    major, minor, patch = minimum
    return f'{major}.{minor}.{patch}' if patch else f'{major}.{minor}'
