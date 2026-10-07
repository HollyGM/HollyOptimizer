import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.macos_target import minimum_macos_version


def macho(version, *, sdk=(26, 4, 0), legacy=False, cpu=0x100000C, platform=1):
    def packed(parts):
        major, minor, patch = parts
        return (major << 16) | (minor << 8) | patch

    if legacy:
        command = struct.pack('<IIII', 0x24, 16, packed(version), packed(sdk))
    else:
        command = struct.pack('<IIIIII', 0x32, 24, platform, packed(version), packed(sdk), 0)
    header = struct.pack('<IIIIIIII', 0xFEEDFACF, cpu, 0, 6, 1, len(command), 0, 0)
    return header + command


def universal(*slices):
    offset = 8 + 20 * len(slices)
    architectures = []
    contents = []
    for cpu, data in slices:
        architectures.append(struct.pack('>IIIII', cpu, 0, offset, len(data), 0))
        contents.append(data)
        offset += len(data)
    return struct.pack('>II', 0xCAFEBABE, len(slices)) + b''.join(architectures + contents)


class MacOSDeploymentTargetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def binary(self, name, data, kind='BINARY'):
        path = self.root / name
        path.write_bytes(data)
        return name, str(path), kind

    def test_python_runtime_can_raise_the_source_code_minimum(self):
        python = self.binary('Python', macho((26, 0, 0)))
        extension = self.binary('_objc.so', macho((10, 13, 0)), 'EXTENSION')
        self.assertEqual(minimum_macos_version([python, extension]), '26.0')

    def test_new_sdk_does_not_raise_the_deployment_target(self):
        binary = self.binary('library.dylib', macho((11, 0, 0), sdk=(26, 4, 0)))
        self.assertEqual(minimum_macos_version([binary]), '12.0')

    def test_legacy_load_command_and_patch_version_are_preserved(self):
        binary = self.binary('library.dylib', macho((13, 2, 1), legacy=True))
        self.assertEqual(minimum_macos_version([binary]), '13.2.1')

    def test_highest_requirement_across_universal_slices_is_used(self):
        binary = self.binary('universal.dylib', universal(
            (0x1000007, macho((13, 0, 0), cpu=0x1000007)),
            (0x100000C, macho((15, 1, 0))),
        ))
        self.assertEqual(minimum_macos_version([binary]), '15.1')

    def test_optional_data_and_symlink_entries_do_not_raise_the_minimum(self):
        helper = self.binary('hollyoptimizer-ai', macho((26, 0, 0)), 'DATA')
        self.assertEqual(minimum_macos_version([
            helper, ('Python', 'missing-symlink-target', 'SYMLINK'),
        ]), '12.0')

    def test_non_macho_files_and_other_platform_targets_are_ignored(self):
        text = self.binary('readme', b'Not a native binary')
        ios = self.binary('ios.dylib', macho((26, 0, 0), platform=2))
        self.assertEqual(minimum_macos_version([text, ios]), '12.0')

    def test_malformed_native_binary_blocks_understated_metadata(self):
        truncated = self.binary('broken.dylib', b'\xcf\xfa\xed\xfe')
        with self.assertRaises(ValueError):
            minimum_macos_version([truncated])


class BuildScriptTests(unittest.TestCase):
    def test_build_resolves_project_root_before_running_python(self):
        project = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory, 'python-probe')
            probe.write_text('#!/bin/sh\npwd\nexit 1\n')
            probe.chmod(0o755)
            result = subprocess.run(
                ['/bin/bash', str(project / 'build.sh')],
                cwd=directory,
                env={**os.environ, 'PYTHON_BIN': str(probe), 'HOLLYOPTIMIZER_RELEASE': '0'},
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines()[0], str(project))


if __name__ == '__main__':
    unittest.main()
