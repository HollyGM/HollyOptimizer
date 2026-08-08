"""
Auditoria de arquitetura para Macs com Apple Silicon (M1…M5).

Somente leitura: este módulo nunca move, altera ou remove arquivos. Ele responde
a uma pergunta que nenhuma outra aba responde — *quais aplicativos ainda são
Intel* e portanto rodam traduzidos pelo Rosetta 2, gastando mais RAM e bateria
do que a versão nativa do mesmo app.

A classificação lê o cabeçalho Mach-O do executável principal de cada bundle
diretamente em Python. Chamar `lipo`/`file` uma vez por aplicativo custaria um
subprocesso por app (centenas de forks); ler 4 KB do cabeçalho custa um open()
e resolve o mesmo problema.
"""

import os
import platform
import struct
import threading

from .diagnostics import record_issue
from .utils import (
    format_size,
    is_safe_scan_candidate,
    read_plist,
    run_command,
)

# Mach-O magics. Os arquivos "fat" (universal) são sempre big-endian.
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_X86 = 7
CPU_TYPE_ARM = 12
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64

_CPU_NAMES = {
    CPU_TYPE_ARM64: "arm64",
    CPU_TYPE_X86_64: "x86_64",
    CPU_TYPE_ARM: "arm",
    CPU_TYPE_X86: "i386",
}

# Um bundle universal com dezenas de fatias é patológico; o limite evita ler um
# arquivo corrompido como se fosse um cabeçalho gigante.
_MAX_FAT_ARCHS = 32

APP_ROOTS = ("/Applications", "~/Applications", "/Applications/Utilities")

_SCAN_LOCK = threading.RLock()


def _read_architectures(binary_path: str) -> list[str]:
    """Lista as arquiteturas presentes em um executável Mach-O."""
    try:
        with open(binary_path, "rb") as handle:
            header = handle.read(8)
            if len(header) < 8:
                return []

            magic = struct.unpack(">I", header[:4])[0]

            if magic in (FAT_MAGIC, FAT_MAGIC_64):
                count = struct.unpack(">I", header[4:8])[0]
                if not 0 < count <= _MAX_FAT_ARCHS:
                    return []
                entry_size = 32 if magic == FAT_MAGIC_64 else 20
                table = handle.read(entry_size * count)
                if len(table) < entry_size * count:
                    return []
                architectures = []
                for index in range(count):
                    offset = index * entry_size
                    cputype = struct.unpack(">i", table[offset : offset + 4])[0]
                    name = _CPU_NAMES.get(cputype)
                    if name and name not in architectures:
                        architectures.append(name)
                return architectures

            # Mach-O simples: o cputype é o segundo campo, na endianness do arquivo.
            for endian, thin_magics in ((">I", (MH_MAGIC, MH_MAGIC_64)), ("<I", (MH_MAGIC, MH_MAGIC_64))):
                value = struct.unpack(endian, header[:4])[0]
                if value in thin_magics:
                    cputype = struct.unpack(endian.replace("I", "i"), header[4:8])[0]
                    name = _CPU_NAMES.get(cputype)
                    return [name] if name else []
            return []
    except (OSError, struct.error) as exc:
        record_issue("silicon", exc, binary_path)
        return []


def _bundle_executable(app_path: str) -> tuple[str, bool]:
    """
    Resolve o executável principal do bundle.

    Retorna (caminho, é_web_app). Atalhos de web app criados pelo Chrome ou pelo
    Safari ("Adicionar ao Dock") são bundles legítimos sem `Contents/MacOS`:
    não têm binário nenhum, então não são "arquitetura desconhecida" — são
    páginas web e não têm o que traduzir.
    """
    macos_dir = os.path.join(app_path, "Contents", "MacOS")
    if not os.path.isdir(macos_dir):
        return "", True

    info = read_plist(os.path.join(app_path, "Contents", "Info.plist"))
    name = info.get("CFBundleExecutable")
    if isinstance(name, str) and name and "/" not in name:
        candidate = os.path.join(macos_dir, name)
        if os.path.isfile(candidate):
            return candidate, False

    # Alguns bundles antigos omitem CFBundleExecutable; cai para o único
    # arquivo em Contents/MacOS quando não há ambiguidade.
    try:
        entries = [
            os.path.join(macos_dir, entry)
            for entry in os.listdir(macos_dir)
            if os.path.isfile(os.path.join(macos_dir, entry))
        ]
    except OSError:
        return "", False
    if len(entries) == 1:
        return entries[0], False
    return "", len(entries) == 0


def _is_script_launcher(binary_path: str) -> bool:
    """Um `#!` no início marca um lançador interpretado, não um Mach-O."""
    try:
        with open(binary_path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


def classify_architectures(
    architectures: list[str], *, web_app: bool = False, script: bool = False
) -> tuple[str, str]:
    """Traduz a lista de fatias em (categoria, rótulo legível)."""
    has_arm = "arm64" in architectures
    has_intel = "x86_64" in architectures or "i386" in architectures

    if has_arm and has_intel:
        return "universal", "Universal (arm64 + Intel)"
    if has_arm:
        return "native", "Nativo Apple Silicon"
    if has_intel:
        return "intel", "Somente Intel — roda via Rosetta 2"
    if web_app:
        return "webapp", "Atalho de web app — sem binário nativo"
    if script:
        return "script", "Lançador em script — arquitetura definida pelo interpretador"
    return "unknown", "Arquitetura não identificada"


def _iter_app_bundles() -> list[str]:
    """Enumera bundles .app de primeiro nível nas raízes conhecidas."""
    seen = set()
    bundles = []
    for root in APP_ROOTS:
        expanded = os.path.expanduser(root)
        if not os.path.isdir(expanded):
            continue
        try:
            names = sorted(os.listdir(expanded))
        except OSError as exc:
            record_issue("silicon", exc, expanded)
            continue
        for name in names:
            if not name.endswith(".app"):
                continue
            app_path = os.path.join(expanded, name)
            resolved = os.path.realpath(app_path)
            if resolved in seen or not os.path.isdir(app_path):
                continue
            # Um symlink em /Applications apontando para outro volume não é um
            # app instalado ali; a mesma porta de segurança das outras varreduras
            # se aplica.
            if not is_safe_scan_candidate(app_path, allow_package_self=True):
                continue
            seen.add(resolved)
            bundles.append(app_path)
    return bundles


def get_hardware_profile() -> dict:
    """Perfil do Mac atual: chip, núcleos P/E, memória e estado do Rosetta."""
    def _sysctl(key: str) -> str:
        code, stdout, _ = run_command(["/usr/sbin/sysctl", "-n", key], timeout=10)
        return stdout.strip() if code == 0 else ""

    def _sysctl_int(key: str) -> int:
        try:
            return int(_sysctl(key))
        except ValueError:
            return 0

    machine = platform.machine()
    apple_silicon = machine == "arm64"
    performance_cores = _sysctl_int("hw.perflevel0.logicalcpu")
    efficiency_cores = _sysctl_int("hw.perflevel1.logicalcpu")
    total_cores = _sysctl_int("hw.ncpu")
    memory_bytes = _sysctl_int("hw.memsize")

    if performance_cores and efficiency_cores:
        core_summary = (
            f"{total_cores} núcleos ({performance_cores} de performance + "
            f"{efficiency_cores} de eficiência)"
        )
    else:
        core_summary = f"{total_cores} núcleos" if total_cores else "Indisponível"

    rosetta_installed = os.path.isdir("/Library/Apple/usr/libexec/oah")

    return {
        "chip": _sysctl("machdep.cpu.brand_string") or "Indisponível",
        "architecture": machine,
        "apple_silicon": apple_silicon,
        "total_cores": total_cores,
        "performance_cores": performance_cores,
        "efficiency_cores": efficiency_cores,
        "core_summary": core_summary,
        "memory_bytes": memory_bytes,
        "memory_human": format_size(memory_bytes),
        "model_identifier": _sysctl("hw.model") or "Indisponível",
        "macos_version": platform.mac_ver()[0] or "Indisponível",
        "rosetta_installed": rosetta_installed,
        "rosetta_label": (
            "Rosetta 2 instalado — apps Intel conseguem abrir, traduzidos"
            if rosetta_installed
            else "Rosetta 2 não instalado — apps somente Intel não abrem neste Mac"
        ),
    }


def scan_app_architectures() -> dict:
    """
    Classifica cada aplicativo instalado como nativo, universal ou Intel.

    Nada é removido nem modificado. Aplicativos Intel são apenas sinalizados:
    a correção correta é procurar a versão Apple Silicon no site do fabricante,
    e não apagar o app.
    """
    with _SCAN_LOCK:
        profile = get_hardware_profile()
        apps = []
        totals = {
            "native": 0, "universal": 0, "intel": 0,
            "webapp": 0, "script": 0, "unknown": 0,
        }
        intel_bytes = 0

        for app_path in _iter_app_bundles():
            executable, web_app = _bundle_executable(app_path)
            architectures = _read_architectures(executable) if executable else []
            script = bool(executable) and not architectures and _is_script_launcher(executable)
            category, label = classify_architectures(
                architectures, web_app=web_app, script=script
            )
            totals[category] = totals.get(category, 0) + 1

            size_bytes = 0
            if category == "intel":
                try:
                    size_bytes = os.path.getsize(executable) if executable else 0
                except OSError:
                    size_bytes = 0
                intel_bytes += size_bytes

            apps.append(
                {
                    "name": os.path.basename(app_path).removesuffix(".app"),
                    "path": app_path,
                    "architectures": architectures,
                    "architectures_human": ", ".join(architectures) or "desconhecida",
                    "category": category,
                    "category_label": label,
                    "binary_bytes": size_bytes,
                    "binary_human": format_size(size_bytes) if size_bytes else "—",
                }
            )

        # Intel primeiro: é a única categoria sobre a qual há algo a fazer.
        order = {
            "intel": 0, "unknown": 1, "script": 2,
            "universal": 3, "native": 4, "webapp": 5,
        }
        apps.sort(key=lambda item: (order.get(item["category"], 9), item["name"].casefold()))

        if not profile["apple_silicon"]:
            summary = (
                "Este Mac é Intel: a auditoria de arquitetura é informativa e "
                "nenhum aplicativo roda traduzido."
            )
        elif totals["intel"]:
            summary = (
                f"{totals['intel']} aplicativo(s) somente Intel rodam traduzidos pelo "
                f"Rosetta 2 neste {profile['chip']}. Versões nativas consomem menos "
                "RAM e bateria — procure a atualização Apple Silicon de cada um."
            )
        else:
            summary = (
                f"Nenhum aplicativo somente Intel instalado: tudo roda nativo neste "
                f"{profile['chip']}."
            )

        return {
            "profile": profile,
            "summary": summary,
            "totals": totals,
            "intel_binary_bytes": intel_bytes,
            "intel_binary_human": format_size(intel_bytes),
            "scanned": len(apps),
            "apps": apps,
            "read_only": True,
        }
