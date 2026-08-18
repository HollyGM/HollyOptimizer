# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# Em arquivos .spec do PyInstaller não existe __file__, então usamos o
# diretório de trabalho (build.sh roda no raiz do projeto) para importar a
# versão central (core/version.py) e nunca divergir do autoteste.
sys.path.insert(0, os.getcwd())
from core.version import (  # noqa: E402
    APP_NAME,
    BUNDLE_IDENTIFIER,
    BUILD,
    VERSION,
)

_icon = 'HollyOptimizer.icns' if os.path.exists('HollyOptimizer.icns') else None
_target_arch = os.environ.get('HOLLYOPTIMIZER_TARGET_ARCH') or None
_codesign_identity = os.environ.get('CODESIGN_IDENTITY') or None

_datas = [('gui', 'gui'), ('hollyoptimizer_app_icon.png', '.')]
_ai_helper = os.path.join('tools', 'ai_summary', 'hollyoptimizer-ai')
if os.path.isfile(_ai_helper):
    # Optional on-device Apple Intelligence helper (Foundation Models). Built
    # separately by build.sh only on Apple Silicon; harmless to omit — the
    # app already falls back to a deterministic summary when it is missing.
    _datas.append((_ai_helper, 'ai'))

a = Analysis(
    ['hollyoptimizer_gui.py'],
    pathex=[],
    binaries=[],
    datas=_datas,
    hiddenimports=['webview', 'objc', 'Foundation', 'AppKit'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=_target_arch,
    codesign_identity=_codesign_identity,
    entitlements_file='entitlements.plist',
    icon=[_icon] if _icon else None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=APP_NAME,
)
app = BUNDLE(
    coll,
    name=f'{APP_NAME}.app',
    icon=_icon,
    bundle_identifier=BUNDLE_IDENTIFIER,
    info_plist={
        'CFBundleDisplayName': APP_NAME,
        'CFBundleShortVersionString': VERSION,
        'CFBundleVersion': str(BUILD),
        'LSMinimumSystemVersion': '12.0',
        'NSHighResolutionCapable': True,
        'NSAppleEventsUsageDescription': f'{APP_NAME} usa automação do Finder para esvaziar a Lixeira e do System Events para listar e remover itens de início de sessão. A autenticação administrativa é solicitada apenas em operações de sistema explícitas.',
    },
)
