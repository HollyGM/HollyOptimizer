#!/bin/bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
RELEASE_MODE="${HOLLYOPTIMIZER_RELEASE:-0}"

HOST_ARCH="$(/usr/bin/uname -m)"

if [ "$RELEASE_MODE" = "1" ]; then
    : "${CODESIGN_IDENTITY:?CODESIGN_IDENTITY é obrigatório em HOLLYOPTIMIZER_RELEASE=1}"
    : "${NOTARY_PROFILE:?NOTARY_PROFILE é obrigatório em HOLLYOPTIMIZER_RELEASE=1}"
    # Padrão = arquitetura nativa do host. Em um Mac Apple Silicon, universal2
    # dobra o tamanho do bundle e obriga toda dependência nativa a oferecer a
    # fatia x86_64 — custo real por uma fatia Intel que nunca será executada.
    # Para distribuir também a Macs Intel, defina HOLLYOPTIMIZER_TARGET_ARCH=universal2
    # explicitamente.
    export HOLLYOPTIMIZER_TARGET_ARCH="${HOLLYOPTIMIZER_TARGET_ARCH:-$HOST_ARCH}"
fi

TARGET_ARCH="${HOLLYOPTIMIZER_TARGET_ARCH:-$HOST_ARCH}"



"$PYTHON_BIN" -c "import PyInstaller, webview, objc, Foundation, AppKit" || {
    echo "❌ Dependências ausentes para $PYTHON_BIN. Instale requirements.txt nesse ambiente."
    exit 1
}

echo "=========================================="
echo "Iniciando compilação do HollyOptimizer"
echo "=========================================="

# ── Versionamento ──────────────────────────────────────────────────────────
# Builds are reproducible and never rewrite tracked source files. Version and
# build are changed intentionally in the single source core/version.py.
VERSION_INFO="$("$PYTHON_BIN" -c 'from core.version import VERSION_STRING; print(VERSION_STRING)')"
echo "📈 Versão: $VERSION_INFO"

echo "🧹 Limpando artefatos de compilações anteriores..."
rm -rf build dist

if [ ! -f "HollyOptimizer.spec" ]; then
    echo "❌ HollyOptimizer.spec não encontrado. Abortando."
    exit 1
fi

if [ ! -f "HollyOptimizer.icns" ]; then
    echo "⚠️  HollyOptimizer.icns não encontrado — compile sem ícone ou adicione o arquivo."
fi

echo "📦 Executando PyInstaller com HollyOptimizer.spec..."
"$PYTHON_BIN" -m PyInstaller --clean --noconfirm HollyOptimizer.spec

APP_PATH="dist/HollyOptimizer.app"

echo "🧪 Executando autoteste dentro do bundle..."
"$APP_PATH/Contents/MacOS/HollyOptimizer" --self-test

ARCHS="$(/usr/bin/lipo -archs "$APP_PATH/Contents/MacOS/HollyOptimizer")"
echo "🏗️  Arquitetura gerada: $ARCHS (alvo: $TARGET_ARCH)"

# O binário precisa conter exatamente o que foi pedido: um alvo universal2 que
# saiu apenas arm64 seria distribuído quebrado em Macs Intel, e um alvo nativo
# que saiu Intel rodaria traduzido no próprio Mac que o compilou.
if [ "$TARGET_ARCH" = "universal2" ]; then
    if [[ "$ARCHS" != *"arm64"* || "$ARCHS" != *"x86_64"* ]]; then
        echo "❌ Alvo universal2 pedido, mas o binário saiu como: $ARCHS"
        [ "$RELEASE_MODE" = "1" ] && exit 1
    fi
elif [[ "$ARCHS" != *"$TARGET_ARCH"* ]]; then
    echo "❌ Alvo $TARGET_ARCH pedido, mas o binário saiu como: $ARCHS"
    [ "$RELEASE_MODE" = "1" ] && exit 1
elif [ "$TARGET_ARCH" = "arm64" ]; then
    echo "✓ Build nativo Apple Silicon — sem tradução por Rosetta 2."
fi

if [ -n "${CODESIGN_IDENTITY:-}" ]; then
    echo "🔐 Aplicando assinatura Developer ID e hardened runtime..."
    # PyInstaller signs collected nested binaries with CODESIGN_IDENTITY.
    # Sign only the outer bundle here; --deep is reserved for verification.
    codesign --force --options runtime --timestamp \
        --entitlements entitlements.plist \
        --sign "$CODESIGN_IDENTITY" "$APP_PATH"
    codesign --verify --deep --strict --verbose=2 "$APP_PATH"

    if [ -n "${NOTARY_PROFILE:-}" ]; then
        NOTARY_ZIP="dist/HollyOptimizer-notarization.zip"
        echo "📨 Enviando bundle para notarização..."
        ditto -c -k --keepParent "$APP_PATH" "$NOTARY_ZIP"
        xcrun notarytool submit "$NOTARY_ZIP" \
            --keychain-profile "$NOTARY_PROFILE" --wait
        xcrun stapler staple "$APP_PATH"
        rm -f "$NOTARY_ZIP"
        spctl --assess --type execute --verbose=4 "$APP_PATH"
    else
        echo "⚠️  NOTARY_PROFILE não definido; assinatura aplicada sem notarização."
    fi
else
    if [ "$RELEASE_MODE" = "1" ]; then
        echo "❌ Release sem assinatura foi bloqueada."
        exit 1
    fi
    echo "⚠️  CODESIGN_IDENTITY não definido; bundle permanece com assinatura ad-hoc para desenvolvimento."
fi

echo ""
echo "=========================================="
echo "✓ COMPILAÇÃO CONCLUÍDA COM SUCESSO! 🎉"
echo "=========================================="
echo "O aplicativo autônomo foi gerado em:"
echo "📂 $APP_PATH"
echo "=========================================="
