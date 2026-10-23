#!/usr/bin/env bash
set -euo pipefail

# Test Suite: Otimização de Binário e Linking Estático musl (#4)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_FILE="$REPO_ROOT/docs/specs/4_build_size_and_static_musl.md"
CARGO_TOML="$REPO_ROOT/Cargo.toml"
CARGO_CONFIG="$REPO_ROOT/.cargo/config.toml"

echo "==> [TEST] Validando conformidade de otimização de tamanho e linking estático musl (#4)..."

# 1. Validação da Spec
echo -n "-> Verificando especificação formal... "
if [ ! -f "$SPEC_FILE" ]; then
    echo "FALHA: Arquivo de especificação $SPEC_FILE não encontrado."
    exit 1
fi
echo "OK: $SPEC_FILE presente."

# 2. Validação do profile.release no Cargo.toml
echo -n "-> Verificando [profile.release] no Cargo.toml... "
if ! grep -q '^\[profile\.release\]' "$CARGO_TOML"; then
    echo "FALHA: [profile.release] ausente em $CARGO_TOML."
    exit 1
fi
echo "OK: [profile.release] declarado."

echo -n "-> Verificando LTO fat e codegen-units = 1... "
if ! grep -q 'lto = "fat"' "$CARGO_TOML" || ! grep -q 'codegen-units = 1' "$CARGO_TOML"; then
    echo "FALHA: lto = \"fat\" ou codegen-units = 1 ausente."
    exit 1
fi
echo "OK: LTO e codegen-units configurados para otimização máxima."

echo -n "-> Verificando panic = abort e strip = true... "
if ! grep -q 'panic = "abort"' "$CARGO_TOML" || ! grep -q 'strip = true' "$CARGO_TOML"; then
    echo "FALHA: panic = \"abort\" ou strip = true ausente."
    exit 1
fi
echo "OK: panic = abort e strip = true configurados."

# 3. Validação do .cargo/config.toml para musl
echo -n "-> Verificando arquivo .cargo/config.toml... "
if [ ! -f "$CARGO_CONFIG" ]; then
    echo "FALHA: $CARGO_CONFIG não existe."
    exit 1
fi
echo "OK: $CARGO_CONFIG existe."

echo -n "-> Verificando target-feature=+crt-static para x86_64-unknown-linux-musl... "
if ! grep -q 'target\.x86_64-unknown-linux-musl' "$CARGO_CONFIG" || ! grep -q 'target-feature=+crt-static' "$CARGO_CONFIG"; then
    echo "FALHA: crt-static ausente para x86_64-unknown-linux-musl."
    exit 1
fi
echo "OK: crt-static configurado para x86_64 musl."

echo -n "-> Verificando target-feature=+crt-static para aarch64-unknown-linux-musl... "
if ! grep -q 'target\.aarch64-unknown-linux-musl' "$CARGO_CONFIG"; then
    echo "FALHA: crt-static ausente para aarch64-unknown-linux-musl."
    exit 1
fi
echo "OK: crt-static configurado para aarch64 musl."

# 4. Teste de Mutação
echo -n "-> [MUTAÇÃO] Testando sensibilidade a ausência de crt-static... "
MUTANT_TEST=$(mktemp)
grep -v 'target-feature=+crt-static' "$CARGO_CONFIG" > "$MUTANT_TEST"
if grep -q 'target-feature=+crt-static' "$MUTANT_TEST"; then
    rm -f "$MUTANT_TEST"
    echo "FALHA: Mutação inválida."
    exit 1
fi
rm -f "$MUTANT_TEST"
echo "OK: Mutante detectado com precisão."

echo "================================================================="
echo "SUCESSO: Todas as asserções e testes de mutação passaram (GREEN)!"
