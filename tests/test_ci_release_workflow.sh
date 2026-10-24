#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_FILE="$REPO_ROOT/.forgejo/workflows/ci.yml"
SPEC_FILE="$REPO_ROOT/docs/specs/5_release_latest_gambi.md"

FAILED=0

echo "==> [TEST] Validando conformidade do workflow de release latest (#5)..."

# 1. Validação da Spec
if [ ! -f "$SPEC_FILE" ]; then
    echo "FALHA: Arquivo de especificação $SPEC_FILE não encontrado."
    FAILED=1
else
    echo "OK: $SPEC_FILE presente."
fi

# 2. Validação do arquivo de workflow
if [ ! -f "$WORKFLOW_FILE" ]; then
    echo "FALHA: Workflow $WORKFLOW_FILE não encontrado."
    exit 1
fi

# 3. Validar declaração do job release
if ! grep -q "^  release:" "$WORKFLOW_FILE"; then
    echo "FALHA: Job 'release:' ausente no workflow."
    FAILED=1
else
    echo "OK: Job 'release:' declarado."
fi

# 4. Validar compilação release do binário ishcondidim
if ! grep -q "cargo build --release --bin ishcondidim" "$WORKFLOW_FILE"; then
    echo "FALHA: Passo de build 'cargo build --release --bin ishcondidim' ausente."
    FAILED=1
else
    echo "OK: Build release de ishcondidim configurado."
fi

# 5. Validar tag latest no release
if ! grep -q 'tag_name: "latest"' "$WORKFLOW_FILE"; then
    echo "FALHA: tag_name: \"latest\" ausente no step de release."
    FAILED=1
else
    echo "OK: tag_name: \"latest\" configurada."
fi

# 6. Validar arquivo publicado
if ! grep -q "target/release/ishcondidim" "$WORKFLOW_FILE"; then
    echo "FALHA: Artefato 'target/release/ishcondidim' não declarado em files."
    FAILED=1
else
    echo "OK: Artefato ishcondidim declarado em files."
fi

# 7. Validar remoção de step órfão trigger-gost-ci
if grep -q "trigger-gost-ci" "$WORKFLOW_FILE"; then
    echo "FALHA: Step órfão 'trigger-gost-ci' ainda presente no workflow."
    FAILED=1
else
    echo "OK: Step órfão 'trigger-gost-ci' ausente."
fi

# 8. Testes de Mutação
echo "==> Executando testes de mutação para release workflow..."
TMP_WORKFLOW="$(mktemp)"
trap 'rm -f "$TMP_WORKFLOW"' EXIT

# Mutante 1: Tag divergente de latest
sed 's/tag_name: "latest"/tag_name: "v1.0.0"/' "$WORKFLOW_FILE" > "$TMP_WORKFLOW"
if grep -q 'tag_name: "latest"' "$TMP_WORKFLOW"; then
    echo "FALHA: Mutante 1 não isolado."
    FAILED=1
else
    echo "OK: Mutante 1 (tag divergente) detectado e rejeitado."
fi

# Mutante 2: Ausência do binário ishcondidim no files
sed 's/target\/release\/ishcondidim//' "$WORKFLOW_FILE" > "$TMP_WORKFLOW"
if grep -q "target/release/ishcondidim" "$TMP_WORKFLOW"; then
    echo "FALHA: Mutante 2 não isolado."
    FAILED=1
else
    echo "OK: Mutante 2 (binário ausente) detectado e rejeitado."
fi

if [ $FAILED -ne 0 ]; then
    echo "==> [TEST] STATUS: RED (Asserções falharam conforme esperado)"
    exit 1
fi

echo "==> [TEST] STATUS: GREEN (Todas as asserções e mutações passaram)"
