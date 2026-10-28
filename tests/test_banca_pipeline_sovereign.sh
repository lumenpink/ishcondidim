#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW_FILE="$REPO_ROOT/.forgejo/workflows/ci.yml"
SPEC_FILE="$REPO_ROOT/docs/specs/3_updater_opendesktop_xdg.md"

FAILED=0

echo "==> [TEST] Validando conformidade da esteira soberana Banca (#3)..."

# 1. Spec presente
if [ ! -f "$SPEC_FILE" ]; then
    echo "FALHA: $SPEC_FILE não encontrado."
    FAILED=1
else
    echo "OK: $SPEC_FILE presente."
fi

# 2. Workflow presente
if [ ! -f "$WORKFLOW_FILE" ]; then
    echo "FALHA: $WORKFLOW_FILE não encontrado."
    exit 1
fi

# 3. Validar declaração do job deploy-banca
if ! grep -q "deploy-banca:" "$WORKFLOW_FILE"; then
    echo "FALHA: Job 'deploy-banca:' ausente no workflow."
    FAILED=1
else
    echo "OK: Job 'deploy-banca:' declarado."
fi

# 4. Validar container soberano gost-ci-cross
if ! grep -q "gambi.2lp.in/lumen/gost-ci-cross" "$WORKFLOW_FILE"; then
    echo "FALHA: Container soberano 'gost-ci-cross' não configurado no deploy-banca."
    FAILED=1
else
    echo "OK: Container soberano 'gost-ci-cross' presente."
fi

# 5. Validar upload R2 e rotação na Banca
if ! grep -q "rotate-downloads.py" "$WORKFLOW_FILE"; then
    echo "FALHA: Script 'rotate-downloads.py' da Banca não invocado."
    FAILED=1
else
    echo "OK: Rotação via 'rotate-downloads.py' configurada."
fi

# 6. Validar ausência de binários pesados no Codeberg
if grep -q "action-gh-release" "$WORKFLOW_FILE"; then
    echo "FALHA: action-gh-release ainda presente no workflow (deve ser expurgado)."
    FAILED=1
else
    echo "OK: action-gh-release expurgado com sucesso."
fi

if [ $FAILED -ne 0 ]; then
    echo "==> [TEST] STATUS: RED (Asserções falharam conforme esperado)"
    exit 1
fi

echo "==> [TEST] STATUS: GREEN (Esteira soberana conforme)"
