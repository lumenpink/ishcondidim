# Especificação Técnica: Ajuste de Publicação de Release Soberana no Forgejo

**Ticket Associado:** #8  
**Branch:** `fix/8-forgejo-release-prune`  
**Norma:** GOST 1.4.0

## 1. Objetivo
Evitar erro 404 retornado pela API do Forgejo quando `action-gh-release` tenta deletar assets existentes usando o endpoint exclusivo do GitHub (`DELETE /releases/assets/{id}`).

## 2. Requisitos Técnicos
1. No arquivo `.forgejo/workflows/ci.yml`, ajustar o passo anterior à publicação de release para excluir a release inteira com a tag `latest` caso ela exista:
   ```bash
   REL_INFO=$(curl -s -H "Authorization: token $TOKEN" "$API_URL/repos/$REPO/releases/tags/latest" || true)
   REL_ID=$(echo "$REL_INFO" | jq -r .id 2>/dev/null || echo "")
   if [ -n "$REL_ID" ] && [ "$REL_ID" != "null" ]; then
     echo "Excluindo release anterior $REL_ID no Forgejo para recriação atômica..."
     curl -s -X DELETE -H "Authorization: token $TOKEN" "$API_URL/repos/$REPO/releases/$REL_ID" || true
   fi
   ```
2. Garantir que a `action-gh-release` encontre um estado limpo para criar a nova release e fazer o upload do asset sem tentar deletar assets via endpoint inexistente.

## 3. Critérios de Aceitação
- Testes unitários do repositório (`cargo test`) executam com sucesso.
- Sintaxe válida no `.forgejo/workflows/ci.yml`.
