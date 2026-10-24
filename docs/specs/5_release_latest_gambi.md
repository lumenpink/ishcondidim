# Especificação Técnica — Publicação Automática de Release linux-x86_64 com Tag latest na Gambi (#5)

- **ID do Ticket:** #5
- **Status:** Aprovado
- **Autora:** Lumen
- **Alinhamento:** GOST 1.5.0

## 1. Contexto & Motivação
O daemon milter `ishcondidim` implementa suporte a Autocrypt L1 server-side com gestão automática de chaves OpenPGP no Postfix. Ele roda como serviço na stack de correio e é referenciado em testes e builds irmãs no ecossistema Lauda.
O objetivo é automatizar a publicação do binário pré-compilado para a arquitetura `linux-x86_64` na release da Gambi (`gambi.2lp.in`) sob a tag canônica `latest`, eliminando dependências externas e recompilações desnecessárias.

## 2. Requisitos Técnicos
1. **Gatilho:**
   - Push na branch `main` e tags `v*`.
2. **Dependência:**
   - O job `release` depende da aprovação prévia do job `test` (`needs: [test]`).
3. **Compilação do Binário:**
   - `cargo build --release --bin ishcondidim`.
4. **Publicação da Release:**
   - Utilização de `softprops/action-gh-release@v2`.
   - `tag_name: "latest"`.
   - Anexo único do artefato `target/release/ishcondidim`.
5. **Saneamento:**
   - Remoção de jobs legados/órfãos (`trigger-gost-ci`).

## 3. Critérios de Aceitação
- Teste automatizado `tests/test_ci_release_workflow.sh` validando a estrutura do workflow.
- Validação estrita via `cccp check --strict`.
