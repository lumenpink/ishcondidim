# Especificação Técnica: Conformidade com Padrão XDG e Integração Banca

- **Ticket**: #3
- **Escopo**: Implementação de auto-atualização atômica OpenDesktop/XDG na CLI do `ishcondidim` e publicação soberana na Banca via Cloudflare R2 com retenção automatizada.

## 1. Contexto e Motivação
Para assegurar conformidade com a norma GOST e o perfil Lumen, o `ishcondidim` deve gerenciar suas configurações e estados de runtime conforme a especificação da freedesktop.org (XDG Base Directory). A distribuição de binários compilados deve ser soberana, eliminando a dependência de releases pesados no Codeberg e integrando-se diretamente à Banca (`https://banca.2lp.in/downloads/ishcondidim/`).

## 2. Requisitos Técnicos

### 2.1 Resolução de Caminhos XDG
1. **Configuração do Usuário**:
   - Resolução: `${XDG_CONFIG_HOME:-~/.config}/ishcondidim/config.toml`.
2. **Estado e Cache de Atualização**:
   - Resolução: `${XDG_STATE_HOME:-~/.local/state}/ishcondidim/update_check.json`.
3. **Binário de Destino para Auto-Update**:
   - Padrão: `~/.local/bin/ishcondidim` (ou o próprio caminho de execução atual retornado por `std::env::current_exe()`).

### 2.2 Estrutura da Seção `[update]` no `config.toml`
```toml
[update]
channel = "stable"           # "stable" ou "nightly"
pinned = false               # Se true, ignora alertas e bloqueia update automático
pin = ""                     # Versão específica fixada quando pinned = true
auto_check = true            # Verificação automática em segundo plano
check_interval_hours = 24    # Intervalo mínimo entre checagens remotas
auto_update = false          # Atualização automática atômica (desabilitada por padrão)
```

### 2.3 Cache de Estado (`update_check.json`)
```json
{
  "last_check_timestamp": 1729411200,
  "latest_remote_version": "0.1.1",
  "channel": "stable"
}
```

### 2.4 Precedência de Resolução de Canal
1. Flag de linha de comando: `--channel <canal>`
2. Variável de ambiente: `ISHCONDIDIM_CHANNEL`
3. Arquivo `config.toml`: `update.channel`
4. Fallback padrão: `"stable"`

### 2.5 Subcomandos da CLI
- `ishcondidim update [--channel <c>] [--pin <v>] [--force] [--dry-run]`
- `ishcondidim check-update [--channel <c>]`
- `ishcondidim config show` / `ishcondidim config get`
- `ishcondidim config pin [<version>]`
- `ishcondidim config unpin`
- `ishcondidim config set-auto-check <true|false>`
- `ishcondidim config set-channel <stable|nightly>`
- `ishcondidim config set-auto-update <true|false>`

### 2.6 Verificação Periódica no Startup
Ao iniciar o daemon milter ou comando comum da CLI:
- Se `auto_check == true` e `pinned == false`:
  - Se houver versão mais recente no cache, emitir aviso em `stderr`:
    ```text
    💡 [ishcondidim] Nova versão disponível: vX.Y.Z (atual: vA.B.C).
       Execute 'ishcondidim update' para atualizar.
    ```
  - Se decorrido o intervalo de horas, disparar consulta rápida/não-bloqueante ao endpoint remoto `https://banca.2lp.in/downloads/ishcondidim/<channel>-latest.version` e persistir em `update_check.json`.

### 2.7 Atualização Atômica com Rollback
- O download do binário remoto é gravado em um arquivo temporário no mesmo diretório do binário alvo (`target_dir`), garantindo operação no mesmo sistema de arquivos.
- Aplicação de permissões executáveis `0755`.
- Criação de backup temporário do binário original antes do rename atômico.
- Em caso de falha no rename ou validação, efetuar rollback imediato restaurando o executável anterior.

### 2.8 Esteira CI/CD para a Banca
- Compilação no container soberano `gambi.2lp.in/lumen/gost-ci-cross:latest`.
- Envio de artefatos para o bucket R2 (`twolp-bucket/downloads/ishcondidim/...`).
- Rotação via `scripts/rotate-downloads.py` mantendo retenção de 5 versões estáveis e 10 nightlies.
- Remoção do envio de binários no Codeberg Releases.
