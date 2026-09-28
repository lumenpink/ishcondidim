# ⚙️ Referência de Configuração (`ishcondidim.toml`)

O arquivo de configuração do Ishcondidim utiliza o formato **TOML** e suporta **resolução hierárquica** em cascata com **Live Hot-Reload** (via `notify`).

---

## 🏗️ Resolução Hierárquica

As configurações são avaliadas na seguinte ordem de precedência:

$$\text{Remetente Específico} \longrightarrow \text{Domínio} \longrightarrow \text{Padrão (Default)}$$

---

## 📋 Parâmetros Globais

### `[server]`
* `listen`: Socket de comunicação do Milter.
  * Socket UNIX: `unix:/run/ishcondidim/ishcondidim.sock` *(recomendado)*.
  * Socket TCP: `inet:127.0.0.1:8898`.

### `[storage]`
* `keys_dir`: Caminho onde as chaves privadas e públicas locais são guardadas (permissão `0700`).
  * Padrão: `/var/lib/ishcondidim/keys`.
* `peers_dir`: Caminho onde o cache de chaves públicas dos contatos externos é armazenado.
  * Padrão: `/var/lib/ishcondidim/peers`.

---

## 🔐 Parâmetros de Perfil (`[default]`, `[domains.*]`, `[senders.*]`)

* `prefer_encrypt` *(string)*: `mutual` (padrão recomendado) ou `nopreference`.
* `auto_generate_keys` *(bool)*: Se `true` (padrão), gera automaticamente um par Ed25519 + X25519 na primeira mensagem de saída.
* `auto_add_header` *(bool)*: Se `true` (padrão), injeta o cabeçalho `Autocrypt:` nas mensagens de saída.
* `auto_collect_peers` *(bool)*: Se `true` (padrão), armazena e atualiza chaves públicas dos remetentes de e-mails recebidos.
* `encryption_mode` *(string)*:
  * `opportunistic` (padrão): Cifra em PGP/MIME automaticamente se todos os destinatários tiverem chave Autocrypt ativa.
  * `header_only`: Apenas publica o cabeçalho `Autocrypt:`, mantendo o corpo em texto claro.
  * `disabled`: Não executa ações de cifragem para este perfil.
* `decrypt_incoming` *(bool)*: Se `true` (padrão), decifra e-mails PGP/MIME recebidos e anexa o banner de validação visual.
* `security_word` *(string, opcional)*: Palavra secreta interna conhecida apenas entre o usuário e o servidor, estampada no banner de mensagens decifradas para prevenção absoluta de falsificação.
