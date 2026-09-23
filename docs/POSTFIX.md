# 🐧 Integração com o Postfix

Instruções para ativar o **Ixcondidim** no Postfix, preservando autenticação **DKIM** e ordem de execução de outros filtros (como o **Papéli**).

---

## 🏗️ Ordem Crítica dos Milters

Quando você utiliza filtros que alteram o corpo da mensagem (como Papéli e Ixcondidim) junto com assinadores de DKIM (como OpenDKIM ou Rspamd), **a ordem dos milters é crucial**:

$$\text{Papéli (Papel de Carta)} \longrightarrow \text{Ixcondidim (Autocrypt/Cifragem)} \longrightarrow \text{OpenDKIM / Rspamd (Assinatura DKIM)}$$

> [!IMPORTANT]
> O assinador DKIM deve ser sempre o **último** da cadeia em mensagens que saem, para que a assinatura digital de transporte cubra a mensagem final já envelopada ou cifrada.

---

## ⚙️ Configuração no `main.cf`

Edite `/etc/postfix/main.cf`:

```apache
# Configurações do Milter
milter_default_action = accept
milter_protocol = 6

# Cadeia de Milters via UNIX sockets (ou TCP inet:127.0.0.1:8898)
smtpd_milters = unix:/run/papeli/papeli.sock, unix:/run/ixcondidim/ixcondidim.sock, unix:/run/opendkim/opendkim.sock
non_smtpd_milters = $smtpd_milters
```

---

## 🔒 Permissões do Socket UNIX

O Postfix precisa de permissão de escrita no socket UNIX criado pelo daemon.

Certifique-se de que o diretório `/run/ixcondidim` pertença ao grupo `postfix`:
```bash
sudo mkdir -p /run/ixcondidim
sudo chown postfix:postfix /run/ixcondidim
sudo chmod 0770 /run/ixcondidim
```

---

## 🔄 Reiniciando os Serviços

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ixcondidim
sudo systemctl restart postfix
```

Verifique os logs:
```bash
sudo journalctl -u ixcondidim -f
```
