# 📡 Protocolo Milter e Ciclo de Vida de Mensagens

O **Ixcondidim** atua como um filtro **Milter** (Mail Filter) padrão do Sendmail/Postfix, interceptando o fluxo SMTP em tempo real.

---

## 🔄 Fluxo de Eventos Milter

```text
Postfix                       Ixcondidim
   │                               │
   ├─────── SMFIC_OPTNEG ─────────>│  Negociação de versão do protocolo e ações
   │<────── SMFIC_OPTNEG (OK) ─────┤  (SMFIF_ADDHDRS | SMFIF_CHGBODY | SMFIF_CHGHDRS)
   │                               │
   ├─────── SMFIC_CONNECT ────────>│
   │<────── SMFIS_CONTINUE ────────┤
   │                               │
   ├─────── SMFIC_MAIL ───────────>│  Identificação do remetente
   │<────── SMFIS_CONTINUE ────────┤
   │                               │
   ├─────── SMFIC_RCPT ───────────>│  Identificação dos destinatários
   │<────── SMFIS_CONTINUE ────────┤
   │                               │
   ├─────── SMFIC_HEADER ─────────>│  Coleta e validação de cabeçalhos
   │<────── SMFIS_CONTINUE ────────┤
   │                               │
   ├─────── SMFIC_BODY ───────────>│  Acúmulo de fragmentos do corpo
   │<────── SMFIS_CONTINUE ────────┤
   │                               │
   ├─────── SMFIC_BODYEOB ────────>│  Fim da mensagem: processamento principal
   │<────── SMFIR_ADDHEADER ───────┤  (Injeta 'Autocrypt' se saída)
   │<────── SMFIR_REPLBODY ────────┤  (Substitui por PGP/MIME se cifrado ou decifrado)
   │<────── SMFIS_CONTINUE ────────┤  Conclusão
```

---

## ⚙️ Ações Habilitadas na Negociação (`SMFIC_OPTNEG`)

* `SMFIF_ADDHDRS` (`0x01`): Permite adicionar novos cabeçalhos (`Autocrypt:` e informativos de segurança).
* `SMFIF_CHGBODY` (`0x02`): Permite substituir o corpo da mensagem via `SMFIR_REPLBODY` em chunks de 64 KB (para cifragem PGP/MIME ou decifragem com banner).
* `SMFIF_CHGHDRS` (`0x10`): Permite atualizar ou reescrever cabeçalhos MIME.
