# 🔐 Especificação Autocrypt Level 1 no Ishcondidim

O **Ishcondidim** implementa a especificação oficial **Autocrypt Level 1** para servidores de e-mail de forma 100% autônoma.

---

## 🎯 Princípios do Autocrypt

O Autocrypt resolve o problema histórico de usabilidade do OpenPGP:
1. **Zero-Configuration no Cliente:** O usuário não precisa instalar extensões nem gerenciar chaves no Thunderbird, Apple Mail, Webmail ou celular.
2. **Troca Descentralizada de Chaves:** As chaves públicas viajam de forma transparente nos cabeçalhos de e-mail convencionais (`Autocrypt:`).
3. **Criptografia Oportunística:** Mensagens são cifradas assim que ambos os participantes possuem suporte e chaves trocadas.

---

## 📬 Estrutura do Cabeçalho `Autocrypt:`

Todo e-mail enviado por um remetente gerenciado pelo **Ishcondidim** recebe o cabeçalho:

```http
Autocrypt: addr=lumen@kiridu.net; prefer-encrypt=mutual; keydata=mQGNBG...
```

* `addr`: O endereço de e-mail do remetente (normalizado em minúsculas).
* `prefer-encrypt`: `mutual` indica que o remetente deseja que mensagens futuras sejam cifradas se ambos os lados suportarem. `nopreference` indica suporte passivo.
* `keydata`: A chave pública OpenPGP (Transferable Public Key) em formato binário codificada em Base64 (sem quebras de linha ou armadura ASCII).

---

## 🛡️ Máquina de Estados de Pares (Peer State) e Prevenção de Lockout

Uma das maiores inovações do Autocrypt é evitar que um usuário fique impedido de ler mensagens (*lockout*) ao alternar para um cliente sem suporte a PGP.

O **Ishcondidim** implementa rigorosamente a máquina de estados baseada no cabeçalho `Date` da mensagem:

1. **E-mail recebido COM cabeçalho Autocrypt válido (`Date` mais recente):**
   * Armazena a nova chave pública no diretório `peers/`.
   * Ativa a cifragem para o contato (`autocrypt_enabled = true`).
   * Próximos e-mails enviados para ele serão cifrados em **PGP/MIME**.

2. **E-mail recebido SEM cabeçalho Autocrypt (`Date` mais recente):**
   * Detecta que o contato provavelmente trocou de cliente (ex: respondeu de um celular sem PGP).
   * **Executa downgrade imediato para texto claro** (`autocrypt_enabled = false`).
   * Próximos e-mails enviados para ele voltam a ser entregues em texto claro com o nosso cabeçalho anexado, garantindo que o contato consiga ler a mensagem sem problemas!

---

## 👥 Threads e `Autocrypt-Gossip:`

Em e-mails com múltiplos destinatários (`To:` e `Cc:`), o cabeçalho `Autocrypt-Gossip:` permite que os participantes aprendam as chaves uns dos outros mesmo sem terem trocado mensagens diretas previamente.
