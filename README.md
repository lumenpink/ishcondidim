# 🍲 Ixcondidim

> **Filtro Milter Postfix em Rust para Autocrypt Level 1 Server-Side com gestão automática de chaves OpenPGP, prevenção de lockout e selo anti-spoofing.**

[![Codeberg](https://img.shields.io/badge/Codeberg-lumenpink%2Fixcondidim-blue?logo=codeberg)](https://codeberg.org/lumenpink/ixcondidim)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-lightgrey.svg)](https://unlicense.org)
[![Website](https://img.shields.io/badge/Site-ixcondidim.2lp.in-seagreen)](https://ixcondidim.2lp.in)

---

## 🎯 O que é o Ixcondidim?

O **Ixcondidim** (*"escondidinho"* saboroso com privacidade garantida) é um daemon de filtro Milter para servidores de e-mail **Postfix** que implementa o padrão aberto **Autocrypt Level 1** inteiramente no lado do servidor.

Com ele:
1. Os usuários locais enviam e-mails normalmente a partir de qualquer cliente (Thunderbird, iPhone, Android, Outlook ou Webmail).
2. O **Ixcondidim** verifica se o remetente já possui um par de chaves OpenPGP no keystore local. Se não tiver, **gera na hora um par moderno Ed25519 + X25519**.
3. Injeta o cabeçalho oficial `Autocrypt: addr=...; prefer-encrypt=mutual; keydata=...` em todas as mensagens de saída.
4. Quando contatos externos respondem com Autocrypt, o servidor guarda as chaves públicas deles automaticamente.
5. Se ambos os lados possuem chaves, as próximas mensagens são **cifradas automaticamente em PGP/MIME (`multipart/encrypted`)**.
6. Mensagens recebidas cifradas são **decifradas no servidor** e entregues legíveis no Webmail/IMAP com um **banner de autenticidade**, protegido por uma **palavra de segurança secreta** para evitar farsas de phishing!

---

## 🏗️ Arquitetura do Sistema

```text
[Cliente de E-mail] (Webmail, iPhone, Thunderbird, K-9)
        │
        │ SMTP Submission (Porta 587 / 465)
        ▼
   ┌─────────┐
   │ Postfix │
   └────┬────┘
        │ Protocolo Milter (UNIX Socket ou TCP inet)
        ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                    IXCONDIDIM MILTER                        │
 │                                                             │
 │  1. MAIL FROM / From:                                       │
 │     └─ Valida se remetente pertence a domínio gerenciado    │
 │  2. Keystore Local (0700):                                  │
 │     └─ Gera par Ed25519/X25519 on-the-fly se não existir    │
 │  3. Injeção de Cabeçalho:                                   │
 │     └─ SMFIR_ADDHEADER 'Autocrypt: addr=...; keydata=...'   │
 │  4. Máquina de Estados de Pares (Anti-Lockout):             │
 │     ├─ Aprende chaves públicas de e-mails recebidos         │
 │     └─ Faz downgrade para plain se contato trocar de cliente│
 │  5. Criptografia Oportunística (PGP/MIME RFC 3156):         │
 │     └─ Cifra corpo se destinatários tiverem chaves ativas   │
 │  6. Decifragem Inbound & Banner com Palavra Secreta:        │
 │     ├─ Decifra mensagens recebidas em PGP/MIME              │
 │     ├─ Injeta banner com status de assinatura e segredo     │
 │     └─ Sanitização anti-spoofing em mensagens de texto claro│
 └──────────────────────────────┬──────────────────────────────┘
                                │ Mensagem protegida / autenticada
                                ▼
                       ┌─────────────────┐
                       │ OpenDKIM/Rspamd │ (Assina o e-mail pós-cifragem)
                       └────────┬────────┘
                                │
                                ▼
                       [Internet / Destino]
```

---

## ✨ Principais Diferenciais

### 1. Curvas Elípticas Ultrarrápidas (Ed25519 + X25519)
Ao invés de certificados RSA pesados e lentos de 4096 bits, o **Ixcondidim** utiliza Ed25519 para assinatura e X25519 para troca de chaves. O cabeçalho Autocrypt ocupa cerca de 1 KB e a geração de chaves é instantânea na memória.

### 2. Prevenção Inteligente de Lockout (Autocrypt State Machine)
Se um contato que usava Autocrypt responder de repente de um aparelho sem PGP, o Ixcondidim detecta a mensagem sem Autocrypt e **retorna automaticamente para texto claro**. Isso evita a clássica falha de trancar o interlocutor fora da conversa.

### 3. Selo de Validação com Palavra de Segurança
Mensagens decifradas no servidor recebem um banner claro com o status da assinatura digital e a **Palavra Secreta de Validação** definida na configuração. E-mails de spam ou phishing que tentem forjar o selo do Ixcondidim em texto claro são desarmados pelo mecanismo de sanitização anti-spoofing.

### 4. Zero Dependências Externas (Rust Puro)
O daemon utiliza a crate nativa `pgp`, dispensando `gpg`, `gpg-agent`, `libgpgme` ou daemons auxiliares no sistema.

---

## 🚀 Como Executar

### Compilação:
```bash
cargo build --release
```

### Execução local:
```bash
./target/release/ixcondidim --config ixcondidim.toml
```

---

## 🧪 Testes Automatizados

Toda a suíte de testes unitários e de integração pode ser executada com:
```bash
cargo test
```

---

## 📄 Licença

Este projeto é software livre e de domínio público sob **GNU General Public License v3.0**. Consulte o arquivo [UNLICENSE](UNLICENSE) para detalhes.
