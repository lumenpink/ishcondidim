# 🗝️ Arquitetura do Keystore e Criptografia

O **Ishcondidim** utiliza criptografia OpenPGP nativa 100% em Rust através da crate `pgp`, eliminando completamente o acoplamento com daemons externos como `gpg-agent` ou ferramentas C legadas.

---

## 🚀 Curvas Elípticas Modernas (Sem RSA)

Seguindo as melhores práticas modernas de criptografia:
* **Chave Primária de Assinatura e Certificação:** **Ed25519** (RFC 8032). Rápida, com assinaturas determinísticas de tamanho ultracompacto.
* **Subchave de Cifragem:** **Curve25519 / X25519** (ECDH). Compartilhamento seguro de segredos de alta performance.
* **Tamanho de Cabeçalho:** Enquanto chaves RSA 4096 produzem cabeçalhos Autocrypt pesados de 3 a 5 KB, as chaves Ed25519/X25519 cabem confortavelmente em ~1 KB.

---

## 📁 Estrutura de Arquivos no Disco

```text
/var/lib/ishcondidim/
├── keys/                           # Chaves dos usuários locais (Modo 0700)
│   ├── usuario@kiridu.net.sec      # Chave privada protegida (Modo 0600)
│   └── usuario@kiridu.net.pub      # Chave pública (Modo 0644)
└── peers/                          # Estado dos contatos externos (Modo 0700)
    ├── alice@externo.com.json      # Metadata do par (prefer_encrypt, effective_date)
    └── bob@externo.org.json
```

---

## 🛡️ Segurança e Permissões de Arquivo

* O diretório de chaves privadas é configurado automaticamente com permissão POSIX `0700` (`rwx------`).
* Os arquivos de chaves privadas (`.sec`) são criados exclusivamente com modo `0600` (`rw-------`).
* O daemon roda sob o usuário e grupo do Postfix (`postfix:postfix`), sem privilégios de root em produção.
