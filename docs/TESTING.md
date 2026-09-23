# 🧪 Estratégia de Testes Automatizados

O **Ixcondidim** possui uma suíte completa de testes automatizados unitários e de integração, garantindo que o protocolo Milter, a máquina de estados do Autocrypt e o motor criptográfico permaneçam intactos.

---

## 🏃 Como Executar os Testes

Execute toda a suíte com:
```bash
cargo test
```

Para executar um módulo de teste específico:
```bash
cargo test --test crypto_test
cargo test --test keystore_test
cargo test --test mime_test
cargo test --test milter_test
cargo test --test e2e_test
```

---

## 📊 Matriz de Cobertura de Testes

| Arquivo de Teste | Área Testada | Casos Críticos |
| :--- | :--- | :--- |
| `tests/config_test.rs` | Parser TOML e Resolução | Cascata `default` $\to$ `domains` $\to$ `senders`, herança de `security_word`. |
| `tests/crypto_test.rs` | OpenPGP Rust Puro | Geração de chaves Ed25519/X25519, serialização binária sem armadura para headers, assinatura e decifragem. |
| `tests/autocrypt_test.rs` | Headers Autocrypt L1 | Formatação, parsing com espaços e atributos de extensão (`_client`), Autocrypt-Gossip. |
| `tests/keystore_test.rs` | Keystore & Peer State | Permissões de arquivo, downgrade automático para plain text ao receber mensagem nova sem Autocrypt. |
| `tests/mime_test.rs` | Encriptação & Decifragem | Montagem PGP/MIME, injeção de banner com `security_word`, sanitização anti-spoofing em plain text. |
| `tests/milter_test.rs` | Lógica de Negócio Milter | Fluxo de saída (injeção de headers), fluxo de entrada (coleta de peers), cifragem oportuna quando ambos têm chave. |
| `tests/e2e_test.rs` | Protocolo Milter Real | Simulação de stream SMTP completa com frames `OPTNEG`, `CONNECT`, `MAIL`, `RCPT`, `HEADER`, `BODY`, `BODYEOB`. |
