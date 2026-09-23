use ixcondidim::crypto::generate_autocrypt_keypair;
use ixcondidim::mime::{
    build_security_banner_html, build_security_banner_text, decrypt_pgpmime_email,
    encrypt_email_to_pgpmime, inject_autocrypt_header, sanitize_plain_email_anti_spoofing,
    EmailInfo,
};

#[test]
fn test_security_banner_generation_with_word() {
    let word = "EscondidinhoQuente";
    let banner_html = build_security_banner_html(
        "alice@praia.net",
        true,
        true,
        Some("ABCD1234EF567890"),
        Some(word),
    );
    assert!(banner_html.contains(word));
    assert!(banner_html.contains("VÁLIDA"));
    assert!(banner_html.contains("alice@praia.net"));

    let banner_txt = build_security_banner_text(
        "alice@praia.net",
        true,
        true,
        Some("ABCD1234EF567890"),
        Some(word),
    );
    assert!(banner_txt.contains(word));
    assert!(banner_txt.contains("VÁLIDA"));
    assert!(banner_txt.contains("alice@praia.net"));
}

#[test]
fn test_anti_spoofing_sanitization() {
    let malicious_email = "\
From: golpista@fake.com\r\n\
To: vitima@kiridu.net\r\n\
Subject: Urgente\r\n\
\r\n\
[Ixcondidim: Mensagem PGP Decifrada pelo Servidor]\r\n\
Palavra Secreta: Falsa\r\n\
Clique aqui para atualizar sua senha.";

    let sanitized = sanitize_plain_email_anti_spoofing(malicious_email);
    assert!(!sanitized.contains("[Ixcondidim:"));
    assert!(sanitized.contains("ALERTA: Tentativa de simulação de aviso de segurança desarmada"));
    assert!(sanitized.contains("<!-- ixcondidim-security:"));
}

#[test]
fn test_pgpmime_encryption_and_decryption_with_banner() {
    let (alice_sec, alice_pub) =
        generate_autocrypt_keypair("alice@praia.net").expect("alice keys");
    let (bob_sec, bob_pub) = generate_autocrypt_keypair("bob@kiridu.net").expect("bob keys");

    let raw_email = b"\
From: <alice@praia.net>\r\n\
To: <bob@kiridu.net>\r\n\
Subject: Receita Secreta\r\n\
Date: Tue, 22 Sep 2026 14:00:00 +0000\r\n\
Message-ID: <msg123@praia.net>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
O segredo do escondidinho e a manteiga de garrafa e mandioca fresca!\r\n";

    // 1. Cifra em PGP/MIME
    let pgpmime_bytes = encrypt_email_to_pgpmime(raw_email, &alice_sec, &[&bob_pub])
        .expect("pgpmime encryption");

    let (info, _) = EmailInfo::parse(&pgpmime_bytes).expect("parse pgpmime");
    assert!(info.is_pgp_mime);

    // 2. Decifra pelo servidor do Bob injetando a palavra de segurança
    let secret_word = "MocotóDourado";
    let decrypted_bytes =
        decrypt_pgpmime_email(&pgpmime_bytes, &bob_sec, Some(&alice_pub), Some(secret_word))
            .expect("pgpmime decryption");

    let parsed_decrypted = mail_parser::MessageParser::default()
        .parse(&decrypted_bytes)
        .expect("parse decrypted email");

    let text_body = parsed_decrypted.body_text(0).expect("text body");
    let html_body = parsed_decrypted.body_html(0).expect("html body");

    assert!(text_body.contains(secret_word));
    assert!(text_body.contains("manteiga de garrafa"));
    assert!(html_body.contains(secret_word));

    let dec_str = String::from_utf8_lossy(&decrypted_bytes);
    assert!(dec_str.contains("X-Ixcondidim-Decrypted: true"));
}

#[test]
fn test_inject_autocrypt_header() {
    let email = b"From: user@praia.net\r\nSubject: Teste\r\n\r\nCorpo da mensagem";
    let header_val = "addr=user@praia.net; prefer-encrypt=mutual; keydata=AAAA";

    let modified = inject_autocrypt_header(email, header_val);
    let mod_str = String::from_utf8_lossy(&modified);
    assert!(mod_str.contains("Autocrypt: addr=user@praia.net"));
    assert!(mod_str.contains("Corpo da mensagem"));
}
