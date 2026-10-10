use ishcondidim::config::Config;
use ishcondidim::keystore::KeyStore;
use ishcondidim::milter::EmailProcessor;
use std::sync::{Arc, RwLock};
use tempfile::tempdir;

#[test]
fn test_milter_outgoing_and_opportunistic_workflow() {
    let temp = tempdir().expect("tempdir");
    let keys_dir = temp.path().join("keys");
    let peers_dir = temp.path().join("peers");

    let keystore = Arc::new(KeyStore::new(&keys_dir, &peers_dir).expect("keystore"));

    let toml = r#"
        [default]
        prefer_encrypt = "mutual"
        encryption_mode = "opportunistic"
        decrypt_incoming = true
        security_word = "AreiaBranca"

        [domains."kiridu.net"]
        prefer_encrypt = "mutual"
    "#;

    let config = Arc::new(RwLock::new(Config::from_toml(toml).expect("config")));
    let processor = EmailProcessor::new(config, Arc::clone(&keystore));

    // Passo 1: Usuário local (Lumen) envia e-mail para um novo contato (Pedro)
    let email_out1 = b"\
From: <lumen@kiridu.net>\r\n\
To: <pedro@amigo.org>\r\n\
Subject: Ola Pedro\r\n\
\r\n\
Oi Pedro, vamos comer um escondidinho hoje?";

    let out1 = processor.process_email(email_out1);

    // Deve ter adicionado o cabeçalho Autocrypt
    assert!(
        out1.add_headers
            .iter()
            .any(|(k, v)| k == "Autocrypt" && v.contains("addr=lumen@kiridu.net"))
    );
    // Como ainda não temos a chave de Pedro, não cifra (fica plain)
    assert!(out1.replace_body.is_none());

    // Passo 2: Pedro responde enviando um e-mail com o cabeçalho Autocrypt dele
    let (_, pedro_pub) =
        ishcondidim::crypto::generate_autocrypt_keypair("pedro@amigo.org").expect("pedro keys");
    let pedro_pub_bytes =
        ishcondidim::crypto::public_key_to_binary(&pedro_pub).expect("pedro pub bytes");
    let ac_pedro =
        ishcondidim::autocrypt::AutocryptHeader::new("pedro@amigo.org", "mutual", &pedro_pub_bytes);

    let email_in_from_pedro = format!(
        "From: <pedro@amigo.org>\r\n\
         To: <lumen@kiridu.net>\r\n\
         Subject: Re: Ola Pedro\r\n\
         Autocrypt: {}\r\n\
         \r\n\
         Bora! Que horas?",
        ac_pedro.to_header_value()
    );

    let out2 = processor.process_email(email_in_from_pedro.as_bytes());
    // Pedro é externo, nada alterado no corpo desta mensagem
    assert!(out2.replace_body.is_none());

    // Verifica que o KeyStore agora conhece a chave de Pedro!
    let pedro_known = keystore.get_peer_public_key("pedro@amigo.org");
    assert!(
        pedro_known.is_some(),
        "KeyStore deve ter aprendido a chave de Pedro"
    );

    // Passo 3: Lumen responde Pedro novamente
    // AGORA SIM: Como ambos possuem chave e Pedro quer mutual, o milter CIFRA EM PGP/MIME!
    let email_out2 = b"\
From: <lumen@kiridu.net>\r\n\
To: <pedro@amigo.org>\r\n\
Subject: Re: Ola Pedro\r\n\
\r\n\
Combinado! No quiosque as 19h.";

    let out3 = processor.process_email(email_out2);
    assert!(
        out3.replace_body.is_some(),
        "O e-mail deve ter sido cifrado em PGP/MIME!"
    );
    let body_bytes = out3.replace_body.unwrap();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("multipart/encrypted"));
    assert!(body_str.contains("application/pgp-encrypted"));
}
