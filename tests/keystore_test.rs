use ixcondidim::autocrypt::AutocryptHeader;
use ixcondidim::crypto::{generate_autocrypt_keypair, public_key_to_binary};
use ixcondidim::keystore::KeyStore;
use pgp::types::KeyDetails;
use tempfile::tempdir;

#[test]
fn test_keystore_get_or_generate_local_key() {
    let temp = tempdir().expect("tempdir");
    let keys_dir = temp.path().join("keys");
    let peers_dir = temp.path().join("peers");

    let keystore = KeyStore::new(&keys_dir, &peers_dir).expect("init keystore");

    // 1. Gera na primeira chamada
    let email = "pescador@kiridu.net";
    let (sec1, pub1) = keystore
        .get_or_generate_keypair(email, true)
        .expect("generate")
        .expect("some key");

    // 2. Carrega existente na segunda chamada
    let (sec2, pub2) = keystore
        .get_or_generate_keypair(email, true)
        .expect("load")
        .expect("some key");

    assert_eq!(sec1.fingerprint(), sec2.fingerprint());
    assert_eq!(pub1.fingerprint(), pub2.fingerprint());
}

#[test]
fn test_autocrypt_peer_state_machine_and_downgrade() {
    let temp = tempdir().expect("tempdir");
    let keys_dir = temp.path().join("keys");
    let peers_dir = temp.path().join("peers");

    let keystore = KeyStore::new(&keys_dir, &peers_dir).expect("init keystore");

    let peer_email = "amigo@externo.com";
    let (_, peer_pub) = generate_autocrypt_keypair(peer_email).expect("peer keys");
    let peer_pub_bytes = public_key_to_binary(&peer_pub).expect("binary");

    let ac_header = AutocryptHeader::new(peer_email, "mutual", &peer_pub_bytes);

    // 1. Chega mensagem com Autocrypt na data T=1000
    keystore
        .update_peer_state(peer_email, Some(&ac_header), Some(1000))
        .expect("update");

    let state = keystore.get_peer_state(peer_email).expect("state");
    assert!(state.autocrypt_enabled);
    assert_eq!(state.prefer_encrypt, "mutual");
    assert!(keystore.get_peer_public_key(peer_email).is_some());

    // 2. Chega mensagem antiga sem Autocrypt na data T=500 (deve ser ignorada para evitar replay/desordem)
    keystore
        .update_peer_state(peer_email, None, Some(500))
        .expect("update old");

    let state_after_old = keystore.get_peer_state(peer_email).expect("state");
    assert!(state_after_old.autocrypt_enabled);

    // 3. Chega mensagem NOVA sem Autocrypt na data T=2000
    // REGRA DO AUTOCRYPT L1: Contato mudou de cliente ou desativou PGP -> DOWNGRADE PARA PLAIN!
    keystore
        .update_peer_state(peer_email, None, Some(2000))
        .expect("update newer without autocrypt");

    let state_downgraded = keystore.get_peer_state(peer_email).expect("state");
    assert!(
        !state_downgraded.autocrypt_enabled,
        "Peer deve ter sido desativado (downgrade) para evitar lockout!"
    );
    assert!(
        keystore.get_peer_public_key(peer_email).is_none(),
        "Nao deve retornar chave publica ativa para peer em modo plain"
    );

    // 4. Contato volta a mandar mensagem com Autocrypt na data T=3000 -> REATIVADO!
    keystore
        .update_peer_state(peer_email, Some(&ac_header), Some(3000))
        .expect("update re-enabled");

    let state_re_enabled = keystore.get_peer_state(peer_email).expect("state");
    assert!(state_re_enabled.autocrypt_enabled);
    assert!(keystore.get_peer_public_key(peer_email).is_some());
}
