use ishcondidim::crypto::{
    decrypt_message, generate_autocrypt_keypair, public_key_from_armor, public_key_from_binary,
    public_key_to_armor, public_key_to_binary, secret_key_from_armor, secret_key_to_armor,
    sign_and_encrypt,
};
use pgp::types::KeyDetails;

#[test]
fn test_generate_and_serialize_keys() {
    let email = "aloha@praia.net";
    let (sec, pubkey) = generate_autocrypt_keypair(email).expect("generate keys");

    // Teste de serialização binária da chave pública (para o cabeçalho Autocrypt)
    let bin = public_key_to_binary(&pubkey).expect("pub to binary");
    assert!(!bin.is_empty());
    let pub_recovered = public_key_from_binary(&bin).expect("pub from binary");
    assert_eq!(pubkey.fingerprint(), pub_recovered.fingerprint());

    // Teste de serialização ASCII armor da chave privada
    let sec_armor = secret_key_to_armor(&sec).expect("sec to armor");
    assert!(sec_armor.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    let sec_recovered = secret_key_from_armor(&sec_armor).expect("sec from armor");
    assert_eq!(sec.fingerprint(), sec_recovered.fingerprint());

    // Teste de serialização ASCII armor da chave pública
    let pub_armor = public_key_to_armor(&pubkey).expect("pub to armor");
    assert!(pub_armor.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    let pub_armor_rec = public_key_from_armor(&pub_armor).expect("pub from armor");
    assert_eq!(pubkey.fingerprint(), pub_armor_rec.fingerprint());
}

#[test]
fn test_sign_and_encrypt_roundtrip() {
    let alice_email = "alice@praia.net";
    let bob_email = "bob@praia.net";

    let (alice_sec, alice_pub) = generate_autocrypt_keypair(alice_email).expect("alice keys");
    let (bob_sec, bob_pub) = generate_autocrypt_keypair(bob_email).expect("bob keys");

    let secret_message = b"Ola Bob! Nosso escondidinho de carne seca esta pronto no quiosque.";

    // Alice assina e cifra para Bob
    let encrypted =
        sign_and_encrypt(secret_message, &alice_sec, &[&bob_pub]).expect("encryption");
    assert!(encrypted.contains("-----BEGIN PGP MESSAGE-----"));

    // Bob decifra e verifica a assinatura de Alice
    let dec_res =
        decrypt_message(encrypted.as_bytes(), &bob_sec, Some(&alice_pub)).expect("decryption");

    assert_eq!(dec_res.content, secret_message);
    assert!(dec_res.is_signed);
    assert!(dec_res.is_signature_valid);
    assert!(dec_res.signer_key_id.is_some());
}
