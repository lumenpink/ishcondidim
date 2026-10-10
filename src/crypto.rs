use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, Password};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    KeyGenError(String),
    SerializationError(String),
    DeserializationError(String),
    EncryptionError(String),
    DecryptionError(String),
    VerificationError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::KeyGenError(e) => write!(f, "OpenPGP KeyGen Error: {}", e),
            CryptoError::SerializationError(e) => write!(f, "OpenPGP Serialization Error: {}", e),
            CryptoError::DeserializationError(e) => {
                write!(f, "OpenPGP Deserialization Error: {}", e)
            }
            CryptoError::EncryptionError(e) => write!(f, "OpenPGP Encryption Error: {}", e),
            CryptoError::DecryptionError(e) => write!(f, "OpenPGP Decryption Error: {}", e),
            CryptoError::VerificationError(e) => write!(f, "OpenPGP Verification Error: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

#[derive(Debug, Clone)]
pub struct DecryptedResult {
    pub content: Vec<u8>,
    pub is_signed: bool,
    pub is_signature_valid: bool,
    pub signer_key_id: Option<String>,
}

/// Gera um par de chaves OpenPGP Ed25519 (assinatura) + X25519 (cifragem) conforme Autocrypt Level 1
pub fn generate_autocrypt_keypair(
    email: &str,
) -> Result<(SignedSecretKey, SignedPublicKey), CryptoError> {
    let mut rng = ChaCha8Rng::from_entropy();

    let key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_sign(true)
        .can_certify(true)
        .primary_user_id(format!("<{}>", email.trim().to_lowercase()))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                .can_encrypt(EncryptionCaps::All)
                .build()
                .map_err(|e| CryptoError::KeyGenError(e.to_string()))?,
        )
        .build()
        .map_err(|e| CryptoError::KeyGenError(e.to_string()))?;

    let secret_key = key_params
        .generate(&mut rng)
        .map_err(|e| CryptoError::KeyGenError(e.to_string()))?;

    let public_key = secret_key.to_public_key();

    Ok((secret_key, public_key))
}

/// Serializa uma chave pública para bytes binários brutos (sem armadura ASCII, para keydata)
pub fn public_key_to_binary(public_key: &SignedPublicKey) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = Vec::new();
    public_key
        .to_writer(&mut bytes)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    Ok(bytes)
}

/// Carrega uma chave pública a partir de bytes binários brutos
pub fn public_key_from_binary(bytes: &[u8]) -> Result<SignedPublicKey, CryptoError> {
    SignedPublicKey::from_bytes(bytes).map_err(|e| CryptoError::DeserializationError(e.to_string()))
}

/// Serializa chave privada para armadura ASCII (.sec)
pub fn secret_key_to_armor(secret_key: &SignedSecretKey) -> Result<String, CryptoError> {
    secret_key
        .to_armored_string(None.into())
        .map_err(|e| CryptoError::SerializationError(e.to_string()))
}

/// Carrega chave privada de armadura ASCII
pub fn secret_key_from_armor(armor: &str) -> Result<SignedSecretKey, CryptoError> {
    let (key, _) = SignedSecretKey::from_string(armor)
        .map_err(|e| CryptoError::DeserializationError(e.to_string()))?;
    Ok(key)
}

/// Serializa chave pública para armadura ASCII (.pub)
pub fn public_key_to_armor(public_key: &SignedPublicKey) -> Result<String, CryptoError> {
    public_key
        .to_armored_string(None.into())
        .map_err(|e| CryptoError::SerializationError(e.to_string()))
}

/// Carrega chave pública de armadura ASCII
pub fn public_key_from_armor(armor: &str) -> Result<SignedPublicKey, CryptoError> {
    let (key, _) = SignedPublicKey::from_string(armor)
        .map_err(|e| CryptoError::DeserializationError(e.to_string()))?;
    Ok(key)
}

/// Assina e cifra dados para múltiplos destinatários
pub fn sign_and_encrypt(
    plaintext: &[u8],
    sender_secret: &SignedSecretKey,
    recipient_publics: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    let mut rng = ChaCha8Rng::from_entropy();

    let builder = MessageBuilder::from_reader("", plaintext);
    let mut encrypting_builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    for recipient in recipient_publics {
        if !recipient.public_subkeys.is_empty() {
            for sub in &recipient.public_subkeys {
                encrypting_builder
                    .encrypt_to_key(&mut rng, sub)
                    .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
            }
        } else {
            encrypting_builder
                .encrypt_to_key(&mut rng, &recipient.primary_key)
                .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        }
    }

    encrypting_builder.sign(
        &sender_secret.primary_key,
        Password::empty(),
        HashAlgorithm::Sha256,
    );

    let armored = encrypting_builder
        .to_armored_string(&mut rng, None.into())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    Ok(armored)
}

/// Decifra uma mensagem PGP (binária ou ASCII armored) e verifica assinatura
pub fn decrypt_message(
    encrypted_data: &[u8],
    recipient_secret: &SignedSecretKey,
    expected_sender_pub: Option<&SignedPublicKey>,
) -> Result<DecryptedResult, CryptoError> {
    let msg = if let Ok(str_data) = std::str::from_utf8(encrypted_data) {
        if str_data.contains("-----BEGIN PGP MESSAGE-----") {
            let (msg, _) = Message::from_string(str_data)
                .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
            msg
        } else {
            Message::from_bytes(encrypted_data)
                .map_err(|e| CryptoError::DecryptionError(e.to_string()))?
        }
    } else {
        Message::from_bytes(encrypted_data)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?
    };

    let decrypted = msg
        .decrypt(&Password::empty(), recipient_secret)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    let mut decompressed = decrypted
        .decompress()
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    let content = decompressed
        .as_data_vec()
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    let mut is_signed = false;
    let mut is_signature_valid = false;
    let mut signer_key_id = None;

    if let Some(pubkey) = expected_sender_pub {
        if decompressed.verify(&pubkey.primary_key).is_ok() {
            is_signed = true;
            is_signature_valid = true;
            signer_key_id = Some(hex::encode(pubkey.fingerprint().as_bytes()));
        }
    }

    Ok(DecryptedResult {
        content,
        is_signed,
        is_signature_valid,
        signer_key_id,
    })
}
