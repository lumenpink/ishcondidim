use crate::autocrypt::AutocryptHeader;
use crate::crypto::{
    CryptoError, generate_autocrypt_keypair, public_key_from_armor, public_key_from_binary,
    public_key_to_armor, secret_key_from_armor, secret_key_to_armor,
};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum KeyStoreError {
    IoError(String),
    CryptoError(String),
    JsonError(String),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::IoError(e) => write!(f, "KeyStore IO Error: {}", e),
            KeyStoreError::CryptoError(e) => write!(f, "KeyStore Crypto Error: {}", e),
            KeyStoreError::JsonError(e) => write!(f, "KeyStore JSON Error: {}", e),
        }
    }
}

impl std::error::Error for KeyStoreError {}

impl From<CryptoError> for KeyStoreError {
    fn from(e: CryptoError) -> Self {
        KeyStoreError::CryptoError(e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    pub addr: String,
    pub public_key_armor: Option<String>,
    pub prefer_encrypt: String,
    pub autocrypt_enabled: bool,
    pub effective_date: Option<i64>,
    pub last_seen: i64,
}

pub struct KeyStore {
    keys_dir: PathBuf,
    peers_dir: PathBuf,
}

impl KeyStore {
    pub fn new<P: AsRef<Path>>(keys_dir: P, peers_dir: P) -> Result<Self, KeyStoreError> {
        let keys_path = keys_dir.as_ref().to_path_buf();
        let peers_path = peers_dir.as_ref().to_path_buf();

        fs::create_dir_all(&keys_path).map_err(|e| KeyStoreError::IoError(e.to_string()))?;
        fs::create_dir_all(&peers_path).map_err(|e| KeyStoreError::IoError(e.to_string()))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&keys_path, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(&peers_path, fs::Permissions::from_mode(0o700));
        }

        Ok(Self {
            keys_dir: keys_path,
            peers_dir: peers_path,
        })
    }

    fn sanitize_email_for_filename(email: &str) -> String {
        email
            .trim()
            .to_lowercase()
            .replace('/', "_")
            .replace('\\', "_")
    }

    /// Obtém ou gera um par de chaves OpenPGP local para uma conta interna
    pub fn get_or_generate_keypair(
        &self,
        email: &str,
        auto_generate: bool,
    ) -> Result<Option<(SignedSecretKey, SignedPublicKey)>, KeyStoreError> {
        let filename = Self::sanitize_email_for_filename(email);
        let sec_path = self.keys_dir.join(format!("{}.sec", filename));
        let pub_path = self.keys_dir.join(format!("{}.pub", filename));

        if sec_path.exists() && pub_path.exists() {
            let sec_str =
                fs::read_to_string(&sec_path).map_err(|e| KeyStoreError::IoError(e.to_string()))?;
            let pub_str =
                fs::read_to_string(&pub_path).map_err(|e| KeyStoreError::IoError(e.to_string()))?;

            let sec_key = secret_key_from_armor(&sec_str)?;
            let pub_key = public_key_from_armor(&pub_str)?;
            return Ok(Some((sec_key, pub_key)));
        }

        if !auto_generate {
            return Ok(None);
        }

        // Gera novo par Ed25519 + X25519
        let (sec_key, pub_key) = generate_autocrypt_keypair(email)?;

        let sec_armor = secret_key_to_armor(&sec_key)?;
        let pub_armor = public_key_to_armor(&pub_key)?;

        {
            let mut file =
                File::create(&sec_path).map_err(|e| KeyStoreError::IoError(e.to_string()))?;
            #[cfg(unix)]
            {
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
            file.write_all(sec_armor.as_bytes())
                .map_err(|e| KeyStoreError::IoError(e.to_string()))?;
        }

        {
            let mut file =
                File::create(&pub_path).map_err(|e| KeyStoreError::IoError(e.to_string()))?;
            #[cfg(unix)]
            {
                let _ = file.set_permissions(fs::Permissions::from_mode(0o644));
            }
            file.write_all(pub_armor.as_bytes())
                .map_err(|e| KeyStoreError::IoError(e.to_string()))?;
        }

        Ok(Some((sec_key, pub_key)))
    }

    /// Obtém o par de chaves local apenas se já existir
    pub fn get_local_keypair(
        &self,
        email: &str,
    ) -> Result<Option<(SignedSecretKey, SignedPublicKey)>, KeyStoreError> {
        self.get_or_generate_keypair(email, false)
    }

    /// Carrega o estado de um contato externo
    pub fn get_peer_state(&self, email: &str) -> Option<PeerState> {
        let filename = Self::sanitize_email_for_filename(email);
        let peer_path = self.peers_dir.join(format!("{}.json", filename));
        if !peer_path.exists() {
            return None;
        }

        let content = fs::read_to_string(peer_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Obtém a chave pública do contato externo, se ele tiver Autocrypt ativo
    pub fn get_peer_public_key(&self, email: &str) -> Option<SignedPublicKey> {
        let state = self.get_peer_state(email)?;
        if !state.autocrypt_enabled {
            return None;
        }

        let armor = state.public_key_armor.as_deref()?;
        public_key_from_armor(armor).ok()
    }

    /// Atualiza o estado de um peer a partir de uma mensagem recebida (Autocrypt Level 1 State Machine)
    pub fn update_peer_state(
        &self,
        sender_email: &str,
        autocrypt_header: Option<&AutocryptHeader>,
        message_date_timestamp: Option<i64>,
    ) -> Result<(), KeyStoreError> {
        let clean_email = sender_email.trim().to_lowercase();
        let filename = Self::sanitize_email_for_filename(&clean_email);
        let peer_path = self.peers_dir.join(format!("{}.json", filename));

        let now = chrono::Utc::now().timestamp();
        let current_state = self.get_peer_state(&clean_email);

        let mut state = current_state.unwrap_or_else(|| PeerState {
            addr: clean_email.clone(),
            public_key_armor: None,
            prefer_encrypt: "nopreference".to_string(),
            autocrypt_enabled: false,
            effective_date: None,
            last_seen: now,
        });

        state.last_seen = now;
        let msg_date = message_date_timestamp.unwrap_or(now);

        if let Some(header) = autocrypt_header {
            // Verifica se a mensagem é mais recente ou igual ao effective_date atual
            let is_newer_or_equal = state
                .effective_date
                .map(|cur| msg_date >= cur)
                .unwrap_or(true);

            if is_newer_or_equal {
                // Tenta carregar a chave pública do cabeçalho
                if let Ok(pub_key) = public_key_from_binary(&header.keydata) {
                    if let Ok(armor) = public_key_to_armor(&pub_key) {
                        state.public_key_armor = Some(armor);
                        state.prefer_encrypt = header.prefer_encrypt.clone();
                        state.autocrypt_enabled = true;
                        state.effective_date = Some(msg_date);
                    }
                }
            }
        } else {
            // E-mail recebido SEM cabeçalho Autocrypt:
            // Regra crucial de prevenção de lockout do Autocrypt Level 1:
            // Se a mensagem for mais recente que o effective_date, faz downgrade para plain!
            let is_strictly_newer = state
                .effective_date
                .map(|cur| msg_date > cur)
                .unwrap_or(false);

            if is_strictly_newer {
                state.autocrypt_enabled = false;
                state.effective_date = Some(msg_date);
            }
        }

        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| KeyStoreError::JsonError(e.to_string()))?;

        fs::write(&peer_path, json).map_err(|e| KeyStoreError::IoError(e.to_string()))?;

        Ok(())
    }
}
