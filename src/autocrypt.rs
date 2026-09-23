use base64::prelude::*;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug)]
pub enum AutocryptError {
    MissingAttribute(String),
    InvalidAttribute(String),
    Base64Error(String),
}

impl fmt::Display for AutocryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutocryptError::MissingAttribute(a) => write!(f, "Autocrypt falta atributo: {}", a),
            AutocryptError::InvalidAttribute(a) => write!(f, "Autocrypt atributo inválido: {}", a),
            AutocryptError::Base64Error(e) => write!(f, "Autocrypt erro de base64: {}", e),
        }
    }
}

impl std::error::Error for AutocryptError {}

#[derive(Debug, Clone, PartialEq)]
pub struct AutocryptHeader {
    pub addr: String,
    pub prefer_encrypt: String,
    pub keydata: Vec<u8>,
    pub keydata_base64: String,
    pub extra_attributes: HashMap<String, String>,
}

impl AutocryptHeader {
    /// Faz o parse do valor de um cabeçalho Autocrypt
    pub fn parse(header_value: &str) -> Result<Self, AutocryptError> {
        let mut addr = None;
        let mut prefer_encrypt = "nopreference".to_string();
        let mut keydata_raw = None;
        let mut extra_attributes = HashMap::new();

        // Autocrypt atributos são separados por ';'
        for part in header_value.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap_or("").trim();
            let val = kv.next().unwrap_or("").trim();

            match key {
                "addr" => {
                    addr = Some(val.to_lowercase());
                }
                "prefer-encrypt" => {
                    if val == "mutual" || val == "nopreference" {
                        prefer_encrypt = val.to_string();
                    } else {
                        // Atributo desconhecido em prefer-encrypt deve cair para nopreference conforme RFC
                        prefer_encrypt = "nopreference".to_string();
                    }
                }
                "keydata" => {
                    // Remove espaços ou quebras de linha no base64
                    let clean_b64: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                    keydata_raw = Some(clean_b64);
                }
                other => {
                    // Atributos de extensão permitidos
                    if !other.is_empty() {
                        extra_attributes.insert(other.to_string(), val.to_string());
                    }
                }
            }
        }

        let addr = addr.ok_or_else(|| AutocryptError::MissingAttribute("addr".to_string()))?;
        let keydata_base64 =
            keydata_raw.ok_or_else(|| AutocryptError::MissingAttribute("keydata".to_string()))?;

        let keydata = BASE64_STANDARD
            .decode(&keydata_base64)
            .map_err(|e| AutocryptError::Base64Error(e.to_string()))?;

        Ok(Self {
            addr,
            prefer_encrypt,
            keydata,
            keydata_base64,
            extra_attributes,
        })
    }

    /// Formata a struct para o valor do cabeçalho Autocrypt
    pub fn to_header_value(&self) -> String {
        format!(
            "addr={}; prefer-encrypt={}; keydata={}",
            self.addr, self.prefer_encrypt, self.keydata_base64
        )
    }

    /// Cria uma nova instância a partir de bytes binários de chave
    pub fn new(addr: &str, prefer_encrypt: &str, key_bytes: &[u8]) -> Self {
        let clean_addr = addr.trim().to_lowercase();
        let keydata_base64 = BASE64_STANDARD.encode(key_bytes);
        Self {
            addr: clean_addr,
            prefer_encrypt: prefer_encrypt.to_string(),
            keydata: key_bytes.to_vec(),
            keydata_base64,
            extra_attributes: HashMap::new(),
        }
    }
}

/// Formata um cabeçalho Autocrypt-Gossip para compartilhamento de chaves entre múltiplos destinatários
pub fn format_autocrypt_gossip(addr: &str, key_bytes: &[u8]) -> String {
    let clean_addr = addr.trim().to_lowercase();
    let b64 = BASE64_STANDARD.encode(key_bytes);
    format!("addr={}; keydata={}", clean_addr, b64)
}
