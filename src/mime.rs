use crate::autocrypt::AutocryptHeader;
use crate::crypto::{decrypt_message, sign_and_encrypt};
use mail_builder::headers::raw::Raw;
use mail_builder::MessageBuilder;
use mail_parser::{HeaderValue, MessageParser, MimeHeaders};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use std::fmt;

#[derive(Debug)]
pub enum MimeProcessingError {
    ParseError(String),
    BuildError(String),
    CryptoError(String),
}

impl fmt::Display for MimeProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MimeProcessingError::ParseError(e) => write!(f, "MIME Parse Error: {}", e),
            MimeProcessingError::BuildError(e) => write!(f, "MIME Build Error: {}", e),
            MimeProcessingError::CryptoError(e) => write!(f, "MIME Crypto Error: {}", e),
        }
    }
}

impl std::error::Error for MimeProcessingError {}

#[derive(Debug, Clone)]
pub struct EmailInfo {
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub subject: Option<String>,
    pub date_timestamp: Option<i64>,
    pub is_pgp_mime: bool,
    pub autocrypt_header: Option<AutocryptHeader>,
}

impl EmailInfo {
    pub fn parse(raw_bytes: &[u8]) -> Result<(Self, mail_parser::Message<'_>), MimeProcessingError> {
        let msg = MessageParser::default()
            .parse(raw_bytes)
            .ok_or_else(|| MimeProcessingError::ParseError("Falha ao analisar MIME".into()))?;

        let from = msg
            .from()
            .and_then(|f| f.first())
            .and_then(|addr| addr.address())
            .map(|s| s.to_lowercase());

        let mut to = Vec::new();
        if let Some(to_addrs) = msg.to() {
            for addr in to_addrs.iter() {
                if let Some(a) = addr.address() {
                    to.push(a.to_lowercase());
                }
            }
        }

        let mut cc = Vec::new();
        if let Some(cc_addrs) = msg.cc() {
            for addr in cc_addrs.iter() {
                if let Some(a) = addr.address() {
                    cc.push(a.to_lowercase());
                }
            }
        }

        let subject = msg.subject().map(|s| s.to_string());
        let date_timestamp = msg.date().map(|d| d.to_timestamp());

        // Verifica se é PGP/MIME (Content-Type: multipart/encrypted; protocol="application/pgp-encrypted")
        let is_pgp_mime = msg
            .header("Content-Type")
            .map(|h| match h {
                HeaderValue::ContentType(ct) => {
                    ct.c_type.eq_ignore_ascii_case("multipart")
                        && ct.c_subtype.as_deref().unwrap_or("").eq_ignore_ascii_case("encrypted")
                }
                _ => false,
            })
            .unwrap_or(false);

        // Extrai o cabeçalho Autocrypt
        let mut autocrypt_header = None;
        if let Some(from_addr) = &from {
            for h in msg.headers() {
                if h.name.as_str().eq_ignore_ascii_case("Autocrypt") {
                    if let HeaderValue::Text(val) = &h.value {
                        if let Ok(parsed_ac) = AutocryptHeader::parse(val) {
                            if parsed_ac.addr == *from_addr {
                                autocrypt_header = Some(parsed_ac);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let info = Self {
            from,
            to,
            cc,
            subject,
            date_timestamp,
            is_pgp_mime,
            autocrypt_header,
        };

        Ok((info, msg))
    }
}

/// Sanitiza e-mails em texto claro para evitar que atacantes forjem o banner de segurança oficial
pub fn sanitize_plain_email_anti_spoofing(content: &str) -> String {
    let patterns = [
        "[Ishcondidim:",
        "[ishcondidim:",
        "ishcondidim-badge",
        "🔒 [Ishcondidim",
        "[Ixcondidim:",
        "[ixcondidim:",
        "ixcondidim-badge",
        "🔒 [Ixcondidim",
    ];

    let mut result = content.to_string();
    let mut modified = false;

    for pat in patterns {
        if result.contains(pat) {
            result = result.replace(
                pat,
                "[⚠️ ALERTA: Tentativa de simulação de aviso de segurança desarmada: ",
            );
            modified = true;
        }
    }

    if modified {
        format!(
            "<!-- ishcondidim-security: neutralized suspicious badge simulation -->\n{}",
            result
        )
    } else {
        result
    }
}

/// Constrói o banner visual de validação (com security_word se configurada)
pub fn build_security_banner_html(
    sender: &str,
    is_signed: bool,
    is_signature_valid: bool,
    signer_key: Option<&str>,
    security_word: Option<&str>,
) -> String {
    let word_html = if let Some(word) = security_word {
        format!(
            "<tr><td style=\"padding: 2px 8px 2px 0; color: #475569;\">Palavra Secreta:</td><td><strong style=\"color: #047857; background: #d1fae5; padding: 1px 6px; border-radius: 3px;\">[{}]</strong> (Validação de Autenticidade)</td></tr>",
            word
        )
    } else {
        String::new()
    };

    let sig_status_html = if is_signed && is_signature_valid {
        "<span style=\"color: #059669; font-weight: bold;\">✓ VÁLIDA (Assinatura digital confirmada)</span>"
    } else if is_signed {
        "<span style=\"color: #dc2626; font-weight: bold;\">✗ INVÁLIDA (Falha na verificação da assinatura)</span>"
    } else {
        "<span style=\"color: #d97706;\">ℹ Não assinada pelo remetente</span>"
    };

    let key_html = signer_key.unwrap_or("Chave embutida no pacote");

    format!(
        r#"<div style="border-left: 4px solid #10b981; background: #f0fdf4; padding: 12px 16px; margin: 0 0 16px 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 13px; line-height: 1.5; color: #1e293b; border-radius: 4px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
  <div style="display: flex; align-items: center; font-weight: bold; color: #166534; font-size: 14px; margin-bottom: 6px;">
    🔒 [Ixcondidim: Mensagem PGP Decifrada pelo Servidor]
  </div>
  <table style="border-collapse: collapse; font-size: 12px; width: 100%;">
    {word_html}
    <tr><td style="padding: 2px 8px 2px 0; color: #475569; width: 120px;">Remetente:</td><td><code>{sender}</code></td></tr>
    <tr><td style="padding: 2px 8px 2px 0; color: #475569;">Assinatura:</td><td>{sig_status_html}</td></tr>
    <tr><td style="padding: 2px 8px 2px 0; color: #475569;">ID da Chave:</td><td><code>{key_html}</code></td></tr>
  </table>
</div>
"#,
        word_html = word_html,
        sender = sender,
        sig_status_html = sig_status_html,
        key_html = key_html
    )
}

/// Constrói o banner visual de validação para texto puro (`text/plain`)
pub fn build_security_banner_text(
    sender: &str,
    is_signed: bool,
    is_signature_valid: bool,
    signer_key: Option<&str>,
    security_word: Option<&str>,
) -> String {
    let word_line = if let Some(word) = security_word {
        format!("│ Palavra Secreta de Validação: [{}]\n", word)
    } else {
        String::new()
    };

    let sig_status = if is_signed && is_signature_valid {
        "VÁLIDA (Assinatura digital confirmada)"
    } else if is_signed {
        "INVÁLIDA (Falha na verificação)"
    } else {
        "Não assinada"
    };

    let key_id = signer_key.unwrap_or("N/A");

    format!(
        "┌── 🔒 [Ixcondidim: Mensagem PGP Decifrada pelo Servidor] ──────────────\n\
         {}│ Remetente: {}\n\
         │ Assinatura Digital: {}\n\
         │ ID da Chave: {}\n\
         └───────────────────────────────────────────────────────────────────────\n\n",
        word_line, sender, sig_status, key_id
    )
}

/// Encripta uma mensagem para múltiplos destinatários no formato padrão PGP/MIME (RFC 3156)
pub fn encrypt_email_to_pgpmime(
    raw_original_bytes: &[u8],
    sender_secret: &SignedSecretKey,
    recipient_publics: &[&SignedPublicKey],
) -> Result<Vec<u8>, MimeProcessingError> {
    // 1. Cifra os bytes originais com OpenPGP
    let armored_encrypted = sign_and_encrypt(raw_original_bytes, sender_secret, recipient_publics)
        .map_err(|e| MimeProcessingError::CryptoError(e.to_string()))?;

    // 2. Extrai cabeçalhos originais (From, To, Cc, Subject, Message-ID, Date)
    let parsed = MessageParser::default()
        .parse(raw_original_bytes)
        .ok_or_else(|| MimeProcessingError::ParseError("Falha ao reanalisar MIME".into()))?;

    let boundary = format!("ishcondidim_boundary_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

    let mut out = Vec::new();

    // Copia cabeçalhos principais essenciais
    if let Some(from) = parsed.from().and_then(|f| f.first()).and_then(|a| a.address()) {
        out.extend_from_slice(format!("From: <{}>\r\n", from).as_bytes());
    }
    if let Some(subject) = parsed.subject() {
        out.extend_from_slice(format!("Subject: {}\r\n", subject).as_bytes());
    }
    if let Some(msg_id) = parsed.message_id() {
        out.extend_from_slice(format!("Message-ID: <{}>\r\n", msg_id).as_bytes());
    }
    if let Some(date) = parsed.date() {
        out.extend_from_slice(format!("Date: {}\r\n", date.to_rfc822()).as_bytes());
    }

    out.extend_from_slice(
        format!(
            "MIME-Version: 1.0\r\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{}\"\r\n\r\n",
            boundary
        )
        .as_bytes(),
    );

    // Parte 1: identificação do protocolo PGP/MIME
    out.extend_from_slice(
        format!(
            "--{}\r\n\
             Content-Type: application/pgp-encrypted\r\n\
             Content-Description: PGP/MIME version identification\r\n\r\n\
             Version: 1\r\n\r\n",
            boundary
        )
        .as_bytes(),
    );

    // Parte 2: o payload cifrado
    out.extend_from_slice(
        format!(
            "--{}\r\n\
             Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
             Content-Description: OpenPGP encrypted message\r\n\
             Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n\
             {}\r\n\
             --{}--\r\n",
            boundary, armored_encrypted, boundary
        )
        .as_bytes(),
    );

    Ok(out)
}

/// Decifra um e-mail PGP/MIME recebido e injeta o banner de segurança com palavra de segurança
pub fn decrypt_pgpmime_email(
    raw_encrypted_bytes: &[u8],
    recipient_secret: &SignedSecretKey,
    expected_sender_pub: Option<&SignedPublicKey>,
    security_word: Option<&str>,
) -> Result<Vec<u8>, MimeProcessingError> {
    let parsed = MessageParser::default()
        .parse(raw_encrypted_bytes)
        .ok_or_else(|| MimeProcessingError::ParseError("Falha ao analisar mensagem PGP/MIME".into()))?;

    // Procura o payload cifrado na segunda parte (application/octet-stream)
    let mut encrypted_payload: Option<Vec<u8>> = None;

    for part in &parsed.parts {
        if let Some(content_type) = part.content_type() {
            if content_type.c_type.eq_ignore_ascii_case("application")
                && content_type.c_subtype.as_deref().unwrap_or("").eq_ignore_ascii_case("octet-stream")
            {
                encrypted_payload = Some(part.contents().to_vec());
                break;
            }
        }
    }

    let payload = encrypted_payload.ok_or_else(|| {
        MimeProcessingError::ParseError("Nenhum anexo application/octet-stream encontrado no PGP/MIME".into())
    })?;

    // Decifra o payload
    let dec_res = decrypt_message(&payload, recipient_secret, expected_sender_pub)
        .map_err(|e| MimeProcessingError::CryptoError(e.to_string()))?;

    let sender = parsed
        .from()
        .and_then(|f| f.first())
        .and_then(|a| a.address())
        .unwrap_or("desconhecido");

    // Decodifica a mensagem decifrada como MIME
    let decrypted_msg = MessageParser::default().parse(&dec_res.content);

    let final_bytes = if let Some(inner) = decrypted_msg {
        // Se a mensagem interna tiver HTML ou Plain, injeta o banner
        let banner_html = build_security_banner_html(
            sender,
            dec_res.is_signed,
            dec_res.is_signature_valid,
            dec_res.signer_key_id.as_deref(),
            security_word,
        );
        let banner_text = build_security_banner_text(
            sender,
            dec_res.is_signed,
            dec_res.is_signature_valid,
            dec_res.signer_key_id.as_deref(),
            security_word,
        );

        let mut builder = MessageBuilder::new();

        if let Some(from) = inner.from().and_then(|f| f.first()).and_then(|a| a.address()) {
            builder = builder.from(from);
        }
        if let Some(sub) = inner.subject() {
            builder = builder.subject(sub);
        }
        if let Some(date) = inner.date() {
            builder = builder.date(date.to_timestamp());
        }

        // Adiciona cabeçalho informativo do Ixcondidim
        builder = builder.header(
            "X-Ixcondidim-Decrypted",
            Raw::new("true; verified=pass"),
        );

        let body_html = inner
            .body_html(0)
            .map(|h| format!("{}{}", banner_html, h));
        let body_text = inner
            .body_text(0)
            .map(|t| format!("{}{}", banner_text, t));

        if let Some(txt) = body_text {
            builder = builder.text_body(txt);
        }
        if let Some(html) = body_html {
            builder = builder.html_body(html);
        }
        if inner.body_text(0).is_none() && inner.body_html(0).is_none() {
            builder = builder.text_body(banner_text);
        }

        builder.write_to_vec().map_err(|e| MimeProcessingError::BuildError(e.to_string()))?
    } else {
        // Não é MIME válido, anexa como texto bruto
        let banner_text = build_security_banner_text(
            sender,
            dec_res.is_signed,
            dec_res.is_signature_valid,
            dec_res.signer_key_id.as_deref(),
            security_word,
        );
        let mut combined = banner_text.into_bytes();
        combined.extend_from_slice(&dec_res.content);
        combined
    };

    Ok(final_bytes)
}

/// Injeta o cabeçalho Autocrypt no e-mail de saída
pub fn inject_autocrypt_header(
    raw_email: &[u8],
    autocrypt_header_val: &str,
) -> Vec<u8> {
    let header_line = format!("Autocrypt: {}\r\n", autocrypt_header_val);
    let mut out = Vec::with_capacity(raw_email.len() + header_line.len());

    // Procura o fim dos cabeçalhos (\r\n\r\n ou \n\n)
    if let Some(pos) = raw_email.windows(4).position(|w| w == b"\r\n\r\n") {
        out.extend_from_slice(&raw_email[..pos]);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(header_line.as_bytes());
        out.extend_from_slice(&raw_email[pos..]);
    } else if let Some(pos) = raw_email.windows(2).position(|w| w == b"\n\n") {
        out.extend_from_slice(&raw_email[..pos]);
        out.extend_from_slice(b"\n");
        out.extend_from_slice(format!("Autocrypt: {}\n", autocrypt_header_val).as_bytes());
        out.extend_from_slice(&raw_email[pos..]);
    } else {
        out.extend_from_slice(header_line.as_bytes());
        out.extend_from_slice(raw_email);
    }

    out
}
