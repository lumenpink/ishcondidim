use crate::autocrypt::AutocryptHeader;
use crate::config::Config;
use crate::crypto::public_key_to_binary;
use crate::keystore::KeyStore;
use crate::mime::{
    EmailInfo, decrypt_pgpmime_email, encrypt_email_to_pgpmime, sanitize_plain_email_anti_spoofing,
};
use pgp::composed::SignedPublicKey;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, RwLock};

// Protocol constants do Sendmail / Postfix Milter
pub const SMFIC_OPTNEG: u8 = b'O';
pub const SMFIC_MACRO: u8 = b'D';
pub const SMFIC_CONNECT: u8 = b'C';
pub const SMFIC_HELO: u8 = b'H';
pub const SMFIC_MAIL: u8 = b'M';
pub const SMFIC_RCPT: u8 = b'R';
pub const SMFIC_DATA: u8 = b'T';
pub const SMFIC_HEADER: u8 = b'L';
pub const SMFIC_EOH: u8 = b'N';
pub const SMFIC_BODY: u8 = b'B';
pub const SMFIC_BODYEOB: u8 = b'E';
pub const SMFIC_ABORT: u8 = b'A';
pub const SMFIC_QUIT: u8 = b'Q';
pub const SMFIC_QUIT_NC: u8 = b'K';
pub const SMFIC_UNKNOWN: u8 = b'U';

pub const SMFIS_CONTINUE: u8 = b'c';
pub const SMFIR_REPLBODY: u8 = b'b';
pub const SMFIR_CHGHEADER: u8 = b'm';
pub const SMFIR_ADDHEADER: u8 = b'h';

pub const SMFIF_ADDHDRS: u32 = 0x00000001;
pub const SMFIF_CHGBODY: u32 = 0x00000002;
pub const SMFIF_CHGHDRS: u32 = 0x00000010;

#[derive(Debug, Default)]
pub struct ProcessedOutput {
    pub add_headers: Vec<(String, String)>,
    pub replace_body: Option<Vec<u8>>,
}

pub struct EmailProcessor {
    config: Arc<RwLock<Config>>,
    keystore: Arc<KeyStore>,
}

impl EmailProcessor {
    pub fn new(config: Arc<RwLock<Config>>, keystore: Arc<KeyStore>) -> Self {
        Self { config, keystore }
    }

    pub fn process_email(&self, raw_bytes: &[u8]) -> ProcessedOutput {
        let mut output = ProcessedOutput::default();

        let (info, _parsed) = match EmailInfo::parse(raw_bytes) {
            Ok(res) => res,
            Err(_) => return output,
        };

        let cfg = match self.config.read() {
            Ok(c) => c.clone(),
            Err(_) => return output,
        };

        let sender_email = info.from.as_deref().unwrap_or("");
        let sender_resolved = cfg.resolve(Some(sender_email));

        if sender_resolved.is_managed {
            // ============================================================
            // FLUXO DE SAÍDA (OUTGOING EMAIL)
            // ============================================================
            let keypair_res = self
                .keystore
                .get_or_generate_keypair(sender_email, sender_resolved.auto_generate_keys);

            if let Ok(Some((sec_key, pub_key))) = keypair_res {
                // 1. Gera o cabeçalho Autocrypt
                if sender_resolved.auto_add_header {
                    if let Ok(pub_bytes) = public_key_to_binary(&pub_key) {
                        let ac = AutocryptHeader::new(
                            sender_email,
                            &sender_resolved.prefer_encrypt,
                            &pub_bytes,
                        );
                        output
                            .add_headers
                            .push(("Autocrypt".to_string(), ac.to_header_value()));
                    }
                }

                // 2. Verifica se devemos encriptar oportunisticamente em PGP/MIME
                if sender_resolved.encryption_mode == "opportunistic" {
                    let mut all_recipients_keys: Vec<SignedPublicKey> = Vec::new();
                    let mut can_encrypt_all = !info.to.is_empty();

                    for rcpt in &info.to {
                        if let Some(peer_key) = self.keystore.get_peer_public_key(rcpt) {
                            all_recipients_keys.push(peer_key);
                        } else {
                            can_encrypt_all = false;
                            break;
                        }
                    }

                    if can_encrypt_all && !all_recipients_keys.is_empty() {
                        let recipient_refs: Vec<&SignedPublicKey> =
                            all_recipients_keys.iter().collect();
                        if let Ok(pgpmime_bytes) =
                            encrypt_email_to_pgpmime(raw_bytes, &sec_key, &recipient_refs)
                        {
                            output.replace_body = Some(pgpmime_bytes);
                        }
                    }
                }
            }
        } else {
            // ============================================================
            // FLUXO DE ENTRADA (INCOMING EMAIL / PEER DISCOVERY)
            // ============================================================
            // 1. Atualiza a máquina de estado do contato externo no KeyStore
            if !sender_email.is_empty() && sender_resolved.auto_collect_peers {
                let _ = self.keystore.update_peer_state(
                    sender_email,
                    info.autocrypt_header.as_ref(),
                    info.date_timestamp,
                );
            }

            // 2. Proteção Anti-Spoofing: e-mails em texto claro não podem imitar o selo
            if !info.is_pgp_mime {
                if let Ok(utf8_content) = std::str::from_utf8(raw_bytes) {
                    let sanitized = sanitize_plain_email_anti_spoofing(utf8_content);
                    if sanitized != utf8_content {
                        output.replace_body = Some(sanitized.into_bytes());
                    }
                }
            }

            // 3. Decifragem Server-Side de mensagens PGP/MIME recebidas
            if info.is_pgp_mime {
                // Encontra qual destinatário é uma conta local gerenciada
                for rcpt in &info.to {
                    let rcpt_resolved = cfg.resolve(Some(rcpt));
                    if rcpt_resolved.is_managed && rcpt_resolved.decrypt_incoming {
                        if let Ok(Some((sec_key, _))) = self.keystore.get_local_keypair(rcpt) {
                            let expected_sender_pub =
                                self.keystore.get_peer_public_key(sender_email);
                            if let Ok(decrypted_bytes) = decrypt_pgpmime_email(
                                raw_bytes,
                                &sec_key,
                                expected_sender_pub.as_ref(),
                                rcpt_resolved.security_word.as_deref(),
                            ) {
                                output.replace_body = Some(decrypted_bytes);
                                output.add_headers.push((
                                    "X-Ixcondidim-Status".to_string(),
                                    "decrypted-and-verified".to_string(),
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        output
    }
}

pub fn handle_milter_stream<S: Read + Write>(mut stream: S, processor: &EmailProcessor) {
    let mut header_buffer = Vec::new();
    let mut body_buffer = Vec::new();

    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).is_err() {
            break;
        }
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        if packet_len == 0 {
            continue;
        }

        let mut packet = vec![0u8; packet_len];
        if stream.read_exact(&mut packet).is_err() {
            break;
        }

        let cmd = packet[0];
        let payload = &packet[1..];

        match cmd {
            SMFIC_OPTNEG => {
                let mut response = Vec::new();
                response.push(SMFIC_OPTNEG);
                response.extend_from_slice(&6u32.to_be_bytes()); // Protocol v6
                let actions = SMFIF_CHGBODY | SMFIF_ADDHDRS | SMFIF_CHGHDRS;
                response.extend_from_slice(&actions.to_be_bytes());
                response.extend_from_slice(&0u32.to_be_bytes());

                send_frame(&mut stream, &response);
            }
            SMFIC_MACRO => {
                // Notificação de macros do MTA: não espera resposta! NUNCA responder a macros!
            }
            SMFIC_CONNECT | SMFIC_HELO | SMFIC_MAIL | SMFIC_RCPT | SMFIC_DATA | SMFIC_UNKNOWN => {
                send_simple_response(&mut stream, SMFIS_CONTINUE);
            }
            SMFIC_HEADER => {
                if let Some(pos) = payload.iter().position(|&b| b == 0) {
                    let name = &payload[..pos];
                    let mut val = &payload[pos + 1..];
                    if let Some(val_pos) = val.iter().position(|&b| b == 0) {
                        val = &val[..val_pos];
                    }
                    header_buffer.extend_from_slice(name);
                    header_buffer.extend_from_slice(b": ");
                    header_buffer.extend_from_slice(val);
                    header_buffer.extend_from_slice(b"\r\n");
                } else {
                    header_buffer.extend_from_slice(payload);
                    header_buffer.extend_from_slice(b"\r\n");
                }
                send_simple_response(&mut stream, SMFIS_CONTINUE);
            }
            SMFIC_EOH => {
                send_simple_response(&mut stream, SMFIS_CONTINUE);
            }
            SMFIC_BODY => {
                body_buffer.extend_from_slice(payload);
                send_simple_response(&mut stream, SMFIS_CONTINUE);
            }
            SMFIC_BODYEOB => {
                let full_message = if header_buffer.is_empty() {
                    body_buffer.clone()
                } else if body_buffer.starts_with(b"From:")
                    || body_buffer.starts_with(b"From: ")
                    || body_buffer.starts_with(b"Received:")
                    || body_buffer.starts_with(b"Return-Path:")
                {
                    body_buffer.clone()
                } else {
                    let mut full = Vec::with_capacity(header_buffer.len() + 2 + body_buffer.len());
                    full.extend_from_slice(&header_buffer);
                    full.extend_from_slice(b"\r\n");
                    full.extend_from_slice(&body_buffer);
                    full
                };

                let result = processor.process_email(&full_message);
                eprintln!(
                    "[ishcondidim] EOB: full_len={}, add_headers={}, repl_body={}",
                    full_message.len(),
                    result.add_headers.len(),
                    result.replace_body.is_some()
                );

                // 1. Injeta cabeçalhos (ex: Autocrypt, X-Ixcondidim-Status)
                for (name, val) in result.add_headers {
                    let mut hdr_packet = Vec::with_capacity(name.len() + val.len() + 3);
                    hdr_packet.push(SMFIR_ADDHEADER);
                    hdr_packet.extend_from_slice(name.as_bytes());
                    hdr_packet.push(0);
                    hdr_packet.extend_from_slice(val.as_bytes());
                    hdr_packet.push(0);
                    send_frame(&mut stream, &hdr_packet);
                }

                // 2. Substitui o corpo se tiver sido cifrado ou decifrado
                if let Some(new_bytes) = result.replace_body {
                    let (header_part, body_part) = split_headers_body(&new_bytes);

                    if let Some(ctype) = extract_header_value(header_part, "Content-Type") {
                        send_change_header(&mut stream, 1, "Content-Type", &ctype);
                    }
                    if let Some(mime_ver) = extract_header_value(header_part, "MIME-Version") {
                        send_change_header(&mut stream, 1, "MIME-Version", &mime_ver);
                    }
                    // Remove Content-Transfer-Encoding no nível superior, pois multipart/* não pode ter CTE raiz
                    send_change_header(&mut stream, 1, "Content-Transfer-Encoding", "");

                    for chunk in body_part.chunks(65000) {
                        let mut repl_packet = Vec::with_capacity(chunk.len() + 1);
                        repl_packet.push(SMFIR_REPLBODY);
                        repl_packet.extend_from_slice(chunk);
                        send_frame(&mut stream, &repl_packet);
                    }
                }

                send_simple_response(&mut stream, SMFIS_CONTINUE);
                header_buffer.clear();
                body_buffer.clear();
            }
            SMFIC_ABORT => {
                header_buffer.clear();
                body_buffer.clear();
            }
            SMFIC_QUIT | SMFIC_QUIT_NC => {
                break;
            }
            _ => {
                send_simple_response(&mut stream, SMFIS_CONTINUE);
            }
        }
    }
}

pub fn split_headers_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        (&raw[..pos], &raw[pos + 2..])
    } else {
        (b"", raw)
    }
}

pub fn extract_header_value(headers: &[u8], target_name: &str) -> Option<String> {
    let headers_str = std::str::from_utf8(headers).ok()?;
    let target = target_name.to_lowercase();
    let mut current_header: Option<(String, String)> = None;
    let mut result = None;

    for line in headers_str.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, ref mut val)) = current_header {
                val.push(' ');
                val.push_str(line.trim());
            }
        } else {
            if let Some((name, val)) = current_header.take() {
                if name == target {
                    result = Some(val);
                    break;
                }
            }
            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                let val = line[colon_pos + 1..].trim().to_string();
                current_header = Some((name, val));
            }
        }
    }
    if result.is_none() {
        if let Some((name, val)) = current_header {
            if name == target {
                result = Some(val);
            }
        }
    }
    result
}

pub fn send_change_header<W: Write>(writer: &mut W, index: u32, name: &str, value: &str) {
    let mut pkt = Vec::new();
    pkt.push(SMFIR_CHGHEADER);
    pkt.extend_from_slice(&index.to_be_bytes());
    pkt.extend_from_slice(name.as_bytes());
    pkt.push(0);
    pkt.extend_from_slice(value.as_bytes());
    pkt.push(0);
    send_frame(writer, &pkt);
}

fn send_frame<W: Write>(writer: &mut W, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    let _ = writer.write_all(&len);
    let _ = writer.write_all(data);
    let _ = writer.flush();
}

fn send_simple_response<W: Write>(writer: &mut W, code: u8) {
    send_frame(writer, &[code]);
}

pub fn run_milter_listener(listen: &str, processor: Arc<EmailProcessor>) -> std::io::Result<()> {
    if let Some(sock_path) = listen.strip_prefix("unix:") {
        let path = Path::new(sock_path);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        let listener = UnixListener::bind(path)?;
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                let proc = Arc::clone(&processor);
                std::thread::spawn(move || {
                    handle_milter_stream(s, &proc);
                });
            }
        }
    } else if let Some(addr) = listen.strip_prefix("inet:") {
        let listener = TcpListener::bind(addr)?;
        for stream in listener.incoming() {
            if let Ok(s) = stream {
                let proc = Arc::clone(&processor);
                std::thread::spawn(move || {
                    handle_milter_stream(s, &proc);
                });
            }
        }
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Formato de escuta inválido: {}. Use 'unix:/caminho' ou 'inet:ip:porta'",
                listen
            ),
        ));
    }

    Ok(())
}
