use ishcondidim::config::Config;
use ishcondidim::keystore::KeyStore;
use ishcondidim::milter::{
    EmailProcessor, SMFIC_BODY, SMFIC_BODYEOB, SMFIC_CONNECT, SMFIC_HEADER, SMFIC_MAIL,
    SMFIC_OPTNEG, SMFIC_QUIT, SMFIC_RCPT, SMFIR_ADDHEADER, SMFIS_CONTINUE, handle_milter_stream,
};
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, RwLock};
use tempfile::tempdir;

struct MockMilterStream {
    incoming: Cursor<Vec<u8>>,
    outgoing: Vec<u8>,
}

impl MockMilterStream {
    fn new(data: Vec<u8>) -> Self {
        Self {
            incoming: Cursor::new(data),
            outgoing: Vec::new(),
        }
    }
}

impl Read for MockMilterStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.incoming.read(buf)
    }
}

impl Write for MockMilterStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_milter_frame(cmd: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    let len = (payload.len() + 1) as u32;
    frame.extend_from_slice(&len.to_be_bytes());
    frame.push(cmd);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn test_milter_protocol_session_e2e() {
    let temp = tempdir().expect("tempdir");
    let keys_dir = temp.path().join("keys");
    let peers_dir = temp.path().join("peers");

    let keystore = Arc::new(KeyStore::new(&keys_dir, &peers_dir).expect("keystore"));
    let toml = r#"
        [default]
        prefer_encrypt = "mutual"
        encryption_mode = "opportunistic"

        [domains."kiridu.net"]
        prefer_encrypt = "mutual"
    "#;
    let config = Arc::new(RwLock::new(Config::from_toml(toml).expect("config")));
    let processor = EmailProcessor::new(config, keystore);

    // Constrói a sequência de pacotes milter que o Postfix enviaria
    let mut client_bytes = Vec::new();

    // 1. Handshake OPTNEG
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_OPTNEG, &[0; 12]));

    // 2. CONNECT, MAIL, RCPT
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_CONNECT, b"mail.kiridu.net\0"));
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_MAIL, b"<lumen@kiridu.net>\0"));
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_RCPT, b"<amigo@praia.net>\0"));

    // 3. HEADER & BODY
    client_bytes.extend_from_slice(&encode_milter_frame(
        SMFIC_HEADER,
        b"From: <lumen@kiridu.net>",
    ));
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_HEADER, b"To: <amigo@praia.net>"));
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_HEADER, b"Subject: Ola praia"));
    client_bytes.extend_from_slice(&encode_milter_frame(
        SMFIC_BODY,
        b"\r\nEscondidinho quentinho com queijo coalho.",
    ));

    // 4. BODYEOB
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_BODYEOB, &[]));

    // 5. QUIT
    client_bytes.extend_from_slice(&encode_milter_frame(SMFIC_QUIT, &[]));

    let mut stream = MockMilterStream::new(client_bytes);
    handle_milter_stream(&mut stream, &processor);

    // Analisa as respostas do milter na stream
    let mut resp = Cursor::new(stream.outgoing);
    let mut saw_optneg_resp = false;
    let mut saw_addheader_resp = false;

    while let Ok(len_buf) = {
        let mut b = [0u8; 4];
        resp.read_exact(&mut b).map(|_| b)
    } {
        let packet_len = u32::from_be_bytes(len_buf) as usize;
        let mut packet = vec![0u8; packet_len];
        if resp.read_exact(&mut packet).is_err() {
            break;
        }

        let cmd = packet[0];
        if cmd == SMFIC_OPTNEG {
            saw_optneg_resp = true;
        } else if cmd == SMFIR_ADDHEADER {
            let payload = String::from_utf8_lossy(&packet[1..]);
            if payload.contains("Autocrypt") {
                saw_addheader_resp = true;
            }
        } else if cmd == SMFIS_CONTINUE {
            // normal
        }
    }

    assert!(
        saw_optneg_resp,
        "Milter deve ter respondido negociacao de protocolo"
    );
    assert!(
        saw_addheader_resp,
        "Milter deve ter injetado cabecalho Autocrypt no BODYEOB"
    );
}
