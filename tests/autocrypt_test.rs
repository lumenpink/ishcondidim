use ishcondidim::autocrypt::{format_autocrypt_gossip, AutocryptHeader};

#[test]
fn test_parse_and_format_autocrypt_header() {
    let dummy_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let ac = AutocryptHeader::new("chef@escondidinho.com", "mutual", &dummy_key);

    let header_str = ac.to_header_value();
    assert!(header_str.contains("addr=chef@escondidinho.com"));
    assert!(header_str.contains("prefer-encrypt=mutual"));
    assert!(header_str.contains("keydata="));

    let parsed = AutocryptHeader::parse(&header_str).expect("parse autocrypt header");
    assert_eq!(parsed.addr, "chef@escondidinho.com");
    assert_eq!(parsed.prefer_encrypt, "mutual");
    assert_eq!(parsed.keydata, dummy_key);
}

#[test]
fn test_parse_autocrypt_with_spaces_and_extensions() {
    let header_val = "addr=amigo@praia.com; prefer-encrypt=nopreference; _client=ishcondidim; keydata= AQIDBAUGBwgJCg== ";
    let parsed = AutocryptHeader::parse(header_val).expect("parse with extensions and spaces");

    assert_eq!(parsed.addr, "amigo@praia.com");
    assert_eq!(parsed.prefer_encrypt, "nopreference");
    assert_eq!(parsed.keydata, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    assert_eq!(
        parsed.extra_attributes.get("_client").map(|s| s.as_str()),
        Some("ishcondidim")
    );
}

#[test]
fn test_autocrypt_gossip_formatting() {
    let dummy_key = vec![10, 20, 30];
    let gossip = format_autocrypt_gossip("contato@praia.com", &dummy_key);
    assert!(gossip.starts_with("addr=contato@praia.com; keydata="));
}
