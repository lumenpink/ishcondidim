use ixcondidim::config::Config;

#[test]
fn test_default_config_resolution() {
    let toml = r#"
        [server]
        listen = "unix:/run/ixcondidim/test.sock"

        [default]
        prefer_encrypt = "mutual"
        encryption_mode = "opportunistic"
        decrypt_incoming = true
        security_word = "SaborDePraia"
    "#;

    let cfg = Config::from_toml(toml).expect("parse toml");
    assert_eq!(cfg.server.listen, "unix:/run/ixcondidim/test.sock");

    let resolved = cfg.resolve(Some("user@unknown.com"));
    assert!(!resolved.is_managed);
    assert_eq!(resolved.prefer_encrypt, "mutual");
    assert_eq!(resolved.encryption_mode, "opportunistic");
    assert!(resolved.decrypt_incoming);
    assert_eq!(resolved.security_word.as_deref(), Some("SaborDePraia"));
}

#[test]
fn test_hierarchical_resolution_domain_and_sender() {
    let toml = r#"
        [default]
        prefer_encrypt = "nopreference"
        encryption_mode = "opportunistic"
        decrypt_incoming = false
        security_word = "DefaultWord"

        [domains."kiridu.net"]
        prefer_encrypt = "mutual"
        decrypt_incoming = true
        security_word = "KiriduPraiano"

        [senders."boss@kiridu.net"]
        prefer_encrypt = "mutual"
        encryption_mode = "header_only"
        security_word = "DiretoriaSegredo"
    "#;

    let cfg = Config::from_toml(toml).expect("parse toml");

    // 1. Domínio gerenciado
    let res_dev = cfg.resolve(Some("dev@kiridu.net"));
    assert!(res_dev.is_managed);
    assert_eq!(res_dev.prefer_encrypt, "mutual");
    assert_eq!(res_dev.encryption_mode, "opportunistic");
    assert!(res_dev.decrypt_incoming);
    assert_eq!(res_dev.security_word.as_deref(), Some("KiriduPraiano"));

    // 2. Remetente específico (sobrescreve domínio)
    let res_boss = cfg.resolve(Some("boss@kiridu.net"));
    assert!(res_boss.is_managed);
    assert_eq!(res_boss.prefer_encrypt, "mutual");
    assert_eq!(res_boss.encryption_mode, "header_only");
    assert!(res_boss.decrypt_incoming);
    assert_eq!(res_boss.security_word.as_deref(), Some("DiretoriaSegredo"));

    // 3. Remetente externo
    let res_ext = cfg.resolve(Some("external@outro.com"));
    assert!(!res_ext.is_managed);
    assert_eq!(res_ext.prefer_encrypt, "nopreference");
    assert!(!res_ext.decrypt_incoming);
    assert_eq!(res_ext.security_word.as_deref(), Some("DefaultWord"));
}
