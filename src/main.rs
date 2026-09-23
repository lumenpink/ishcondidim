use ixcondidim::config::{Config, ConfigManager};
use ixcondidim::keystore::KeyStore;
use ixcondidim::milter::{run_milter_listener, EmailProcessor};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut config_path = PathBuf::from("ixcondidim.toml");

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--config" || args[i] == "-c" {
            if i + 1 < args.len() {
                config_path = PathBuf::from(&args[i + 1]);
                i += 1;
            }
        }
        i += 1;
    }

    println!("============================================================");
    println!(" 🍲 Ixcondidim - Filtro Milter Postfix Autocrypt L1 em Rust");
    println!("    Sabor caseiro, privacidade garantida e zero atrito");
    println!("============================================================");

    let config = if config_path.exists() {
        println!("Carregando configuração de: {}", config_path.display());
        Config::from_file(&config_path)?
    } else {
        println!(
            "Aviso: {} não encontrado. Usando configuração padrão.",
            config_path.display()
        );
        let mut cfg = Config::default();
        cfg.default.prefer_encrypt = Some("mutual".into());
        cfg.default.encryption_mode = Some("opportunistic".into());
        cfg.default.decrypt_incoming = Some(true);
        cfg
    };

    let listen = config.server.listen.clone();
    let keys_dir = config.storage.keys_dir.clone();
    let peers_dir = config.storage.peers_dir.clone();

    println!("Diretório de chaves locais: {}", keys_dir.display());
    println!("Diretório de contatos (peers): {}", peers_dir.display());

    let keystore = Arc::new(KeyStore::new(keys_dir, peers_dir)?);
    let manager = ConfigManager::from_config(config, config_path);
    let processor = Arc::new(EmailProcessor::new(manager.get_config(), keystore));

    println!("Servidor Milter escutando em: {}", listen);
    println!("Pronto para interceptar e proteger e-mails no Postfix.");
    println!("Pressione Ctrl+C para encerrar.");

    run_milter_listener(&listen, processor)?;

    Ok(())
}
