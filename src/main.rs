use ishcondidim::config::{Config, ConfigManager};
use ishcondidim::keystore::KeyStore;
use ishcondidim::milter::{run_milter_listener, EmailProcessor};
use ishcondidim::update::{
    cmd_check_update, cmd_config, cmd_update, run_startup_check, CURRENT_VERSION,
};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Roteamento de subcomandos XDG/CLI
    if args.len() > 1 {
        match args[1].as_str() {
            "check-update" => {
                let mut channel = None;
                let mut i = 2;
                while i < args.len() {
                    if args[i] == "--channel" && i + 1 < args.len() {
                        channel = Some(args[i + 1].as_str());
                        i += 1;
                    }
                    i += 1;
                }
                return cmd_check_update(channel);
            }
            "update" => {
                let mut channel = None;
                let mut pin = None;
                let mut force = false;
                let mut dry_run = false;
                let mut i = 2;
                while i < args.len() {
                    if args[i] == "--channel" && i + 1 < args.len() {
                        channel = Some(args[i + 1].as_str());
                        i += 1;
                    } else if args[i] == "--pin" && i + 1 < args.len() {
                        pin = Some(args[i + 1].as_str());
                        i += 1;
                    } else if args[i] == "--force" || args[i] == "-f" {
                        force = true;
                    } else if args[i] == "--dry-run" {
                        dry_run = true;
                    }
                    i += 1;
                }
                return cmd_update(channel, pin, force, dry_run);
            }
            "config" => {
                let config_subargs = if args.len() > 2 {
                    args[2..].to_vec()
                } else {
                    vec!["show".to_string()]
                };
                return cmd_config(&config_subargs);
            }
            _ => {}
        }
    }

    let mut config_path = PathBuf::from("ishcondidim.toml");

    let mut i = 1;
    while i < args.len() {
        if (args[i] == "--config" || args[i] == "-c") && i + 1 < args.len() {
            config_path = PathBuf::from(&args[i + 1]);
            i += 1;
        }
        i += 1;
    }

    // Verificação periódica de atualização no startup (alerta sutil em stderr)
    run_startup_check(CURRENT_VERSION);

    println!("============================================================");
    println!(" 🍲 Ishcondidim - Filtro Milter Postfix Autocrypt L1 em Rust");
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
