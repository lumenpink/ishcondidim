use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub enum ConfigError {
    IoError(String),
    TomlError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "Config IO Error: {}", e),
            ConfigError::TomlError(e) => write!(f, "Config TOML Error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
}

fn default_listen() -> String {
    "unix:/run/ixcondidim/ixcondidim.sock".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_keys_dir")]
    pub keys_dir: PathBuf,
    #[serde(default = "default_peers_dir")]
    pub peers_dir: PathBuf,
}

fn default_keys_dir() -> PathBuf {
    PathBuf::from("/var/lib/ixcondidim/keys")
}

fn default_peers_dir() -> PathBuf {
    PathBuf::from("/var/lib/ixcondidim/peers")
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            keys_dir: default_keys_dir(),
            peers_dir: default_peers_dir(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub prefer_encrypt: Option<String>,
    pub auto_generate_keys: Option<bool>,
    pub auto_add_header: Option<bool>,
    pub auto_collect_peers: Option<bool>,
    pub encryption_mode: Option<String>,
    pub decrypt_incoming: Option<bool>,
    pub security_word: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, toml::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub default: ProfileConfig,
    #[serde(default)]
    pub domains: HashMap<String, ProfileConfig>,
    #[serde(default)]
    pub senders: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConfig {
    pub is_managed: bool,
    pub prefer_encrypt: String,
    pub auto_generate_keys: bool,
    pub auto_add_header: bool,
    pub auto_collect_peers: bool,
    pub encryption_mode: String,
    pub decrypt_incoming: bool,
    pub security_word: Option<String>,
    pub extra: HashMap<String, toml::Value>,
}

impl Config {
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(|e| ConfigError::TomlError(e.to_string()))
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::IoError(format!("{}: {}", path.display(), e)))?;
        Self::from_toml(&content)
    }

    pub fn is_domain_managed(&self, domain: &str) -> bool {
        self.domains.contains_key(domain)
    }

    pub fn resolve(&self, sender_email: Option<&str>) -> ResolvedConfig {
        let mut prefer_encrypt = self
            .default
            .prefer_encrypt
            .clone()
            .unwrap_or_else(|| "mutual".to_string());
        let mut auto_generate_keys = self.default.auto_generate_keys.unwrap_or(true);
        let mut auto_add_header = self.default.auto_add_header.unwrap_or(true);
        let mut auto_collect_peers = self.default.auto_collect_peers.unwrap_or(true);
        let mut encryption_mode = self
            .default
            .encryption_mode
            .clone()
            .unwrap_or_else(|| "opportunistic".to_string());
        let mut decrypt_incoming = self.default.decrypt_incoming.unwrap_or(true);
        let mut security_word = self.default.security_word.clone();
        let mut extra = self.default.extra.clone();

        let mut is_managed = false;

        if let Some(email) = sender_email {
            let email_clean = email.trim().to_lowercase();
            let domain = email_clean.split('@').nth(1).unwrap_or("");

            // 1. Cascata de Domínio
            if let Some(dom_cfg) = self.domains.get(domain) {
                is_managed = true;
                if let Some(v) = &dom_cfg.prefer_encrypt {
                    prefer_encrypt = v.clone();
                }
                if let Some(v) = dom_cfg.auto_generate_keys {
                    auto_generate_keys = v;
                }
                if let Some(v) = dom_cfg.auto_add_header {
                    auto_add_header = v;
                }
                if let Some(v) = dom_cfg.auto_collect_peers {
                    auto_collect_peers = v;
                }
                if let Some(v) = &dom_cfg.encryption_mode {
                    encryption_mode = v.clone();
                }
                if let Some(v) = dom_cfg.decrypt_incoming {
                    decrypt_incoming = v;
                }
                if dom_cfg.security_word.is_some() {
                    security_word = dom_cfg.security_word.clone();
                }
                for (k, v) in &dom_cfg.extra {
                    extra.insert(k.clone(), v.clone());
                }
            }

            // 2. Cascata específica de Remetente (sobrescreve domínio)
            if let Some(snd_cfg) = self.senders.get(&email_clean) {
                is_managed = true;
                if let Some(v) = &snd_cfg.prefer_encrypt {
                    prefer_encrypt = v.clone();
                }
                if let Some(v) = snd_cfg.auto_generate_keys {
                    auto_generate_keys = v;
                }
                if let Some(v) = snd_cfg.auto_add_header {
                    auto_add_header = v;
                }
                if let Some(v) = snd_cfg.auto_collect_peers {
                    auto_collect_peers = v;
                }
                if let Some(v) = &snd_cfg.encryption_mode {
                    encryption_mode = v.clone();
                }
                if let Some(v) = snd_cfg.decrypt_incoming {
                    decrypt_incoming = v;
                }
                if snd_cfg.security_word.is_some() {
                    security_word = snd_cfg.security_word.clone();
                }
                for (k, v) in &snd_cfg.extra {
                    extra.insert(k.clone(), v.clone());
                }
            }
        }

        ResolvedConfig {
            is_managed,
            prefer_encrypt,
            auto_generate_keys,
            auto_add_header,
            auto_collect_peers,
            encryption_mode,
            decrypt_incoming,
            security_word,
            extra,
        }
    }
}

pub struct ConfigManager {
    config: Arc<RwLock<Config>>,
    _watcher: Option<RecommendedWatcher>,
}

impl ConfigManager {
    pub fn new(path: PathBuf) -> Result<Self, ConfigError> {
        let config = Config::from_file(&path)?;
        let config_arc = Arc::new(RwLock::new(config));

        let config_clone = Arc::clone(&config_arc);
        let watch_path = path.clone();

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        if let Ok(new_cfg) = Config::from_file(&watch_path) {
                            if let Ok(mut w) = config_clone.write() {
                                *w = new_cfg;
                                eprintln!("[ixcondidim] Configuração recarregada com sucesso!");
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[ixcondidim] Erro no watcher de configuração: {:?}", e),
            },
            notify::Config::default(),
        )
        .map_err(|e| ConfigError::IoError(e.to_string()))?;

        let _ = watcher.watch(&path, RecursiveMode::NonRecursive);

        Ok(Self {
            config: config_arc,
            _watcher: Some(watcher),
        })
    }

    pub fn from_config(config: Config, path: PathBuf) -> Self {
        let config_arc = Arc::new(RwLock::new(config));
        let config_clone = Arc::clone(&config_arc);
        let watch_path = path.clone();

        let watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| match res {
                Ok(event) => {
                    if event.kind.is_modify() {
                        if let Ok(new_cfg) = Config::from_file(&watch_path) {
                            if let Ok(mut w) = config_clone.write() {
                                *w = new_cfg;
                                eprintln!("[ixcondidim] Configuração recarregada com sucesso!");
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[ixcondidim] Erro no watcher: {:?}", e),
            },
            notify::Config::default(),
        );

        let active_watcher = match watcher {
            Ok(mut w) => {
                let _ = w.watch(&path, RecursiveMode::NonRecursive);
                Some(w)
            }
            Err(_) => None,
        };

        Self {
            config: config_arc,
            _watcher: active_watcher,
        }
    }

    pub fn get_config(&self) -> Arc<RwLock<Config>> {
        Arc::clone(&self.config)
    }
}
