//! Módulo de atualização atômica e conformidade com padrão OpenDesktop (XDG Base Directory).

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const APP_NAME: &str = "ishcondidim";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub pin: String,
    #[serde(default = "default_true")]
    pub auto_check: bool,
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u64,
    #[serde(default)]
    pub auto_update: bool,
}

fn default_channel() -> String {
    "stable".to_string()
}

fn default_true() -> bool {
    true
}

fn default_check_interval() -> u64 {
    24
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            channel: default_channel(),
            pinned: false,
            pin: String::new(),
            auto_check: true,
            check_interval_hours: default_check_interval(),
            auto_update: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfigFile {
    #[serde(default)]
    pub update: UpdateConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateState {
    pub last_check_timestamp: u64,
    pub latest_remote_version: String,
    pub channel: String,
}

/// Retorna o caminho de configuração segundo o padrão XDG
pub fn get_config_path() -> PathBuf {
    if let Ok(val) = env::var("XDG_CONFIG_HOME") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join(APP_NAME).join("config.toml");
        }
    }
    if let Ok(home) = env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join(".config")
                .join(APP_NAME)
                .join("config.toml");
        }
    }
    PathBuf::from(".config/ishcondidim/config.toml")
}

/// Retorna o caminho de cache/estado segundo o padrão XDG
pub fn get_state_path() -> PathBuf {
    if let Ok(val) = env::var("XDG_STATE_HOME") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join(APP_NAME)
                .join("update_check.json");
        }
    }
    if let Ok(home) = env::var("HOME") {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed)
                .join(".local")
                .join("state")
                .join(APP_NAME)
                .join("update_check.json");
        }
    }
    PathBuf::from(".local/state/ishcondidim/update_check.json")
}

/// Retorna o caminho padrão de instalação do binário executável
pub fn get_target_bin_path() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        let p = PathBuf::from(home)
            .join(".local")
            .join("bin")
            .join(APP_NAME);
        if p.exists() {
            return p;
        }
    }
    if let Ok(exe) = env::current_exe() {
        return exe;
    }
    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("bin")
            .join(APP_NAME);
    }
    PathBuf::from(APP_NAME)
}

/// Carrega a configuração de atualização
pub fn load_update_config(path: Option<&Path>) -> UpdateConfig {
    let p = path.map(PathBuf::from).unwrap_or_else(get_config_path);
    if !p.exists() {
        return UpdateConfig::default();
    }
    if let Ok(content) = fs::read_to_string(&p) {
        if let Ok(app_cfg) = toml::from_str::<AppConfigFile>(&content) {
            return app_cfg.update;
        }
    }
    UpdateConfig::default()
}

/// Salva a configuração de atualização
pub fn save_update_config(
    cfg: &UpdateConfig,
    path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = path.map(PathBuf::from).unwrap_or_else(get_config_path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let app_cfg = AppConfigFile {
        update: cfg.clone(),
    };
    let content = toml::to_string_pretty(&app_cfg)?;
    fs::write(&p, content)?;
    Ok(())
}

/// Carrega o estado de cache de atualização
pub fn load_update_state(path: Option<&Path>) -> UpdateState {
    let p = path.map(PathBuf::from).unwrap_or_else(get_state_path);
    if !p.exists() {
        return UpdateState::default();
    }
    if let Ok(content) = fs::read_to_string(&p) {
        if let Ok(state) = serde_json::from_str::<UpdateState>(&content) {
            return state;
        }
    }
    UpdateState::default()
}

/// Salva o estado de cache de atualização
pub fn save_update_state(
    state: &UpdateState,
    path: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let p = path.map(PathBuf::from).unwrap_or_else(get_state_path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    fs::write(&p, content)?;
    Ok(())
}

/// Resolve o canal ativo com estrita ordem de precedência:
/// flag > env > config > "stable"
pub fn resolve_channel(
    flag: Option<&str>,
    env_val: Option<&str>,
    config_path: Option<&Path>,
) -> String {
    if let Some(f) = flag.map(str::trim).filter(|s| !s.is_empty()) {
        return f.to_ascii_lowercase();
    }
    if let Some(e) = env_val.map(str::trim).filter(|s| !s.is_empty()) {
        return e.to_ascii_lowercase();
    }
    if let Ok(e) = env::var("ISHCONDIDIM_CHANNEL") {
        let trimmed = e.trim();
        if !trimmed.is_empty() {
            return trimmed.to_ascii_lowercase();
        }
    }
    let cfg = load_update_config(config_path);
    let ch = cfg.channel.trim();
    if !ch.is_empty() {
        return ch.to_ascii_lowercase();
    }
    "stable".to_string()
}

/// Verifica se a versão está travada (pinning)
pub fn is_version_pinned(cfg: &UpdateConfig, _current_ver: &str) -> bool {
    cfg.pinned || !cfg.pin.trim().is_empty()
}

/// Retorna os endpoints soberanos oficiais de distribuição na Banca: (stable_url, nightly_url, version_url)
pub fn get_distribution_endpoints(channel: &str) -> (String, String, String) {
    let stable = format!("https://banca.2lp.in/downloads/{}/stable-latest", APP_NAME);
    let nightly = format!("https://banca.2lp.in/downloads/{}/nightly-latest", APP_NAME);
    let ver = if channel == "nightly" {
        format!(
            "https://banca.2lp.in/downloads/{}/nightly-latest.version",
            APP_NAME
        )
    } else {
        format!(
            "https://banca.2lp.in/downloads/{}/stable-latest.version",
            APP_NAME
        )
    };
    (stable, nightly, ver)
}

/// Retorna a URL de download correspondente à seleção
pub fn get_download_url(channel: &str, pin: Option<&str>) -> String {
    if let Some(p) = pin.map(str::trim).filter(|s| !s.is_empty()) {
        let clean = p.trim_start_matches('v');
        format!(
            "https://banca.2lp.in/downloads/{}/{}-{}-linux-x86_64",
            APP_NAME, APP_NAME, clean
        )
    } else if channel == "nightly" {
        format!("https://banca.2lp.in/downloads/{}/nightly-latest", APP_NAME)
    } else {
        format!("https://banca.2lp.in/downloads/{}/stable-latest", APP_NAME)
    }
}

/// Compara se a versão remota é mais recente que a local conforme SemVer
pub fn semver_is_newer(remote: &str, current: &str) -> bool {
    let r_clean = remote.trim().trim_start_matches('v');
    let c_clean = current.trim().trim_start_matches('v');
    if r_clean == c_clean {
        return false;
    }

    fn parse_parts(s: &str) -> (Vec<u64>, String) {
        let mut parts = Vec::new();
        let mut rest = String::new();
        let main_part = s.split('+').next().unwrap_or(s);
        let base = main_part.split('-').next().unwrap_or(main_part);
        for seg in base.split('.') {
            if let Ok(n) = seg.parse::<u64>() {
                parts.push(n);
            }
        }
        if main_part.contains('-') {
            rest = main_part.splitn(2, '-').nth(1).unwrap_or("").to_string();
        }
        (parts, rest)
    }

    let (r_parts, r_extra) = parse_parts(r_clean);
    let (c_parts, c_extra) = parse_parts(c_clean);

    for (r, c) in r_parts.iter().zip(c_parts.iter()) {
        if r > c {
            return true;
        }
        if r < c {
            return false;
        }
    }
    if r_parts.len() > c_parts.len() {
        return true;
    }
    if r_parts.len() < c_parts.len() {
        return false;
    }

    if !c_extra.is_empty() && r_extra.is_empty() {
        return true;
    }
    if c_extra.is_empty() && !r_extra.is_empty() {
        return false;
    }
    if !r_extra.is_empty() && !c_extra.is_empty() {
        return r_extra > c_extra;
    }

    r_clean > c_clean
}

/// Executa a atualização atômica de forma segura no filesystem
pub fn perform_atomic_update(
    target_path: &Path,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let parent = target_path
        .parent()
        .ok_or("Diretório pai do destino inválido")?;
    fs::create_dir_all(parent)?;

    let temp_path = parent.join(format!(".{}-update-{}", APP_NAME, std::process::id()));
    fs::write(&temp_path, bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&temp_path, perms)?;
    }

    let backup_path = parent.join(format!(".{}-backup.bak", APP_NAME));
    let has_backup = if target_path.exists() {
        let _ = fs::remove_file(&backup_path);
        fs::copy(target_path, &backup_path).is_ok()
    } else {
        false
    };

    if let Err(e) = fs::rename(&temp_path, target_path) {
        if has_backup && backup_path.exists() {
            let _ = fs::rename(&backup_path, target_path);
        }
        let _ = fs::remove_file(&temp_path);
        return Err(format!("Falha na substituição atômica: {}", e).into());
    }

    if has_backup && backup_path.exists() {
        let _ = fs::remove_file(&backup_path);
    }

    Ok(())
}

/// Verificação não-bloqueante no startup emitida discretamente em stderr
pub fn run_startup_check(current_version: &str) {
    let cfg = load_update_config(None);
    if !cfg.auto_check || cfg.pinned || !cfg.pin.is_empty() {
        return;
    }

    let state = load_update_state(None);
    let channel = resolve_channel(None, None, None);

    if !state.latest_remote_version.is_empty()
        && semver_is_newer(&state.latest_remote_version, current_version)
    {
        eprintln!(
            "💡 [{}] Nova versão disponível: v{} (atual: v{}).\n   Execute '{} update' para atualizar.",
            APP_NAME, state.latest_remote_version, current_version, APP_NAME
        );
        return;
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let interval_secs = cfg.check_interval_hours * 3600;
    if now.saturating_sub(state.last_check_timestamp) >= interval_secs {
        let (_, _, ver_url) = get_distribution_endpoints(&channel);
        if let Ok(output) = Command::new("curl")
            .args(["-sSf", "--max-time", "1", &ver_url])
            .output()
        {
            if output.status.success() {
                let remote_ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !remote_ver.is_empty() {
                    let mut new_state = state;
                    new_state.last_check_timestamp = now;
                    new_state.latest_remote_version = remote_ver.clone();
                    new_state.channel = channel;
                    let _ = save_update_state(&new_state, None);

                    if semver_is_newer(&remote_ver, current_version) {
                        eprintln!(
                            "💡 [{}] Nova versão disponível: v{} (atual: v{}).\n   Execute '{} update' para atualizar.",
                            APP_NAME, remote_ver, current_version, APP_NAME
                        );
                    }
                }
            }
        }
    }
}

/// Subcomando: ishcondidim check-update
pub fn cmd_check_update(channel_override: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let channel = resolve_channel(channel_override, None, None);
    let cfg = load_update_config(None);
    let current_ver = CURRENT_VERSION;
    let (_, _, ver_url) = get_distribution_endpoints(&channel);

    println!("⚡ {} Updater // Banca Soberana 2lp.in", APP_NAME);
    println!("Canal de Distribuição : {}", channel);
    println!("Versão Local Atual    : v{}", current_ver);
    println!("Endpoint de Consulta  : {}", ver_url);

    if is_version_pinned(&cfg, current_ver) {
        let pin_label = if cfg.pin.is_empty() {
            current_ver
        } else {
            &cfg.pin
        };
        println!(
            "📌 Versão pinada em v{}. Atualizações automáticas ignoradas.",
            pin_label
        );
        return Ok(());
    }

    let output = Command::new("curl")
        .args(["-sSf", "--max-time", "3", &ver_url])
        .output();

    let remote_ver = match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }
        _ => String::new(),
    };

    if remote_ver.is_empty() {
        println!("Versão Remota         : indisponível (servidor offline ou rota não publicada)");
        println!("\nNão foi possível validar atualizações no momento.");
        return Ok(());
    }

    println!("Versão Remota         : v{}", remote_ver);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let state = UpdateState {
        last_check_timestamp: now,
        latest_remote_version: remote_ver.clone(),
        channel: channel.clone(),
    };
    let _ = save_update_state(&state, None);

    if semver_is_newer(&remote_ver, current_ver) {
        println!(
            "\n★ Nova versão disponível: v{} -> v{}",
            current_ver, remote_ver
        );
        println!("Para atualizar agora, execute:");
        println!("  {} update --channel {}", APP_NAME, channel);
    } else {
        println!(
            "\n✔ O {} já está atualizado na versão mais recente do canal {}.",
            APP_NAME, channel
        );
    }

    Ok(())
}

/// Subcomando: ishcondidim update
pub fn cmd_update(
    channel_override: Option<&str>,
    pin_override: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel = resolve_channel(channel_override, None, None);
    let cfg = load_update_config(None);
    let current_ver = CURRENT_VERSION;

    if !force && is_version_pinned(&cfg, current_ver) {
        let pin_val = if cfg.pin.is_empty() {
            current_ver
        } else {
            &cfg.pin
        };
        eprintln!(
            "Erro: Versão pinada em v{}. Use --force para atualizar mesmo assim.",
            pin_val
        );
        return Err("Operação bloqueada por pinning de versão".into());
    }

    let pin = pin_override.or_else(|| {
        if !cfg.pin.is_empty() {
            Some(cfg.pin.as_str())
        } else {
            None
        }
    });

    let download_url = get_download_url(&channel, pin);
    let target_path = get_target_bin_path();

    println!("⚡ {} Auto-Update", APP_NAME);
    println!("Canal Selecionado : {}", channel);
    if let Some(p) = pin {
        println!("Versão Fixada     : v{}", p);
    }
    println!("Versão Atual      : v{}", current_ver);
    println!("Baixando de       : {}", download_url);
    println!("Destino           : {}", target_path.display());

    if dry_run {
        println!("(dry-run ativado: nenhuma alteração gravada no disco)");
        return Ok(());
    }

    let temp_dl_path =
        std::env::temp_dir().join(format!("{}-dl-{}", APP_NAME, std::process::id()));

    let status = Command::new("curl")
        .args(["-sSL", "-o", temp_dl_path.to_str().unwrap(), &download_url])
        .status()?;

    if !status.success() {
        let _ = fs::remove_file(&temp_dl_path);
        return Err(format!("Falha no download via curl de {}", download_url).into());
    }

    let bytes = fs::read(&temp_dl_path)?;
    let _ = fs::remove_file(&temp_dl_path);
    if bytes.is_empty() {
        return Err("Arquivo baixado está vazio.".into());
    }

    perform_atomic_update(&target_path, &bytes)?;

    println!(
        "✔ {} atualizado com sucesso em '{}'!",
        APP_NAME,
        target_path.display()
    );

    Ok(())
}

/// Subcomando: ishcondidim config <subcommand>
pub fn cmd_config(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let sub = args.first().map(String::as_str).unwrap_or("show");
    let mut cfg = load_update_config(None);

    match sub {
        "show" | "get" => {
            let path = get_config_path();
            println!("# Configuração Atual: {}", path.display());
            let app_cfg = AppConfigFile { update: cfg };
            println!("{}", toml::to_string_pretty(&app_cfg)?);
        }
        "pin" => {
            let version = args.get(1).map(String::as_str).unwrap_or(CURRENT_VERSION);
            cfg.pinned = true;
            cfg.pin = version.trim_start_matches('v').to_string();
            save_update_config(&cfg, None)?;
            println!("✔ Versão fixada (pinned) em: v{}", cfg.pin);
        }
        "unpin" => {
            cfg.pinned = false;
            cfg.pin.clear();
            save_update_config(&cfg, None)?;
            println!("✔ Travamento de versão removido (unpinned).");
        }
        "set-channel" => {
            let ch = args
                .get(1)
                .ok_or("Uso: ishcondidim config set-channel <stable|nightly>")?;
            let clean = ch.trim().to_ascii_lowercase();
            if clean != "stable" && clean != "nightly" {
                return Err("Canal inválido. Opções permitidas: 'stable' ou 'nightly'".into());
            }
            cfg.channel = clean.clone();
            save_update_config(&cfg, None)?;
            println!("✔ Canal ativo atualizado para: {}", clean);
        }
        "set-auto-check" => {
            let val = args
                .get(1)
                .ok_or("Uso: ishcondidim config set-auto-check <true|false>")?;
            cfg.auto_check = val.trim().parse::<bool>()?;
            save_update_config(&cfg, None)?;
            println!("✔ Verificação automática configurada para: {}", cfg.auto_check);
        }
        "set-auto-update" => {
            let val = args
                .get(1)
                .ok_or("Uso: ishcondidim config set-auto-update <true|false>")?;
            cfg.auto_update = val.trim().parse::<bool>()?;
            save_update_config(&cfg, None)?;
            println!(
                "✔ Atualização automática em segundo plano configurada para: {}",
                cfg.auto_update
            );
        }
        other => {
            eprintln!("Subcomando de configuração desconhecido: '{}'", other);
            eprintln!("Opções válidas: show, pin, unpin, set-channel, set-auto-check, set-auto-update");
            return Err("Subcomando de config inválido".into());
        }
    }

    Ok(())
}
