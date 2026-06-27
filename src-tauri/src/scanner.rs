use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File},
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use flate2::read::GzDecoder;
use magika::FileType;
use memmap2::Mmap;
use object::{Object, ObjectSection};
use rayon::join;
use scanbridge::FileHasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{ipc::Channel, State};
use thiserror::Error;
use tokio::task;
use ts_rs::TS;
use uuid::Uuid;
use walkdir::WalkDir;
use yara_x::{Compiler, Rules, Scanner};

#[cfg(windows)]
use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileAttributesW, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY,
    INVALID_FILE_ATTRIBUTES,
};

const BUILT_IN_YARA_RULES: &str = r#"
rule Synthetic_Scanner_Test_File {
  meta:
    severity = "malicious"
    description = "Internal scanner smoke-test marker"
  strings:
    $marker = "CODEX-VIRUS-SCANNER-SMOKE-TEST"
  condition:
    $marker
}

rule Suspicious_PowerShell_Download {
  meta:
    severity = "suspicious"
    description = "PowerShell download-and-execute behavior"
  strings:
    $ps = "powershell" nocase
    $download = "downloadstring" nocase
    $bypass = "executionpolicy bypass" nocase
  condition:
    $ps and ($download or $bypass)
}
"#;

const MAX_EVENT_MESSAGE: usize = 256;

#[derive(Debug, Clone, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ScanOptions {
    pub include_archives: bool,
    pub cloud_lookup: bool,
    pub max_file_mb: u64,
    pub max_archive_depth: u8,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            include_archives: true,
            cloud_lookup: false,
            max_file_mb: 64,
            max_archive_depth: 2,
        }
    }
}

impl ScanOptions {
    fn max_file_bytes(&self) -> u64 {
        self.max_file_mb.clamp(1, 4096) * 1024 * 1024
    }
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct StartScanResponse {
    pub scan_id: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, optional_fields)]
pub struct CloudStatus {
    pub enabled: bool,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Malicious,
    Unknown,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum CloudVerdict {
    Disabled,
    NotRequested,
    Clean,
    Suspicious,
    Malicious,
    Unknown,
    Error,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, optional_fields)]
pub struct CloudLookupResult {
    pub provider: String,
    pub verdict: CloudVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harmless: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub undetected: Option<u64>,
}

impl CloudLookupResult {
    fn disabled(reason: impl Into<String>) -> Self {
        Self {
            provider: "virustotal".to_string(),
            verdict: CloudVerdict::Disabled,
            reason: Some(reason.into()),
            malicious: None,
            suspicious: None,
            harmless: None,
            undetected: None,
        }
    }

    fn not_requested() -> Self {
        Self {
            provider: "virustotal".to_string(),
            verdict: CloudVerdict::NotRequested,
            reason: Some("cloud lookup was not requested".to_string()),
            malicious: None,
            suspicious: None,
            harmless: None,
            undetected: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ExecutableMetadata {
    pub format: String,
    pub architecture: String,
    pub sections: usize,
    pub entry: u64,
    pub imports: Vec<String>,
    pub section_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PackerDetection {
    pub detected: bool,
    pub name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct StaticAnalysis {
    pub entropy: f64,
    pub threat_score: u8,
    pub signals: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub packer: PackerDetection,
}

impl StaticAnalysis {
    fn empty() -> Self {
        Self {
            entropy: 0.0,
            threat_score: 0,
            signals: Vec::new(),
            suspicious_strings: Vec::new(),
            packer: PackerDetection {
                detected: false,
                name: "None".to_string(),
                confidence: 0.0,
                indicators: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, optional_fields)]
pub struct EngineStatus {
    pub built_in_yara_sources: usize,
    pub external_yara_sources: usize,
    pub hash_indicators: usize,
    pub magika_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magika_error: Option<String>,
    pub signature_sources: Vec<String>,
    pub load_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, optional_fields)]
pub struct HashSignatureMatch {
    pub algorithm: String,
    pub hash: String,
    pub verdict: ScanVerdict,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct WindowsFileAttributes {
    pub hidden: bool,
    pub system: bool,
    pub reparse_point: bool,
    pub temporary: bool,
    pub readonly: bool,
    pub archive: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ContentClassification {
    pub label: String,
    pub mime_type: String,
    pub group: String,
    pub description: String,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Finding {
    pub path: String,
    pub verdict: ScanVerdict,
    pub source: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, optional_fields)]
pub struct ScanFileResult {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
    pub verdict: ScanVerdict,
    pub yara_matches: Vec<String>,
    pub hash_matches: Vec<HashSignatureMatch>,
    pub cloud: CloudLookupResult,
    pub static_analysis: StaticAnalysis,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_attributes: Option<WindowsFileAttributes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<ExecutableMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub archive_depth: u8,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ScanSummary {
    pub files_seen: u64,
    pub files_scanned: u64,
    pub findings: u64,
    pub skipped: u64,
    pub errors: u64,
    pub canceled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, optional_fields)]
pub struct CompromiseTarget {
    pub id: String,
    pub group_id: String,
    pub label: String,
    pub path: String,
    pub exists: bool,
    pub recommended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct CompromiseTargetGroup {
    pub id: String,
    pub name: String,
    pub description: String,
    pub risk: String,
    pub target_count: usize,
    pub available_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct CompromiseCheckSuite {
    pub report_only: bool,
    pub groups: Vec<CompromiseTargetGroup>,
    pub targets: Vec<CompromiseTarget>,
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, TS)]
#[serde(
    tag = "event",
    content = "data",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(export, rename_all_fields = "camelCase")]
pub enum ScanEvent {
    ScanStarted {
        scan_id: String,
        targets: Vec<String>,
    },
    FileStarted {
        scan_id: String,
        path: String,
    },
    FileFinished {
        scan_id: String,
        result: ScanFileResult,
    },
    Finding {
        scan_id: String,
        finding: Finding,
    },
    Progress {
        scan_id: String,
        files_seen: u64,
        files_scanned: u64,
        findings: u64,
        current_path: String,
    },
    ScanCompleted {
        scan_id: String,
        summary: ScanSummary,
    },
    ScanError {
        scan_id: String,
        path: Option<String>,
        message: String,
    },
}

pub trait ScanEventSink {
    fn emit(&self, event: ScanEvent);
}

pub struct ChannelEventSink {
    channel: Channel<ScanEvent>,
}

impl ChannelEventSink {
    pub fn new(channel: Channel<ScanEvent>) -> Self {
        Self { channel }
    }
}

impl ScanEventSink for ChannelEventSink {
    fn emit(&self, event: ScanEvent) {
        let _ = self.channel.send(event);
    }
}

#[derive(Default, Clone)]
pub struct ScanRegistry {
    cancellations: Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>,
}

impl ScanRegistry {
    fn insert(&self, scan_id: String) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancellations
            .lock()
            .expect("scan registry lock poisoned")
            .insert(scan_id, Arc::clone(&cancel));
        cancel
    }

    fn cancel(&self, scan_id: &str) {
        if let Some(cancel) = self
            .cancellations
            .lock()
            .expect("scan registry lock poisoned")
            .get(scan_id)
        {
            cancel.store(true, Ordering::SeqCst);
        }
    }

    fn remove(&self, scan_id: &str) {
        self.cancellations
            .lock()
            .expect("scan registry lock poisoned")
            .remove(scan_id);
    }
}

#[derive(Debug, Error)]
enum ScannerError {
    #[error("failed to compile built-in YARA rules: {0}")]
    YaraCompile(String),
    #[error("failed to scan with YARA: {0}")]
    YaraScan(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Default)]
struct SignatureConfig {
    yara_paths: Vec<PathBuf>,
    hash_db_path: Option<PathBuf>,
}

impl SignatureConfig {
    fn from_env() -> Self {
        Self {
            yara_paths: env::var_os("VIRUSSCANNER_YARA_RULES")
                .map(|paths| env::split_paths(&paths).collect())
                .unwrap_or_default(),
            hash_db_path: env::var_os("VIRUSSCANNER_HASH_DB").map(PathBuf::from),
        }
    }
}

struct SignatureBundle {
    rules: Rules,
    status: EngineStatus,
    hash_indicators: HashMap<String, HashSignatureMatch>,
}

impl SignatureBundle {
    fn load(config: SignatureConfig) -> Result<Self, ScannerError> {
        let mut status = EngineStatus {
            built_in_yara_sources: 1,
            ..EngineStatus::default()
        };
        let mut compiler = Compiler::new();
        compiler
            .add_source(BUILT_IN_YARA_RULES)
            .map_err(|err| ScannerError::YaraCompile(err.to_string()))?;

        for rule_path in collect_yara_rule_paths(&config.yara_paths, &mut status) {
            match fs::read_to_string(&rule_path) {
                Ok(source) => {
                    let mut validator = Compiler::new();
                    match validator.add_source(source.as_str()) {
                        Ok(_) => match compiler.add_source(source.as_str()) {
                            Ok(_) => {
                                status.external_yara_sources += 1;
                                status
                                    .signature_sources
                                    .push(rule_path.display().to_string());
                            }
                            Err(err) => status.load_errors.push(format!(
                                "{}: {}",
                                rule_path.display(),
                                truncate_message(&err.to_string())
                            )),
                        },
                        Err(err) => status.load_errors.push(format!(
                            "{}: {}",
                            rule_path.display(),
                            truncate_message(&err.to_string())
                        )),
                    }
                }
                Err(err) => status
                    .load_errors
                    .push(format!("{}: {}", rule_path.display(), err)),
            }
        }

        let mut hash_indicators = HashMap::new();
        if let Some(path) = config.hash_db_path.as_ref() {
            load_hash_database(path, &mut status, &mut hash_indicators);
        }

        status.hash_indicators = hash_indicators.len();

        Ok(Self {
            rules: compiler.build(),
            status,
            hash_indicators,
        })
    }

    fn from_env() -> Result<Self, ScannerError> {
        Self::load(SignatureConfig::from_env())
    }

    fn match_hashes(&self, sha256: &str, blake3: &str) -> Vec<HashSignatureMatch> {
        [
            self.hash_indicators.get(&hash_key("sha256", sha256)),
            self.hash_indicators.get(&hash_key("blake3", blake3)),
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }
}

struct MagikaClassifier {
    session: Option<magika::Session>,
    error: Option<String>,
}

impl MagikaClassifier {
    fn new() -> Self {
        match magika::Session::new() {
            Ok(session) => Self {
                session: Some(session),
                error: None,
            },
            Err(err) => Self {
                session: None,
                error: Some(truncate_message(&err.to_string())),
            },
        }
    }

    fn is_available(&self) -> bool {
        self.session.is_some()
    }

    fn error(&self) -> Option<String> {
        self.error.clone()
    }

    fn identify(&mut self, bytes: &[u8]) -> Option<ContentClassification> {
        let session = self.session.as_mut()?;
        match session.identify_content_sync(bytes) {
            Ok(file_type) => Some(content_classification_from_file_type(&file_type)),
            Err(err) => {
                self.error = Some(truncate_message(&err.to_string()));
                None
            }
        }
    }
}

fn content_classification_from_file_type(file_type: &FileType) -> ContentClassification {
    let info = file_type.info();
    ContentClassification {
        label: info.label.to_string(),
        mime_type: info.mime_type.to_string(),
        group: info.group.to_string(),
        description: info.description.to_string(),
        score: file_type.score(),
    }
}

fn add_magika_status(status: &mut EngineStatus) {
    let classifier = MagikaClassifier::new();
    status.magika_available = classifier.is_available();
    status.magika_error = classifier.error();
}

#[derive(Debug, Deserialize)]
struct HashDatabase {
    indicators: Vec<HashIndicatorEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HashIndicatorEntry {
    algorithm: String,
    hash: String,
    verdict: ScanVerdict,
    name: String,
    source: Option<String>,
}

fn collect_yara_rule_paths(paths: &[PathBuf], status: &mut EngineStatus) -> Vec<PathBuf> {
    let mut rules = Vec::new();

    for path in paths {
        if path.is_file() {
            rules.push(path.clone());
            continue;
        }

        if path.is_dir() {
            for entry in WalkDir::new(path).follow_links(false) {
                match entry {
                    Ok(entry) if entry.file_type().is_file() && is_yara_rule_file(entry.path()) => {
                        rules.push(entry.path().to_path_buf());
                    }
                    Ok(_) => {}
                    Err(err) => status.load_errors.push(err.to_string()),
                }
            }
            continue;
        }

        status
            .load_errors
            .push(format!("signature path not found: {}", path.display()));
    }

    rules.sort();
    rules
}

fn is_yara_rule_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase()),
        Some(extension) if extension == "yar" || extension == "yara"
    )
}

fn load_hash_database(
    path: &Path,
    status: &mut EngineStatus,
    hash_indicators: &mut HashMap<String, HashSignatureMatch>,
) {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            status
                .load_errors
                .push(format!("{}: {}", path.display(), err));
            return;
        }
    };

    let database: HashDatabase = match serde_json::from_str(&content) {
        Ok(database) => database,
        Err(err) => {
            status.load_errors.push(format!(
                "{}: invalid hash database: {}",
                path.display(),
                truncate_message(&err.to_string())
            ));
            return;
        }
    };

    for indicator in database.indicators {
        let algorithm = indicator.algorithm.to_ascii_lowercase();
        if algorithm != "sha256" && algorithm != "blake3" {
            status.load_errors.push(format!(
                "{}: unsupported hash algorithm {}",
                path.display(),
                indicator.algorithm
            ));
            continue;
        }

        if !matches!(
            indicator.verdict,
            ScanVerdict::Malicious | ScanVerdict::Suspicious
        ) {
            status.load_errors.push(format!(
                "{}: hash indicator {} must be malicious or suspicious",
                path.display(),
                indicator.name
            ));
            continue;
        }

        let normalized_hash = indicator.hash.trim().to_ascii_lowercase();
        if !is_hex_hash(&normalized_hash) {
            status.load_errors.push(format!(
                "{}: hash indicator {} is not valid hexadecimal",
                path.display(),
                indicator.name
            ));
            continue;
        }

        hash_indicators.insert(
            hash_key(&algorithm, &normalized_hash),
            HashSignatureMatch {
                algorithm,
                hash: normalized_hash,
                verdict: indicator.verdict,
                name: indicator.name,
                source: indicator
                    .source
                    .or_else(|| Some(path.display().to_string())),
            },
        );
    }

    status.signature_sources.push(path.display().to_string());
}

fn is_hex_hash(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hash_key(algorithm: &str, hash: &str) -> String {
    format!(
        "{}:{}",
        algorithm.to_ascii_lowercase(),
        hash.to_ascii_lowercase()
    )
}

#[cfg(windows)]
fn windows_file_attributes(display_path: &str) -> Option<WindowsFileAttributes> {
    if display_path.starts_with("memory::") || display_path.contains("::") {
        return None;
    }

    let wide_path: Vec<u16> = OsStr::new(display_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attributes = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return None;
    }

    Some(WindowsFileAttributes {
        hidden: attributes & FILE_ATTRIBUTE_HIDDEN != 0,
        system: attributes & FILE_ATTRIBUTE_SYSTEM != 0,
        reparse_point: attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        temporary: attributes & FILE_ATTRIBUTE_TEMPORARY != 0,
        readonly: attributes & FILE_ATTRIBUTE_READONLY != 0,
        archive: attributes & FILE_ATTRIBUTE_ARCHIVE != 0,
    })
}

#[cfg(not(windows))]
fn windows_file_attributes(_display_path: &str) -> Option<WindowsFileAttributes> {
    None
}

#[tauri::command]
pub fn start_scan(
    paths: Vec<String>,
    options: ScanOptions,
    on_event: Channel<ScanEvent>,
    state: State<'_, ScanRegistry>,
) -> Result<StartScanResponse, String> {
    if paths.is_empty() {
        return Err("at least one scan target is required".to_string());
    }

    let scan_id = Uuid::new_v4().to_string();
    let cancel = state.insert(scan_id.clone());
    let registry = state.inner().clone();
    let scan_id_for_task = scan_id.clone();

    task::spawn_blocking(move || {
        let sink = ChannelEventSink::new(on_event);
        let result = run_scan(
            &scan_id_for_task,
            paths,
            options,
            cancel,
            &sink,
            VirusTotalClient::from_env(),
        );

        if let Err(err) = result {
            sink.emit(ScanEvent::ScanError {
                scan_id: scan_id_for_task.clone(),
                path: None,
                message: truncate_message(&err.to_string()),
            });
        }

        registry.remove(&scan_id_for_task);
    });

    Ok(StartScanResponse { scan_id })
}

#[tauri::command]
pub fn cancel_scan(scan_id: String, state: State<'_, ScanRegistry>) -> Result<(), String> {
    state.cancel(&scan_id);
    Ok(())
}

#[tauri::command]
pub fn get_cloud_status() -> CloudStatus {
    cloud_status_from_env(env::var("VIRUSTOTAL_API_KEY").ok())
}

#[tauri::command]
pub fn get_engine_status() -> Result<EngineStatus, String> {
    SignatureBundle::from_env()
        .map(|bundle| {
            let mut status = bundle.status;
            add_magika_status(&mut status);
            status
        })
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub fn get_compromise_check_suite() -> CompromiseCheckSuite {
    compromise_check_suite_from_paths(CompromisePathInputs::from_env())
}

pub fn cloud_status_from_env(api_key: Option<String>) -> CloudStatus {
    match api_key {
        Some(key) if !key.trim().is_empty() => CloudStatus {
            enabled: true,
            provider: "virustotal".to_string(),
            reason: None,
        },
        _ => CloudStatus {
            enabled: false,
            provider: "virustotal".to_string(),
            reason: Some("VIRUSTOTAL_API_KEY is not set".to_string()),
        },
    }
}

#[derive(Debug, Clone, Default)]
struct CompromisePathInputs {
    home_dir: Option<PathBuf>,
    app_data: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    program_data: Option<PathBuf>,
    temp_dir: Option<PathBuf>,
}

impl CompromisePathInputs {
    fn from_env() -> Self {
        Self {
            home_dir: env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .or_else(home_from_drive_path),
            app_data: env::var_os("APPDATA").map(PathBuf::from),
            local_app_data: env::var_os("LOCALAPPDATA").map(PathBuf::from),
            program_data: env::var_os("PROGRAMDATA").map(PathBuf::from),
            temp_dir: Some(env::temp_dir()),
        }
    }
}

fn home_from_drive_path() -> Option<PathBuf> {
    let drive = env::var_os("HOMEDRIVE")?;
    let path = env::var_os("HOMEPATH")?;
    let mut home = PathBuf::from(drive);
    home.push(path);
    Some(home)
}

fn compromise_check_suite_from_paths(inputs: CompromisePathInputs) -> CompromiseCheckSuite {
    let definitions = vec![
        (
            "quick",
            "Quick User Sweep",
            "Common user-writeable locations where suspicious downloads and dropped files are usually found.",
            "medium",
            vec![
                path_target(&inputs.home_dir, &["Downloads"], "Downloads"),
                path_target(&inputs.home_dir, &["Desktop"], "Desktop"),
                path_target(&inputs.home_dir, &["Documents"], "Documents"),
                direct_target(&inputs.temp_dir, "User temp"),
            ],
        ),
        (
            "persistence",
            "Startup And Persistence",
            "Startup folders and PowerShell profile locations that often reveal persistence attempts.",
            "high",
            vec![
                path_target(
                    &inputs.app_data,
                    &["Microsoft", "Windows", "Start Menu", "Programs", "Startup"],
                    "Current user startup",
                ),
                path_target(
                    &inputs.program_data,
                    &["Microsoft", "Windows", "Start Menu", "Programs", "Startup"],
                    "All users startup",
                ),
                path_target(
                    &inputs.home_dir,
                    &["Documents", "WindowsPowerShell"],
                    "Windows PowerShell profile",
                ),
                path_target(
                    &inputs.home_dir,
                    &["Documents", "PowerShell"],
                    "PowerShell 7 profile",
                ),
            ],
        ),
        (
            "high-risk",
            "High-Risk App Data",
            "Per-user application data locations where unexpected scripts, archives, and executables deserve review.",
            "medium",
            vec![
                path_target(&inputs.app_data, &[], "Roaming app data"),
                path_target(&inputs.local_app_data, &[], "Local app data"),
                path_target(
                    &inputs.local_app_data,
                    &["Microsoft", "Windows", "INetCache"],
                    "Browser cache",
                ),
            ],
        ),
    ];

    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    let mut targets = Vec::new();

    for (group_id, name, description, risk, candidates) in definitions {
        let before = targets.len();
        for candidate in candidates.into_iter().flatten() {
            let path_key = candidate.path.display().to_string().to_ascii_lowercase();
            if seen.insert(path_key) {
                targets.push(candidate.into_target(group_id));
            }
        }
        let group_targets = &targets[before..];
        groups.push(CompromiseTargetGroup {
            id: group_id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            risk: risk.to_string(),
            target_count: group_targets.len(),
            available_count: group_targets
                .iter()
                .filter(|target| target.recommended)
                .count(),
        });
    }

    CompromiseCheckSuite {
        report_only: true,
        groups,
        targets,
        next_actions: vec![
            "Review malicious and suspicious findings before changing files.".to_string(),
            "Re-run selected targets with cloud hash lookup when a VirusTotal key is configured."
                .to_string(),
            "Investigate unexpected startup entries or scripts with high static scores.".to_string(),
        ],
    }
}

struct CompromiseTargetCandidate {
    label: String,
    path: PathBuf,
}

impl CompromiseTargetCandidate {
    fn into_target(self, group_id: &str) -> CompromiseTarget {
        let exists = self.path.exists();
        let readable = path_is_readable(&self.path);
        let recommended = exists && readable;
        let reason = if !exists {
            Some("path does not exist".to_string())
        } else if !readable {
            Some("path is not readable".to_string())
        } else {
            None
        };
        let id = format!(
            "{}-{}",
            group_id,
            self.label
                .to_ascii_lowercase()
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
        );

        CompromiseTarget {
            id,
            group_id: group_id.to_string(),
            label: self.label,
            path: self.path.display().to_string(),
            exists,
            recommended,
            reason,
        }
    }
}

fn direct_target(path: &Option<PathBuf>, label: &str) -> Option<CompromiseTargetCandidate> {
    path.as_ref().map(|path| CompromiseTargetCandidate {
        label: label.to_string(),
        path: path.clone(),
    })
}

fn path_target(
    base: &Option<PathBuf>,
    segments: &[&str],
    label: &str,
) -> Option<CompromiseTargetCandidate> {
    let mut path = base.as_ref()?.clone();
    for segment in segments {
        path.push(segment);
    }
    Some(CompromiseTargetCandidate {
        label: label.to_string(),
        path,
    })
}

fn path_is_readable(path: &Path) -> bool {
    if path.is_dir() {
        fs::read_dir(path).is_ok()
    } else {
        File::open(path).is_ok()
    }
}

fn run_scan<C: CloudLookup>(
    scan_id: &str,
    paths: Vec<String>,
    options: ScanOptions,
    cancel: Arc<AtomicBool>,
    sink: &dyn ScanEventSink,
    cloud: C,
) -> Result<ScanSummary, ScannerError> {
    let signatures = SignatureBundle::from_env()?;
    let mut runner =
        ScanRunner::new_with_signatures(scan_id, options, cancel, sink, cloud, signatures)?;
    runner.run(paths)
}

struct ScanRunner<'a, C: CloudLookup> {
    scan_id: &'a str,
    options: ScanOptions,
    cancel: Arc<AtomicBool>,
    sink: &'a dyn ScanEventSink,
    signatures: SignatureBundle,
    magika: MagikaClassifier,
    cloud: C,
    summary: ScanSummary,
}

impl<'a, C: CloudLookup> ScanRunner<'a, C> {
    #[cfg(test)]
    fn new(
        scan_id: &'a str,
        options: ScanOptions,
        cancel: Arc<AtomicBool>,
        sink: &'a dyn ScanEventSink,
        cloud: C,
    ) -> Result<Self, ScannerError> {
        Self::new_with_signatures(
            scan_id,
            options,
            cancel,
            sink,
            cloud,
            SignatureBundle::load(SignatureConfig::default())?,
        )
    }

    fn new_with_signatures(
        scan_id: &'a str,
        options: ScanOptions,
        cancel: Arc<AtomicBool>,
        sink: &'a dyn ScanEventSink,
        cloud: C,
        signatures: SignatureBundle,
    ) -> Result<Self, ScannerError> {
        Ok(Self {
            scan_id,
            options,
            cancel,
            sink,
            signatures,
            magika: MagikaClassifier::new(),
            cloud,
            summary: ScanSummary::default(),
        })
    }

    fn run(&mut self, paths: Vec<String>) -> Result<ScanSummary, ScannerError> {
        self.emit(ScanEvent::ScanStarted {
            scan_id: self.scan_id.to_string(),
            targets: paths.clone(),
        });

        for target in paths {
            if self.is_canceled() {
                break;
            }

            let path = PathBuf::from(&target);
            if path.is_dir() {
                if let Err(err) = self.scan_directory(&path) {
                    self.emit_error(Some(path.display().to_string()), err.to_string());
                }
            } else if let Err(err) = self.scan_path(&path) {
                self.emit_error(Some(path.display().to_string()), err.to_string());
            }
        }

        self.summary.canceled = self.is_canceled();
        self.emit(ScanEvent::ScanCompleted {
            scan_id: self.scan_id.to_string(),
            summary: self.summary.clone(),
        });

        Ok(self.summary.clone())
    }

    fn scan_directory(&mut self, root: &Path) -> Result<(), ScannerError> {
        for entry in WalkDir::new(root).follow_links(false) {
            if self.is_canceled() {
                break;
            }

            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    self.emit_error(None, err.to_string());
                    continue;
                }
            };

            if entry.file_type().is_file() {
                if let Err(err) = self.scan_path(entry.path()) {
                    self.emit_error(Some(entry.path().display().to_string()), err.to_string());
                }
            }
        }

        Ok(())
    }

    fn scan_path(&mut self, path: &Path) -> Result<(), ScannerError> {
        if self.is_canceled() {
            return Ok(());
        }

        self.summary.files_seen += 1;
        let display_path = path.display().to_string();
        self.emit(ScanEvent::FileStarted {
            scan_id: self.scan_id.to_string(),
            path: display_path.clone(),
        });

        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                self.finish_error(display_path, err.to_string(), 0, 0);
                return Ok(());
            }
        };
        self.scan_opened_file(&display_path, &mut file, 0)
    }

    fn scan_opened_file(
        &mut self,
        display_path: &str,
        file: &mut File,
        archive_depth: u8,
    ) -> Result<(), ScannerError> {
        let size = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                self.finish_error(display_path.to_string(), err.to_string(), 0, archive_depth);
                return Ok(());
            }
        };

        if size > self.options.max_file_bytes() {
            self.finish_skipped(
                display_path.to_string(),
                size,
                "file is larger than maxFileMb".to_string(),
                archive_depth,
            );
            return Ok(());
        }

        if size == 0 {
            self.scan_bytes(display_path, &[], archive_depth)?;
            return Ok(());
        }

        match unsafe { Mmap::map(&*file) } {
            Ok(mmap) => {
                if mmap.len() as u64 > self.options.max_file_bytes() {
                    self.finish_skipped(
                        display_path.to_string(),
                        mmap.len() as u64,
                        "file is larger than maxFileMb".to_string(),
                        archive_depth,
                    );
                    return Ok(());
                }
                self.scan_bytes(display_path, &mmap, archive_depth)?;
            }
            Err(_) => {
                let mut bytes = Vec::new();
                if let Err(err) = file
                    .by_ref()
                    .take(self.options.max_file_bytes() + 1)
                    .read_to_end(&mut bytes)
                {
                    self.finish_error(
                        display_path.to_string(),
                        err.to_string(),
                        size,
                        archive_depth,
                    );
                    return Ok(());
                }
                if bytes.len() as u64 > self.options.max_file_bytes() {
                    self.finish_skipped(
                        display_path.to_string(),
                        bytes.len() as u64,
                        "file is larger than maxFileMb".to_string(),
                        archive_depth,
                    );
                    return Ok(());
                }
                self.scan_bytes(display_path, &bytes, archive_depth)?;
            }
        }

        Ok(())
    }

    fn scan_bytes(
        &mut self,
        display_path: &str,
        bytes: &[u8],
        archive_depth: u8,
    ) -> Result<ScanFileResult, ScannerError> {
        if self.is_canceled() {
            return Ok(empty_result(
                display_path,
                bytes.len() as u64,
                ScanVerdict::Skipped,
                Some("scan canceled".to_string()),
                archive_depth,
            ));
        }

        let max_scan_size = self.options.max_file_bytes() as usize;
        let ((hashes, yara_matches), executable) = join(
            || {
                join(
                    || FileHasher::new().with_sha256(true).hash_bytes(bytes),
                    || scan_yara_rules(&self.signatures.rules, max_scan_size, bytes),
                )
            },
            || parse_executable_metadata(bytes),
        );
        let yara_matches = match yara_matches {
            Ok(matches) => matches,
            Err(err) => {
                let result = self.finish_error(
                    display_path.to_string(),
                    err.to_string(),
                    bytes.len() as u64,
                    archive_depth,
                );
                return Ok(result);
            }
        };
        let sha256 = hashes.sha256.unwrap_or_else(|| sha256_hex(bytes));
        let blake3 = hashes.blake3;
        let hash_matches = self.signatures.match_hashes(&sha256, &blake3);
        let suspicious_imports = executable
            .as_ref()
            .map(suspicious_imports)
            .unwrap_or_default();
        let static_analysis =
            analyze_static_signals(bytes, executable.as_ref(), &suspicious_imports);
        let windows_attributes = windows_file_attributes(display_path);
        let content = self.magika.identify(bytes);
        let local_suspicious = !suspicious_imports.is_empty() || static_analysis.threat_score >= 35;

        let cloud = if self.options.cloud_lookup {
            self.cloud.lookup_hash(&sha256)
        } else {
            CloudLookupResult::not_requested()
        };

        let mut verdict = if yara_matches.is_empty() {
            ScanVerdict::Clean
        } else {
            ScanVerdict::Malicious
        };

        if verdict == ScanVerdict::Clean && local_suspicious {
            verdict = ScanVerdict::Suspicious;
        }

        verdict = merge_hash_verdict(verdict, &hash_matches);

        verdict = merge_cloud_verdict(verdict, &cloud);

        let result = ScanFileResult {
            path: display_path.to_string(),
            size: bytes.len() as u64,
            sha256,
            blake3,
            verdict: verdict.clone(),
            yara_matches: yara_matches.clone(),
            hash_matches: hash_matches.clone(),
            cloud,
            static_analysis: static_analysis.clone(),
            windows_attributes,
            content,
            executable,
            skipped_reason: None,
            error: None,
            archive_depth,
        };

        self.finish_result(result.clone());

        if matches!(verdict, ScanVerdict::Malicious | ScanVerdict::Suspicious) {
            let source = if yara_matches.is_empty() {
                if hash_matches.is_empty() {
                    "heuristic".to_string()
                } else {
                    "local-hash".to_string()
                }
            } else {
                "yara-x".to_string()
            };
            let title = if yara_matches.is_empty() {
                hash_matches
                    .first()
                    .map(|indicator| format!("Known hash: {}", indicator.name))
                    .or_else(|| static_analysis.signals.first().cloned())
                    .unwrap_or_else(|| "Suspicious static analysis".to_string())
            } else {
                format!("Matched {}", yara_matches.join(", "))
            };
            self.emit(ScanEvent::Finding {
                scan_id: self.scan_id.to_string(),
                finding: Finding {
                    path: display_path.to_string(),
                    verdict,
                    source,
                    title,
                    detail: finding_detail(&static_analysis, &hash_matches),
                },
            });
            self.summary.findings += 1;
        }

        if self.options.include_archives {
            self.scan_archive_members(display_path, bytes, archive_depth)?;
        }

        Ok(result)
    }

    fn scan_archive_members(
        &mut self,
        display_path: &str,
        bytes: &[u8],
        archive_depth: u8,
    ) -> Result<(), ScannerError> {
        if archive_depth >= self.options.max_archive_depth {
            if looks_like_archive(display_path) {
                self.finish_skipped(
                    format!("{display_path}::*"),
                    0,
                    "archive recursion limit reached".to_string(),
                    archive_depth.saturating_add(1),
                );
            }
            return Ok(());
        }

        let next_depth = archive_depth.saturating_add(1);
        let lower = display_path.to_ascii_lowercase();
        if lower.ends_with(".zip") {
            self.scan_zip_members(display_path, bytes, next_depth)?;
        } else if lower.ends_with(".tar") {
            self.scan_tar_members(display_path, bytes, next_depth)?;
        } else if lower.ends_with(".gz") || lower.ends_with(".gzip") {
            self.scan_gzip_member(display_path, bytes, next_depth)?;
        }

        Ok(())
    }

    fn scan_zip_members(
        &mut self,
        display_path: &str,
        bytes: &[u8],
        archive_depth: u8,
    ) -> Result<(), ScannerError> {
        let cursor = Cursor::new(bytes);
        let mut archive = match zip::ZipArchive::new(cursor) {
            Ok(archive) => archive,
            Err(err) => {
                self.emit_error(Some(display_path.to_string()), err.to_string());
                return Ok(());
            }
        };

        for index in 0..archive.len() {
            if self.is_canceled() {
                break;
            }

            let mut file = match archive.by_index(index) {
                Ok(file) => file,
                Err(err) => {
                    self.emit_error(Some(display_path.to_string()), err.to_string());
                    continue;
                }
            };

            if file.is_dir() {
                continue;
            }

            let entry_path = format!("{display_path}::{}", file.name());
            self.summary.files_seen += 1;
            self.emit(ScanEvent::FileStarted {
                scan_id: self.scan_id.to_string(),
                path: entry_path.clone(),
            });

            if file.size() > self.options.max_file_bytes() {
                self.finish_skipped(
                    entry_path,
                    file.size(),
                    "archive member is larger than maxFileMb".to_string(),
                    archive_depth,
                );
                continue;
            }

            let mut data = Vec::new();
            if let Err(err) = file
                .by_ref()
                .take(self.options.max_file_bytes() + 1)
                .read_to_end(&mut data)
            {
                self.finish_error(entry_path, err.to_string(), file.size(), archive_depth);
                continue;
            }
            if data.len() as u64 > self.options.max_file_bytes() {
                self.finish_skipped(
                    entry_path,
                    data.len() as u64,
                    "archive member is larger than maxFileMb".to_string(),
                    archive_depth,
                );
                continue;
            }
            self.scan_bytes(&entry_path, &data, archive_depth)?;
        }

        Ok(())
    }

    fn scan_tar_members(
        &mut self,
        display_path: &str,
        bytes: &[u8],
        archive_depth: u8,
    ) -> Result<(), ScannerError> {
        let cursor = Cursor::new(bytes);
        let mut archive = tar::Archive::new(cursor);
        let entries = match archive.entries() {
            Ok(entries) => entries,
            Err(err) => {
                self.emit_error(Some(display_path.to_string()), err.to_string());
                return Ok(());
            }
        };

        for entry in entries {
            if self.is_canceled() {
                break;
            }

            let mut entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    self.emit_error(Some(display_path.to_string()), err.to_string());
                    continue;
                }
            };
            if !entry.header().entry_type().is_file() {
                continue;
            }

            let entry_name = entry
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| "member".to_string());
            let entry_path = format!("{display_path}::{entry_name}");
            let size = entry.header().size().unwrap_or(0);
            self.summary.files_seen += 1;
            self.emit(ScanEvent::FileStarted {
                scan_id: self.scan_id.to_string(),
                path: entry_path.clone(),
            });

            if size > self.options.max_file_bytes() {
                self.finish_skipped(
                    entry_path,
                    size,
                    "archive member is larger than maxFileMb".to_string(),
                    archive_depth,
                );
                continue;
            }

            let mut data = Vec::new();
            if let Err(err) = entry
                .by_ref()
                .take(self.options.max_file_bytes() + 1)
                .read_to_end(&mut data)
            {
                self.finish_error(entry_path, err.to_string(), size, archive_depth);
                continue;
            }
            if data.len() as u64 > self.options.max_file_bytes() {
                self.finish_skipped(
                    entry_path,
                    data.len() as u64,
                    "archive member is larger than maxFileMb".to_string(),
                    archive_depth,
                );
                continue;
            }
            self.scan_bytes(&entry_path, &data, archive_depth)?;
        }

        Ok(())
    }

    fn scan_gzip_member(
        &mut self,
        display_path: &str,
        bytes: &[u8],
        archive_depth: u8,
    ) -> Result<(), ScannerError> {
        let mut decoder = GzDecoder::new(Cursor::new(bytes));
        let mut data = Vec::new();
        let max = self.options.max_file_bytes() + 1;
        let entry_path = format!("{display_path}::decompressed");
        self.summary.files_seen += 1;
        self.emit(ScanEvent::FileStarted {
            scan_id: self.scan_id.to_string(),
            path: entry_path.clone(),
        });

        if let Err(err) = decoder.by_ref().take(max).read_to_end(&mut data) {
            self.finish_error(entry_path, err.to_string(), 0, archive_depth);
            return Ok(());
        }

        if data.len() as u64 > self.options.max_file_bytes() {
            self.finish_skipped(
                entry_path,
                data.len() as u64,
                "gzip member is larger than maxFileMb".to_string(),
                archive_depth,
            );
            return Ok(());
        }

        self.scan_bytes(&entry_path, &data, archive_depth)?;
        Ok(())
    }

    fn finish_result(&mut self, result: ScanFileResult) {
        if result.verdict == ScanVerdict::Skipped {
            self.summary.skipped += 1;
        } else if result.verdict == ScanVerdict::Error {
            self.summary.errors += 1;
        } else {
            self.summary.files_scanned += 1;
        }

        let path = result.path.clone();
        self.emit(ScanEvent::FileFinished {
            scan_id: self.scan_id.to_string(),
            result,
        });
        self.emit_progress(path);
    }

    fn finish_skipped(&mut self, path: String, size: u64, reason: String, archive_depth: u8) {
        let result = empty_result(
            &path,
            size,
            ScanVerdict::Skipped,
            Some(reason),
            archive_depth,
        );
        self.finish_result(result);
    }

    fn finish_error(
        &mut self,
        path: String,
        message: String,
        size: u64,
        archive_depth: u8,
    ) -> ScanFileResult {
        let mut result = empty_result(&path, size, ScanVerdict::Error, None, archive_depth);
        result.error = Some(truncate_message(&message));
        self.finish_result(result.clone());
        self.emit_scan_error(Some(path), message);
        result
    }

    fn emit_error(&mut self, path: Option<String>, message: String) {
        self.summary.errors += 1;
        self.emit_scan_error(path, message);
    }

    fn emit_scan_error(&self, path: Option<String>, message: String) {
        self.emit(ScanEvent::ScanError {
            scan_id: self.scan_id.to_string(),
            path,
            message: truncate_message(&message),
        });
    }

    fn emit_progress(&self, current_path: String) {
        self.emit(ScanEvent::Progress {
            scan_id: self.scan_id.to_string(),
            files_seen: self.summary.files_seen,
            files_scanned: self.summary.files_scanned,
            findings: self.summary.findings,
            current_path,
        });
    }

    fn emit(&self, event: ScanEvent) {
        self.sink.emit(event);
    }

    fn is_canceled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }
}

fn empty_result(
    path: &str,
    size: u64,
    verdict: ScanVerdict,
    skipped_reason: Option<String>,
    archive_depth: u8,
) -> ScanFileResult {
    ScanFileResult {
        path: path.to_string(),
        size,
        sha256: String::new(),
        blake3: String::new(),
        verdict,
        yara_matches: Vec::new(),
        hash_matches: Vec::new(),
        cloud: CloudLookupResult::not_requested(),
        static_analysis: StaticAnalysis::empty(),
        windows_attributes: None,
        content: None,
        executable: None,
        skipped_reason,
        error: None,
        archive_depth,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_executable_metadata(bytes: &[u8]) -> Option<ExecutableMetadata> {
    let file = object::File::parse(bytes).ok()?;
    let imports = file
        .imports()
        .unwrap_or_default()
        .into_iter()
        .take(24)
        .map(|import| {
            format!(
                "{}!{}",
                bytes_to_lossy(import.library()),
                bytes_to_lossy(import.name())
            )
        })
        .collect();
    let section_names = file
        .sections()
        .filter_map(|section| section.name().ok().map(ToString::to_string))
        .take(24)
        .collect();

    Some(ExecutableMetadata {
        format: format!("{:?}", file.format()),
        architecture: format!("{:?}", file.architecture()),
        sections: file.sections().count(),
        entry: file.entry(),
        imports,
        section_names,
    })
}

fn suspicious_imports(metadata: &ExecutableMetadata) -> Vec<String> {
    let suspicious = [
        "virtualalloc",
        "writeprocessmemory",
        "createremotethread",
        "loadlibrary",
        "getprocaddress",
        "ntprotectvirtualmemory",
        "internetopen",
        "urldownloadtofile",
        "cryptdecrypt",
        "setwindowshookex",
    ];

    metadata
        .imports
        .iter()
        .filter(|import| {
            let lower = import.to_ascii_lowercase();
            suspicious.iter().any(|needle| lower.contains(needle))
        })
        .take(16)
        .cloned()
        .collect()
}

fn analyze_static_signals(
    bytes: &[u8],
    executable: Option<&ExecutableMetadata>,
    suspicious_imports: &[String],
) -> StaticAnalysis {
    let entropy = calculate_entropy(bytes);
    let packer = detect_packer(bytes, entropy);
    let suspicious_strings = detect_suspicious_strings(bytes);
    let mut score = 0.0;
    let mut signals = Vec::new();

    if packer.detected {
        score += 15.0;
        signals.push(format!(
            "Packed with {} ({:.0}% confidence)",
            packer.name,
            packer.confidence * 100.0
        ));
    }

    if entropy > 7.8 {
        score += 25.0;
        signals.push(format!("Very high entropy: {entropy:.2}"));
    } else if entropy > 7.5 {
        score += 20.0;
        signals.push(format!("High entropy: {entropy:.2}"));
    } else if entropy > 7.2 {
        score += 10.0;
        signals.push(format!("Elevated entropy: {entropy:.2}"));
    }

    if let Some(metadata) = executable {
        if metadata.imports.is_empty() {
            score += 20.0;
            signals.push("No imports in executable".to_string());
        } else if metadata.imports.len() < 5 {
            score += 10.0;
            signals.push(format!("Very few imports: {}", metadata.imports.len()));
        }
    }

    if !suspicious_imports.is_empty() {
        score += (suspicious_imports.len() as f64 * 3.0).min(30.0);
        signals.extend(
            suspicious_imports
                .iter()
                .take(8)
                .map(|import| format!("Suspicious API: {import}")),
        );
    }

    if !suspicious_strings.is_empty() {
        score += (suspicious_strings.len() as f64 * 4.0).min(20.0);
        signals.extend(
            suspicious_strings
                .iter()
                .take(6)
                .map(|value| format!("Suspicious string: {value}")),
        );
    }

    StaticAnalysis {
        entropy,
        threat_score: score.min(100.0).round() as u8,
        signals,
        suspicious_strings,
        packer,
    }
}

fn calculate_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0_usize; 256];
    for byte in bytes {
        frequencies[*byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    frequencies
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn detect_packer(bytes: &[u8], entropy: f64) -> PackerDetection {
    let signatures: &[(&str, &[&[u8]])] = &[
        ("UPX", &[b"UPX0", b"UPX1", b"UPX2", b".UPX"]),
        ("ASPack", &[b".aspack", b".adata", b"ASPack"]),
        (
            "Themida/WinLicense",
            &[b".themida", b"Themida", b"WinLicense"],
        ),
        ("VMProtect", &[b".vmp0", b".vmp1", b".vmp2", b"VMProtect"]),
        ("PECompact", &[b"PECompact", b"pec1", b"pec2"]),
        ("MPRESS", &[b".MPRESS1", b".MPRESS2", b"MPRESS"]),
        ("NSPack", &[b".nsp0", b".nsp1", b".nsp2"]),
        ("FSG", &[b"FSG!", b".fsg"]),
        ("PEtite", &[b".petite", b"PEtite"]),
        ("Armadillo", &[b".armadil", b"Armadillo"]),
    ];

    let mut indicators = Vec::new();
    for (name, patterns) in signatures {
        if patterns
            .iter()
            .any(|pattern| contains_bytes(bytes, pattern))
        {
            indicators.push(format!("Signature match: {name}"));
            return PackerDetection {
                detected: true,
                name: (*name).to_string(),
                confidence: if entropy > 7.5 { 0.95 } else { 0.85 },
                indicators,
            };
        }
    }

    if entropy > 7.8 {
        return PackerDetection {
            detected: true,
            name: "Unknown packer or encrypted payload".to_string(),
            confidence: 0.70,
            indicators: vec![format!("Very high entropy: {entropy:.2}")],
        };
    }

    PackerDetection {
        detected: false,
        name: "None".to_string(),
        confidence: 0.0,
        indicators: Vec::new(),
    }
}

fn detect_suspicious_strings(bytes: &[u8]) -> Vec<String> {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let patterns = [
        ("PowerShell", "powershell"),
        ("cmd.exe", "cmd.exe"),
        ("Windows Defender tamper phrase", "disable-windowsdefender"),
        ("credential dumping phrase", "lsass"),
        (
            "registry run key",
            "\\software\\microsoft\\windows\\currentversion\\run",
        ),
        ("download command", "downloadstring"),
        ("script execution policy bypass", "executionpolicy bypass"),
        ("HTTP URL", "http://"),
        ("HTTPS URL", "https://"),
        ("keylogger marker", "keylogger"),
        ("ransom note marker", "decrypt your files"),
    ];

    patterns
        .iter()
        .filter(|(_, needle)| lower.contains(needle))
        .map(|(label, _)| (*label).to_string())
        .take(12)
        .collect()
}

fn contains_bytes(bytes: &[u8], pattern: &[u8]) -> bool {
    !pattern.is_empty()
        && bytes.len() >= pattern.len()
        && bytes.windows(pattern.len()).any(|window| window == pattern)
}

fn finding_detail(static_analysis: &StaticAnalysis, hash_matches: &[HashSignatureMatch]) -> String {
    let mut detail =
        "Report-only finding. No file was quarantined, deleted, or uploaded.".to_string();

    if !hash_matches.is_empty() {
        detail.push_str(" Hash indicators: ");
        detail.push_str(
            &hash_matches
                .iter()
                .map(|indicator| {
                    format!(
                        "{} {} ({})",
                        indicator.algorithm, indicator.hash, indicator.name
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
        );
    }

    if !static_analysis.signals.is_empty() {
        detail.push_str(" Signals: ");
        detail.push_str(&static_analysis.signals.join("; "));
    }

    detail
}

fn scan_yara_rules(
    rules: &Rules,
    max_scan_size: usize,
    bytes: &[u8],
) -> Result<Vec<String>, ScannerError> {
    let mut scanner = Scanner::new(rules);
    scanner.max_scan_size(max_scan_size);
    let results = scanner
        .scan(bytes)
        .map_err(|err| ScannerError::YaraScan(err.to_string()))?;
    Ok(results
        .matching_rules()
        .map(|rule| rule.identifier().to_string())
        .collect())
}

fn bytes_to_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn merge_cloud_verdict(local: ScanVerdict, cloud: &CloudLookupResult) -> ScanVerdict {
    match (&local, &cloud.verdict) {
        (ScanVerdict::Malicious, _) | (_, CloudVerdict::Malicious) => ScanVerdict::Malicious,
        (ScanVerdict::Suspicious, _) | (_, CloudVerdict::Suspicious) => ScanVerdict::Suspicious,
        (ScanVerdict::Clean, CloudVerdict::Unknown) => ScanVerdict::Unknown,
        _ => local,
    }
}

fn merge_hash_verdict(local: ScanVerdict, hash_matches: &[HashSignatureMatch]) -> ScanVerdict {
    if hash_matches
        .iter()
        .any(|indicator| indicator.verdict == ScanVerdict::Malicious)
    {
        return ScanVerdict::Malicious;
    }

    if local == ScanVerdict::Clean
        && hash_matches
            .iter()
            .any(|indicator| indicator.verdict == ScanVerdict::Suspicious)
    {
        return ScanVerdict::Suspicious;
    }

    local
}

fn looks_like_archive(display_path: &str) -> bool {
    let lower = display_path.to_ascii_lowercase();
    lower.ends_with(".zip")
        || lower.ends_with(".tar")
        || lower.ends_with(".gz")
        || lower.ends_with(".gzip")
}

fn truncate_message(message: &str) -> String {
    if message.len() <= MAX_EVENT_MESSAGE {
        return message.to_string();
    }

    format!(
        "{}...",
        message.chars().take(MAX_EVENT_MESSAGE).collect::<String>()
    )
}

pub trait CloudLookup {
    fn lookup_hash(&self, sha256: &str) -> CloudLookupResult;
}

pub struct VirusTotalClient {
    api_key: Option<String>,
    client: reqwest::blocking::Client,
}

impl VirusTotalClient {
    fn from_env() -> Self {
        Self {
            api_key: env::var("VIRUSTOTAL_API_KEY")
                .ok()
                .filter(|key| !key.trim().is_empty()),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(12))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }
}

impl CloudLookup for VirusTotalClient {
    fn lookup_hash(&self, sha256: &str) -> CloudLookupResult {
        let Some(api_key) = self.api_key.as_ref() else {
            return CloudLookupResult::disabled("VIRUSTOTAL_API_KEY is not set");
        };

        let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
        match self.client.get(url).header("x-apikey", api_key).send() {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().unwrap_or_default();
                parse_virustotal_response(status, &body)
            }
            Err(err) => CloudLookupResult {
                provider: "virustotal".to_string(),
                verdict: CloudVerdict::Error,
                reason: Some(truncate_message(&err.to_string())),
                malicious: None,
                suspicious: None,
                harmless: None,
                undetected: None,
            },
        }
    }
}

pub fn parse_virustotal_response(status: u16, body: &str) -> CloudLookupResult {
    if status == 404 {
        return CloudLookupResult {
            provider: "virustotal".to_string(),
            verdict: CloudVerdict::Unknown,
            reason: Some("hash is unknown to VirusTotal".to_string()),
            malicious: None,
            suspicious: None,
            harmless: None,
            undetected: None,
        };
    }

    if !(200..300).contains(&status) {
        return CloudLookupResult {
            provider: "virustotal".to_string(),
            verdict: CloudVerdict::Error,
            reason: Some(format!("VirusTotal returned HTTP {status}")),
            malicious: None,
            suspicious: None,
            harmless: None,
            undetected: None,
        };
    }

    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(err) => {
            return CloudLookupResult {
                provider: "virustotal".to_string(),
                verdict: CloudVerdict::Error,
                reason: Some(format!("invalid VirusTotal response: {err}")),
                malicious: None,
                suspicious: None,
                harmless: None,
                undetected: None,
            }
        }
    };

    let stats = &value["data"]["attributes"]["last_analysis_stats"];
    let malicious = stats["malicious"].as_u64().unwrap_or(0);
    let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
    let harmless = stats["harmless"].as_u64().unwrap_or(0);
    let undetected = stats["undetected"].as_u64().unwrap_or(0);
    let verdict = if malicious > 0 {
        CloudVerdict::Malicious
    } else if suspicious > 0 {
        CloudVerdict::Suspicious
    } else {
        CloudVerdict::Clean
    };

    CloudLookupResult {
        provider: "virustotal".to_string(),
        verdict,
        reason: None,
        malicious: Some(malicious),
        suspicious: Some(suspicious),
        harmless: Some(harmless),
        undetected: Some(undetected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use std::{
        fs,
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone, Default)]
    struct VecSink {
        events: Arc<Mutex<Vec<ScanEvent>>>,
    }

    impl ScanEventSink for VecSink {
        fn emit(&self, event: ScanEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[derive(Clone)]
    struct StaticCloud {
        result: CloudLookupResult,
    }

    impl CloudLookup for StaticCloud {
        fn lookup_hash(&self, _sha256: &str) -> CloudLookupResult {
            self.result.clone()
        }
    }

    fn clean_cloud() -> StaticCloud {
        StaticCloud {
            result: CloudLookupResult {
                provider: "virustotal".to_string(),
                verdict: CloudVerdict::Clean,
                reason: None,
                malicious: Some(0),
                suspicious: Some(0),
                harmless: Some(10),
                undetected: Some(1),
            },
        }
    }

    fn test_options() -> ScanOptions {
        ScanOptions {
            include_archives: true,
            cloud_lookup: false,
            max_file_mb: 1,
            max_archive_depth: 1,
        }
    }

    fn temp_file(name: &str, bytes: &[u8]) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("virus-scanner-test-{}-{name}", Uuid::new_v4()));
        fs::write(&path, bytes).unwrap();
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let mut path = env::temp_dir();
        path.push(format!("virus-scanner-test-{}-{name}", Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn patch_zip_uncompressed_size(bytes: &mut [u8], size: u32) {
        let local_header = [0x50, 0x4b, 0x03, 0x04];
        let central_header = [0x50, 0x4b, 0x01, 0x02];

        let local = bytes
            .windows(local_header.len())
            .position(|window| window == local_header)
            .unwrap();
        bytes[local + 22..local + 26].copy_from_slice(&size.to_le_bytes());

        let central = bytes
            .windows(central_header.len())
            .position(|window| window == central_header)
            .unwrap();
        bytes[central + 24..central + 28].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn detects_builtin_yara_rule_without_host_av_test_string() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let marker = b"CODEX-VIRUS-SCANNER-SMOKE-TEST";

        let mut runner =
            ScanRunner::new("scan", test_options(), cancel, &sink, clean_cloud()).unwrap();
        let result = runner
            .scan_bytes("memory::synthetic-test.txt", marker, 0)
            .unwrap();

        assert_eq!(result.verdict, ScanVerdict::Malicious);
        assert_eq!(runner.summary.findings, 1);
        assert!(sink.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ScanEvent::Finding { finding, .. }
                if finding.title.contains("Synthetic_Scanner_Test_File")
        )));
    }

    #[test]
    fn external_yara_rule_marks_matching_file_malicious() {
        let rules_dir = temp_dir("rules");
        let rule_path = rules_dir.join("synthetic.yar");
        fs::write(
            &rule_path,
            r#"
rule External_Synthetic_Marker {
  strings:
    $marker = "EXTERNAL-SAFE-SIGNATURE-MARKER"
  condition:
    $marker
}
"#,
        )
        .unwrap();

        let signatures = SignatureBundle::load(SignatureConfig {
            yara_paths: vec![rules_dir.clone()],
            hash_db_path: None,
        })
        .unwrap();
        assert_eq!(signatures.status.external_yara_sources, 1);

        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new_with_signatures(
            "scan",
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
            signatures,
        )
        .unwrap();
        let result = runner
            .scan_bytes(
                "memory::external-rule.txt",
                b"EXTERNAL-SAFE-SIGNATURE-MARKER",
                0,
            )
            .unwrap();

        assert_eq!(result.verdict, ScanVerdict::Malicious);
        assert!(result
            .yara_matches
            .contains(&"External_Synthetic_Marker".to_string()));

        let _ = fs::remove_dir_all(rules_dir);
    }

    #[test]
    fn local_hash_database_marks_matching_file_malicious() {
        let sample = b"LOCAL-HASH-SIGNATURE-MARKER";
        let sha256 = sha256_hex(sample);
        let hash_db = temp_file(
            "hash-db.json",
            format!(
                r#"{{
  "indicators": [
    {{
      "algorithm": "sha256",
      "hash": "{sha256}",
      "verdict": "malicious",
      "name": "Synthetic local hash"
    }}
  ]
}}"#
            )
            .as_bytes(),
        );

        let signatures = SignatureBundle::load(SignatureConfig {
            yara_paths: Vec::new(),
            hash_db_path: Some(hash_db.clone()),
        })
        .unwrap();
        assert_eq!(signatures.status.hash_indicators, 1);

        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new_with_signatures(
            "scan",
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
            signatures,
        )
        .unwrap();
        let result = runner
            .scan_bytes("memory::hash-match.bin", sample, 0)
            .unwrap();

        assert_eq!(result.verdict, ScanVerdict::Malicious);
        assert_eq!(result.hash_matches.len(), 1);
        assert_eq!(result.hash_matches[0].name, "Synthetic local hash");

        let _ = fs::remove_file(hash_db);
    }

    #[rstest]
    #[case(ScanVerdict::Clean, ScanVerdict::Suspicious, ScanVerdict::Suspicious)]
    #[case(
        ScanVerdict::Suspicious,
        ScanVerdict::Malicious,
        ScanVerdict::Malicious
    )]
    #[case(
        ScanVerdict::Malicious,
        ScanVerdict::Suspicious,
        ScanVerdict::Malicious
    )]
    fn hash_verdict_merging_uses_highest_local_severity(
        #[case] local: ScanVerdict,
        #[case] hash_verdict: ScanVerdict,
        #[case] expected: ScanVerdict,
    ) {
        let indicator = HashSignatureMatch {
            algorithm: "sha256".to_string(),
            hash: "a".repeat(64),
            verdict: hash_verdict,
            name: "Parameterized hash".to_string(),
            source: None,
        };

        assert_eq!(merge_hash_verdict(local, &[indicator]), expected);
    }

    #[cfg(windows)]
    #[test]
    fn windows_sys_file_attributes_are_reported_for_real_files() {
        let path = temp_file("windows-attributes.txt", b"metadata");
        let attributes = windows_file_attributes(&path.display().to_string());

        assert!(attributes.is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn signature_status_reports_invalid_external_rule_without_disabling_builtins() {
        let rules_dir = temp_dir("bad-rules");
        fs::write(rules_dir.join("bad.yar"), "not a valid yara rule").unwrap();

        let signatures = SignatureBundle::load(SignatureConfig {
            yara_paths: vec![rules_dir.clone()],
            hash_db_path: None,
        })
        .unwrap();

        assert_eq!(signatures.status.built_in_yara_sources, 1);
        assert_eq!(signatures.status.external_yara_sources, 0);
        assert_eq!(signatures.status.load_errors.len(), 1);

        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut runner = ScanRunner::new_with_signatures(
            "scan",
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
            signatures,
        )
        .unwrap();
        let result = runner
            .scan_bytes(
                "memory::synthetic-test.txt",
                b"CODEX-VIRUS-SCANNER-SMOKE-TEST",
                0,
            )
            .unwrap();

        assert_eq!(result.verdict, ScanVerdict::Malicious);
        assert!(result
            .yara_matches
            .contains(&"Synthetic_Scanner_Test_File".to_string()));

        let _ = fs::remove_dir_all(rules_dir);
    }

    #[test]
    fn scanbridge_hasher_outputs_sha256_and_blake3() {
        let hashes = FileHasher::new().with_sha256(true).hash_bytes(b"abc");

        assert_eq!(
            hashes.sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(hashes.blake3, blake3::hash(b"abc").to_hex().to_string());
    }

    #[test]
    fn static_analysis_flags_packer_and_strings() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut bytes: Vec<u8> = (0_u8..=255).cycle().take(8192).collect();
        bytes.extend_from_slice(b"UPX0 powershell http://example.test/payload");

        let mut runner =
            ScanRunner::new("scan", test_options(), cancel, &sink, clean_cloud()).unwrap();
        let result = runner
            .scan_bytes("memory::packed-suspicious.bin", &bytes, 0)
            .unwrap();

        assert_eq!(result.verdict, ScanVerdict::Suspicious);
        assert!(result.static_analysis.packer.detected);
        assert!(result.static_analysis.threat_score >= 35);
        assert!(result
            .static_analysis
            .signals
            .iter()
            .any(|signal| signal.contains("Packed with UPX")));
    }

    #[test]
    fn magika_file_type_maps_to_content_classification() {
        let classification =
            content_classification_from_file_type(&FileType::Ruled(magika::ContentType::Txt));

        assert_eq!(classification.label, "txt");
        assert_eq!(classification.mime_type, "text/plain");
        assert_eq!(classification.score, 1.0);
    }

    #[test]
    fn clean_file_scans_clean() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let path = temp_file("clean.txt", b"hello from a harmless document");

        let summary = run_scan(
            "scan",
            vec![path.display().to_string()],
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
        )
        .unwrap();

        assert_eq!(summary.files_scanned, 1);
        assert_eq!(summary.findings, 0);
        assert!(sink.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ScanEvent::FileFinished { result, .. } if result.verdict == ScanVerdict::Clean
        )));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_file_counts_one_error_and_scan_completes() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut missing = env::temp_dir();
        missing.push(format!("virus-scanner-test-{}-missing.txt", Uuid::new_v4()));
        let clean = temp_file("after-missing.txt", b"still scanned");

        let summary = run_scan(
            "scan",
            vec![missing.display().to_string(), clean.display().to_string()],
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
        )
        .unwrap();

        assert_eq!(summary.errors, 1);
        assert_eq!(summary.files_scanned, 1);
        assert!(sink
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, ScanEvent::ScanCompleted { .. })));

        let _ = fs::remove_file(clean);
    }

    #[test]
    fn missing_virustotal_key_disables_cloud() {
        let status = cloud_status_from_env(None);
        assert!(!status.enabled);
        assert_eq!(status.provider, "virustotal");
    }

    #[test]
    fn virustotal_404_is_unknown_without_upload() {
        let result = parse_virustotal_response(404, r#"{"error":{"code":"NotFoundError"}}"#);
        assert_eq!(result.verdict, CloudVerdict::Unknown);
    }

    #[test]
    fn compromise_suite_marks_existing_targets_recommended_and_missing_targets_skipped() {
        let home = temp_dir("suite-home");
        let downloads = home.join("Downloads");
        fs::create_dir_all(&downloads).unwrap();
        let app_data = temp_dir("suite-appdata");
        let local_app_data = temp_dir("suite-localappdata");
        let program_data = temp_dir("suite-programdata");
        let temp = temp_dir("suite-temp");

        let suite = compromise_check_suite_from_paths(CompromisePathInputs {
            home_dir: Some(home.clone()),
            app_data: Some(app_data.clone()),
            local_app_data: Some(local_app_data.clone()),
            program_data: Some(program_data.clone()),
            temp_dir: Some(temp.clone()),
        });

        assert!(suite.report_only);
        assert!(suite
            .groups
            .iter()
            .any(|group| group.id == "persistence" && group.risk == "high"));
        assert!(suite
            .targets
            .iter()
            .any(|target| target.path == downloads.display().to_string()
                && target.exists
                && target.recommended));
        assert!(suite
            .targets
            .iter()
            .any(|target| target.path.ends_with("Microsoft\\Windows\\Start Menu\\Programs\\Startup")
                && !target.exists
                && !target.recommended
                && target.reason.as_deref() == Some("path does not exist")));

        let _ = fs::remove_dir_all(home);
        let _ = fs::remove_dir_all(app_data);
        let _ = fs::remove_dir_all(local_app_data);
        let _ = fs::remove_dir_all(program_data);
        let _ = fs::remove_dir_all(temp);
    }

    #[test]
    fn compromise_suite_keeps_targets_unique() {
        let root = temp_dir("suite-unique");
        let suite = compromise_check_suite_from_paths(CompromisePathInputs {
            home_dir: Some(root.clone()),
            app_data: Some(root.clone()),
            local_app_data: Some(root.clone()),
            program_data: Some(root.clone()),
            temp_dir: Some(root.clone()),
        });
        let mut paths = suite
            .targets
            .iter()
            .map(|target| target.path.clone())
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();

        assert_eq!(paths.len(), suite.targets.len());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn oversized_file_is_skipped() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let large = vec![0_u8; (1024 * 1024) + 1];
        let path = temp_file("large.bin", &large);
        let options = test_options();

        let mut runner = ScanRunner::new("scan", options, cancel, &sink, clean_cloud()).unwrap();
        runner.scan_path(&path).unwrap();

        assert!(sink.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ScanEvent::FileFinished { result, .. } if result.verdict == ScanVerdict::Skipped
        )));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn opened_file_that_grows_over_limit_is_skipped() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let path = temp_file("grown-after-open.bin", b"small");
        let mut file = File::open(&path).unwrap();
        fs::write(&path, vec![0_u8; (1024 * 1024) + 1]).unwrap();

        let mut runner =
            ScanRunner::new("scan", test_options(), cancel, &sink, clean_cloud()).unwrap();
        runner
            .scan_opened_file(&path.display().to_string(), &mut file, 0)
            .unwrap();

        assert!(sink.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ScanEvent::FileFinished { result, .. }
                if result.verdict == ScanVerdict::Skipped
                    && result.skipped_reason.as_deref() == Some("file is larger than maxFileMb")
        )));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn zip_member_actual_read_over_limit_is_skipped() {
        let mut zip_bytes = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut zip_bytes);
            writer
                .start_file("large.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&vec![b'a'; (1024 * 1024) + 1]).unwrap();
            writer.finish().unwrap();
        }

        let mut zip_bytes = zip_bytes.into_inner();
        patch_zip_uncompressed_size(&mut zip_bytes, 1);

        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let path = temp_file("lying-size.zip", &zip_bytes);

        let summary = run_scan(
            "scan",
            vec![path.display().to_string()],
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
        )
        .unwrap();

        assert_eq!(summary.skipped, 1);
        assert!(sink.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ScanEvent::FileFinished { result, .. }
                if result.path.ends_with("::large.txt")
                    && result.verdict == ScanVerdict::Skipped
                    && result.skipped_reason.as_deref()
                        == Some("archive member is larger than maxFileMb")
        )));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn archive_recursion_limit_skips_nested_archive() {
        let mut inner = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut inner);
            writer
                .start_file("nested.txt", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer
                .write_all(b"nested content that should not be scanned")
                .unwrap();
            writer.finish().unwrap();
        }

        let mut outer = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut outer);
            writer
                .start_file("inner.zip", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&inner.into_inner()).unwrap();
            writer.finish().unwrap();
        }

        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(false));
        let path = temp_file("outer.zip", &outer.into_inner());

        let summary = run_scan(
            "scan",
            vec![path.display().to_string()],
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
        )
        .unwrap();

        assert_eq!(summary.findings, 0);
        assert!(sink.events.lock().unwrap().iter().any(|event| matches!(
            event,
            ScanEvent::FileFinished { result, .. }
                if result.verdict == ScanVerdict::Skipped
                    && result.skipped_reason.as_deref() == Some("archive recursion limit reached")
        )));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn scan_cancellation_completes_as_canceled() {
        let sink = VecSink::default();
        let cancel = Arc::new(AtomicBool::new(true));
        let path = temp_file("cancel.txt", b"content");

        let summary = run_scan(
            "scan",
            vec![path.display().to_string()],
            test_options(),
            cancel,
            &sink,
            clean_cloud(),
        )
        .unwrap();

        assert!(summary.canceled);
        assert_eq!(summary.files_scanned, 0);

        let _ = fs::remove_file(path);
    }
}
