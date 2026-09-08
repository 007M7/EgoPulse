#![cfg(windows)]

use portable_pty::{CommandBuilder as PtyCommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const LIVE_TUI_PLAN_ENV: &str = "EGOPULSE_LIVE_TUI_PLAN";
const SCREEN_ROWS: u16 = 40;
const SCREEN_COLUMNS: u16 = 140;
const OUTPUT_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const REPORT_FILE: &str = "repository-tui-live-report.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryTuiLivePlan {
    binary: PathBuf,
    instance: String,
    working_directory: PathBuf,
    output_directory: PathBuf,
    steps: Vec<RepositoryTuiLiveStep>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryTuiLiveStep {
    wait_for: String,
    #[serde(default)]
    keys: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RepositoryTuiLiveReport {
    status: &'static str,
    completed_steps: usize,
    selected_task_id: Option<String>,
    artifacts: Vec<String>,
    failure_code: Option<&'static str>,
}

impl Default for RepositoryTuiLiveReport {
    fn default() -> Self {
        Self {
            status: "running",
            completed_steps: 0,
            selected_task_id: None,
            artifacts: Vec::new(),
            failure_code: None,
        }
    }
}

struct ConptyOutput {
    bytes: Vec<u8>,
    screen: vt100::Parser,
    overflowed: bool,
    reader_failed: bool,
}

impl Default for ConptyOutput {
    fn default() -> Self {
        Self {
            bytes: Vec::new(),
            screen: vt100::Parser::new(SCREEN_ROWS, SCREEN_COLUMNS, 0),
            overflowed: false,
            reader_failed: false,
        }
    }
}

struct OutputSnapshot {
    screen: String,
    raw: Vec<u8>,
    overflowed: bool,
    reader_failed: bool,
}

struct RepositoryTuiConptySession {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
    writer: Option<Box<dyn Write + Send>>,
    output: Arc<Mutex<ConptyOutput>>,
    reader: Option<thread::JoinHandle<()>>,
    cursor_queries_answered: usize,
}

impl RepositoryTuiConptySession {
    fn spawn(plan: &RepositoryTuiLivePlan) -> Result<Self, &'static str> {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: SCREEN_ROWS,
                cols: SCREEN_COLUMNS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|_| "conpty_open_failed")?;
        let command = repository_tui_command(plan)?;
        let child = pair
            .slave
            .spawn_command(command)
            .map_err(|_| "tui_spawn_failed")?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|_| "conpty_reader_clone_failed")?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|_| "conpty_writer_open_failed")?;
        drop(pair.slave);

        let output = Arc::new(Mutex::new(ConptyOutput::default()));
        let reader_output = Arc::clone(&output);
        let reader = thread::spawn(move || {
            let mut chunk = [0_u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(read) => {
                        let Ok(mut output) = reader_output.lock() else {
                            break;
                        };
                        let remaining = OUTPUT_LIMIT_BYTES.saturating_sub(output.bytes.len());
                        let retained = read.min(remaining);
                        output.bytes.extend_from_slice(&chunk[..retained]);
                        output.screen.process(&chunk[..retained]);
                        if retained != read {
                            output.overflowed = true;
                        }
                    }
                    Err(_) => {
                        if let Ok(mut output) = reader_output.lock() {
                            output.reader_failed = true;
                        }
                        break;
                    }
                }
            }
        });

        Ok(Self {
            child,
            _master: pair.master,
            writer: Some(writer),
            output,
            reader: Some(reader),
            cursor_queries_answered: 0,
        })
    }

    fn snapshot(&self) -> Result<OutputSnapshot, &'static str> {
        let output = self.output.lock().map_err(|_| "conpty_output_poisoned")?;
        Ok(OutputSnapshot {
            screen: output.screen.screen().contents(),
            raw: output.bytes.clone(),
            overflowed: output.overflowed,
            reader_failed: output.reader_failed,
        })
    }

    fn send_keys(&mut self, keys: &[u8]) -> Result<(), &'static str> {
        let writer = self.writer.as_mut().ok_or("conpty_writer_closed")?;
        writer
            .write_all(keys)
            .map_err(|_| "conpty_key_write_failed")?;
        writer.flush().map_err(|_| "conpty_key_flush_failed")
    }

    fn answer_cursor_queries(&mut self, raw: &[u8]) -> Result<(), &'static str> {
        let queries = raw
            .windows(4)
            .filter(|window| *window == b"\x1b[6n")
            .count();
        while self.cursor_queries_answered < queries {
            self.send_keys(b"\x1b[1;1R")?;
            self.cursor_queries_answered += 1;
        }
        Ok(())
    }

    fn wait_for_exit(&mut self, total_steps: usize) -> Result<(), &'static str> {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        let mut next_progress = Instant::now() + PROGRESS_INTERVAL;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|_| "tui_exit_check_failed")? {
                return status.success().then_some(()).ok_or("tui_exit_nonzero");
            }
            if Instant::now() >= deadline {
                return Err("tui_exit_deadline");
            }
            if Instant::now() >= next_progress {
                println!(
                    "repository_tui_live: awaiting plan exit after stage {total_steps}/{total_steps}"
                );
                next_progress += PROGRESS_INTERVAL;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn finish_reader(&mut self) -> Result<(), &'static str> {
        self.writer.take();
        let deadline = Instant::now() + REAP_TIMEOUT;
        while self
            .reader
            .as_ref()
            .is_some_and(|reader| !reader.is_finished())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        let Some(reader) = self.reader.take() else {
            return Ok(());
        };
        if !reader.is_finished() {
            self.reader = Some(reader);
            return Err("conpty_reader_drain_deadline");
        }
        reader.join().map_err(|_| "conpty_reader_join_failed")
    }
}

impl Drop for RepositoryTuiConptySession {
    fn drop(&mut self) {
        self.writer.take();
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let deadline = Instant::now() + REAP_TIMEOUT;
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        if self
            .reader
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
            && let Some(reader) = self.reader.take()
        {
            let _ = reader.join();
        }
    }
}

#[test]
#[ignore = "requires a user-provided EGOPULSE_LIVE_TUI_PLAN and live daemon"]
fn repository_tui_live_plan() {
    let Some(plan_path) = env::var_os(LIVE_TUI_PLAN_ENV).map(PathBuf::from) else {
        return;
    };
    let plan = load_plan(&plan_path).unwrap_or_else(|code| panic!("repository_tui_live: {code}"));
    let mut report = RepositoryTuiLiveReport::default();
    let result = run_plan(&plan, &mut report);
    if let Err(code) = result {
        report.status = "failed";
        report.failure_code = Some(code);
    } else {
        report.status = "passed";
    }
    write_report(&plan.output_directory, &report)
        .unwrap_or_else(|code| panic!("repository_tui_live: {code}"));
    if let Err(code) = result {
        panic!("repository_tui_live: {code}; see the private plan output directory");
    }
}

fn load_plan(plan_path: &Path) -> Result<RepositoryTuiLivePlan, &'static str> {
    if !plan_path.is_absolute() {
        return Err("plan_path_not_absolute");
    }
    let bytes = fs::read(plan_path).map_err(|_| "plan_read_failed")?;
    if bytes.len() > 1024 * 1024 {
        return Err("plan_too_large");
    }
    let plan =
        serde_json::from_slice::<RepositoryTuiLivePlan>(&bytes).map_err(|_| "plan_invalid")?;
    validate_plan(&plan)?;
    Ok(plan)
}

fn validate_plan(plan: &RepositoryTuiLivePlan) -> Result<(), &'static str> {
    if !plan.binary.is_absolute()
        || !plan.working_directory.is_absolute()
        || !plan.output_directory.is_absolute()
        || !plan.binary.is_file()
        || !plan.working_directory.is_dir()
    {
        return Err("plan_path_invalid");
    }
    if plan.instance.is_empty()
        || plan.instance.len() > 256
        || plan.instance.chars().any(char::is_control)
    {
        return Err("plan_instance_invalid");
    }
    if plan.steps.is_empty() || plan.steps.len() > 128 {
        return Err("plan_steps_invalid");
    }
    for step in &plan.steps {
        let timeout_seconds = step.timeout_seconds.unwrap_or(30);
        if step.wait_for.is_empty()
            || step.wait_for.len() > 8192
            || step.keys.as_ref().is_some_and(|keys| keys.len() > 32768)
            || !(30..=900).contains(&timeout_seconds)
        {
            return Err("plan_step_invalid");
        }
    }
    if plan.steps.last().and_then(|step| step.keys.as_deref()) != Some("q") {
        return Err("plan_must_finish_with_q");
    }
    Ok(())
}

fn repository_tui_command(plan: &RepositoryTuiLivePlan) -> Result<PtyCommandBuilder, &'static str> {
    const INHERITED_ENVIRONMENT: [&str; 6] = [
        "SystemRoot",
        "PATH",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
    ];

    let mut command = PtyCommandBuilder::new(plan.binary.as_os_str());
    command.env_clear();
    for name in INHERITED_ENVIRONMENT {
        let value = env::var_os(name).ok_or("host_environment_missing")?;
        command.env(name, value);
    }
    command.env("EGOPULSE_IPC_INSTANCE", &plan.instance);
    command.cwd(plan.working_directory.as_os_str());
    command.args(&["--instance".to_owned(), plan.instance.clone()]);
    Ok(command)
}

fn run_plan(
    plan: &RepositoryTuiLivePlan,
    report: &mut RepositoryTuiLiveReport,
) -> Result<(), &'static str> {
    fs::create_dir_all(&plan.output_directory).map_err(|_| "output_directory_create_failed")?;
    if plan.output_directory.join(REPORT_FILE).exists() {
        return Err("output_report_already_exists");
    }

    let mut session = RepositoryTuiConptySession::spawn(plan)?;
    for (index, step) in plan.steps.iter().enumerate() {
        wait_for_checkpoint(&mut session, plan, index, step, report)?;
        report.completed_steps = index + 1;
    }
    if let Err(code) = session.wait_for_exit(plan.steps.len()) {
        save_failure_artifacts(&session, plan, plan.steps.len(), report);
        return Err(code);
    }
    if let Err(code) = session.finish_reader() {
        save_failure_artifacts(&session, plan, plan.steps.len(), report);
        return Err(code);
    }
    let snapshot = session.snapshot().inspect_err(|_| {
        save_failure_artifacts(&session, plan, plan.steps.len(), report);
    })?;
    if snapshot.overflowed {
        save_failure_artifacts(&session, plan, plan.steps.len(), report);
        return Err("output_limit_exceeded");
    }
    if snapshot.reader_failed {
        save_failure_artifacts(&session, plan, plan.steps.len(), report);
        return Err("conpty_reader_failed");
    }
    record_snapshot(plan, report, "final-screen.txt", "final-raw.bin", &snapshot)?;
    if let Some(task_id) = selected_u04c_task_id(&snapshot.screen) {
        report.selected_task_id = Some(task_id);
    }
    Ok(())
}

fn wait_for_checkpoint(
    session: &mut RepositoryTuiConptySession,
    plan: &RepositoryTuiLivePlan,
    index: usize,
    step: &RepositoryTuiLiveStep,
    report: &mut RepositoryTuiLiveReport,
) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(step.timeout_seconds.unwrap_or(30));
    let mut next_progress = Instant::now() + PROGRESS_INTERVAL;
    loop {
        let snapshot = session.snapshot().inspect_err(|_| {
            save_failure_artifacts(session, plan, index + 1, report);
        })?;
        if snapshot.overflowed {
            save_failure_artifacts(session, plan, index + 1, report);
            return Err("output_limit_exceeded");
        }
        if snapshot.reader_failed {
            save_failure_artifacts(session, plan, index + 1, report);
            return Err("conpty_reader_failed");
        }
        if session.answer_cursor_queries(&snapshot.raw).is_err() {
            save_failure_artifacts(session, plan, index + 1, report);
            return Err("cursor_query_reply_failed");
        }
        if snapshot.screen.contains(&step.wait_for) {
            let screen_name = format!("checkpoint-{:03}-screen.txt", index + 1);
            let raw_name = format!("checkpoint-{:03}-raw.bin", index + 1);
            record_snapshot(plan, report, &screen_name, &raw_name, &snapshot)?;
            if let Some(task_id) = selected_u04c_task_id(&snapshot.screen) {
                report.selected_task_id = Some(task_id);
            }
            if let Some(keys) = &step.keys {
                session.send_keys(keys.as_bytes())?;
            }
            return Ok(());
        }
        if session
            .child
            .try_wait()
            .map_err(|_| "tui_exit_check_failed")?
            .is_some()
        {
            save_failure_artifacts(session, plan, index + 1, report);
            return Err("tui_exited_before_checkpoint");
        }
        if Instant::now() >= deadline {
            save_failure_artifacts(session, plan, index + 1, report);
            return Err("checkpoint_deadline");
        }
        if Instant::now() >= next_progress {
            println!(
                "repository_tui_live: waiting for stage {}/{}",
                index + 1,
                plan.steps.len()
            );
            next_progress += PROGRESS_INTERVAL;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn save_failure_artifacts(
    session: &RepositoryTuiConptySession,
    plan: &RepositoryTuiLivePlan,
    stage: usize,
    report: &mut RepositoryTuiLiveReport,
) {
    let Ok(snapshot) = session.snapshot() else {
        return;
    };
    let screen_name = format!("failure-{:03}-screen.txt", stage);
    let raw_name = format!("failure-{:03}-raw.bin", stage);
    let _ = record_snapshot(plan, report, &screen_name, &raw_name, &snapshot);
}

fn record_snapshot(
    plan: &RepositoryTuiLivePlan,
    report: &mut RepositoryTuiLiveReport,
    screen_name: &str,
    raw_name: &str,
    snapshot: &OutputSnapshot,
) -> Result<(), &'static str> {
    write_private_file(
        &plan.output_directory,
        screen_name,
        snapshot.screen.as_bytes(),
    )?;
    write_private_file(&plan.output_directory, raw_name, &snapshot.raw)?;
    report.artifacts.push(screen_name.to_owned());
    report.artifacts.push(raw_name.to_owned());
    Ok(())
}

fn write_report(
    output_directory: &Path,
    report: &RepositoryTuiLiveReport,
) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec_pretty(report).map_err(|_| "report_serialize_failed")?;
    write_private_file(output_directory, REPORT_FILE, &bytes)
}

fn write_private_file(
    output_directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), &'static str> {
    let path = output_directory.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "private_artifact_create_failed")?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .map_err(|_| "private_artifact_write_failed")
}

fn selected_u04c_task_id(screen: &str) -> Option<String> {
    let valid_identity_character = |character: char| {
        character.is_ascii_alphanumeric() || matches!(character, ':' | '-' | '_' | '.')
    };
    let visible_task_id = screen.split('>').skip(1).find_map(|selected| {
        let selected = selected.trim_start();
        let visible_task_id = selected.split_ascii_whitespace().next()?;
        (!visible_task_id.is_empty()
            && visible_task_id.starts_with("task")
            && visible_task_id.chars().all(valid_identity_character))
        .then_some(visible_task_id)
    })?;
    let governed_detail = screen.split_once("Execution / Recovery Facts")?.1;
    let full_task_id = governed_detail
        .split_once("Task task")?
        .1
        .chars()
        .take_while(|character| valid_identity_character(*character))
        .fold(String::from("task"), |mut task_id, character| {
            task_id.push(character);
            task_id
        });
    (full_task_id.starts_with(visible_task_id)
        && !visible_task_id.is_empty()
        && !full_task_id.is_empty())
    .then_some(full_task_id)
}
