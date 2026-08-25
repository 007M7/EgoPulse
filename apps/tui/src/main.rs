#![forbid(unsafe_code)]

use std::{
    io::{self, stdout},
    process::ExitCode,
    time::{Duration, SystemTime},
};

use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use egopulse_client_kernel::ClientKernel;
use egopulse_domain_contracts::v01::egopulse::{
    harness::v1::ApprovalRequestLifecycleKind,
    localapi::v1::{
        ClientSurface, GetProjectionStatusRequest, HarnessApprovalView,
        ListHarnessApprovalViewsRequest, ListTaskViewsRequest, LocalApiErrorCode, ProjectionHealth,
        TaskView,
    },
    task::v1::TaskStatus,
};
use egopulse_local_api::{LocalApiClient, LocalApiConnection, LocalIpcAddress};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "egopulse-tui", version, about = "EgoPulse terminal surface")]
struct Args {
    /// Use a specific local daemon instance.
    #[arg(long, default_value = "default")]
    instance: String,
    /// Print the foundation probe without entering raw terminal mode.
    #[arg(long)]
    foundation_check: bool,
    /// Fetch one snapshot and render it as plain text.
    #[arg(long)]
    once: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Panel {
    Tasks,
    Approvals,
}

impl Panel {
    const ALL: [Self; 2] = [Self::Tasks, Self::Approvals];

    fn index(self) -> usize {
        match self {
            Self::Tasks => 0,
            Self::Approvals => 1,
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Tasks => Self::Approvals,
            Self::Approvals => Self::Tasks,
        }
    }
}

struct AttachedClient {
    connection: LocalApiConnection,
    kernel: ClientKernel,
}

impl AttachedClient {
    async fn open(instance: &str) -> Result<Self, String> {
        let address = LocalIpcAddress::for_instance(instance).map_err(|error| error.to_string())?;
        let connection = LocalApiClient::platform_default()
            .connect(address)
            .await
            .map_err(|error| format!("daemon unavailable: {error}"))?;
        let mut kernel = ClientKernel::new(
            format!("egopulse-tui-{}", Uuid::now_v7()),
            ClientSurface::Tui,
        )
        .map_err(|error| format!("client kernel unavailable: {error}"))?;
        let request = kernel
            .open_session_request(Uuid::now_v7().to_string())
            .map_err(|error| format!("session request invalid: {error}"))?;
        let response = connection
            .session_service()
            .open_session(request)
            .await
            .map_err(|error| format!("open session failed: {error}"))?
            .into_inner();
        kernel
            .accept_open_session(response, SystemTime::now())
            .map_err(|error| format!("session rejected: {error}"))?;
        Ok(Self { connection, kernel })
    }

    fn metadata(
        &self,
    ) -> Result<egopulse_domain_contracts::v01::egopulse::localapi::v1::ClientRequestMetadata, String>
    {
        self.kernel
            .request_metadata(Uuid::now_v7().to_string(), None, SystemTime::now())
            .map_err(|error| error.to_string())
    }

    async fn snapshot(&self) -> Result<Snapshot, String> {
        let status = self
            .connection
            .read_model_service()
            .get_projection_status(GetProjectionStatusRequest {
                client: Some(self.metadata()?),
            })
            .await
            .map_err(|error| error.to_string())?
            .into_inner();
        if let Some(error) = status.error {
            return Err(local_error_message(error));
        }
        let metadata = status
            .metadata
            .ok_or_else(|| "projection metadata missing".to_owned())?;

        let tasks = self
            .connection
            .read_model_service()
            .list_task_views(ListTaskViewsRequest {
                client: Some(self.metadata()?),
                status_filter: Vec::new(),
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| error.to_string())?
            .into_inner();
        if let Some(error) = tasks.error {
            return Err(local_error_message(error));
        }

        let approvals = self
            .connection
            .read_model_service()
            .list_harness_approval_views(ListHarnessApprovalViewsRequest {
                client: Some(self.metadata()?),
                request_lifecycle_filter: Vec::new(),
                decision_state_filter: Vec::new(),
                task_ids: Vec::new(),
                actionable_only: false,
                page_size: 100,
                page_cursor: None,
                minimum_position: None,
            })
            .await
            .map_err(|error| error.to_string())?
            .into_inner();
        if let Some(error) = approvals.error {
            return Err(local_error_message(error));
        }

        Ok(Snapshot {
            health: ProjectionHealth::try_from(metadata.health)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned()),
            stale: metadata.stale,
            position: metadata
                .position
                .map(|value| format!("{}:{}", value.epoch, value.sequence))
                .unwrap_or_else(|| "unknown".to_owned()),
            tasks: tasks.views,
            approvals: approvals.views,
        })
    }
}

struct Snapshot {
    health: String,
    stale: bool,
    position: String,
    tasks: Vec<TaskView>,
    approvals: Vec<HarnessApprovalView>,
}

struct App {
    instance: String,
    client: Option<AttachedClient>,
    snapshot: Option<Snapshot>,
    panel: Panel,
    message: String,
    refresh_interval: Duration,
}

impl App {
    fn new(instance: String) -> Self {
        Self {
            instance,
            client: None,
            snapshot: None,
            panel: Panel::Tasks,
            message: "Connecting to local daemon…".to_owned(),
            refresh_interval: Duration::from_secs(2),
        }
    }

    async fn refresh(&mut self) {
        if self.client.is_none() {
            match AttachedClient::open(&self.instance).await {
                Ok(client) => self.client = Some(client),
                Err(error) => {
                    self.message = error;
                    return;
                }
            }
        }
        let result = self
            .client
            .as_ref()
            .expect("client is attached")
            .snapshot()
            .await;
        match result {
            Ok(snapshot) => {
                self.message = format!(
                    "Connected · {} tasks · {} approvals · press r to refresh, q to quit",
                    snapshot.tasks.len(),
                    snapshot.approvals.len()
                );
                self.snapshot = Some(snapshot);
            }
            Err(error) => {
                self.message = format!("Disconnected: {error} · press r to reconnect");
                self.client = None;
            }
        }
    }

    fn render(&self, frame: &mut Frame<'_>) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(2),
            ])
            .split(frame.area());
        let snapshot = self.snapshot.as_ref();
        let title = snapshot.map_or_else(
            || "EgoPulse · TUI · disconnected".to_owned(),
            |value| {
                format!(
                    "EgoPulse · TUI · {} · {} · position {}",
                    value.health,
                    if value.stale { "stale" } else { "fresh" },
                    value.position
                )
            },
        );
        frame.render_widget(
            Paragraph::new(title)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Local control plane"),
                )
                .style(Style::default().fg(Color::Cyan)),
            layout[0],
        );

        let tabs = Tabs::new(
            Panel::ALL
                .iter()
                .map(|panel| match panel {
                    Panel::Tasks => Line::from("Tasks"),
                    Panel::Approvals => Line::from("Approvals"),
                })
                .collect::<Vec<_>>(),
        )
        .select(self.panel.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Governed views"),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
        let body = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1)])
            .split(layout[1]);
        frame.render_widget(tabs, body[0]);
        match (self.panel, snapshot) {
            (Panel::Tasks, Some(snapshot)) => render_tasks(frame, body[1], &snapshot.tasks),
            (Panel::Approvals, Some(snapshot)) => {
                render_approvals(frame, body[1], &snapshot.approvals)
            }
            (_, None) => frame.render_widget(
                Paragraph::new("No projection snapshot available.")
                    .block(Block::default().borders(Borders::ALL))
                    .wrap(Wrap { trim: true }),
                body[1],
            ),
        }
        frame.render_widget(
            Paragraph::new(self.message.as_str()).style(Style::default().fg(Color::Gray)),
            layout[2],
        );
    }
}

fn render_tasks(frame: &mut Frame<'_>, area: Rect, tasks: &[TaskView]) {
    let rows = tasks.iter().map(|view| {
        let task = view.task.as_ref();
        Row::new([
            Cell::from(task.map_or("-", |value| value.task_id.as_str())),
            Cell::from(
                task.and_then(|value| TaskStatus::try_from(value.status).ok())
                    .map(|value| value.as_str_name())
                    .unwrap_or("TASK_STATUS_UNSPECIFIED"),
            ),
            Cell::from(task.map_or("-".to_owned(), |value| value.revision.to_string())),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Percentage(48),
                Constraint::Percentage(32),
                Constraint::Length(12),
            ],
        )
        .header(Row::new(["Task", "Status", "Revision"]).style(Style::default().fg(Color::Yellow)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Projected Tasks"),
        ),
        area,
    );
}

fn render_approvals(frame: &mut Frame<'_>, area: Rect, approvals: &[HarnessApprovalView]) {
    let rows = approvals.iter().map(|view| {
        Row::new([
            Cell::from(view.approval_request_id.clone()),
            Cell::from(
                ApprovalRequestLifecycleKind::try_from(view.request_lifecycle)
                    .map(|value| value.as_str_name())
                    .unwrap_or("APPROVAL_REQUEST_LIFECYCLE_UNSPECIFIED"),
            ),
            Cell::from(view.request_revision.to_string()),
            Cell::from(view.task_id.clone()),
        ])
    });
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Percentage(34),
                Constraint::Percentage(27),
                Constraint::Length(12),
                Constraint::Percentage(27),
            ],
        )
        .header(
            Row::new(["Approval", "Lifecycle", "Revision", "Task"])
                .style(Style::default().fg(Color::Yellow)),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Projected Approvals"),
        ),
        area,
    );
}

fn local_error_message(
    error: egopulse_domain_contracts::v01::egopulse::localapi::v1::LocalApiError,
) -> String {
    let code = LocalApiErrorCode::try_from(error.code)
        .map(|value| value.as_str_name().to_owned())
        .unwrap_or_else(|_| "LOCAL_API_ERROR_UNKNOWN".to_owned());
    if error.retryable {
        format!("{code} (retryable)")
    } else {
        code
    }
}

async fn run_once(mut app: App) -> Result<(), String> {
    app.refresh().await;
    if let Some(snapshot) = app.snapshot {
        println!(
            "EgoPulse TUI: connected health={} stale={} position={} tasks={} approvals={}",
            snapshot.health,
            snapshot.stale,
            snapshot.position,
            snapshot.tasks.len(),
            snapshot.approvals.len()
        );
        Ok(())
    } else {
        Err(app.message)
    }
}

async fn run_interactive(args: Args) -> Result<(), String> {
    let mut app = App::new(args.instance);
    app.refresh().await;
    let mut terminal = init_terminal().map_err(|error| error.to_string())?;
    let result = run_loop(&mut terminal, &mut app).await;
    restore_terminal(&mut terminal).map_err(|error| error.to_string())?;
    result
}

async fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<(), String> {
    let mut next_refresh = tokio::time::Instant::now();
    loop {
        terminal
            .draw(|frame| app.render(frame))
            .map_err(|error| error.to_string())?;
        if tokio::time::Instant::now() >= next_refresh {
            if app.snapshot.is_some() {
                app.refresh().await;
            }
            next_refresh = tokio::time::Instant::now() + app.refresh_interval;
        }
        if event::poll(Duration::from_millis(150)).map_err(|error| error.to_string())?
            && let Event::Key(key) = event::read().map_err(|error| error.to_string())?
            && key.kind == KeyEventKind::Press
        {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Char('r') => {
                    app.message = "Refreshing…".to_owned();
                    app.refresh().await;
                    next_refresh = tokio::time::Instant::now() + app.refresh_interval;
                }
                KeyCode::Tab | KeyCode::Right | KeyCode::Left => app.panel = app.panel.next(),
                _ => {}
            }
        }
    }
}

fn init_terminal() -> io::Result<DefaultTerminal> {
    enable_raw_mode()?;
    let mut output = stdout();
    execute!(output, EnterAlternateScreen)?;
    Ok(ratatui::init())
}

fn restore_terminal(terminal: &mut DefaultTerminal) -> io::Result<()> {
    ratatui::restore();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    if args.foundation_check {
        let health = LocalApiClient::platform_default().foundation_health();
        println!("EgoPulse TUI: {}", health.state.as_str());
        return ExitCode::SUCCESS;
    }
    let result = if args.once {
        run_once(App::new(args.instance)).await
    } else {
        run_interactive(args).await
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("EgoPulse TUI: {error}");
            ExitCode::from(3)
        }
    }
}
