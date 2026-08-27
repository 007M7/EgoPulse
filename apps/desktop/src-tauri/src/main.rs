#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use egopulse_client_operations::{ClientReadError, attach};
use egopulse_domain_contracts::v01::egopulse::{
    harness::v1::ApprovalRequestLifecycleKind, localapi::v1::ClientSurface, task::v1::TaskStatus,
};
use egopulse_local_api::{LocalApiClient, LocalTransport};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FoundationStatus {
    product: &'static str,
    architecture_version: &'static str,
    status: &'static str,
    transport: &'static str,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopTask {
    task_id: String,
    revision: u64,
    work_revision: u64,
    status: String,
    work_type: String,
    hold_reason_code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopApproval {
    approval_request_id: String,
    task_id: String,
    request_lifecycle: String,
    request_revision: u64,
    display_summary_ref: String,
    requested_scope_ref: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopSnapshot {
    instance: String,
    projection_health: String,
    stale: bool,
    position: String,
    tasks: Vec<DesktopTask>,
    approvals: Vec<DesktopApproval>,
}

fn transport_name(transport: LocalTransport) -> &'static str {
    match transport {
        LocalTransport::WindowsNamedPipe => "windows-named-pipe",
        LocalTransport::UnixDomainSocket => "unix-domain-socket",
    }
}

#[tauri::command]
fn foundation_status() -> FoundationStatus {
    let client = LocalApiClient::platform_default();
    let health = client.foundation_health();
    FoundationStatus {
        product: "EgoPulse",
        architecture_version: health.architecture_version,
        status: health.state.as_str(),
        transport: transport_name(client.transport()),
    }
}

#[tauri::command]
async fn dashboard_snapshot(instance: String) -> Result<DesktopSnapshot, String> {
    let instance = if instance.trim().is_empty() {
        "default".to_owned()
    } else {
        instance
    };
    let attachment = attach(
        &instance,
        ClientSurface::Desktop,
        format!("egopulse-desktop-{}", uuid::Uuid::now_v7()),
    )
    .await
    .map_err(|error| error.to_string())?;
    let projection = attachment
        .read_projection_snapshot()
        .await
        .map_err(|error| match error {
            ClientReadError::Api(error) => format!("local API rejected the read: {error:?}"),
            other => other.to_string(),
        })?;
    let position = projection
        .metadata
        .position
        .as_ref()
        .map(|value| format!("{}:{}", value.epoch, value.sequence))
        .unwrap_or_else(|| "unknown".to_owned());
    let projection_health =
        egopulse_domain_contracts::v01::egopulse::localapi::v1::ProjectionHealth::try_from(
            projection.metadata.health,
        )
        .map(|value| value.as_str_name().to_owned())
        .unwrap_or_else(|_| "PROJECTION_HEALTH_UNKNOWN".to_owned());
    let tasks = projection
        .tasks
        .into_iter()
        .filter_map(|view| view.task)
        .map(|task| DesktopTask {
            task_id: task.task_id,
            revision: task.revision,
            work_revision: task.work_revision,
            status: TaskStatus::try_from(task.status)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "TASK_STATUS_UNKNOWN".to_owned()),
            work_type: task.work_type,
            hold_reason_code: task.hold_reason_code,
        })
        .collect();
    let approvals = projection
        .approvals
        .into_iter()
        .map(|approval| DesktopApproval {
            approval_request_id: approval.approval_request_id,
            task_id: approval.task_id,
            request_lifecycle: ApprovalRequestLifecycleKind::try_from(approval.request_lifecycle)
                .map(|value| value.as_str_name().to_owned())
                .unwrap_or_else(|_| "APPROVAL_REQUEST_LIFECYCLE_UNKNOWN".to_owned()),
            request_revision: approval.request_revision,
            display_summary_ref: approval.display_summary_ref,
            requested_scope_ref: approval.requested_scope_ref,
        })
        .collect();
    Ok(DesktopSnapshot {
        instance,
        projection_health,
        stale: projection.metadata.stale,
        position,
        tasks,
        approvals,
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            foundation_status,
            dashboard_snapshot
        ])
        .run(tauri::generate_context!())
        .expect("failed to run EgoPulse desktop foundation shell");
}
