import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

type FoundationStatus = {
  product: string;
  architectureVersion: string;
  status: string;
  transport: string;
};

type DesktopTask = {
  taskId: string;
  revision: number;
  workRevision: number;
  status: string;
  workType: string;
  holdReasonCode: string | null;
};

type DesktopApproval = {
  approvalRequestId: string;
  taskId: string;
  requestLifecycle: string;
  requestRevision: number;
  displaySummaryRef: string;
  requestedScopeRef: string;
};

type DesktopSnapshot = {
  instance: string;
  projectionHealth: string;
  stale: boolean;
  position: string;
  tasks: DesktopTask[];
  approvals: DesktopApproval[];
};

type TaskDraft = {
  workType: string;
  inputSnapshotId: string;
  targetScopeRef: string;
  acceptanceContractId: string;
  acceptanceContractVersion: string;
  acceptanceContractSha256: string;
  budgetProfileId: string;
  budgetProfileVersion: string;
  budgetProfileSha256: string;
};

const staticHealth: FoundationStatus = {
  product: "EgoPulse",
  architectureVersion: "1.0",
  status: "foundation-only",
  transport: "windows-named-pipe",
};

export function App() {
  const [health, setHealth] = useState<FoundationStatus>(staticHealth);
  const [snapshot, setSnapshot] = useState<DesktopSnapshot | null>(null);
  const [instance, setInstance] = useState("default");
  const [busy, setBusy] = useState(false);
  const [taskBusy, setTaskBusy] = useState(false);
  const [taskDraft, setTaskDraft] = useState<TaskDraft>({
    workType: "",
    inputSnapshotId: "",
    targetScopeRef: "",
    acceptanceContractId: "",
    acceptanceContractVersion: "",
    acceptanceContractSha256: "",
    budgetProfileId: "",
    budgetProfileVersion: "",
    budgetProfileSha256: "",
  });
  const [note, setNote] = useState("Desktop is ready; connect to the local governed daemon to load a projection.");

  async function inspectNativeBoundary() {
    try {
      const next = await invoke<FoundationStatus>("foundation_status");
      setHealth(next);
      setNote("Shared Rust client boundary answered. No second control plane is created by Desktop.");
    } catch {
      setNote("Browser preview is active. Run through Tauri to inspect the native boundary.");
    }
  }

  async function connectToDaemon() {
    setBusy(true);
    try {
      const next = await invoke<DesktopSnapshot>("dashboard_snapshot", { instance });
      setSnapshot(next);
      setHealth((current) => ({ ...current, status: "connected" }));
      setNote(`Projection loaded at ${next.position}; ${next.tasks.length} task(s), ${next.approvals.length} approval(s).`);
    } catch (error) {
      setSnapshot(null);
      setNote(`Local daemon unavailable or projection rejected: ${String(error)}`);
    } finally {
      setBusy(false);
    }
  }

  function updateTaskDraft(field: keyof TaskDraft, value: string) {
    setTaskDraft((current) => ({ ...current, [field]: value }));
  }

  async function submitTask(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setTaskBusy(true);
    try {
      const result = await invoke<{
        taskId: string;
        revision: number;
        status: string;
        replayed: boolean;
        awaitTokenPresent: boolean;
      }>("create_task", { request: { instance, ...taskDraft } });
      setNote(`Task ${result.taskId} created at revision ${result.revision}; refresh the projection to observe it.`);
      await connectToDaemon();
    } catch (error) {
      setNote(`Task creation rejected: ${String(error)}`);
    } finally {
      setTaskBusy(false);
    }
  }

  return (
    <main className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">GOVERNED DESKTOP SURFACE</p>
          <h1>EgoPulse</h1>
          <p className="lede">
            Desktop presents the same local Rust kernel and governed projection used by CLI and TUI.
            It never becomes a second Task, Memory, or Provider authority.
          </p>
        </div>
        <div className="hero-actions">
          <label>
            <span>Daemon instance</span>
            <input value={instance} onChange={(event) => setInstance(event.target.value)} />
          </label>
          <button type="button" onClick={connectToDaemon} disabled={busy}>
            {busy ? "Connecting…" : "Connect to daemon"}
          </button>
          <button className="secondary" type="button" onClick={inspectNativeBoundary}>
            Inspect native boundary
          </button>
        </div>
      </header>

      <section className="status" aria-label="Foundation status">
        <div><span>Product</span><strong>{health.product}</strong></div>
        <div><span>Architecture</span><strong>{health.architectureVersion}</strong></div>
        <div><span>Runtime</span><strong>{health.status}</strong></div>
        <div><span>Transport</span><strong>{health.transport}</strong></div>
      </section>

      <p className="note" role="status">{note}</p>

      <section className="write-panel" aria-label="Create task">
        <div className="section-heading">
          <div>
            <p className="eyebrow">EXPLICIT WRITE</p>
            <h2>Create governed task</h2>
          </div>
          <span className="badge">TASK AUTHORITY</span>
        </div>
        <p className="muted">All contract references are required. The form submits through the authenticated Local API and never writes locally from the WebView.</p>
        <form onSubmit={submitTask}>
          <div className="form-grid">
            <label>Work type<input required value={taskDraft.workType} onChange={(event) => updateTaskDraft("workType", event.target.value)} /></label>
            <label>Input snapshot ID<input required value={taskDraft.inputSnapshotId} onChange={(event) => updateTaskDraft("inputSnapshotId", event.target.value)} /></label>
            <label>Target scope ref<input required value={taskDraft.targetScopeRef} onChange={(event) => updateTaskDraft("targetScopeRef", event.target.value)} /></label>
            <label>Acceptance contract ID<input required value={taskDraft.acceptanceContractId} onChange={(event) => updateTaskDraft("acceptanceContractId", event.target.value)} /></label>
            <label>Acceptance version<input required value={taskDraft.acceptanceContractVersion} onChange={(event) => updateTaskDraft("acceptanceContractVersion", event.target.value)} /></label>
            <label>Acceptance SHA-256<input required value={taskDraft.acceptanceContractSha256} onChange={(event) => updateTaskDraft("acceptanceContractSha256", event.target.value)} /></label>
            <label>Budget profile ID<input required value={taskDraft.budgetProfileId} onChange={(event) => updateTaskDraft("budgetProfileId", event.target.value)} /></label>
            <label>Budget version<input required value={taskDraft.budgetProfileVersion} onChange={(event) => updateTaskDraft("budgetProfileVersion", event.target.value)} /></label>
            <label>Budget SHA-256<input required value={taskDraft.budgetProfileSha256} onChange={(event) => updateTaskDraft("budgetProfileSha256", event.target.value)} /></label>
          </div>
          <button type="submit" disabled={taskBusy}>{taskBusy ? "Submitting…" : "Create task"}</button>
        </form>
      </section>

      {snapshot ? (
        <section className="dashboard" aria-label="Governed projection">
          <div className="section-heading">
            <div>
              <p className="eyebrow">READ MODEL</p>
              <h2>Local projection</h2>
            </div>
            <span className={snapshot.stale ? "badge warning" : "badge"}>
              {snapshot.stale ? "STALE" : snapshot.projectionHealth}
            </span>
          </div>

          <div className="cards">
            <article className="card"><span>Tasks</span><strong>{snapshot.tasks.length}</strong></article>
            <article className="card"><span>Approvals</span><strong>{snapshot.approvals.length}</strong></article>
            <article className="card"><span>Position</span><strong>{snapshot.position}</strong></article>
          </div>

          <div className="tables">
            <section className="panel">
              <h3>Tasks</h3>
              {snapshot.tasks.length === 0 ? <p className="muted">No task projection is available.</p> : (
                <ul>{snapshot.tasks.map((task) => (
                  <li key={task.taskId}>
                    <div><strong>{task.workType || "Untitled task"}</strong><small>{task.taskId}</small></div>
                    <span>{task.status.replace("TASK_STATUS_", "")}</span>
                  </li>
                ))}</ul>
              )}
            </section>
            <section className="panel">
              <h3>Approval queue</h3>
              {snapshot.approvals.length === 0 ? <p className="muted">No approval requests are projected.</p> : (
                <ul>{snapshot.approvals.map((approval) => (
                  <li key={approval.approvalRequestId}>
                    <div><strong>{approval.displaySummaryRef || "Approval request"}</strong><small>{approval.approvalRequestId}</small></div>
                    <span>{approval.requestLifecycle.replace("APPROVAL_REQUEST_LIFECYCLE_", "")}</span>
                  </li>
                ))}</ul>
              )}
            </section>
          </div>
        </section>
      ) : (
        <section className="empty-state">
          <p className="eyebrow">NO PROJECTION ATTACHED</p>
          <h2>Start or attach to the local daemon</h2>
          <p>Desktop will show only the daemon’s authenticated, bounded read model after a successful session handshake.</p>
        </section>
      )}
    </main>
  );
}
