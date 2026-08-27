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
  actionDigestSha256: string;
  requestObservationId: string;
  requestObservationSequence: number;
  availableActionCodes: string[];
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

type MemoryCandidateDraft = {
  memoryId: string;
  content: string;
  sourceRef: string;
  scopeRef: string;
  idempotencyKey: string;
};

type MemoryReviewDraft = {
  memoryId: string;
  expectedRevision: string;
  evidenceRef: string;
  idempotencyKey: string;
};

type MemoryRetrievalDraft = {
  query: string;
  scopeRef: string;
  maxResults: string;
  minScore: string;
};

type MemoryRetrievalResult = {
  algorithmId: string;
  querySha256: string;
  snapshotSha256: string;
  evidenceRef: string;
  candidates: Array<{
    memoryId: string;
    sourceRef: string;
    contentSha256: string;
    score: number;
    matchedTerms: string[];
  }>;
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
  const [approvalBusy, setApprovalBusy] = useState<string | null>(null);
  const [approvalReason, setApprovalReason] = useState("desktop-user-decision");
  const [memoryBusy, setMemoryBusy] = useState(false);
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
  const [memoryCandidate, setMemoryCandidate] = useState<MemoryCandidateDraft>({
    memoryId: "",
    content: "",
    sourceRef: "",
    scopeRef: "",
    idempotencyKey: "desktop-memory-candidate-1",
  });
  const [memoryReview, setMemoryReview] = useState<MemoryReviewDraft>({
    memoryId: "",
    expectedRevision: "",
    evidenceRef: "",
    idempotencyKey: "desktop-memory-review-1",
  });
  const [memoryRetrieval, setMemoryRetrieval] = useState<MemoryRetrievalDraft>({
    query: "",
    scopeRef: "",
    maxResults: "8",
    minScore: "0",
  });
  const [retrievalResult, setRetrievalResult] = useState<MemoryRetrievalResult | null>(null);
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

  async function cancelTask(task: DesktopTask) {
    const reasonCode = window.prompt("Cancellation reason code", "desktop-user-cancelled");
    if (!reasonCode?.trim()) {
      setNote("Task cancellation was not submitted: a reason code is required.");
      return;
    }
    setTaskBusy(true);
    try {
      const result = await invoke<{
        taskId: string;
        revision: number;
        status: string;
        replayed: boolean;
        awaitTokenPresent: boolean;
      }>("cancel_task", {
        request: {
          instance,
          taskId: task.taskId,
          expectedRevision: task.revision,
          reasonCode,
        },
      });
      setNote(`Cancellation requested for ${result.taskId}; status is ${result.status}.`);
      await connectToDaemon();
    } catch (error) {
      setNote(`Task cancellation rejected: ${String(error)}`);
    } finally {
      setTaskBusy(false);
    }
  }

  async function decideApproval(approval: DesktopApproval, decision: "allow-once" | "deny") {
    setApprovalBusy(approval.approvalRequestId);
    try {
      const result = await invoke<{
        authorityDecisionRef: string;
        committed: boolean;
        replayed: boolean;
        decision: string;
        state: string;
        stateRevision: number;
        awaitTokenPresent: boolean;
      }>("decide_approval", {
        request: {
          instance,
          approvalRequestId: approval.approvalRequestId,
          expectedActionDigestSha256: approval.actionDigestSha256,
          expectedRequestObservationId: approval.requestObservationId,
          expectedRequestObservationSequence: approval.requestObservationSequence,
          expectedRequestRevision: approval.requestRevision,
          decision,
          reasonCode: approvalReason,
        },
      });
      setNote(`Approval ${result.decision} at authority revision ${result.stateRevision}; refreshing projection.`);
      await connectToDaemon();
    } catch (error) {
      setNote(`Approval decision rejected: ${String(error)}`);
    } finally {
      setApprovalBusy(null);
    }
  }

  async function submitMemoryCandidate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMemoryBusy(true);
    try {
      const result = await invoke<{ memoryId: string; revision: number; state: string }>("submit_memory_candidate", {
        request: { instance, ...memoryCandidate },
      });
      setNote(`Memory candidate ${result.memoryId} is ${result.state} at revision ${result.revision}.`);
      await connectToDaemon();
    } catch (error) {
      setNote(`Memory candidate rejected: ${String(error)}`);
    } finally {
      setMemoryBusy(false);
    }
  }

  async function reviewMemory(decision: "accept_memory" | "revoke_memory") {
    setMemoryBusy(true);
    try {
      const result = await invoke<{ memoryId: string; revision: number; state: string }>(decision, {
        request: {
          instance,
          memoryId: memoryReview.memoryId,
          expectedRevision: Number(memoryReview.expectedRevision),
          evidenceRef: memoryReview.evidenceRef,
          idempotencyKey: memoryReview.idempotencyKey,
        },
      });
      setNote(`Memory ${result.memoryId} is ${result.state} at revision ${result.revision}.`);
      await connectToDaemon();
    } catch (error) {
      setNote(`Memory review rejected: ${String(error)}`);
    } finally {
      setMemoryBusy(false);
    }
  }

  async function retrieveMemory(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMemoryBusy(true);
    setRetrievalResult(null);
    try {
      const result = await invoke<MemoryRetrievalResult>("retrieve_memory", {
        request: {
          instance,
          query: memoryRetrieval.query,
          scopeRef: memoryRetrieval.scopeRef,
          maxResults: Number(memoryRetrieval.maxResults),
          minScore: Number(memoryRetrieval.minScore),
        },
      });
      setRetrievalResult(result);
      setNote(`Memory retrieval returned ${result.candidates.length} reference(s) from the accepted snapshot.`);
    } catch (error) {
      setNote(`Memory retrieval rejected: ${String(error)}`);
    } finally {
      setMemoryBusy(false);
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

      <section className="write-panel memory-panel" aria-label="Memory governance">
        <div className="section-heading">
          <div>
            <p className="eyebrow">EXPLICIT WRITE</p>
            <h2>Memory governance</h2>
          </div>
          <span className="badge">MEMORY AUTHORITY</span>
        </div>
        <p className="muted">Candidates are not authoritative. Submission, acceptance and revocation all use the same Rust Memory Authority and durability barrier as CLI and TUI.</p>
        <div className="memory-grid">
          <form onSubmit={submitMemoryCandidate}>
            <h3>Submit candidate</h3>
            <div className="form-grid">
              <label>Memory ID<input required value={memoryCandidate.memoryId} onChange={(event) => setMemoryCandidate((current) => ({ ...current, memoryId: event.target.value }))} /></label>
              <label>Source ref<input required value={memoryCandidate.sourceRef} onChange={(event) => setMemoryCandidate((current) => ({ ...current, sourceRef: event.target.value }))} /></label>
              <label>Scope ref<input required value={memoryCandidate.scopeRef} onChange={(event) => setMemoryCandidate((current) => ({ ...current, scopeRef: event.target.value }))} /></label>
              <label>Idempotency key<input required value={memoryCandidate.idempotencyKey} onChange={(event) => setMemoryCandidate((current) => ({ ...current, idempotencyKey: event.target.value }))} /></label>
            </div>
            <label>Candidate content<textarea required value={memoryCandidate.content} onChange={(event) => setMemoryCandidate((current) => ({ ...current, content: event.target.value }))} /></label>
            <button type="submit" disabled={memoryBusy}>{memoryBusy ? "Submitting…" : "Submit candidate"}</button>
          </form>
          <div>
            <h3>Review memory</h3>
            <div className="form-grid">
              <label>Memory ID<input required value={memoryReview.memoryId} onChange={(event) => setMemoryReview((current) => ({ ...current, memoryId: event.target.value }))} /></label>
              <label>Expected revision<input required type="number" min="0" value={memoryReview.expectedRevision} onChange={(event) => setMemoryReview((current) => ({ ...current, expectedRevision: event.target.value }))} /></label>
              <label>Evidence ref<input required value={memoryReview.evidenceRef} onChange={(event) => setMemoryReview((current) => ({ ...current, evidenceRef: event.target.value }))} /></label>
              <label>Idempotency key<input required value={memoryReview.idempotencyKey} onChange={(event) => setMemoryReview((current) => ({ ...current, idempotencyKey: event.target.value }))} /></label>
            </div>
            <div className="button-row review-buttons">
              <button type="button" onClick={() => reviewMemory("accept_memory")} disabled={memoryBusy}>Accept</button>
              <button className="secondary" type="button" onClick={() => reviewMemory("revoke_memory")} disabled={memoryBusy}>Revoke</button>
            </div>
          </div>
        </div>
        <div className="retrieval-panel">
          <h3>Retrieve accepted Memory</h3>
          <p className="muted">Results are reference-only and bound to one accepted snapshot. Candidate or revoked records never enter retrieval.</p>
          <form onSubmit={retrieveMemory}>
            <div className="form-grid">
              <label>Query<input required value={memoryRetrieval.query} onChange={(event) => setMemoryRetrieval((current) => ({ ...current, query: event.target.value }))} /></label>
              <label>Scope ref<input required value={memoryRetrieval.scopeRef} onChange={(event) => setMemoryRetrieval((current) => ({ ...current, scopeRef: event.target.value }))} /></label>
              <label>Max results<input required type="number" min="1" max="64" value={memoryRetrieval.maxResults} onChange={(event) => setMemoryRetrieval((current) => ({ ...current, maxResults: event.target.value }))} /></label>
              <label>Minimum score<input required type="number" min="0" max="1" step="0.01" value={memoryRetrieval.minScore} onChange={(event) => setMemoryRetrieval((current) => ({ ...current, minScore: event.target.value }))} /></label>
            </div>
            <button type="submit" disabled={memoryBusy}>{memoryBusy ? "Retrieving..." : "Retrieve memory"}</button>
          </form>
          {retrievalResult ? (
            <div className="retrieval-result" aria-label="Memory retrieval result">
              <small>Algorithm: {retrievalResult.algorithmId}</small>
              <small>Snapshot: {retrievalResult.snapshotSha256}</small>
              <small>Evidence: {retrievalResult.evidenceRef}</small>
              {retrievalResult.candidates.length === 0 ? <p className="muted">No accepted Memory matched this query.</p> : (
                <ul>{retrievalResult.candidates.map((candidate) => (
                  <li key={candidate.memoryId}>
                    <strong>{candidate.memoryId}</strong>
                    <span>score {candidate.score}</span>
                    <small>{candidate.sourceRef}</small>
                  </li>
                ))}</ul>
              )}
            </div>
          ) : null}
        </div>
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
                    <div className="task-actions">
                      <span>{task.status.replace("TASK_STATUS_", "")}</span>
                      {!["TASK_STATUS_CANCELLED", "TASK_STATUS_COMPLETED", "TASK_STATUS_REJECTED"].includes(task.status) ? (
                        <button className="secondary" type="button" onClick={() => cancelTask(task)} disabled={taskBusy}>
                          {taskBusy ? "Saving…" : "Request cancellation"}
                        </button>
                      ) : null}
                    </div>
                  </li>
                ))}</ul>
              )}
            </section>
            <section className="panel">
              <h3>Approval queue</h3>
              <label className="approval-reason">Decision reason code<input value={approvalReason} onChange={(event) => setApprovalReason(event.target.value)} /></label>
              {snapshot.approvals.length === 0 ? <p className="muted">No approval requests are projected.</p> : (
                <ul>{snapshot.approvals.map((approval) => (
                  <li key={approval.approvalRequestId}>
                    <div>
                      <strong>{approval.displaySummaryRef || "Approval request"}</strong>
                      <small>{approval.approvalRequestId}</small>
                      <small>scope: {approval.requestedScopeRef || "not disclosed"}</small>
                      <small>action: {approval.actionDigestSha256 || "not disclosed"}</small>
                    </div>
                    <div className="approval-actions">
                      <span>{approval.requestLifecycle.replace("APPROVAL_REQUEST_LIFECYCLE_", "")}</span>
                      {approval.availableActionCodes.includes("AVAILABLE_ACTION_KIND_DECIDE_HARNESS_APPROVAL") ? (
                        <div className="button-row">
                          <button type="button" onClick={() => decideApproval(approval, "allow-once")} disabled={approvalBusy !== null}>
                            {approvalBusy === approval.approvalRequestId ? "Saving…" : "Allow once"}
                          </button>
                          <button className="secondary" type="button" onClick={() => decideApproval(approval, "deny")} disabled={approvalBusy !== null}>Deny</button>
                        </div>
                      ) : <small className="muted">Decision unavailable</small>}
                    </div>
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
