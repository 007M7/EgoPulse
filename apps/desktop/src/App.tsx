import { invoke } from "@tauri-apps/api/core";
import { useState } from "react";

type FoundationHealth = {
  product: string;
  status: string;
  transport: string;
};

const staticHealth: FoundationHealth = {
  product: "EgoPulse",
  status: "foundation-only",
  transport: "not-started",
};

export function App() {
  const [health, setHealth] = useState<FoundationHealth>(staticHealth);
  const [note, setNote] = useState("UI shell loaded; no AgentOS workflow is active.");

  async function inspectNativeBoundary() {
    try {
      const next = await invoke<FoundationHealth>("foundation_status");
      setHealth(next);
      setNote("Native boundary answered. Runtime transport remains intentionally absent.");
    } catch {
      setNote("Browser preview is active. Run through Tauri to inspect the native boundary.");
    }
  }

  return (
    <main className="shell">
      <p className="eyebrow">FOUNDATION GATE</p>
      <h1>EgoPulse</h1>
      <p className="lede">
        A clean product repository for the AgentOS architecture. This screen proves only the
        desktop shell and native invocation seam—not an implemented cognitive or governance plane.
      </p>

      <section className="status" aria-label="Foundation status">
        <div>
          <span>Product</span>
          <strong>{health.product}</strong>
        </div>
        <div>
          <span>Runtime</span>
          <strong>{health.status}</strong>
        </div>
        <div>
          <span>Transport</span>
          <strong>{health.transport}</strong>
        </div>
      </section>

      <button type="button" onClick={inspectNativeBoundary}>
        Inspect native boundary
      </button>
      <p className="note">{note}</p>
    </main>
  );
}
