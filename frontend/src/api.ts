import type { Hass, Snapshot } from "./types";

export class UbError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

/** One websocket command. Throws UbError with the backend's error code. */
export async function ws<T = any>(hass: Hass, type: string, extra: Record<string, unknown> = {}): Promise<T> {
  try {
    return await hass.callWS<T>({ type: `unifiblocker/${type}`, ...extra });
  } catch (err: any) {
    throw new UbError(err?.code ?? "error", err?.message ?? String(err));
  }
}

async function soft<T>(p: Promise<T>, fallback: T): Promise<T> {
  try {
    return await p;
  } catch {
    return fallback;
  }
}

/** Everything the panel shows, fetched in parallel. A failing command
 *  leaves its part empty instead of failing the whole refresh. */
export async function fetchSnapshot(hass: Hass): Promise<Snapshot> {
  const [overview, clients, recs, localnet, miners, scans, report, learned] = await Promise.all([
    soft(ws(hass, "overview"), {}),
    soft(ws<{ clients: any[] }>(hass, "clients"), { clients: [] }),
    soft(ws(hass, "recommendations"), {}),
    soft(ws(hass, "localnet_status"), {}),
    soft(ws(hass, "miners"), { rigs: [], summary: {} }),
    soft(ws<{ results: Record<string, any> }>(hass, "scan_results"), { results: {} }),
    soft(ws(hass, "report_status"), null),
    soft(ws(hass, "learned_rules"), null),
  ]);
  return {
    overview, clients: clients.clients || [], recs, localnet, miners,
    scans: scans.results || {}, report, learned, loaded: true, error: "", updated: Date.now(),
  } as Snapshot;
}
