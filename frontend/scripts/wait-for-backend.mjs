const API_TARGET = process.env.VITE_API_TARGET || "http://127.0.0.1:8001";
const HEALTH_URL = `${API_TARGET}/api/health`;
const TIMEOUT_MS = Number(process.env.BACKEND_WAIT_TIMEOUT_MS || 30000);
const INTERVAL_MS = Number(process.env.BACKEND_WAIT_INTERVAL_MS || 1000);

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth() {
  const start = Date.now();
  let lastError = "unknown";

  while (Date.now() - start < TIMEOUT_MS) {
    try {
      const res = await fetch(HEALTH_URL, { method: "GET" });
      if (res.ok) {
        const payload = await res.json().catch(() => ({}));
        const splunk = payload?.splunk_connected ? "connected" : "unreachable";
        console.log(
          `[frontend] Backend ready at ${API_TARGET} (health=ok, splunk=${splunk})`
        );
        return;
      }
      lastError = `HTTP ${res.status}`;
    } catch (err) {
      lastError = err?.message || String(err);
    }
    await sleep(INTERVAL_MS);
  }

  console.error(
    `[frontend] Backend health check failed at ${HEALTH_URL} after ${TIMEOUT_MS}ms (${lastError}).`
  );
  console.error(
    "[frontend] Start backend first or set VITE_API_TARGET to the correct API origin."
  );
  process.exit(1);
}

await waitForHealth();
