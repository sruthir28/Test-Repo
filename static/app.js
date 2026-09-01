const input = document.getElementById("input");
const scanButton = document.getElementById("scan");
const sampleButton = document.getElementById("sample");
const clearButton = document.getElementById("clear");
const statusEl = document.getElementById("status");
const results = document.getElementById("results");
const verdict = document.getElementById("verdict");
const tbody = document.querySelector("#findings tbody");
const redacted = document.getElementById("redacted");

const SAMPLE = `Hi team,

Please reach Jane Doe at jane.doe@example.com or 415-555-0199.
Her SSN is 123-45-6789 and the card on file is 4111 1111 1111 1111.
Request came from 192.168.1.42 on 04/17/1985.`;

let requestToken = 0;

function setStatus(message) {
  statusEl.textContent = message;
  statusEl.hidden = !message;
}

function render(data) {
  verdict.textContent = data.has_pii
    ? `PII detected — ${data.count} finding${data.count === 1 ? "" : "s"}`
    : "No PII detected";
  verdict.className = `verdict ${data.has_pii ? "pii" : "clean"}`;

  tbody.replaceChildren();
  for (const finding of data.findings) {
    const row = document.createElement("tr");
    for (const [text, className] of [
      [finding.type, ""],
      [finding.value, "value"],
      [`${finding.start}–${finding.end}`, ""],
      [finding.confidence, ""],
    ]) {
      const cell = document.createElement("td");
      cell.textContent = text;
      if (className) cell.className = className;
      row.appendChild(cell);
    }
    tbody.appendChild(row);
  }

  redacted.textContent = data.redacted_text;
  results.hidden = false;
}

async function scan() {
  const text = input.value;
  if (!text.trim()) {
    setStatus("Enter some text to scan.");
    results.hidden = true;
    return;
  }

  const token = ++requestToken;
  scanButton.disabled = true;
  setStatus("Scanning…");
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await response.json();
    if (token !== requestToken) return;
    if (!response.ok) {
      throw new Error(data.error || `Request failed (${response.status})`);
    }
    setStatus("");
    render(data);
  } catch (error) {
    if (token !== requestToken) return;
    setStatus(error.message);
    results.hidden = true;
  } finally {
    if (token === requestToken) scanButton.disabled = false;
  }
}

function invalidatePending() {
  requestToken += 1;
  scanButton.disabled = false;
}

scanButton.addEventListener("click", scan);
input.addEventListener("input", invalidatePending);
sampleButton.addEventListener("click", () => {
  invalidatePending();
  input.value = SAMPLE;
  results.hidden = true;
  setStatus("");
});
clearButton.addEventListener("click", () => {
  invalidatePending();
  input.value = "";
  results.hidden = true;
  setStatus("");
});
