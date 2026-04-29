// --- Tab switching ---
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});

// --- Drag & drop .eml ---
const dropZone = document.getElementById("dropZone");
const emlFile = document.getElementById("emlFile");
const emlFilename = document.getElementById("emlFilename");

dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.style.borderColor = "var(--accent)"; });
dropZone.addEventListener("dragleave", () => { dropZone.style.borderColor = ""; });
dropZone.addEventListener("drop", e => {
  e.preventDefault();
  dropZone.style.borderColor = "";
  const file = e.dataTransfer.files[0];
  if (file) setEmlFile(file);
});
emlFile.addEventListener("change", () => { if (emlFile.files[0]) setEmlFile(emlFile.files[0]); });

function setEmlFile(file) {
  const dt = new DataTransfer();
  dt.items.add(file);
  emlFile.files = dt.files;
  emlFilename.textContent = "📎 " + file.name;
  emlFilename.style.display = "block";
}

// --- Clear ---
document.getElementById("clearBtn").addEventListener("click", () => {
  document.getElementById("analyzeForm").reset();
  emlFilename.style.display = "none";
  document.getElementById("resultsEmpty").style.display = "flex";
  document.getElementById("resultsContent").style.display = "none";
  document.getElementById("resultsContent").innerHTML = "";
});

// --- Example phishing email ---
document.getElementById("exampleBtn").addEventListener("click", () => {
  // Switch to manual tab
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
  document.querySelector('[data-tab="manual"]').classList.add("active");
  document.getElementById("tab-manual").classList.add("active");

  document.querySelector('input[name="sender"]').value = "security-alert@paypa1-support.net";
  document.querySelector('input[name="subject"]').value = "URGENT: Your PayPal account has been suspended!";
  document.querySelector('textarea[name="body"]').value =
`Dear Valued Customer,

We have detected suspicious activity on your PayPal account. Your account has been TEMPORARILY SUSPENDED due to multiple failed login attempts from an unrecognized device.

To restore access immediately, you must verify your identity by clicking the link below:

http://paypa1-secure-verify.ru/restore?id=8472&token=abc123

You have 24 HOURS to complete this verification or your account will be PERMANENTLY CLOSED and all funds will be frozen.

Please also confirm the following details:
- Social Security Number
- Credit card number on file
- Date of birth

Do not ignore this message.

PayPal Security Team
© PayPal Inc. All Rights Reserved`;
  document.querySelector('textarea[name="links"]').value = "http://paypa1-secure-verify.ru/restore?id=8472&token=abc123";
});

// --- Form submit ---
document.getElementById("analyzeForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;

  document.getElementById("resultsEmpty").style.display = "none";
  document.getElementById("resultsContent").style.display = "block";
  document.getElementById("resultsContent").innerHTML = `
    <div class="loading-state">
      <div class="spinner"></div>
      <p>Running forensic analysis...</p>
    </div>`;

  const formData = new FormData(e.target);

  try {
    const resp = await fetch("/analyze", { method: "POST", body: formData });
    const data = await resp.json();
    renderResults(data);
  } catch (err) {
    document.getElementById("resultsContent").innerHTML =
      `<p style="color:var(--red);padding:20px;">Error: ${err.message}</p>`;
  }
  btn.disabled = false;
});

// --- Render results ---
function renderResults(data) {
  const score = data.score;
  const verdictClass = score.verdict === "PHISHING" ? "verdict-phishing"
    : score.verdict === "SUSPICIOUS" ? "verdict-suspicious" : "verdict-safe";
  const verdictIcon = score.verdict === "PHISHING" ? "🚨"
    : score.verdict === "SUSPICIOUS" ? "⚠️" : "✅";
  const scoreColor = score.risk_score >= 65 ? "var(--red)"
    : score.risk_score >= 35 ? "var(--amber)" : "var(--green)";

  // Signals
  const signalsHtml = score.signals.length
    ? score.signals.map(s => `
      <div class="finding">
        <div class="finding-body">
          <div class="finding-name">${s.source}</div>
          <div class="finding-detail">${s.detail}</div>
        </div>
        <span class="badge HIGH" style="background:transparent;border:none;color:var(--red);">+${s.weight}</span>
      </div>`).join("")
    : `<div class="no-findings">No significant risk signals detected</div>`;

  // Header findings
  const hf = data.headers.findings || [];
  const headerHtml = hf.length
    ? hf.map(f => `
      <div class="finding ${f.severity}">
        <div class="finding-body">
          <div class="finding-name">${f.category}</div>
          <div class="finding-detail">${f.detail}</div>
        </div>
        <span class="badge ${f.severity}">${f.severity}</span>
      </div>`).join("")
    : `<div class="no-findings">No header anomalies found</div>`;

  // URL results
  const urls = data.urls.results || [];
  const urlHtml = urls.length
    ? urls.map(u => `
      <div class="url-item">
        <div class="url-header">
          <span class="url-text">${u.url}</span>
          <span class="badge ${u.verdict}">${u.verdict.toUpperCase()}</span>
          ${u.phishtank && u.phishtank.in_database ? `<span class="badge malicious">PhishTank ✓</span>` : ""}
        </div>
        ${u.flags.length ? `<div class="url-flags">${u.flags.map(f => `<div class="url-flag">${f}</div>`).join("")}</div>` : ""}
      </div>`).join("")
    : `<div class="no-findings">No URLs found in this email</div>`;

  // Parsed metadata
  const p = data.parsed;
  const metaHtml = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
      ${metaRow("From", p.sender || "—")}
      ${metaRow("Domain", p.sender_domain || "—")}
      ${metaRow("Reply-To", p.reply_to || "—")}
      ${metaRow("Subject", p.subject || "—")}
      ${metaRow("Source", p.source)}
      ${metaRow("Has Attachments", p.has_attachments ? "Yes ⚠️" : "No")}
    </div>`;

  document.getElementById("resultsContent").innerHTML = `
    <div class="verdict-banner ${verdictClass}">
      <div class="verdict-icon">${verdictIcon}</div>
      <div>
        <div class="verdict-label">${score.verdict_label}</div>
        <div class="verdict-summary">Risk score: ${score.risk_score}/100</div>
      </div>
    </div>

    <div class="score-section">
      <div class="score-row">
        <span class="score-label">Risk Score</span>
        <div class="score-bar"><div class="score-fill" style="width:${score.risk_score}%;background:${scoreColor};"></div></div>
        <span class="score-num" style="color:${scoreColor};">${score.risk_score}</span>
      </div>
    </div>

    <div class="result-section">
      <div class="section-header">Email Metadata</div>
      ${metaHtml}
    </div>

    <div class="result-section">
      <div class="section-header">Risk Signals (${score.signals.length})</div>
      <div class="finding-list">${signalsHtml}</div>
    </div>

    <div class="result-section">
      <div class="section-header">Header Analysis (${hf.length} findings)</div>
      <div class="finding-list">${headerHtml}</div>
    </div>

    <div class="result-section">
      <div class="section-header">URL Analysis (${urls.length} URLs)</div>
      ${urlHtml}
    </div>
  `;
}

function metaRow(label, value) {
  return `<div style="padding:7px 10px;background:var(--surface2);border-radius:6px;">
    <div style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;margin-bottom:2px;">${label}</div>
    <div style="font-size:12px;color:var(--text);word-break:break-all;">${value}</div>
  </div>`;
}
