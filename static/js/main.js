// Tab switching
function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById(tab + 'Tab').classList.add('active');
  event.target.classList.add('active');
  document.getElementById('resultBox').classList.add('hidden');
}

// Sample data
const samples = {
  pii: `Dear HR Team,
Please find the details of new employee:
Name: Rahul Sharma
Email: rahul.sharma@company.com
Phone: +91 9876543210
Date of Birth: 15/08/1995
Aadhaar: 234567890123
Address: 45 MG Road, Bangalore`,

  financial: `Transaction Report - Q3 2024
Customer: Priya Mehta (priya.mehta@bank.in)
Credit Card: 4111111111111111
Account Number: 123456789012
SSN: 123-45-6789
Amount: ₹2,45,000 transferred to external account.`,

  credentials: `Server Config Backup:
host=192.168.1.105
db_user=admin
password=Sup3rS3cur3Pass!
api_key=sk-abc123XYZ789longApiTokenValueHere
token=pkLive_abcdefghijklmnopqrstuvwxyz1234`,

  safe: `Meeting Notes - Product Review
Discussed the Q4 roadmap and feature priorities.
The team agreed on launching the new dashboard by November.
Action items were assigned to respective leads.
Next sync scheduled for Friday at 3PM.`
};

function loadSample(type) {
  switchTabDirect('text');
  document.getElementById('textInput').value = samples[type];
}

function switchTabDirect(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById(tab + 'Tab').classList.add('active');
  document.querySelectorAll('.tab')[tab === 'text' ? 0 : 1].classList.add('active');
}

// Scan Text
async function scanText() {
  const text = document.getElementById('textInput').value.trim();
  if (!text) { alert('Please enter some text to scan.'); return; }

  showLoading();
  try {
    const res = await fetch('/scan/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    renderResult(data);
    refreshAlerts();
    refreshStats();
  } catch (e) {
    showError('Scan failed. Is the server running?');
  }
}

// Scan File
async function scanFile() {
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files[0]) { alert('Please select a file first.'); return; }

  document.getElementById('fileName').textContent = '📄 ' + fileInput.files[0].name;
  showLoading();

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const res = await fetch('/scan/file', { method: 'POST', body: formData });
    const data = await res.json();
    renderResult(data);
    refreshAlerts();
    refreshStats();
  } catch (e) {
    showError('File scan failed.');
  }
}

function showLoading() {
  const box = document.getElementById('resultBox');
  box.className = 'result-box';
  box.innerHTML = '<div class="loading">⚡ Scanning...</div>';
}

function showError(msg) {
  const box = document.getElementById('resultBox');
  box.className = 'result-box HIGH';
  box.innerHTML = `<div class="summary-text">❌ ${msg}</div>`;
}

function renderResult(data) {
  const box = document.getElementById('resultBox');
  box.className = `result-box ${data.risk_level}`;

  let findingsHTML = '';
  if (data.findings && data.findings.length > 0) {
    findingsHTML = '<ul class="findings-list">' + data.findings.map(f => `
      <li class="finding-item ${f.risk}">
        <span style="font-size:1.2rem">${f.emoji}</span>
        <span class="finding-type">${f.type}</span>
        <span class="finding-count">${f.count} found</span>
        <span class="finding-samples">${f.samples.join(', ')}</span>
      </li>
    `).join('') + '</ul>';
  }

  box.innerHTML = `
    <div>
      <span class="risk-badge badge-${data.risk_level}">
        ${riskIcon(data.risk_level)} ${data.risk_level} RISK
      </span>
    </div>
    <div class="summary-text">${data.summary}</div>
    ${data.total_matches > 0 ? `<div style="font-size:0.78rem;color:#7a9bbf;margin-bottom:10px">
      Score: ${data.risk_score} &nbsp;|&nbsp; ${data.total_matches} sensitive matches
    </div>` : ''}
    ${findingsHTML}
  `;
}

function riskIcon(level) {
  return { SAFE: '✅', LOW: 'ℹ️', MEDIUM: '⚠️', HIGH: '🚨' }[level] || '❓';
}

// Refresh alerts
async function refreshAlerts() {
  try {
    const res = await fetch('/alerts');
    const alerts = await res.json();
    const log = document.getElementById('alertLog');

    if (alerts.length === 0) {
      log.innerHTML = '<div class="no-alerts">No alerts yet. Run a scan to begin.</div>';
      return;
    }

    log.innerHTML = [...alerts].reverse().map(a => `
      <div class="alert-item ${a.risk}">
        <div class="alert-header">
          <span class="alert-source">📍 ${a.source}</span>
          <span class="alert-time">${a.time}</span>
        </div>
        <div class="alert-findings">
          ${riskIcon(a.risk)} ${a.risk} — ${a.findings.map(f => f.emoji + ' ' + f.type).join(', ')}
        </div>
      </div>
    `).join('');
  } catch(e) {}
}

// Refresh stats
async function refreshStats() {
  try {
    const res = await fetch('/stats');
    const s = await res.json();
    document.getElementById('statTotal').textContent = s.total;
    document.getElementById('statHigh').textContent = s.high;
    document.getElementById('statMedium').textContent = s.medium;
    document.getElementById('statLow').textContent = s.low;
  } catch(e) {}
}

// File drop styling
document.addEventListener('DOMContentLoaded', () => {
  const drop = document.getElementById('fileDrop');
  const fileInput = document.getElementById('fileInput');

  drop.addEventListener('dragover', e => { e.preventDefault(); drop.style.borderColor = '#00d4ff'; });
  drop.addEventListener('dragleave', () => { drop.style.borderColor = '#1e3a5f'; });
  drop.addEventListener('drop', e => {
    e.preventDefault();
    drop.style.borderColor = '#1e3a5f';
    fileInput.files = e.dataTransfer.files;
    document.getElementById('fileName').textContent = '📄 ' + e.dataTransfer.files[0].name;
  });

  refreshStats();
  setInterval(refreshStats, 10000);
});
