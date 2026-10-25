const form = document.getElementById("scanForm");
const btn = document.getElementById("scanBtn");
const errorBox = document.getElementById("errorBox");
let lastReport = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.style.display = "none";
  if (!document.getElementById("authorized").checked) return;
  btn.disabled = true;
  btn.textContent = "MAPPING & CHECKING…";
  document.getElementById("results").style.display = "none";
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        url: document.getElementById("url").value.trim(),
        access_key: document.getElementById("accessKey").value,
        authorized: document.getElementById("authorized").checked
      })
    });
    const data = await response.json();
    if (!response.ok || data.error) throw new Error(data.error || "Assessment failed.");
    lastReport = data.result;
    renderReport(lastReport);
  } catch (error) {
    errorBox.textContent = error.message || "Unexpected error.";
    errorBox.style.display = "block";
  } finally {
    btn.disabled = false;
    btn.textContent = "⌁  START ADVANCED AUDIT";
  }
});

function renderReport(report) {
  document.getElementById("results").style.display = "block";
  document.getElementById("targetMeta").textContent = report.target;
  document.getElementById("highCount").textContent = report.summary.high;
  document.getElementById("medCount").textContent = report.summary.medium;
  document.getElementById("lowCount").textContent = report.summary.low;
  document.getElementById("pagesCount").textContent = report.summary.pages_crawled;
  document.getElementById("formsCount").textContent = report.summary.forms_found;
  document.getElementById("techMeta").innerHTML =
    "HTTP status: <b>" + esc(report.http_status || "Not returned") +
    "</b> · Content type: <b>" + esc(report.content_type) +
    "</b> · Response time: <b>" + esc(report.response_time) +
    "s</b><br>Checked: " + esc(report.checked_at) + " · Target host: " + esc(report.host);
  document.getElementById("findings").innerHTML = report.checks.map(check =>
    '<article class="finding"><div class="findingtop"><h4>' + esc(check.name) +
    '</h4><span class="tag ' + esc(check.severity) + '">' + esc(check.status) +
    '</span></div><p><b>' + esc(check.area) + ':</b> ' + esc(check.detail) + '</p>' +
    (check.fix ? '<p class="fix"><b>Suggested fix:</b> ' + esc(check.fix) + '</p>' : '') +
    '</article>'
  ).join("");
  document.getElementById("pagesList").innerHTML = report.pages.map(page =>
    "<li><b>" + esc(page.status || "ERROR") + "</b> — " + esc(page.url) +
    (page.error ? " (" + esc(page.error) + ")" : "") + "</li>"
  ).join("") || "<li>No pages discovered.</li>";
  document.getElementById("formsList").innerHTML = report.forms.map(form =>
    "<li><b>" + esc(form.method) + "</b> — " + esc(form.page) + " · " +
    esc(form.fields.map(field => field.type + ":" + field.name).join(", ") || "no named inputs") +
    "</li>"
  ).join("") || "<li>No forms observed.</li>";
  document.getElementById("reportNote").textContent = report.limitations;
  document.getElementById("results").scrollIntoView({behavior: "smooth", block: "start"});
}

document.getElementById("downloadBtn").addEventListener("click", () => {
  if (!lastReport) return;
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "night-hex-security-report.json";
  link.click();
  URL.revokeObjectURL(url);
});
document.getElementById("printBtn").addEventListener("click", () => window.print());
document.getElementById("copyBtn").addEventListener("click", async () => {
  if (!lastReport) return;
  const summary = "NIGHT HEX Advanced Report\nTarget: " + lastReport.target +
    "\nHTTP status: " + lastReport.http_status +
    "\nHigh: " + lastReport.summary.high + " | Medium: " + lastReport.summary.medium +
    " | Low: " + lastReport.summary.low + "\n" +
    lastReport.checks.map(c => "- " + c.name + ": " + c.status + " — " + c.detail).join("\n");
  try {
    await navigator.clipboard.writeText(summary);
    document.getElementById("copyBtn").textContent = "Copied!";
    setTimeout(() => document.getElementById("copyBtn").textContent = "Copy summary", 1500);
  } catch (_) {
    window.prompt("Copy report summary:", summary);
  }
});
