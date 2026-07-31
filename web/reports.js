const $ = selector => document.querySelector(selector);
const escapeHtml = (value = "") => String(value).replace(
  /[&<>"']/g, character => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character])
);
let requestSequence = 0;
let filterTimer = null;
let activeArchiveJob = null;
let currentReports = [];

const TEXT_ARTIFACT_EXTENSIONS = /\.(?:json|txt|xml|vbs|vbe|js|jse|ps1|cmd|bat|py|sh|wsf|hta|yaml|yml|csv|log)$/i;

function artifactLabel(item) {
  if (/\.decoded\.[^.]+$/i.test(item.name)) return "Decoded Payload";
  const labels = {report:"File Triage Report", remnux:"REMnux Static Analysis", transcript:"Analysis Agent Transcript", deobfuscated:"Deobfuscated Script", decoded:"Decoded Payload", dynamic:"Dynamic Sandbox Report", virustotal:"VirusTotal Reputation Report", reputation:"Threat Intelligence Report", unpacking:"Unpacking Service Report", package:"Package Analysis Summary", file:"Generated Artifact"};
  return labels[item.kind] || "Analysis Artifact";
}

function artifactMember(item) {
  if (item.member_name) return item.member_name;
  const suffixes = [/\.report\.json$/i, /\.transcript\.json$/i, /\.remnux\.json$/i, /\.virustotal\.json$/i, /\.abusech\.json$/i, /\.unpacme\.json$/i, /\.dynamic\.[^.]+\.json$/i, /\.dynamic\.json$/i, /\.deobfuscated\.txt$/i, /\.decoded\.[^.]+$/i];
  for (const suffix of suffixes) if (suffix.test(item.name)) return item.name.replace(suffix, "");
  return item.kind === "package" ? "Package overview" : item.name;
}

function artifactLink(jobId, item) {
  const viewable = ["report", "dynamic", "transcript", "deobfuscated", "decoded", "remnux", "virustotal", "reputation", "unpacking", "package"].includes(item.kind) || TEXT_ARTIFACT_EXTENSIONS.test(item.path);
  const filters = encodeURIComponent(archiveReturnQuery());
  return {
    viewable,
    url: viewable
      ? `/report.html?job=${encodeURIComponent(jobId)}&artifact=${encodeURIComponent(item.path)}&return=reports&filters=${filters}`
      : `/api/jobs/${encodeURIComponent(jobId)}/artifacts/${encodeURIComponent(item.path)}?download=1`
  };
}

function renderArtifactGroups(job) {
  const groups = new Map();
  job.artifacts.forEach(item => {
    const member = artifactMember(item);
    if (!groups.has(member)) groups.set(member, []);
    groups.get(member).push(item);
  });
  return [...groups.entries()].map(([member, artifacts], index) => {
    const verdict = artifacts.find(item => item.verdict)?.verdict || "unknown";
    return `<details class="artifact-group" ${index === 0 ? "open" : ""}>
      <summary><span>${escapeHtml(member)}</span><span class="artifact-group-meta"><span class="status-pill verdict-${escapeHtml(verdict)}">${escapeHtml(verdict)}</span><small>${artifacts.length} available</small></span></summary>
      <div class="artifact-tabs">${artifacts.map(item => {
        const link = artifactLink(job.id, item);
        return `<a class="artifact-tab" href="${link.url}"><strong>${escapeHtml(artifactLabel(item))}</strong><small>${link.viewable ? "View" : "Download"} · ${escapeHtml(String(item.size))} bytes</small></a>`;
      }).join("")}</div></details>`;
  }).join("") || '<span class="job-time">No artifacts are available.</span>';
}

async function openAnalysisDetails(jobId) {
  const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}`);
  const job = await response.json();
  if (!response.ok) throw new Error(job.detail || "Unable to load analysis details");
  activeArchiveJob = jobId;
  $("#archive-details-title").textContent = job.filename;
  $("#archive-details-status").innerHTML = `<span class="status-pill ${escapeHtml(job.status)}">${escapeHtml(job.status.replaceAll("_", " "))}</span><span>${job.artifacts.length} generated artifacts</span>`;
  $("#archive-artifact-list").innerHTML = renderArtifactGroups(job);
  $("#archive-job-log").textContent = job.log.join("\n") || "No execution log is available.";
  $("#archive-log-lines").textContent = `${job.log.length} lines`;
  const dialog = $("#archive-details");
  if (!dialog.open) dialog.showModal();
}

function queryString() {
  const values = {
    filename: $("#filter-filename").value.trim(),
    file_hash: $("#filter-hash").value.trim(),
    model: $("#filter-model").value.trim(),
    verdict: $("#filter-verdict").value,
    date_from: $("#filter-from").value,
    date_to: $("#filter-to").value
  };
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => { if (value) query.set(key, value); });
  return query.toString();
}

function archiveReturnQuery() {
  const query = new URLSearchParams(queryString());
  query.set("display", $("#reports-per-page").value);
  return query.toString();
}

function renderReports(reports) {
  currentReports = reports;
  const selection = $("#reports-per-page").value;
  const limit = selection === "all" ? reports.length : Number.parseInt(selection, 10);
  const displayed = reports.slice(0, limit);
  $("#report-count").textContent = `${reports.length} matching report${reports.length === 1 ? "" : "s"}`;
  $("#report-display-count").textContent = `Showing ${displayed.length} of ${reports.length} reports`;
  $("#reports-empty").classList.toggle("hidden", reports.length > 0);
  $("#report-results").innerHTML = displayed.map(report => {
    const digest = report.sha256 || "Unavailable";
    return `<tr>
      <td><button class="archive-file archive-detail-open" type="button" data-job-id="${escapeHtml(report.job_id)}">${escapeHtml(report.filename)}</button></td>
      <td><code title="${escapeHtml(digest)}">${escapeHtml(digest)}</code></td>
      <td>${escapeHtml(new Date(report.created_at).toLocaleString())}</td>
      <td>${escapeHtml(report.model)}</td>
      <td><span class="status-pill verdict-${escapeHtml(report.verdict)}">${escapeHtml(report.verdict)}</span></td>
      <td><button class="archive-open archive-detail-open" type="button" data-job-id="${escapeHtml(report.job_id)}">Details →</button></td>
    </tr>`;
  }).join("");
  document.querySelectorAll(".archive-detail-open").forEach(button => button.addEventListener("click", () => {
    openAnalysisDetails(button.dataset.jobId).catch(showArchiveError);
  }));
}

function showArchiveError(exception) {
  $("#reports-error").textContent = exception.message;
  $("#reports-error").classList.remove("hidden");
}

async function loadReports() {
  const sequence = ++requestSequence;
  const error = $("#reports-error");
  error.classList.add("hidden");
  try {
    const query = queryString();
    const response = await fetch(`/api/reports${query ? `?${query}` : ""}`);
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Unable to search reports");
    if (sequence === requestSequence) renderReports(body);
  } catch (exception) {
    if (sequence !== requestSequence) return;
    error.textContent = exception.message;
    error.classList.remove("hidden");
  }
}

function scheduleSearch() {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(loadReports, 220);
}

$("#report-filters").addEventListener("submit", event => { event.preventDefault(); loadReports(); });
$("#report-filters").addEventListener("input", scheduleSearch);
$("#report-filters").addEventListener("change", loadReports);
$("#refresh-reports").addEventListener("click", loadReports);
$("#clear-report-filters").addEventListener("click", () => {
  $("#report-filters").reset();
  loadReports();
});
$("#reports-per-page").addEventListener("change", event => {
  localStorage.setItem("recluseReportsDisplayed", event.currentTarget.value);
  renderReports(currentReports);
});
$("#close-archive-details").addEventListener("click", () => $("#archive-details").close());
$("#archive-details").addEventListener("click", event => {
  if (event.target === $("#archive-details")) $("#archive-details").close();
});

const initial = new URLSearchParams(location.search);
const savedDisplay = initial.get("display") || localStorage.getItem("recluseReportsDisplayed") || "15";
if (["15", "25", "50", "100", "all"].includes(savedDisplay)) $("#reports-per-page").value = savedDisplay;
const filterInputs = {filename:"#filter-filename", file_hash:"#filter-hash", model:"#filter-model", verdict:"#filter-verdict", date_from:"#filter-from", date_to:"#filter-to"};
Object.entries(filterInputs).forEach(([key, selector]) => { if (initial.has(key)) $(selector).value = initial.get(key); });
loadReports().then(() => {
  if (initial.get("job")) openAnalysisDetails(initial.get("job")).catch(showArchiveError);
});
