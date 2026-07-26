const $ = (selector) => document.querySelector(selector);
const form = $("#analysis-form");
const sampleInput = $("#sample-input");
const dropZone = $("#drop-zone");
const fileCard = $("#file-card");
const submitButton = $("#submit-button");
const jobsList = $("#jobs-list");
const emptyState = $("#empty-state");
const drawer = $("#job-drawer");
let selectedFile = null;
let activeJobId = null;
let pollTimer = null;

function formatBytes(bytes) {
  if (!bytes) return "0 bytes";
  const units = ["bytes", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function escapeHtml(value = "") {
  return value.replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}

function setFile(file) {
  selectedFile = file || null;
  if (!file) {
    fileCard.classList.add("hidden");
    dropZone.classList.remove("hidden");
    sampleInput.value = "";
    submitButton.disabled = true;
    return;
  }
  $("#file-name").textContent = file.name;
  $("#file-size").textContent = `${formatBytes(file.size)} · Ready for isolated upload`;
  $("#file-extension").textContent = (file.name.split(".").pop() || "FILE").slice(0, 6).toUpperCase();
  fileCard.classList.remove("hidden");
  dropZone.classList.add("hidden");
  submitButton.disabled = false;
}

sampleInput.addEventListener("change", () => setFile(sampleInput.files[0]));
$("#remove-file").addEventListener("click", () => setFile(null));
["dragenter", "dragover"].forEach(event => dropZone.addEventListener(event, e => {
  e.preventDefault(); dropZone.classList.add("dragging");
}));
["dragleave", "drop"].forEach(event => dropZone.addEventListener(event, e => {
  e.preventDefault(); dropZone.classList.remove("dragging");
}));
dropZone.addEventListener("drop", e => {
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});

$("#toggle-advanced").addEventListener("click", event => {
  const fields = $("#advanced-fields");
  const open = fields.classList.toggle("hidden") === false;
  event.currentTarget.setAttribute("aria-expanded", String(open));
  event.currentTarget.querySelector("span").textContent = open ? "⌃" : "⌄";
});

async function loadDefaults() {
  const response = await fetch("/api/config");
  const config = await response.json();
  $("#model").value = config.model || "";
  $("#password").value = config.password;
  $("#max-turns").value = config.max_turns;
  $("#max-tool-errors").value = config.max_tool_errors;
  $("#reports-dir").value = config.reports_dir;
  $("#verbose").checked = Boolean(config.verbose);
  $("#model-hint").textContent = config.api_base_url ? `Endpoint: ${config.api_base_url}` : "Provider configured by model prefix";
}

function statusText(job) {
  if (job.status === "queued") return "Waiting for the current analysis slot";
  if (job.status === "running") return "Isolated analyzers and model are processing the sample";
  if (job.status === "completed") return `${job.artifacts.length} artifact${job.artifacts.length === 1 ? "" : "s"} generated`;
  return `Analysis ended with return code ${job.return_code ?? "unknown"}`;
}

function renderJobs(jobs) {
  emptyState.classList.toggle("hidden", jobs.length > 0);
  jobsList.innerHTML = jobs.map(job => `
    <article class="job-card" data-job-id="${job.id}">
      <div class="job-top">
        <span class="job-name">${escapeHtml(job.filename)}</span>
        <span class="status-pill ${job.status}">${job.status}</span>
      </div>
      <div class="job-bottom"><span>${escapeHtml(job.parameters.model)}</span><span>${new Date(job.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}</span></div>
    </article>`).join("");
  jobsList.querySelectorAll(".job-card").forEach(card => card.addEventListener("click", () => openJob(card.dataset.jobId)));
}

async function refreshJobs() {
  const response = await fetch("/api/jobs");
  if (response.ok) renderJobs(await response.json());
}

function renderDrawer(job) {
  $("#drawer-title").textContent = job.filename;
  $("#drawer-status").innerHTML = `<span class="status-pill ${job.status}">${job.status}</span><span>${escapeHtml(statusText(job))}</span>`;
  $("#artifact-list").innerHTML = job.artifacts.length
    ? job.artifacts.map(item => `<a class="artifact" href="/api/jobs/${job.id}/artifacts/${encodeURIComponent(item.path)}"><span>${escapeHtml(item.name)}</span><span>${item.kind} · ${formatBytes(item.size)}</span></a>`).join("")
    : `<span class="job-time">Artifacts will appear when the analysis writes them.</span>`;
  const log = job.log.join("\n") || "Waiting for output…";
  const logElement = $("#job-log");
  const nearBottom = logElement.scrollHeight - logElement.scrollTop - logElement.clientHeight < 60;
  logElement.textContent = log;
  $("#log-lines").textContent = `${job.log.length} lines`;
  if (nearBottom) logElement.scrollTop = logElement.scrollHeight;
  if (["completed", "failed"].includes(job.status) && pollTimer) {
    clearInterval(pollTimer); pollTimer = null;
  }
}

async function updateActiveJob() {
  if (!activeJobId) return;
  const response = await fetch(`/api/jobs/${activeJobId}`);
  if (!response.ok) return;
  renderDrawer(await response.json());
  refreshJobs();
}

async function openJob(jobId) {
  activeJobId = jobId;
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  await updateActiveJob();
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(updateActiveJob, 1500);
}

function closeDrawer() {
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  activeJobId = null;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

$("#close-drawer").addEventListener("click", closeDrawer);
$("#drawer-backdrop").addEventListener("click", closeDrawer);
$("#refresh-jobs").addEventListener("click", refreshJobs);

form.addEventListener("submit", async event => {
  event.preventDefault();
  if (!selectedFile) return;
  const error = $("#form-error");
  error.classList.add("hidden");
  submitButton.disabled = true;
  submitButton.querySelector("span").textContent = "Uploading sample…";
  const data = new FormData(form);
  data.set("sample", selectedFile, selectedFile.name);
  data.set("verbose", $("#verbose").checked ? "true" : "false");
  try {
    const response = await fetch("/api/jobs", { method: "POST", body: data });
    const body = await response.json();
    if (!response.ok) throw new Error(body.detail || "Unable to submit analysis");
    setFile(null);
    await refreshJobs();
    await openJob(body.id);
  } catch (exception) {
    error.textContent = exception.message;
    error.classList.remove("hidden");
  } finally {
    submitButton.querySelector("span").textContent = "Begin isolated analysis";
    submitButton.disabled = !selectedFile;
  }
});

Promise.all([loadDefaults(), refreshJobs()]).catch(error => {
  $("#form-error").textContent = `Unable to initialize console: ${error.message}`;
  $("#form-error").classList.remove("hidden");
});
