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
let configState = {};
let pendingUploadInput = null;
const authorizedPublicUploads = new Set();

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
  requestAnimationFrame(syncActivityPanelHeight);
});

async function loadDefaults() {
  const response = await fetch("/api/config");
  const config = await response.json();
  configState = config;
  $("#model").value = config.model || "";
  $("#password").value = config.password;
  $("#max-turns").value = config.max_turns;
  $("#max-tool-errors").value = config.max_tool_errors;
  $("#reports-dir").value = config.reports_dir;
  $("#verbose").checked = Boolean(config.verbose);
  const selectedProviders = new Set(config.dynamic_providers || []);
  for (const provider of ["cape", "anyrun", "joesandbox", "triage"]) {
    const input = $(`#use-${provider}`);
    const available = Boolean(config.dynamic_availability?.[provider]);
    input.disabled = !available;
    input.checked = available && selectedProviders.has(provider);
    $(`#option-${provider}`).classList.toggle("unavailable", !available);
  }
  $("#use-virustotal").disabled = !config.virustotal_available;
  $("#use-virustotal").checked = Boolean(config.virustotal_available && config.virustotal_enabled);
  $("#option-virustotal").classList.toggle("unavailable", !config.virustotal_available);
  $("#use-abusech").disabled = !config.abusech_available;
  $("#use-abusech").checked = Boolean(config.abusech_available && config.abusech_enabled);
  $("#option-abusech").classList.toggle("unavailable", !config.abusech_available);
  $("#use-unpacme").disabled = !config.unpacme_available;
  $("#use-unpacme").checked = Boolean(config.unpacme_available && config.unpacme_enabled);
  $("#option-unpacme").classList.toggle("unavailable", !config.unpacme_available);
  updateUploadControls();
  $("#model-hint").textContent = config.api_base_url ? `Endpoint: ${config.api_base_url}` : "Provider configured by model prefix";
}

const uploadWarning = $("#upload-warning");
const uploadAckInput = $("#upload-ack-input");
const confirmUpload = $("#confirm-upload");
const publicUploadProviders = new Set(["anyrun", "joesandbox", "virustotal"]);

function isPublicUpload(provider) {
  return publicUploadProviders.has(provider)
    || (provider === "triage" && Boolean(configState.triage_public_upload))
    || (provider === "unpacme" && !Boolean(configState.unpacme_private));
}

function updateUploadControls() {
  for (const provider of ["anyrun", "joesandbox", "triage", "unpacme"]) {
    const parent = $(`#use-${provider}`);
    const upload = $(`#upload-${provider}`);
    const disabled = parent.disabled || !parent.checked;
    upload.disabled = disabled;
    if (disabled) upload.checked = false;
    $(`#option-${provider}-upload`).classList.toggle("unavailable", disabled);
  }
  const vtUpload = $("#upload-virustotal");
  vtUpload.disabled = $("#use-virustotal").disabled || !$("#use-virustotal").checked;
  if (vtUpload.disabled) vtUpload.checked = false;
  $("#option-virustotal-upload").classList.toggle("unavailable", vtUpload.disabled);
}

for (const provider of ["anyrun", "joesandbox", "triage", "virustotal", "unpacme"]) {
  $(`#use-${provider}`).addEventListener("change", updateUploadControls);
  $(`#upload-${provider}`).addEventListener("change", event => {
    if (!event.currentTarget.checked || !isPublicUpload(provider)) return;
    pendingUploadInput = event.currentTarget;
    uploadAckInput.value = "";
    confirmUpload.disabled = true;
    $("#upload-warning-copy").textContent = `${provider === "virustotal" ? "VirusTotal" : provider === "triage" ? "Recorded Future Triage" : provider.toUpperCase()} will receive the sample bytes, not merely its hash.`;
    uploadWarning.showModal();
    uploadAckInput.focus();
  });
}

uploadAckInput.addEventListener("input", () => {
  confirmUpload.disabled = uploadAckInput.value.trim() !== "acknowledge";
});
uploadWarning.addEventListener("close", () => {
  if (!pendingUploadInput) return;
  if (uploadWarning.returnValue === "confirm") authorizedPublicUploads.add(pendingUploadInput.id);
  else pendingUploadInput.checked = false;
  pendingUploadInput = null;
});

function statusText(job) {
  if (job.status === "queued") return "Waiting for the current analysis slot";
  if (job.status === "running") return "Isolated analyzers and model are processing the sample";
  if (job.status === "completed") return `${job.artifacts.length} artifact${job.artifacts.length === 1 ? "" : "s"} generated`;
  if (job.status === "completed_with_warnings") return `Useful reports generated; one or more package members could not be fully analyzed`;
  return `Analysis ended with return code ${job.return_code ?? "unknown"}`;
}

function displayStatus(status) {
  return status === "completed_with_warnings" ? "completed with warnings" : status;
}

const TEXT_ARTIFACT_EXTENSIONS = /\.(?:json|txt|xml|vbs|vbe|js|jse|ps1|cmd|bat|py|sh|wsf|hta|yaml|yml|csv|log)$/i;

function artifactLabel(item) {
  if (/\.decoded\.[^.]+$/i.test(item.name)) return "Decoded Payload";
  if (/\.report\.json$/i.test(item.name)) return "File Triage Report";
  if (/\.transcript\.json$/i.test(item.name)) return "Analysis Agent Transcript";
  if (/\.remnux\.json$/i.test(item.name)) return "REMnux Static Analysis";
  const labels = {
    report: "File Triage Report",
    remnux: "REMnux Static Analysis",
    transcript: "Analysis Agent Transcript",
    deobfuscated: "Deobfuscated Script",
    decoded: "Decoded Payload",
    dynamic: "Dynamic Sandbox Report",
    virustotal: "VirusTotal Reputation Report",
    reputation: "Threat Intelligence Report",
    unpacking: "Unpacking Service Report",
    package: "Package Analysis Summary",
    file: "Generated Artifact"
  };
  return labels[item.kind] || "Analysis Artifact";
}

function artifactMember(item) {
  if (item.member_name) return item.member_name;
  const name = item.name;
  const suffixes = [
    /\.report\.json$/i, /\.transcript\.json$/i, /\.remnux\.json$/i,
    /\.virustotal\.json$/i, /\.abusech\.json$/i, /\.unpacme\.json$/i,
    /\.dynamic\.[^.]+\.json$/i, /\.dynamic\.json$/i,
    /\.deobfuscated\.txt$/i, /\.decoded\.[^.]+$/i
  ];
  for (const suffix of suffixes) {
    if (suffix.test(name)) return name.replace(suffix, "");
  }
  if (item.kind === "package") return "Package overview";
  return name;
}

function artifactTarget(jobId, item) {
  const viewable = ["report", "dynamic", "transcript", "deobfuscated", "decoded", "remnux", "virustotal", "reputation", "unpacking", "package"].includes(item.kind)
    || TEXT_ARTIFACT_EXTENSIONS.test(item.path);
  return {
    viewable,
    url: viewable
      ? `/report.html?job=${encodeURIComponent(jobId)}&artifact=${encodeURIComponent(item.path)}&return=details`
      : `/api/jobs/${encodeURIComponent(jobId)}/artifacts/${encodeURIComponent(item.path)}?download=1`
  };
}

function renderArtifactGroups(job) {
  if (!job.artifacts.length) {
    return `<span class="job-time">Artifacts will appear when the analysis writes them.</span>`;
  }
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
        const target = artifactTarget(job.id, item);
        return `<a class="artifact-tab" href="${target.url}">
          <strong>${escapeHtml(artifactLabel(item))}</strong>
          <small>${target.viewable ? "View" : "Download"} · ${formatBytes(item.size)}</small>
        </a>`;
      }).join("")}</div>
    </details>`;
  }).join("");
}

function renderJobs(jobs) {
  jobs = jobs.slice(0, 7);
  emptyState.classList.toggle("hidden", jobs.length > 0);
  jobsList.innerHTML = jobs.map(job => `
    <article class="job-card" data-job-id="${job.id}">
      <div class="job-top">
        <span class="job-name">${escapeHtml(job.filename)}</span>
        <span class="status-pill ${job.status}">${displayStatus(job.status)}</span>
      </div>
      <div class="job-bottom"><span>${escapeHtml(job.parameters.model)}</span><span>${new Date(job.created_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"})}</span></div>
    </article>`).join("");
  jobsList.querySelectorAll(".job-card").forEach(card => card.addEventListener("click", () => openJob(card.dataset.jobId)));
}

function syncActivityPanelHeight() {
  const activity = document.querySelector(".activity-panel");
  const advancedClosed = $("#advanced-fields").classList.contains("hidden");
  const sideBySide = window.matchMedia("(min-width: 901px)").matches;
  activity.style.height = advancedClosed && sideBySide ? `${form.offsetHeight}px` : "";
}

async function refreshJobs() {
  const response = await fetch("/api/jobs");
  if (response.ok) renderJobs(await response.json());
}

function renderDrawer(job) {
  $("#drawer-title").textContent = job.filename;
  $("#drawer-status").innerHTML = `<span class="status-pill ${job.status}">${displayStatus(job.status)}</span><span>${escapeHtml(statusText(job))}</span>`;
  $("#artifact-list").innerHTML = renderArtifactGroups(job);
  const log = job.log.join("\n") || "Waiting for output…";
  const logElement = $("#job-log");
  const nearBottom = logElement.scrollHeight - logElement.scrollTop - logElement.clientHeight < 60;
  logElement.textContent = log;
  $("#log-lines").textContent = `${job.log.length} lines`;
  $("#delete-job").classList.toggle(
    "hidden",
    !["completed", "completed_with_warnings", "failed"].includes(job.status)
  );
  if (nearBottom) logElement.scrollTop = logElement.scrollHeight;
  if (["completed", "completed_with_warnings", "failed"].includes(job.status) && pollTimer) {
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
$("#delete-job").addEventListener("click", async () => {
  if (!activeJobId) return;
  if (!window.confirm("Delete this analysis and all of its generated artifacts? This cannot be undone.")) return;
  const button = $("#delete-job");
  button.disabled = true;
  try {
    const response = await fetch(`/api/jobs/${activeJobId}`, {method: "DELETE"});
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.detail || "Unable to delete analysis");
    }
    closeDrawer();
    await refreshJobs();
  } catch (error) {
    window.alert(error.message);
  } finally {
    button.disabled = false;
  }
});

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
  data.set("dynamic_providers", ["cape", "anyrun", "joesandbox", "triage"]
    .filter(provider => $(`#use-${provider}`).checked && !$(`#use-${provider}`).disabled)
    .join(","));
  data.set("dynamic_upload_providers", ["anyrun", "joesandbox", "triage"]
    .filter(provider => $(`#upload-${provider}`).checked && !$(`#upload-${provider}`).disabled)
    .join(","));
  data.set("virustotal_enabled", $("#use-virustotal").checked ? "true" : "false");
  data.set("virustotal_upload_missing", $("#upload-virustotal").checked ? "true" : "false");
  data.set("unpacme_enabled", $("#use-unpacme").checked ? "true" : "false");
  data.set("unpacme_upload", $("#upload-unpacme").checked ? "true" : "false");
  data.set("abusech_enabled", $("#use-abusech").checked ? "true" : "false");
  const selectedPublicUpload = ["anyrun", "joesandbox", "triage", "virustotal", "unpacme"]
    .some(provider => $(`#upload-${provider}`).checked && isPublicUpload(provider));
  const publicUploadsAuthorized = ["anyrun", "joesandbox", "triage", "virustotal", "unpacme"]
    .filter(provider => $(`#upload-${provider}`).checked && isPublicUpload(provider))
    .every(provider => authorizedPublicUploads.has(`upload-${provider}`));
  data.set("upload_acknowledgement", selectedPublicUpload && publicUploadsAuthorized ? "acknowledge" : "");
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

new ResizeObserver(syncActivityPanelHeight).observe(form);
window.addEventListener("resize", syncActivityPanelHeight);
Promise.all([loadDefaults(), refreshJobs()]).then(async () => {
  syncActivityPanelHeight();
  const requestedJob = new URLSearchParams(location.search).get("job");
  if (requestedJob) await openJob(requestedJob);
}).catch(error => {
  $("#form-error").textContent = `Unable to initialize console: ${error.message}`;
  $("#form-error").classList.remove("hidden");
});
