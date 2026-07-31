const $ = selector => document.querySelector(selector);
const escapeHtml = (value = "") => String(value).replace(
  /[&<>"']/g,
  char => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[char])
);

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function renderMetadata(report) {
  const sample = report.sample || {};
  const analysis = report.analysis || {};
  const rows = [
    ["Status", analysis.status],
    ["Model", analysis.model],
    ["Route", sample.analysis_route],
    ["Detected type", sample.detected_type],
    ["SHA-256", sample.sha256],
    ["Turns", analysis.turns],
    ["Valid tool calls", analysis.valid_tool_calls],
    ["Quality score", report.quality?.score !== undefined ? `${report.quality.score}/100` : null]
  ];
  $("#report-metadata").innerHTML = rows.map(([label, value]) =>
    `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(displayValue(value))}</dd></div>`
  ).join("");
}

function renderCapabilities(capabilities) {
  const container = $("#report-capabilities");
  if (!Array.isArray(capabilities) || !capabilities.length) {
    container.innerHTML = '<span class="empty-value">No capabilities reported.</span>';
    return;
  }
  container.innerHTML = capabilities.map(item =>
    `<span>${escapeHtml(typeof item === "string" ? item : JSON.stringify(item))}</span>`
  ).join("");
}

function flattenIocs(iocs) {
  if (!iocs || typeof iocs !== "object") return [];
  return Object.entries(iocs).flatMap(([kind, values]) => {
    const list = Array.isArray(values) ? values : [values];
    return list.filter(value => value !== null && value !== "").map(value => [
      kind,
      typeof value === "object" ? JSON.stringify(value) : String(value)
    ]);
  });
}

function renderIocs(iocs) {
  const rows = flattenIocs(iocs);
  $("#report-iocs").innerHTML = rows.length
    ? rows.map(([kind, value]) =>
      `<div><span>${escapeHtml(kind)}</span><code>${escapeHtml(value)}</code></div>`
    ).join("")
    : '<span class="empty-value">No indicators reported.</span>';
}

function renderEvidence(evidence) {
  const items = Array.isArray(evidence) ? evidence : [];
  $("#report-evidence").innerHTML = items.length
    ? items.map(item => `
      <article>
        <code>${escapeHtml(item.tool_call_id || "uncited")}</code>
        <p>${escapeHtml(item.claim || item.description || JSON.stringify(item))}</p>
      </article>`).join("")
    : '<span class="empty-value">No evidence citations reported.</span>';
}

function renderRemnux(report, jobId) {
  const remnux = report.analysis?.remnux_mcp || {};
  const status = remnux.status || (remnux.enabled ? "unavailable" : "disabled");
  const artifactPath = remnux.artifact_path || "";
  const artifactName = artifactPath.split("/").pop();
  let detail = `Status: ${status}`;
  if (remnux.depth) detail += ` · Depth: ${remnux.depth}`;
  if (remnux.error) detail += ` · ${remnux.error}`;
  const link = artifactName
    ? `<p><a href="/report.html?job=${encodeURIComponent(jobId)}&artifact=${encodeURIComponent(artifactName)}">Open complete REMnux results</a></p>`
    : "";
  $("#report-remnux").innerHTML =
    `<article><code>Scenario 1 · offline container</code><p>${escapeHtml(detail)}</p>${link}</article>`;
}

function renderAnalystDetails(triage) {
  const details = triage.analyst_details || {};
  const pivots = Array.isArray(details.prioritized_pivots) ? details.prioritized_pivots : [];
  $("#report-pivots").innerHTML = pivots.length
    ? pivots.map(item => `<article>
        <code>${escapeHtml(item.location || "unknown location")}</code>
        <p>${escapeHtml(item.section ? `${item.section}: ` : "")}${escapeHtml((item.reasons || []).join("; "))}</p>
      </article>`).join("")
    : '<span class="empty-value">No prioritized locations reported.</span>';

  const sections = Array.isArray(details.pe?.sections) ? details.pe.sections : [];
  $("#report-sections").innerHTML = sections.length
    ? sections.map(item => `<tr class="${item.high_entropy || (item.writable && item.executable) ? "priority-row" : ""}">
        <td><code>${escapeHtml(item.name || "—")}</code></td>
        <td><code>${escapeHtml(item.rva || "—")}</code></td>
        <td><code>${escapeHtml(item.virtual_address || "—")}</code></td>
        <td><code>${escapeHtml(item.raw_offset || "—")}</code></td>
        <td>${escapeHtml(item.entropy ?? "—")}</td>
        <td>${escapeHtml([item.executable ? "X" : "", item.writable ? "W" : "", item.high_entropy ? "HIGH ENTROPY" : ""].filter(Boolean).join(" · ") || "—")}</td>
      </tr>`).join("")
    : '<tr><td colspan="6" class="empty-value">No PE section detail reported.</td></tr>';

  const yara = Array.isArray(details.yara_matches) ? details.yara_matches : [];
  const anomalies = Array.isArray(details.anomalies) ? details.anomalies : [];
  const signatureItems = [
    ...yara.map(item => ({
      label: `YARA · ${item.rule || "unnamed"}`,
      text: [
        item.description,
        item.author ? `Author: ${item.author}` : "",
        ...(item.matches || []).map(match => `${match.identifier}: ${match.offset_hex}`),
        ...(item.strings || []).map(pattern => `Pattern: ${pattern}`)
      ].filter(Boolean).join(" · ")
    })),
    ...anomalies.map(item => ({
      label: item.signature || "anomaly",
      text: `Severity ${item.severity ?? "—"} · confidence ${item.confidence ?? "—"} · ${JSON.stringify(item.detail)}`
    }))
  ];
  $("#report-signatures").innerHTML = signatureItems.length
    ? signatureItems.map(item => `<article><code>${escapeHtml(item.label)}</code><p>${escapeHtml(item.text)}</p></article>`).join("")
    : '<span class="empty-value">No detailed signatures reported.</span>';

  const metadata = details.binary_metadata || {};
  const imports = Array.isArray(details.interesting_imports) ? details.interesting_imports : [];
  const resources = Array.isArray(details.high_entropy_resources) ? details.high_entropy_resources : [];
  const contextItems = [
    {
      label: "Build and identity",
      text: [
        metadata.compile_timestamp ? `Timestamp: ${metadata.compile_timestamp}` : "",
        metadata.imphash ? `imphash: ${metadata.imphash}` : "",
        metadata.ssdeep ? `ssdeep: ${metadata.ssdeep}` : "",
        metadata.tlsh ? `TLSH: ${metadata.tlsh}` : "",
        `Digitally signed: ${metadata.digitally_signed ? "yes" : "no"}`,
        metadata.pdb_path ? `PDB: ${metadata.pdb_path}` : ""
      ].filter(Boolean).join(" · ")
    },
    ...imports.map(item => ({
      label: `${item.dll || "import"}!${item.api || "unknown"}`,
      text: `${item.address || "unknown address"} · ${(item.categories || []).join(", ")}`
    })),
    ...resources.map(item => ({
      label: `High-entropy resource · ${item.name || "unnamed"}`,
      text: `${item.offset || "unknown offset"} · size ${item.size || "unknown"} · entropy ${item.entropy}`
    }))
  ];
  $("#report-binary-context").innerHTML = contextItems.length
    ? contextItems.map(item => `<article><code>${escapeHtml(item.label)}</code><p>${escapeHtml(item.text)}</p></article>`).join("")
    : '<span class="empty-value">No binary context reported.</span>';

  const steps = Array.isArray(triage.recommended_next_steps)
    ? triage.recommended_next_steps
    : (details.recommended_next_steps || []);
  $("#report-next-steps").innerHTML = steps.length
    ? steps.map(step => `<li>${escapeHtml(step)}</li>`).join("")
    : '<li class="empty-value">No next steps reported.</li>';

  const enrichment = triage.static_enrichment || {};
  const flossStrings = Array.isArray(enrichment.floss?.interesting_strings)
    ? enrichment.floss.interesting_strings : [];
  $("#report-floss").innerHTML = flossStrings.length
    ? flossStrings.map(item => `<article>
        <code>${escapeHtml(item.type || "string")}${item.location ? ` · ${escapeHtml(item.location)}` : ""}</code>
        <p>${escapeHtml(item.value)}</p>
      </article>`).join("")
    : `<span class="empty-value">${escapeHtml(enrichment.floss?.error || "No ranked FLOSS strings reported.")}</span>`;

  const capaCapabilities = Array.isArray(enrichment.capa?.capabilities)
    ? enrichment.capa.capabilities : [];
  $("#report-capa").innerHTML = capaCapabilities.length
    ? capaCapabilities.map(item => `<article>
        <code>${escapeHtml(item.name || "unnamed capability")}</code>
        <p>${escapeHtml([
          item.namespace,
          item.description,
          ...(item.attack || []),
          ...(item.mbc || []),
          item.locations?.length ? `Locations: ${item.locations.join(", ")}` : ""
        ].filter(Boolean).join(" · "))}</p>
      </article>`).join("")
    : `<span class="empty-value">${escapeHtml(enrichment.capa?.error || "No capa capabilities reported.")}</span>`;
}

function renderReport(report, jobId) {
  const triage = report.triage;
  if (!triage || typeof triage !== "object") return false;
  $("#report-overview").classList.remove("hidden");
  $("#report-summary").textContent = triage.summary || "No summary provided.";
  renderMetadata(report);
  renderCapabilities(triage.capabilities);
  renderIocs(triage.iocs);
  renderEvidence(triage.evidence);
  renderRemnux(report, jobId);
  renderAnalystDetails(triage);

  const verdict = $("#report-verdict");
  const value = String(triage.verdict || "unknown").toLowerCase();
  verdict.className = `verdict-card verdict-${value}`;
  verdict.querySelector("strong").textContent = value;
  verdict.querySelector("small").textContent =
    typeof triage.confidence === "number"
      ? `${Math.round(triage.confidence * 100)}% confidence`
      : "Confidence unavailable";
  return true;
}

function artifactDisplayName(artifact) {
  const name = artifact.split("/").pop();
  const labels = [
    [/\.report\.json$/i, "File Triage Report"],
    [/\.remnux\.json$/i, "REMnux Static Analysis"],
    [/\.transcript\.json$/i, "Analysis Agent Transcript"],
    [/\.deobfuscated\.txt$/i, "Deobfuscated Script"],
    [/\.decoded\.[^.]+$/i, "Decoded Payload"],
    [/\.virustotal\.json$/i, "VirusTotal Reputation Report"],
    [/\.abusech\.json$/i, "Threat Intelligence Report"],
    [/\.unpacme\.json$/i, "Unpacking Service Report"],
    [/\.dynamic(?:\.[^.]+)?\.json$/i, "Dynamic Sandbox Report"],
    [/\.package\.json$/i, "Package Analysis Summary"]
  ];
  return labels.find(([pattern]) => pattern.test(name))?.[1] || "Analysis Artifact";
}

async function loadReport() {
  const parameters = new URLSearchParams(location.search);
  const jobId = parameters.get("job");
  const artifact = parameters.get("artifact");
  if (!jobId || !artifact) throw new Error("The report link is missing its job or artifact identifier.");
  const returnTarget = parameters.get("return");
  const filters = parameters.get("filters") || "";
  $("#report-back").href = returnTarget === "reports"
    ? `/reports.html?${filters ? `${filters}&` : ""}job=${encodeURIComponent(jobId)}`
    : `/?job=${encodeURIComponent(jobId)}`;

  const fileName = artifact.split("/").pop();
  $("#report-title").textContent = artifactDisplayName(artifact);
  $("#report-subtitle").textContent = `${fileName} · Job ${jobId}`;
  const encoded = encodeURIComponent(artifact);
  $("#report-download").href = `/api/jobs/${encodeURIComponent(jobId)}/artifacts/${encoded}?download=1`;
  $("#report-download").classList.remove("hidden");

  const response = await fetch(
    `/api/jobs/${encodeURIComponent(jobId)}/artifact-content/${encoded}`
  );
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw new Error(detail.detail || "Unable to load this report.");
  }
  const text = await response.text();
  $("#raw-content").textContent = text;
  try {
    const rendered = renderReport(JSON.parse(text), jobId);
    if (rendered) {
      $("#raw-toggle small").textContent = "Show JSON";
    } else {
      $("#raw-content").classList.remove("hidden");
      $("#raw-toggle").setAttribute("aria-expanded", "true");
      $("#raw-toggle span").textContent = "Artifact content";
      $("#raw-toggle small").textContent = "Hide content";
    }
  } catch {
    $("#raw-content").classList.remove("hidden");
    $("#raw-toggle").setAttribute("aria-expanded", "true");
    $("#raw-toggle span").textContent = "Artifact content";
    $("#raw-toggle small").textContent = "Hide content";
  }
}

$("#raw-toggle").addEventListener("click", event => {
  const raw = $("#raw-content");
  const open = raw.classList.toggle("hidden") === false;
  event.currentTarget.setAttribute("aria-expanded", String(open));
  event.currentTarget.querySelector("small").textContent = open ? "Hide content" : "Show JSON";
});

loadReport().catch(error => {
  $("#report-error").textContent = error.message;
  $("#report-error").classList.remove("hidden");
  $("#report-title").textContent = "Report unavailable";
  $("#report-subtitle").textContent = "The requested local artifact could not be displayed.";
});
