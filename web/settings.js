const $ = selector => document.querySelector(selector);
let keyConfigured = false;
let dynamicKeysConfigured = {};
let virustotalKeyConfigured = false;

function renderSandboxKeyStates() {
  for (const [provider, stateId, rowId] of [
    ["cape", "#cape-key-state", "#clear-cape-key-row"],
    ["anyrun", "#anyrun-key-state", "#clear-anyrun-key-row"],
    ["joesandbox", "#joe-key-state", "#clear-joe-key-row"],
    ["triage", "#triage-key-state", "#clear-triage-key-row"]
  ]) {
    const configured = Boolean(dynamicKeysConfigured[provider]);
    $(stateId).textContent = configured ? "Key stored" : "No key";
    $(stateId).className = configured ? "configured" : "";
    $(rowId).classList.toggle("hidden", !configured);
  }
}

async function loadSettings() {
  const response = await fetch("/api/settings");
  if (!response.ok) throw new Error("Unable to load settings");
  const settings = await response.json();
  $("#settings-model").value = settings.model;
  $("#settings-endpoint").value = settings.api_base_url;
  $("#settings-reports").value = settings.reports_dir;
  $("#settings-password").value = settings.archive_password;
  $("#settings-turns").value = settings.max_turns;
  $("#settings-errors").value = settings.max_tool_errors;
  $("#settings-remnux-enabled").checked = settings.remnux_enabled;
  $("#settings-remnux-depth").value = settings.remnux_depth;
  $("#settings-remnux-timeout").value = settings.remnux_timeout;
  const selectedProviders = new Set(settings.dynamic_providers || []);
  for (const provider of ["cape", "anyrun", "joesandbox", "triage"]) {
    $(`#settings-provider-${provider}`).checked = selectedProviders.has(provider);
  }
  $("#settings-cape-url").value = settings.dynamic_urls?.cape || settings.dynamic_url;
  $("#settings-joe-url").value = settings.dynamic_urls?.joesandbox || "";
  $("#settings-triage-url").value = settings.dynamic_urls?.triage || "https://tria.ge/api/v0";
  $("#settings-dynamic-timeout").value = settings.dynamic_timeout;
  $("#settings-dynamic-poll").value = settings.dynamic_poll_interval;
  $("#settings-dynamic-machine").value = settings.dynamic_machine;
  $("#settings-dynamic-package").value = settings.dynamic_package;
  $("#settings-virustotal-enabled").checked = settings.virustotal_enabled;
  $("#settings-virustotal-timeout").value = settings.virustotal_timeout;
  $("#settings-virustotal-poll").value = settings.virustotal_poll_interval;
  $("#settings-abusech-enabled").checked = settings.abusech_enabled;
  $("#settings-unpacme-enabled").checked = settings.unpacme_enabled;
  $("#settings-unpacme-private").checked = settings.unpacme_private;
  $("#settings-unpacme-timeout").value = settings.unpacme_timeout;
  $("#settings-unpacme-poll").value = settings.unpacme_poll_interval;
  for (const [configured, stateId, rowId] of [
    [settings.abusech_auth_key_configured, "#abusech-key-state", "#clear-abusech-key-row"],
    [settings.unpacme_api_key_configured, "#unpacme-key-state", "#clear-unpacme-key-row"]
  ]) {
    $(stateId).textContent = configured ? "Key stored" : "No key";
    $(stateId).className = configured ? "configured" : "";
    $(rowId).classList.toggle("hidden", !configured);
  }
  virustotalKeyConfigured = settings.virustotal_api_key_configured;
  $("#virustotal-key-state").textContent = virustotalKeyConfigured ? "Key stored" : "No key";
  $("#virustotal-key-state").className = virustotalKeyConfigured ? "configured" : "";
  $("#clear-virustotal-key-row").classList.toggle("hidden", !virustotalKeyConfigured);
  dynamicKeysConfigured = settings.dynamic_tokens_configured || {};
  renderSandboxKeyStates();
  $("#settings-verbose").checked = settings.verbose;
  keyConfigured = settings.api_key_configured;
  $("#key-state").textContent = keyConfigured ? "Key stored" : "No key";
  $("#key-state").className = keyConfigured ? "configured" : "";
  $("#clear-key-row").classList.toggle("hidden", !keyConfigured);
}

$("#settings-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = $("#save-settings");
  const message = $("#settings-message");
  button.disabled = true;
  button.querySelector("span").textContent = "Saving…";
  message.classList.add("hidden");
  const payload = {
    model: $("#settings-model").value.trim(),
    api_base_url: $("#settings-endpoint").value.trim(),
    api_key: $("#settings-api-key").value,
    clear_api_key: $("#clear-api-key").checked,
    reports_dir: $("#settings-reports").value.trim(),
    archive_password: $("#settings-password").value,
    max_turns: Number($("#settings-turns").value),
    max_tool_errors: Number($("#settings-errors").value),
    remnux_enabled: $("#settings-remnux-enabled").checked,
    remnux_depth: $("#settings-remnux-depth").value,
    remnux_timeout: Number($("#settings-remnux-timeout").value),
    dynamic_enabled: ["cape", "anyrun", "joesandbox", "triage"].some(provider => $(`#settings-provider-${provider}`).checked),
    dynamic_provider: "cape",
    dynamic_providers: ["cape", "anyrun", "joesandbox", "triage"].filter(provider => $(`#settings-provider-${provider}`).checked),
    dynamic_url: $("#settings-cape-url").value.trim(),
    cape_url: $("#settings-cape-url").value.trim(),
    cape_token: $("#settings-cape-token").value,
    clear_cape_token: $("#clear-cape-token").checked,
    anyrun_api_key: $("#settings-anyrun-key").value,
    clear_anyrun_api_key: $("#clear-anyrun-key").checked,
    joesandbox_url: $("#settings-joe-url").value.trim(),
    joesandbox_api_key: $("#settings-joe-key").value,
    clear_joesandbox_api_key: $("#clear-joe-key").checked,
    triage_url: $("#settings-triage-url").value.trim(),
    triage_api_key: $("#settings-triage-key").value,
    clear_triage_api_key: $("#clear-triage-key").checked,
    dynamic_timeout: Number($("#settings-dynamic-timeout").value),
    dynamic_poll_interval: Number($("#settings-dynamic-poll").value),
    dynamic_machine: $("#settings-dynamic-machine").value.trim(),
    dynamic_package: $("#settings-dynamic-package").value.trim(),
    dynamic_allow_remote: false,
    virustotal_enabled: $("#settings-virustotal-enabled").checked,
    virustotal_api_key: $("#settings-virustotal-api-key").value,
    clear_virustotal_api_key: $("#clear-virustotal-api-key").checked,
    virustotal_upload_missing: false,
    virustotal_allow_upload: false,
    virustotal_timeout: Number($("#settings-virustotal-timeout").value),
    virustotal_poll_interval: Number($("#settings-virustotal-poll").value),
    abusech_enabled: $("#settings-abusech-enabled").checked,
    abusech_auth_key: $("#settings-abusech-key").value,
    clear_abusech_auth_key: $("#clear-abusech-key").checked,
    unpacme_enabled: $("#settings-unpacme-enabled").checked,
    unpacme_api_key: $("#settings-unpacme-key").value,
    clear_unpacme_api_key: $("#clear-unpacme-key").checked,
    unpacme_private: $("#settings-unpacme-private").checked,
    unpacme_timeout: Number($("#settings-unpacme-timeout").value),
    unpacme_poll_interval: Number($("#settings-unpacme-poll").value),
    verbose: $("#settings-verbose").checked
  };
  try {
    const response = await fetch("/api/settings", {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Unable to save settings");
    $("#settings-api-key").value = "";
    $("#settings-cape-token").value = "";
    $("#settings-anyrun-key").value = "";
    $("#settings-joe-key").value = "";
    $("#settings-triage-key").value = "";
    $("#settings-abusech-key").value = "";
    $("#settings-unpacme-key").value = "";
    $("#settings-virustotal-api-key").value = "";
    $("#clear-cape-token").checked = false;
    $("#clear-anyrun-key").checked = false;
    $("#clear-joe-key").checked = false;
    $("#clear-triage-key").checked = false;
    $("#clear-abusech-key").checked = false;
    $("#clear-unpacme-key").checked = false;
    $("#clear-virustotal-api-key").checked = false;
    $("#clear-api-key").checked = false;
    await loadSettings();
    message.textContent = "Settings saved. New CLI and web analyses will use these defaults.";
    message.className = "settings-message success";
  } catch (error) {
    message.textContent = error.message;
    message.className = "settings-message error";
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Save persistent settings";
  }
});

loadSettings().catch(error => {
  const message = $("#settings-message");
  message.textContent = error.message;
  message.className = "settings-message error";
});
