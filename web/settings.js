const $ = selector => document.querySelector(selector);
let keyConfigured = false;

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
