/**
 * NetScope dashboard — analyze target, render DNS and module status.
 */

(function () {
  "use strict";

  const statusEl = document.getElementById("backend-status");
  const messageEl = document.getElementById("backend-message");
  const form = document.getElementById("analyze-form");
  const targetInput = document.getElementById("target-input");
  const analyzeBtn = document.getElementById("analyze-btn");
  const formError = document.getElementById("form-error");
  const loadingPanel = document.getElementById("loading-panel");
  const resultsSection = document.getElementById("results-section");
  const resultsEmpty = document.getElementById("results-empty");
  const summaryGrid = document.getElementById("summary-grid");
  const dnsMeta = document.getElementById("dns-meta");
  const dnsTableBody = document.getElementById("dns-table-body");
  const dnsEmpty = document.getElementById("dns-empty");
  const moduleList = document.getElementById("module-status-list");

  function setBackendStatus(state, label, message) {
    if (!statusEl) return;
    statusEl.className = "status-pill " + state;
    statusEl.textContent = label;
    if (messageEl) {
      messageEl.textContent = message || "";
    }
  }

  function showFormError(text) {
    if (!formError) return;
    if (text) {
      formError.textContent = text;
      formError.classList.remove("hidden");
    } else {
      formError.textContent = "";
      formError.classList.add("hidden");
    }
  }

  function setLoading(isLoading) {
    if (loadingPanel) loadingPanel.classList.toggle("hidden", !isLoading);
    if (analyzeBtn) analyzeBtn.disabled = isLoading;
    if (targetInput) targetInput.disabled = isLoading;
  }

  function badgeClass(status) {
    const map = {
      success: "badge-success",
      error: "badge-error",
      skipped: "badge-skipped",
      partial: "badge-partial",
      pending: "badge-pending",
    };
    return "badge " + (map[status] || "badge-pending");
  }

  function formatMs(ms) {
    if (ms === null || ms === undefined) return "—";
    return Number(ms).toFixed(1) + " ms";
  }

  function renderSummary(data) {
    if (!summaryGrid) return;
    const dns = data.dns || {};
    const diagnosis = data.diagnosis || {};

    summaryGrid.innerHTML = "";

    const cards = [
      { label: "Target", value: data.target || "—" },
      { label: "DNS status", value: dns.status || "—" },
      { label: "DNS lookup time", value: formatMs(dns.response_time_ms) },
      {
        label: "Health (preview)",
        value: diagnosis.status || "Pending",
      },
    ];

    cards.forEach(function (card) {
      const el = document.createElement("div");
      el.className = "summary-card";
      el.innerHTML =
        '<p class="label">' +
        card.label +
        '</p><p class="value">' +
        escapeHtml(String(card.value)) +
        "</p>";
      summaryGrid.appendChild(el);
    });
  }

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function renderDnsTable(dns) {
    if (!dnsTableBody) return;
    dnsTableBody.innerHTML = "";

    const records = dns.records || {};
    const types = ["A", "AAAA", "MX", "NS", "CNAME"];
    let rowCount = 0;

    types.forEach(function (type) {
      const values = records[type] || [];
      if (values.length === 0) {
        return;
      }
      values.forEach(function (value) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          '<td class="type-cell">' +
          escapeHtml(type) +
          "</td><td>" +
          escapeHtml(value) +
          "</td>";
        dnsTableBody.appendChild(tr);
        rowCount += 1;
      });
    });

    if (dnsMeta) {
      let meta = "Lookup status: " + (dns.status || "unknown");
      if (dns.error) {
        meta += " — " + dns.error;
      }
      dnsMeta.textContent = meta;
    }

    if (dnsEmpty) {
      dnsEmpty.classList.toggle("hidden", rowCount > 0);
    }
  }

  function renderModuleStatus(data) {
    if (!moduleList) return;
    moduleList.innerHTML = "";

    const items = [
      { name: "Connectivity (ping)", status: (data.connectivity || {}).status, note: (data.connectivity || {}).error },
      { name: "TCP ports", status: (data.tcp || {}).status, note: (data.tcp || {}).error },
      { name: "HTTP / HTTPS", status: (data.http || {}).status, note: (data.http || {}).error },
      { name: "Diagnosis engine", status: "pending", note: (data.diagnosis || {}).suggestions?.[0] },
    ];

    items.forEach(function (item) {
      const li = document.createElement("li");
      const status = item.status || "pending";
      li.innerHTML =
        "<span>" +
        escapeHtml(item.name) +
        (item.note ? '<br /><span class="muted">' + escapeHtml(item.note) + "</span>" : "") +
        '</span><span class="' +
        badgeClass(status) +
        '">' +
        escapeHtml(status) +
        "</span>";
      moduleList.appendChild(li);
    });
  }

  function showResults(data) {
    if (resultsEmpty) resultsEmpty.classList.add("hidden");
    if (resultsSection) resultsSection.classList.remove("hidden");
    renderSummary(data);
    renderDnsTable(data.dns || {});
    renderModuleStatus(data);
  }

  async function checkBackendHealth() {
    setBackendStatus("status-loading", "Checking backend…", "");

    try {
      const response = await fetch("/api/health", {
        headers: { Accept: "application/json" },
      });

      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }

      const data = await response.json();
      setBackendStatus(
        "status-ok",
        "Backend online",
        data.message || "Service: " + (data.service || "NetScope")
      );
    } catch (err) {
      setBackendStatus(
        "status-error",
        "Backend unreachable",
        "Start Flask with: python app.py — " + (err.message || "Unknown error")
      );
    }
  }

  async function runAnalysis(target) {
    showFormError("");
    setLoading(true);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ target: target }),
      });

      const data = await response.json();

      if (!response.ok) {
        showFormError(data.error || "Analysis request failed.");
        return;
      }

      showResults(data);
    } catch (err) {
      showFormError("Could not reach the server. " + (err.message || ""));
    } finally {
      setLoading(false);
    }
  }

  if (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      const target = targetInput ? targetInput.value.trim() : "";
      if (!target) {
        showFormError("Please enter a domain name or IP address.");
        return;
      }
      runAnalysis(target);
    });
  }

  document.addEventListener("DOMContentLoaded", checkBackendHealth);
})();
