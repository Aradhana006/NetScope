(function () {
  "use strict";

  var timingChart = null;
  var rttChart = null;
  var dnsChart = null;
  var httpChart = null;
  var healthChart = null;
  var historyCache = [];
  var lastAnalysis = null;
  var isGuest = document.body && document.body.dataset.guest === "true";
  var currentView = "dashboard";

  var viewTitles = {
    dashboard: ["Dashboard", "Welcome back"],
    analyze: ["New Analysis", "Run diagnostics"],
    results: ["Analysis Results", "Layered network view"],
    history: ["History", "Saved analyses"],
    reports: ["Reports", "PDF export"],
  };

  function $(id) { return document.getElementById(id); }

  function switchView(name) {
    if (!viewTitles[name]) return;
    currentView = name;
    document.querySelectorAll(".app-view").forEach(function (el) {
      el.classList.toggle("hidden", el.id !== "view-" + name);
    });
    document.querySelectorAll("#side-nav a[data-view]").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-view") === name);
    });
    var t = viewTitles[name].slice();
    if (isGuest && name === "dashboard") t[1] = "Welcome";
    if ($("page-eyebrow")) $("page-eyebrow").textContent = t[0];
    if ($("page-title")) $("page-title").textContent = t[1];
    if (name === "results") {
      var has = lastAnalysis && $("results-root");
      if ($("results-root")) $("results-root").classList.toggle("hidden", !has);
      if ($("results-empty")) $("results-empty").classList.toggle("hidden", !!has);
    }
  }

  function statusBadge(status) {
    var s = (status || "").toLowerCase();
    if (s === "healthy" || s === "success") return "<span class=\"badge-success\">Success</span>";
    if (s === "degraded") return "<span class=\"badge-warn\">Issue</span>";
    if (s === "unavailable") return "<span class=\"badge-issue\">Issue</span>";
    return "<span class=\"badge-warn\">" + esc(status || "—") + "</span>";
  }

  function rowActions(id) {
    return "<div class=\"row-actions\">" +
      "<button type=\"button\" class=\"icon-btn\" data-action=\"view\" data-id=\"" + id + "\">View</button>" +
      "<a class=\"icon-btn\" href=\"/api/report/" + id + "\">PDF</a>" +
      "</div>";
  }

  function renderHistoryTables(items) {
    var filter = ($("history-search") && $("history-search").value || "").toLowerCase();
    var rows = items.filter(function (it) {
      return !filter || (it.target || "").toLowerCase().indexOf(filter) >= 0;
    });
    var html = rows.length ? rows.map(function (it) {
      return "<tr><td>" + esc(it.target) + "</td><td>" + esc(it.created_at) + "</td><td>" +
        statusBadge(it.status) + "</td><td>" + esc(it.health_score != null ? it.health_score + "%" : "—") +
        "</td><td>" + rowActions(it.id) + "</td></tr>";
    }).join("") : "<tr><td colspan=\"5\" class=\"empty-cell\">No matching runs.</td></tr>";
    if ($("history-table-body")) $("history-table-body").innerHTML = html;
    if ($("recent-analyses-body")) {
      var recent = rows.slice(0, 8);
      $("recent-analyses-body").innerHTML = recent.length ? recent.map(function (it) {
        return "<tr><td>" + esc(it.target) + "</td><td>" + esc(it.created_at) + "</td><td>" +
          statusBadge(it.status) + "</td><td>" + esc(it.health_score != null ? it.health_score + "%" : "—") +
          "</td><td>" + rowActions(it.id) + "</td></tr>";
      }).join("") : "<tr><td colspan=\"5\" class=\"empty-cell\">No analyses yet. Run your first scan above.</td></tr>";
    }
  }

  function renderStatusChips(data) {
    var box = $("status-chips");
    if (!box) return;
    var dns = data.dns || {};
    var ip = data.ip_analysis || {};
    var conn = data.connectivity || {};
    var p443 = ((data.tcp || {}).ports || {})["443"] || {};
    var https = ((data.http || {}).https) || {};
    function chip(title, ok, detail) {
      return "<div class=\"status-chip " + (ok ? "ok" : "warn") + "\"><span class=\"chip-title\">" + esc(title) +
        "</span>" + esc(detail) + "</div>";
    }
    box.innerHTML =
      chip("DNS", dns.status === "success", dns.response_code || dns.status || "—") +
      chip("IP Analysis", ip.status === "success", ip.address_family || ip.status || "—") +
      chip("Connectivity", conn.reachable === true, conn.reachable ? "Reachable" : "Check ICMP") +
      chip("TCP", p443.state === "open", p443.state || "—") +
      chip("HTTP/HTTPS", https.available === true, https.status_code != null ? String(https.status_code) : "—");
  }

  function updateReportPreview(data) {
    if (!data) return;
    var diag = data.diagnosis || {};
    if ($("report-meta")) $("report-meta").textContent = (data.target || "—") + " · " + (data.timestamp || "");
    if ($("report-score")) $("report-score").textContent = "Health " + (diag.health_score != null ? diag.health_score + "%" : "—");
    if ($("report-summary")) {
      $("report-summary").textContent = diag.status
        ? "Overall status: " + diag.status + ". " + ((diag.suggestions && diag.suggestions[0]) || "See full analysis for details.")
        : "Diagnostic summary unavailable.";
    }
    var dl = $("report-download-link");
    var ex = $("report-export-btn");
    if (dl) {
      if (data.id) { dl.href = "/api/report/" + data.id; dl.classList.remove("hidden"); }
      else dl.classList.add("hidden");
    }
    if (ex) ex.classList.toggle("hidden", !lastAnalysis);
  }

  async function loadSavedAnalysis(id) {
    try {
      var r = await fetch("/api/history/" + encodeURIComponent(id));
      if (!r.ok) return;
      var data = await r.json();
      lastAnalysis = data;
      showResults(data);
    } catch (e) {}
  }

  function showResults(data) {
    $("results-root").classList.remove("hidden");
    if ($("results-empty")) $("results-empty").classList.add("hidden");
    if ($("results-target-title")) $("results-target-title").textContent = data.target || "—";
    renderAll(data);
    updateReportPreview(data);
    switchView("results");
    activateResultTab("overview");
  }
  function esc(t) { var d = document.createElement("div"); d.textContent = t == null ? "" : String(t); return d.innerHTML; }

  async function checkHealth() {
    try {
      await fetch("/api/health");
    } catch (e) {}
  }

  function formatMs(v) { return v == null ? "—" : Number(v).toFixed(1) + " ms"; }

  function renderHealth(data) {
    var diag = data.diagnosis || {};
    var score = $("health-score");
    var status = $("health-status");
    var meta = $("health-meta");
    var pdf = $("pdf-link");
    if (score) {
      score.textContent = diag.health_score != null ? diag.health_score : "—";
      if (diag.health_score != null) {
        var s = Number(diag.health_score);
        score.style.borderColor = s >= 80 ? "#059669" : s >= 50 ? "#d97706" : "#dc2626";
      }
    }
    if (status) status.textContent = diag.status || "Pending";
    if (meta) meta.textContent = "Target: " + (data.target || "—") + " · " + (data.timestamp || "");
    var exportBtn = $("pdf-export-btn");
    if (pdf) {
      if (data.id) {
        pdf.href = "/api/report/" + data.id;
        pdf.classList.remove("hidden");
      } else {
        pdf.classList.add("hidden");
      }
    }
    if (exportBtn) exportBtn.classList.toggle("hidden", !lastAnalysis);
  }

  async function loadStats() {
    if (isGuest) return;
    try {
      var r = await fetch("/api/stats");
      if (!r.ok) return;
      var s = await r.json();
      if ($("stat-total")) $("stat-total").textContent = s.total_analyses;
      if ($("stat-reports")) $("stat-reports").textContent = s.reports_saved != null ? s.reports_saved : s.total_analyses;
      if ($("stat-week")) $("stat-week").textContent = s.this_week != null ? s.this_week : "0";
      if ($("stat-issues")) $("stat-issues").textContent = s.issues_found;
    } catch (e) {}
  }

  async function exportCurrentPdf() {
    if (!lastAnalysis) return;
    var r = await fetch("/api/report/export", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/pdf" },
      body: JSON.stringify(lastAnalysis),
    });
    if (!r.ok) return;
    var blob = await r.blob();
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "netscope-report.pdf";
    a.click();
    URL.revokeObjectURL(url);
  }

  function statusClass(ok, warn) {
    if (ok) return "status-pass";
    if (warn) return "status-warn";
    return "status-fail";
  }

  function findingResultLabel(result) {
    var map = {
      passed: "Passed",
      warning: "Warning",
      failed: "Failed",
      inconclusive: "Inconclusive",
      skipped: "Skipped",
    };
    return map[result] || result || "—";
  }

  function findingResultClass(result) {
    if (result === "passed") return "status-pass";
    if (result === "warning") return "status-warn";
    if (result === "failed") return "status-fail";
    if (result === "inconclusive") return "status-inconclusive";
    if (result === "skipped") return "status-skipped";
    return "status-warn";
  }

  function fallbackFindings(data) {
    var dns = data.dns || {};
    var conn = data.connectivity || {};
    var p443 = ((data.tcp || {}).ports || {})["443"] || {};
    var https = ((data.http || {}).https) || {};
    return [
      {
        result: dns.status === "success" ? "passed" : "warning",
        check: "DNS",
        evidence: dns.response_code || dns.status || "—",
        likely_cause: "See DNS records tab.",
        next_step: "Review DNS section for record details.",
      },
      {
        result: conn.reachable ? "passed" : "warning",
        check: "ICMP / Ping",
        evidence: "RTT " + formatMs(conn.average_rtt_ms) + ", loss " + (conn.packet_loss_percent != null ? conn.packet_loss_percent + "%" : "—"),
        likely_cause: "ICMP may be blocked on some networks.",
        next_step: "Compare with TCP/HTTPS findings.",
      },
      {
        result: p443.state === "open" ? "passed" : "warning",
        check: "TCP 443",
        evidence: p443.state || "—",
        likely_cause: "—",
        next_step: "Check Connectivity tab.",
      },
      {
        result: https.available ? "passed" : "warning",
        check: "HTTPS",
        evidence: https.status_code != null ? String(https.status_code) : "—",
        likely_cause: "—",
        next_step: "Check Connectivity tab.",
      },
    ];
  }

  function renderFindingsTable(tbodyId, rows) {
    var body = $(tbodyId);
    if (!body) return;
    body.innerHTML = rows.map(function (f) {
      var cls = findingResultClass(f.result);
      var label = findingResultLabel(f.result);
      return "<tr><td><span class=\"chip " + cls + "\">" + esc(label) + "</span></td><td>" + esc(f.check) +
        "</td><td>" + esc(f.evidence) + "</td><td>" + esc(f.likely_cause) + "</td><td>" + esc(f.next_step) + "</td></tr>";
    }).join("");
  }

  function renderFindings(data) {
    var diag = data.diagnosis || {};
    var rows = (diag.findings && diag.findings.length) ? diag.findings : fallbackFindings(data);
    renderFindingsTable("findings-table-body", rows);
    renderFindingsTable("findings-table-body-diagnosis", rows);
  }

  function dnsNote(note, hasValues, code) {
    if (note) return note;
    return hasValues ? "Record returned (" + (code || "NOERROR") + ")" : "No records of this type (NOERROR).";
  }

  function renderDns(dns) {
    dns = dns || {};
    var badge = $("dns-rcode-badge");
    if (badge) { badge.textContent = dns.response_code || "—"; badge.className = "chip chip-ok"; }
    if ($("dns-meta")) $("dns-meta").textContent = dns.error || ("Lookup " + formatMs(dns.response_time_ms));
    var tbody = $("dns-table-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    ["A", "AAAA", "MX", "NS", "CNAME"].forEach(function (type) {
      var values = (dns.records || {})[type] || [];
      var ttl = (dns.ttls || {})[type];
      var note = dnsNote((dns.errors || {})[type], values.length > 0, dns.response_code);
      if (!values.length) {
        tbody.innerHTML += "<tr><td><span class=\"type-pill\">" + type + "</span></td><td>—</td><td>" + esc(ttl != null ? ttl : "—") + "</td><td>" + esc(note) + "</td></tr>";
        return;
      }
      values.forEach(function (v) {
        tbody.innerHTML += "<tr><td><span class=\"type-pill\">" + type + "</span></td><td class=\"record-value\">" + esc(v) + "</td><td>" + esc(ttl != null ? ttl : "—") + "</td><td>" + esc(note) + "</td></tr>";
      });
    });
  }

  function renderIp(ip) {
    var grid = $("ip-grid");
    if (!grid) return;
    ip = ip || {};
    grid.innerHTML =
      card("Input", ip.input_type) + card("IPv4", ip.ipv4_available ? "Available" : "No") +
      card("IPv6", ip.ipv6_available ? "Available" : "No") + card("Family", ip.address_family);
    (ip.ipv4_addresses || []).slice(0, 6).forEach(function (a) { grid.innerHTML += card("IPv4", a); });
    (ip.ipv6_addresses || []).slice(0, 6).forEach(function (a) { grid.innerHTML += card("IPv6", a); });
  }
  function card(k, v) { return "<div class=\"metric-card\"><p class=\"k\">" + esc(k) + "</p><p class=\"v\">" + esc(v) + "</p></div>"; }

  function renderNetwork(data) {
    var grid = $("network-grid");
    if (!grid) return;
    var c = data.connectivity || {};
    var t = data.tcp || {};
    var h = data.http || {};
    grid.innerHTML =
      card("Ping reachable", c.reachable === true ? "Yes" : c.reachable === false ? "No" : "—") +
      card("Packet loss", c.packet_loss_percent != null ? c.packet_loss_percent + "%" : "—") +
      card("HTTPS", ((h.https || {}).status_code) || "—") +
      card("HTTP", ((h.http || {}).status_code) || "—");
  }

  function renderTransport(block) {
    var section = $("dns-transport-section");
    var grid = $("transport-grid");
    if (!section || !grid) return;
    if (!block || block.status === "skipped") { section.classList.add("hidden"); return; }
    section.classList.remove("hidden");
    var u = block.udp || {};
    var t = block.tcp || {};
    grid.innerHTML =
      card("UDP time", formatMs(u.response_time_ms)) + card("UDP code", u.response_code || u.error || "—") +
      card("TCP time", formatMs(t.response_time_ms)) + card("TCP code", t.response_code || t.error || "—");
  }

  function renderTraceroute(tr) {
    var section = $("traceroute-section");
    var body = $("traceroute-body");
    if (!section || !body) return;
    if (!tr || !tr.hops || !tr.hops.length) { section.classList.add("hidden"); return; }
    section.classList.remove("hidden");
    body.innerHTML = tr.hops.map(function (hop) {
      return "<tr><td>" + esc(hop.hop) + "</td><td class=\"record-value\">" + esc(hop.address) + "</td><td>" + esc(hop.avg_rtt_ms != null ? hop.avg_rtt_ms : (hop.rtt_ms || []).join(", ")) + "</td></tr>";
    }).join("");
  }

  function renderInsights(diag) {
    var acc = $("insights-accordion");
    if (!acc) return;
    var items = (diag && diag.insights) || [];
    if (!items.length && diag && diag.suggestions) {
      items = diag.suggestions.map(function (s) {
        return { issue: "Observation", evidence: s, likely_cause: "See measurements above.", next_step: "Review related check in summary table." };
      });
    }
    acc.innerHTML = items.map(function (it, i) {
      return "<details" + (i === 0 ? " open" : "") + "><summary>" + esc(it.issue) + "</summary>" +
        "<p><strong>Evidence:</strong> " + esc(it.evidence) + "</p>" +
        "<p><strong>Likely cause:</strong> " + esc(it.likely_cause) + "</p>" +
        "<p><strong>Next step:</strong> " + esc(it.next_step) + "</p></details>";
    }).join("");
  }

  function destroyChart(c) { if (c) c.destroy(); return null; }

  function chartTickColor() { return "#64748b"; }
  function chartGridColor() { return "rgba(148,163,184,.25)"; }
  function chartBaseOptions(aspect) {
    return {
      responsive: true,
      maintainAspectRatio: true,
      aspectRatio: aspect || 1.85,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#1e293b",
          titleFont: { size: 14, weight: "600" },
          bodyFont: { size: 13 },
          padding: 10,
          cornerRadius: 8,
        },
      },
    };
  }
  function scaleOptions() {
    return {
      x: { grid: { color: chartGridColor() }, ticks: { color: chartTickColor(), font: { size: 13, weight: "600" } } },
      y: { beginAtZero: true, grid: { color: chartGridColor() }, ticks: { color: chartTickColor(), font: { size: 13 } }, title: { display: true, text: "ms", color: chartTickColor(), font: { size: 12 } } },
    };
  }

  function renderCharts(data) {
    if (typeof Chart === "undefined") return;
    Chart.defaults.font.family = "'Plus Jakarta Sans', system-ui, sans-serif";
    Chart.defaults.font.size = 14;

    var dns = data.dns || {};
    var dnsTypes = ["A", "AAAA", "MX", "NS", "CNAME"];
    var dnsLabels = [];
    var dnsValues = [];
    var baseDns = dns.response_time_ms;
    dnsTypes.forEach(function (type) {
      var rec = (dns.records || {})[type] || [];
      if (rec.length && baseDns != null) {
        dnsLabels.push(type);
        dnsValues.push(Number(baseDns));
      }
    });
    var dnsCanvas = $("dns-chart");
    if (dnsCanvas) {
      dnsChart = destroyChart(dnsChart);
      if (dnsLabels.length) {
        dnsChart = new Chart(dnsCanvas, {
          type: "line",
          data: {
            labels: dnsLabels,
            datasets: [{
              label: "Response time",
              data: dnsValues,
              borderColor: "#0d9488",
              backgroundColor: "rgba(13,148,136,.12)",
              borderWidth: 3,
              pointRadius: 5,
              pointBackgroundColor: "#0f766e",
              tension: 0.35,
              fill: true,
            }],
          },
          options: Object.assign({}, chartBaseOptions(2), { scales: scaleOptions() }),
        });
      }
    }

    var labels = [], values = [];
    if (baseDns != null) { labels.push("DNS"); values.push(baseDns); }
    var p443 = ((data.tcp || {}).ports || {})["443"];
    if (p443 && p443.latency_ms != null) { labels.push("TCP 443"); values.push(p443.latency_ms); }
    var https = (data.http || {}).https;
    if (https && https.response_time_ms != null) { labels.push("HTTPS"); values.push(https.response_time_ms); }
    var canvas = $("timing-chart");
    if (canvas) {
      timingChart = destroyChart(timingChart);
      if (labels.length) {
        timingChart = new Chart(canvas, {
          type: "bar",
          data: {
            labels: labels,
            datasets: [{
              data: values,
              backgroundColor: ["#14b8a6", "#0d9488", "#0f766e"],
              borderRadius: 8,
              barThickness: 42,
            }],
          },
          options: Object.assign({}, chartBaseOptions(1.75), { scales: scaleOptions() }),
        });
      }
    }

    var samples = (data.connectivity || {}).rtt_samples_ms;
    var rttCanvas = $("rtt-chart");
    var rttEmpty = $("rtt-chart-empty");
    if (rttCanvas) {
      rttChart = destroyChart(rttChart);
      if (samples && samples.length) {
        if (rttEmpty) rttEmpty.classList.add("hidden");
        rttCanvas.classList.remove("hidden");
        rttChart = new Chart(rttCanvas, {
          type: "line",
          data: {
            labels: samples.map(function (_, i) { return "Probe " + (i + 1); }),
            datasets: [{
              data: samples,
              borderColor: "#059669",
              backgroundColor: "rgba(5,150,105,.12)",
              borderWidth: 2.5,
              pointRadius: 4,
              tension: 0.3,
              fill: true,
            }],
          },
          options: Object.assign({}, chartBaseOptions(2), { scales: scaleOptions() }),
        });
      } else {
        rttCanvas.classList.add("hidden");
        if (rttEmpty) rttEmpty.classList.remove("hidden");
      }
    }

    var httpLabels = [];
    var httpValues = [];
    if (baseDns != null) { httpLabels.push("DNS"); httpValues.push(baseDns); }
    if (p443 && p443.latency_ms != null) { httpLabels.push("Connect"); httpValues.push(p443.latency_ms); }
    if (https && https.response_time_ms != null) {
      httpLabels.push("Response");
      httpValues.push(https.response_time_ms);
    }
    var httpCanvas = $("http-chart");
    if (httpCanvas) {
      httpChart = destroyChart(httpChart);
      if (httpLabels.length) {
        httpChart = new Chart(httpCanvas, {
          type: "bar",
          data: {
            labels: httpLabels,
            datasets: [{
              data: httpValues,
              backgroundColor: ["#0d9488", "#059669", "#0891b2"],
              borderRadius: 8,
              barThickness: 48,
            }],
          },
          options: Object.assign({}, chartBaseOptions(1.75), { scales: scaleOptions() }),
        });
      }
    }

    var diag = data.diagnosis || {};
    var healthCanvas = $("health-chart");
    if (healthCanvas && diag.health_score != null) {
      healthChart = destroyChart(healthChart);
      var hs = Math.max(0, Math.min(100, Number(diag.health_score)));
      var rest = 100 - hs;
      var ringColor = hs >= 80 ? "#059669" : hs >= 50 ? "#d97706" : "#dc2626";
      healthChart = new Chart(healthCanvas, {
        type: "doughnut",
        data: {
          labels: ["Score", "Remaining"],
          datasets: [{
            data: [hs, rest],
            backgroundColor: [ringColor, "#e2e8f0"],
            borderWidth: 0,
            hoverOffset: 0,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: true,
          aspectRatio: 1,
          cutout: "78%",
          plugins: { legend: { display: false }, tooltip: { enabled: false } },
        },
      });
    } else if (healthCanvas) {
      healthChart = destroyChart(healthChart);
    }
  }

  async function loadHistorySelects() {
    try {
      var r = await fetch("/api/history?limit=30");
      if (!r.ok) return;
      var items = (await r.json()).items || [];
      historyCache = items;
      var base = $("compare-baseline");
      var cur = $("compare-current");
      var list = $("history-list");
      if (!base || !cur) return;
      var opts = "<option value=\"\">Select run</option>" + items.map(function (it) {
        return "<option value=\"" + it.id + "\">#" + it.id + " · " + esc(it.target) + " · " + esc(it.created_at) + "</option>";
      }).join("");
      base.innerHTML = opts;
      cur.innerHTML = opts;
      renderHistoryTables(items);
    } catch (e) {
      if (isGuest && $("history-table-body")) {
        $("history-table-body").innerHTML = "<tr><td colspan=\"5\" class=\"empty-cell\">Log in to view saved history.</td></tr>";
      }
    }
  }

  function activateResultTab(name) {
    document.querySelectorAll(".result-tab").forEach(function (btn) {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === name);
    });
    document.querySelectorAll(".tab-panel").forEach(function (p) {
      p.classList.toggle("hidden", p.getAttribute("data-panel") !== name);
      p.classList.toggle("active", p.getAttribute("data-panel") === name);
    });
  }

  async function runCompare() {
    var b = $("compare-baseline") && $("compare-baseline").value;
    var c = $("compare-current") && $("compare-current").value;
    var box = $("compare-results");
    if (!b || !c || !box) return;
    var r = await fetch("/api/compare?baseline_id=" + encodeURIComponent(b) + "&current_id=" + encodeURIComponent(c));
    var data = await r.json();
    if (!r.ok) { box.textContent = data.error || "Compare failed"; box.classList.remove("hidden"); return; }
    var m = data.metrics || {};
    box.innerHTML = "<p><strong>DNS Δ:</strong> " + esc(m.dns_response_time_ms && m.dns_response_time_ms.delta) + " ms · " +
      "<strong>Loss Δ:</strong> " + esc(m.packet_loss_percent && m.packet_loss_percent.delta) + " · " +
      "<strong>HTTPS Δ:</strong> " + esc(m.https_response_time_ms && m.https_response_time_ms.delta) + " ms</p>" +
      "<ul>" + (data.summary || []).map(function (s) { return "<li>" + esc(s) + "</li>"; }).join("") + "</ul>";
    box.classList.remove("hidden");
  }

  function renderAll(data) {
    renderStatusChips(data);
    renderHealth(data);
    renderFindings(data);
    renderDns(data.dns);
    renderIp(data.ip_analysis);
    renderNetwork(data);
    renderTransport(data.dns_transport);
    renderTraceroute(data.traceroute);
    renderCharts(data);
    renderInsights(data.diagnosis);
    loadHistorySelects();
  }

  async function analyze(target) {
    $("form-error").classList.add("hidden");
    $("analyze-btn").disabled = true;
    $("analyze-btn").classList.add("loading");
    var body = {
      target: target,
      include_dns_transport: $("include-transport") && $("include-transport").checked,
      include_traceroute: $("include-traceroute") && $("include-traceroute").checked,
    };
    try {
      var r = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json" }, body: JSON.stringify(body) });
      var data = await r.json();
      if (!r.ok) {
        $("form-error").textContent = data.error || "Failed";
        $("form-error").classList.remove("hidden");
        return;
      }
      lastAnalysis = data;
      if (data.requires_login_to_save) {
        var modal = $("login-modal");
        if (modal) modal.classList.remove("hidden");
      }
      showResults(data);
      loadStats();
    } catch (e) {
      $("form-error").textContent = "Server unreachable";
      $("form-error").classList.remove("hidden");
    } finally {
      $("analyze-btn").disabled = false;
      $("analyze-btn").classList.remove("loading");
    }
  }

  function bindAnalyzeForm(form, inputId) {
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var t = $(inputId).value.trim();
      if (t) {
        if ($("target-input") && inputId !== "target-input") $("target-input").value = t;
        analyze(t);
      }
    });
  }

  function applyPreferences() {
    try {
      var tr = localStorage.getItem("netscope_pref_transport");
      var route = localStorage.getItem("netscope_pref_traceroute");
      if ($("include-transport") && tr != null) $("include-transport").checked = tr === "1";
      if ($("include-traceroute") && route != null) $("include-traceroute").checked = route === "1";
    } catch (e) {}
  }

  function persistAnalyzeOptions() {
    try {
      if ($("include-transport")) localStorage.setItem("netscope_pref_transport", $("include-transport").checked ? "1" : "0");
      if ($("include-traceroute")) localStorage.setItem("netscope_pref_traceroute", $("include-traceroute").checked ? "1" : "0");
    } catch (e) {}
  }

  document.addEventListener("DOMContentLoaded", function () {
    checkHealth();
    loadHistorySelects();
    loadStats();
    applyPreferences();
    switchView("dashboard");
    bindAnalyzeForm($("analyze-form"), "target-input");
    bindAnalyzeForm($("dashboard-quick-form"), "dashboard-target-input");

    document.querySelectorAll("#side-nav a[data-view]").forEach(function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        switchView(a.getAttribute("data-view"));
      });
    });
    document.querySelectorAll("[data-view-jump]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchView(btn.getAttribute("data-view-jump"));
      });
    });
    document.querySelectorAll(".result-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        activateResultTab(btn.getAttribute("data-tab"));
      });
    });
    document.body.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-action=\"view\"]");
      if (btn) loadSavedAnalysis(btn.getAttribute("data-id"));
    });
    if ($("history-search")) {
      $("history-search").addEventListener("input", function () {
        renderHistoryTables(historyCache);
      });
    }
    var compareBtn = $("compare-btn");
    if (compareBtn) compareBtn.addEventListener("click", runCompare);
    var logoutBtn = $("logout-btn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", async function () {
        await fetch("/api/auth/logout", { method: "POST" });
        window.location.href = "/";
      });
    }
    var exportBtn = $("pdf-export-btn");
    if (exportBtn) exportBtn.addEventListener("click", exportCurrentPdf);
    var reportExport = $("report-export-btn");
    if (reportExport) reportExport.addEventListener("click", exportCurrentPdf);
    var modalClose = $("modal-close");
    if (modalClose) modalClose.addEventListener("click", function () {
      $("login-modal").classList.add("hidden");
    });
    if ($("include-transport")) $("include-transport").addEventListener("change", persistAnalyzeOptions);
    if ($("include-traceroute")) $("include-traceroute").addEventListener("change", persistAnalyzeOptions);
  });
})();
