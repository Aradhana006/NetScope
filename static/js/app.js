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
  };

  function formatTimestampIST(isoStr) {
    if (!isoStr) return "—";
    try {
      var d = new Date(isoStr);
      if (isNaN(d.getTime())) return String(isoStr);
      var formatter = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Asia/Kolkata",
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true,
      });
      var formatted = formatter.format(d);
      return formatted.replace(/\b(am|pm)\b/i, function (m) { return m.toUpperCase(); }) + " IST";
    } catch (e) {
      return String(isoStr);
    }
  }

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
      "<button type=\"button\" class=\"icon-btn\" data-action=\"pdf\" data-id=\"" + id + "\" title=\"Export PDF Report\">PDF</button>" +
      "</div>";
  }

  function renderHistoryTables(items) {
    var filter = ($("history-search") && $("history-search").value || "").toLowerCase();
    var rows = items.filter(function (it) {
      return !filter || (it.target || "").toLowerCase().indexOf(filter) >= 0;
    });
    var html = rows.length ? rows.map(function (it) {
      return "<tr><td>" + esc(it.target) + "</td><td>" + esc(formatTimestampIST(it.created_at)) + "</td><td>" +
        statusBadge(it.status) + "</td><td>" + esc(it.health_score != null ? it.health_score + "%" : "—") +
        "</td><td>" + rowActions(it.id) + "</td></tr>";
    }).join("") : "<tr><td colspan=\"5\" class=\"empty-cell\">No matching runs.</td></tr>";
    if ($("history-table-body")) $("history-table-body").innerHTML = html;
    if ($("recent-analyses-body")) {
      var recent = rows.slice(0, 8);
      $("recent-analyses-body").innerHTML = recent.length ? recent.map(function (it) {
        return "<tr><td>" + esc(it.target) + "</td><td>" + esc(formatTimestampIST(it.created_at)) + "</td><td>" +
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



  async function loadSavedAnalysis(id) {
    try {
      var r = await fetch("/api/history/" + encodeURIComponent(id));
      if (r.status === 401) {
        alert("Session expired. Please log in to view saved analysis details.");
        if ($("login-modal")) $("login-modal").classList.remove("hidden");
        return;
      }
      if (!r.ok) {
        alert("Unable to load saved analysis.");
        return;
      }
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
    if (meta) meta.textContent = "Target: " + (data.target || "—") + " · " + formatTimestampIST(data.timestamp);
    if (pdf) {
      pdf.classList.remove("hidden");
      if (data.id != null) {
        pdf.href = "/api/report/" + encodeURIComponent(data.id);
      } else {
        pdf.href = "#";
      }
    }
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

    // --- Chart 1: DNS by record type ---
    var dns = (data && data.dns) || {};
    var dnsCanvas = $("dns-chart");
    var dnsEmpty = $("dns-chart-empty");
    dnsChart = destroyChart(dnsChart);

    var isIpTarget = (data && data.ip_analysis && data.ip_analysis.input_type !== "hostname") || (dns.response_code === "N/A");
    var dnsLabels = [];
    var dnsValues = [];

    if (isIpTarget) {
      if (dnsCanvas) dnsCanvas.classList.add("hidden");
      if (dnsEmpty) {
        dnsEmpty.textContent = "DNS record lookup not applicable for IP addresses.";
        dnsEmpty.classList.remove("hidden");
      }
    } else if (dns.status === "error" || dns.response_code === "NXDOMAIN" || dns.response_code === "TIMEOUT") {
      if (dnsCanvas) dnsCanvas.classList.add("hidden");
      if (dnsEmpty) {
        dnsEmpty.textContent = dns.response_code === "NXDOMAIN"
          ? "DNS resolution failed (NXDOMAIN — domain does not exist)."
          : "DNS resolution failed (" + (dns.response_code || dns.error || "error") + ").";
        dnsEmpty.classList.remove("hidden");
      }
    } else if (dns.query_times_ms) {
      var dnsTypes = ["A", "AAAA", "MX", "NS", "CNAME"];
      dnsTypes.forEach(function (type) {
        var t = dns.query_times_ms[type];
        if (t != null && !isNaN(t)) {
          dnsLabels.push(type);
          dnsValues.push(Number(t));
        }
      });
      if (dnsLabels.length > 0 && dnsCanvas) {
        if (dnsEmpty) dnsEmpty.classList.add("hidden");
        dnsCanvas.classList.remove("hidden");
        dnsChart = new Chart(dnsCanvas, {
          type: "bar",
          data: {
            labels: dnsLabels,
            datasets: [{
              label: "Query time",
              data: dnsValues,
              backgroundColor: "#0d9488",
              borderRadius: 6,
              barThickness: 36,
            }],
          },
          options: Object.assign({}, chartBaseOptions(1.85), { scales: scaleOptions() }),
        });
      } else {
        if (dnsCanvas) dnsCanvas.classList.add("hidden");
        if (dnsEmpty) {
          dnsEmpty.textContent = "No DNS query timings returned.";
          dnsEmpty.classList.remove("hidden");
        }
      }
    } else if (dns.response_time_ms != null && Number(dns.response_time_ms) > 0) {
      if (dnsCanvas) {
        if (dnsEmpty) dnsEmpty.classList.add("hidden");
        dnsCanvas.classList.remove("hidden");
        dnsChart = new Chart(dnsCanvas, {
          type: "bar",
          data: {
            labels: ["Total DNS Lookup"],
            datasets: [{
              label: "Lookup time",
              data: [Number(dns.response_time_ms)],
              backgroundColor: "#0d9488",
              borderRadius: 6,
              barThickness: 48,
            }],
          },
          options: Object.assign({}, chartBaseOptions(1.85), { scales: scaleOptions() }),
        });
      }
    } else {
      if (dnsCanvas) dnsCanvas.classList.add("hidden");
      if (dnsEmpty) {
        dnsEmpty.textContent = "No DNS records resolved.";
        dnsEmpty.classList.remove("hidden");
      }
    }

    // --- Chart 2: Service latency ---
    var timingCanvas = $("timing-chart");
    var timingEmpty = $("timing-chart-empty");
    timingChart = destroyChart(timingChart);

    var serviceLabels = [];
    var serviceValues = [];
    var serviceColors = [];

    if (!isIpTarget && dns.response_time_ms != null && Number(dns.response_time_ms) > 0) {
      serviceLabels.push("DNS");
      serviceValues.push(Number(dns.response_time_ms));
      serviceColors.push("#14b8a6");
    }

    var tcpPorts = (data && data.tcp && data.tcp.ports) || {};
    var p443 = tcpPorts["443"];
    var p80 = tcpPorts["80"];
    if (p443 && p443.state === "open" && p443.latency_ms != null) {
      serviceLabels.push("TCP 443");
      serviceValues.push(Number(p443.latency_ms));
      serviceColors.push("#0d9488");
    } else if (p80 && p80.state === "open" && p80.latency_ms != null) {
      serviceLabels.push("TCP 80");
      serviceValues.push(Number(p80.latency_ms));
      serviceColors.push("#0d9488");
    }

    var httpData = (data && data.http) || {};
    var httpsBlock = httpData.https;
    var httpBlock = httpData.http;
    if (httpsBlock && httpsBlock.response_time_ms != null && Number(httpsBlock.response_time_ms) > 0) {
      var httpsLabel = httpsBlock.status_code ? "HTTPS (" + httpsBlock.status_code + ")" : "HTTPS";
      serviceLabels.push(httpsLabel);
      serviceValues.push(Number(httpsBlock.response_time_ms));
      serviceColors.push("#0f766e");
    } else if (httpBlock && httpBlock.response_time_ms != null && Number(httpBlock.response_time_ms) > 0) {
      var httpLabel = httpBlock.status_code ? "HTTP (" + httpBlock.status_code + ")" : "HTTP";
      serviceLabels.push(httpLabel);
      serviceValues.push(Number(httpBlock.response_time_ms));
      serviceColors.push("#0f766e");
    }

    if (serviceLabels.length > 0 && timingCanvas) {
      if (timingEmpty) timingEmpty.classList.add("hidden");
      timingCanvas.classList.remove("hidden");
      timingChart = new Chart(timingCanvas, {
        type: "bar",
        data: {
          labels: serviceLabels,
          datasets: [{
            data: serviceValues,
            backgroundColor: serviceColors,
            borderRadius: 8,
            barThickness: 42,
          }],
        },
        options: Object.assign({}, chartBaseOptions(1.75), { scales: scaleOptions() }),
      });
    } else {
      if (timingCanvas) timingCanvas.classList.add("hidden");
      if (timingEmpty) {
        timingEmpty.textContent = "No service latency measurements available (services timed out or unreachable).";
        timingEmpty.classList.remove("hidden");
      }
    }

    // --- Chart 3: Ping RTT samples ---
    var conn = (data && data.connectivity) || {};
    var samples = conn.rtt_samples_ms || [];
    var rttCanvas = $("rtt-chart");
    var rttEmpty = $("rtt-chart-empty");
    rttChart = destroyChart(rttChart);

    if (samples && samples.length > 0 && rttCanvas) {
      if (rttEmpty) rttEmpty.classList.add("hidden");
      rttCanvas.classList.remove("hidden");
      rttChart = new Chart(rttCanvas, {
        type: "line",
        data: {
          labels: samples.map(function (_, i) { return "Probe " + (i + 1); }),
          datasets: [{
            label: "RTT",
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
      if (rttCanvas) rttCanvas.classList.add("hidden");
      if (rttEmpty) {
        var loss = conn.packet_loss_percent;
        var rttMsg = "No ping samples received.";
        if (loss != null && loss === 100) {
          rttMsg = "100% packet loss — ICMP echo requests timed out or were blocked.";
        } else if (conn.error) {
          rttMsg = conn.error;
        }
        rttEmpty.textContent = rttMsg;
        rttEmpty.classList.remove("hidden");
      }
    }

    // --- Chart 4: HTTP stack timing ---
    var httpCanvas = $("http-chart");
    var httpEmpty = $("http-chart-empty");
    httpChart = destroyChart(httpChart);

    var httpStackLabels = [];
    var httpStackValues = [];
    var httpStackColors = [];

    if (p443 && p443.state === "open" && p443.latency_ms != null) {
      httpStackLabels.push("TCP 443 Connect");
      httpStackValues.push(Number(p443.latency_ms));
      httpStackColors.push("#0d9488");
    } else if (p80 && p80.state === "open" && p80.latency_ms != null) {
      httpStackLabels.push("TCP 80 Connect");
      httpStackValues.push(Number(p80.latency_ms));
      httpStackColors.push("#0d9488");
    }

    if (httpBlock && httpBlock.response_time_ms != null && Number(httpBlock.response_time_ms) > 0) {
      var hCode = httpBlock.status_code ? "HTTP (" + httpBlock.status_code + ")" : "HTTP Response";
      httpStackLabels.push(hCode);
      httpStackValues.push(Number(httpBlock.response_time_ms));
      httpStackColors.push("#059669");
    }

    if (httpsBlock && httpsBlock.response_time_ms != null && Number(httpsBlock.response_time_ms) > 0) {
      var hsCode = httpsBlock.status_code ? "HTTPS (" + httpsBlock.status_code + ")" : "HTTPS Response";
      httpStackLabels.push(hsCode);
      httpStackValues.push(Number(httpsBlock.response_time_ms));
      httpStackColors.push("#0891b2");
    }

    if (httpStackLabels.length > 0 && httpCanvas) {
      if (httpEmpty) httpEmpty.classList.add("hidden");
      httpCanvas.classList.remove("hidden");
      httpChart = new Chart(httpCanvas, {
        type: "bar",
        data: {
          labels: httpStackLabels,
          datasets: [{
            data: httpStackValues,
            backgroundColor: httpStackColors,
            borderRadius: 8,
            barThickness: 44,
          }],
        },
        options: Object.assign({}, chartBaseOptions(1.75), { scales: scaleOptions() }),
      });
    } else {
      if (httpCanvas) httpCanvas.classList.add("hidden");
      if (httpEmpty) {
        var hErr = (httpsBlock && httpsBlock.error) || (httpBlock && httpBlock.error) || (httpData && httpData.error) || "HTTP/HTTPS service unavailable.";
        httpEmpty.textContent = "No HTTP timing measurements (" + hErr + ").";
        httpEmpty.classList.remove("hidden");
      }
    }

    // --- Doughnut Gauge: Health Score ---
    var diag = (data && data.diagnosis) || {};
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
        return "<option value=\"" + it.id + "\">#" + it.id + " · " + esc(it.target) + " · " + esc(formatTimestampIST(it.created_at)) + "</option>";
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

  var isAnalyzing = false;
  function setAnalyzeState(busy) {
    var btn = $("analyze-btn");
    if (btn) {
      btn.disabled = busy;
      btn.classList.toggle("loading", busy);
    }
    var qForm = $("dashboard-quick-form");
    if (qForm) {
      var qBtn = qForm.querySelector("button[type=\"submit\"]");
      if (qBtn) qBtn.disabled = busy;
    }
  }

  async function analyze(target) {
    if (isAnalyzing) return;
    isAnalyzing = true;
    if ($("form-error")) $("form-error").classList.add("hidden");
    setAnalyzeState(true);
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
      isAnalyzing = false;
      setAnalyzeState(false);
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

  async function downloadPdfById(id) {
    if (!id) return;
    try {
      var resp = await fetch("/api/report/" + encodeURIComponent(id));
      if (resp.status === 401) {
        alert("Login required to download saved reports. Please log in.");
        if ($("login-modal")) $("login-modal").classList.remove("hidden");
        return;
      }
      if (!resp.ok) {
        var errData = await resp.json().catch(function () { return {}; });
        alert(errData.error || "Report not found or access denied.");
        return;
      }
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "netscope-report-" + id + ".pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    } catch (e) {
      alert("Error downloading report.");
    }
  }

  async function exportCurrentPdf(e) {
    if (e && e.preventDefault) e.preventDefault();
    if (!lastAnalysis) {
      alert("No active analysis to export. Please run or select an analysis first.");
      return;
    }
    var btn = $("report-export-btn") || $("pdf-export-btn");
    var origHtml = btn ? btn.innerHTML : "";
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = "<span class=\"btn-spinner\"></span> Generating PDF…";
    }

    try {
      if (lastAnalysis.id != null) {
        await downloadPdfById(lastAnalysis.id);
        return;
      }
      var resp = await fetch("/api/report/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(lastAnalysis),
      });
      if (!resp.ok) {
        var err = await resp.json().catch(function () { return {}; });
        alert(err.error || "Unable to generate PDF report.");
        return;
      }
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = (lastAnalysis.target || "netscope") + "-report.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    } catch (err) {
      alert("Network error while generating PDF report.");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = origHtml;
      }
    }
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
      var viewBtn = e.target.closest("[data-action=\"view\"]");
      if (viewBtn) {
        loadSavedAnalysis(viewBtn.getAttribute("data-id"));
        return;
      }
      var pdfBtn = e.target.closest("[data-action=\"pdf\"]");
      if (pdfBtn) {
        downloadPdfById(pdfBtn.getAttribute("data-id"));
        return;
      }
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
    var reportExport = $("report-export-btn");
    if (reportExport) reportExport.addEventListener("click", exportCurrentPdf);
    var pdfExportBtn = $("pdf-export-btn");
    if (pdfExportBtn) pdfExportBtn.addEventListener("click", exportCurrentPdf);
    var pdfLink = $("pdf-link");
    if (pdfLink) pdfLink.addEventListener("click", function (e) {
      if (!pdfLink.getAttribute("href") || pdfLink.getAttribute("href") === "#") {
        exportCurrentPdf(e);
      }
    });
    var modalClose = $("modal-close");
    if (modalClose) modalClose.addEventListener("click", function () {
      $("login-modal").classList.add("hidden");
    });
    if ($("include-transport")) $("include-transport").addEventListener("change", persistAnalyzeOptions);
    if ($("include-traceroute")) $("include-traceroute").addEventListener("change", persistAnalyzeOptions);
  });
})();
