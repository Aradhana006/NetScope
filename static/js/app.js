/**
 * NetScope dashboard — API client, rendering, and Chart.js visualizations.
 */

(function () {
  "use strict";

  var timingChart = null;
  var rttChart = null;

  var TYPE_CLASS = {
    A: "type-a",
    AAAA: "type-aaaa",
    MX: "type-mx",
    NS: "type-ns",
    CNAME: "type-cname",
  };

  function $(id) {
    return document.getElementById(id);
  }

  function escapeHtml(text) {
    var div = document.createElement("div");
    div.textContent = text == null ? "" : String(text);
    return div.innerHTML;
  }

  function badgeClass(status) {
    var map = {
      success: "badge-success",
      error: "badge-error",
      skipped: "badge-skipped",
      partial: "badge-partial",
      pending: "badge-pending",
    };
    return "badge " + (map[status] || "badge-pending");
  }

  function friendlyStatus(status) {
    if (status === "skipped") return "Upcoming";
    if (status === "partial") return "Partial";
    if (status === "success") return "OK";
    if (status === "error") return "Failed";
    return "Pending";
  }

  function formatMs(ms) {
    if (ms === null || ms === undefined) return "—";
    return Number(ms).toFixed(1) + " ms";
  }

  /* --- Backend health --- */

  function setBackendStatus(state, label) {
    var dot = $("backend-dot");
    var text = $("backend-status-text");
    if (dot) dot.className = "status-dot status-dot-" + state;
    if (text) text.textContent = label;
  }

  async function checkBackendHealth() {
    setBackendStatus("loading", "Connecting…");
    try {
      var response = await fetch("/api/health", { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(String(response.status));
      await response.json();
      setBackendStatus("ok", "Server ready");
    } catch (e) {
      setBackendStatus("error", "Offline");
    }
  }

  /* --- Form / analyze --- */

  function showFormError(message) {
    var el = $("form-error");
    if (!el) return;
    if (message) {
      el.textContent = message;
      el.classList.remove("hidden");
    } else {
      el.textContent = "";
      el.classList.add("hidden");
    }
  }

  function setLoading(loading) {
    var btn = $("analyze-btn");
    var input = $("target-input");
    if (btn) {
      btn.disabled = loading;
      btn.classList.toggle("loading", loading);
    }
    if (input) input.disabled = loading;
  }

  async function runAnalysis(target) {
    showFormError("");
    setLoading(true);
    var includeTransport = $("include-transport") && $("include-transport").checked;
    var body = { target: target };
    if (includeTransport) body.include_dns_transport = true;

    try {
      var response = await fetch("/api/analyze", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      var data = await response.json();
      if (!response.ok) {
        showFormError(data.error || "Request failed.");
        return;
      }
      renderAll(data);
    } catch (err) {
      showFormError("Could not reach server.");
    } finally {
      setLoading(false);
    }
  }

  /* --- Rendering --- */

  function showResultsNav() {
    document.querySelectorAll(".nav-results").forEach(function (link) {
      link.classList.remove("hidden");
    });
    var root = $("results-root");
    if (root) root.classList.remove("hidden");
  }

  function renderSummary(data) {
    var grid = $("summary-grid");
    if (!grid) return;
    var dns = data.dns || {};
    var ip = data.ip_analysis || {};
    var diag = data.diagnosis || {};

    var cards = [
      { label: "Target", value: data.target },
      { label: "DNS code", value: dns.response_code || "—" },
      { label: "Lookup", value: formatMs(dns.response_time_ms) },
      { label: "Address family", value: ip.address_family || "—" },
      { label: "Health", value: diag.status || "Pending" },
    ];

    grid.innerHTML = cards
      .map(function (c) {
        return (
          '<div class="summary-card animate-in"><p class="label">' +
          escapeHtml(c.label) +
          '</p><p class="value">' +
          escapeHtml(c.value) +
          "</p></div>"
        );
      })
      .join("");
  }

  function renderDns(dns) {
    dns = dns || {};
    var badge = $("dns-rcode-badge");
    if (badge) {
      badge.className = badgeClass(dns.status || "pending");
      badge.textContent = dns.response_code || "—";
    }

    var meta = $("dns-meta");
    if (meta) {
      var parts = [];
      if (dns.error) parts.push(dns.error);
      else parts.push("Overall status: " + friendlyStatus(dns.status));
      meta.textContent = parts.join(" ");
    }

    var tbody = $("dns-table-body");
    var empty = $("dns-empty");
    if (!tbody) return;
    tbody.innerHTML = "";

    var types = ["A", "AAAA", "MX", "NS", "CNAME"];
    var rows = 0;
    var ttls = dns.ttls || {};
    var errors = dns.errors || {};
    var records = dns.records || {};

    types.forEach(function (type) {
      var values = records[type] || [];
      var ttl = ttls[type];
      var note = errors[type];
      if (values.length === 0 && !note) {
        note = "No records";
      }
      if (values.length === 0) {
        var tr0 = document.createElement("tr");
        tr0.innerHTML =
          '<td><span class="type-pill ' +
          (TYPE_CLASS[type] || "type-a") +
          '">' +
          escapeHtml(type) +
          "</span></td><td class=\"muted\">—</td><td>" +
          (ttl != null ? escapeHtml(ttl) : "—") +
          '</td><td class="muted">' +
          escapeHtml(note || "") +
          "</td>";
        tbody.appendChild(tr0);
        rows += 1;
        return;
      }
      values.forEach(function (value, idx) {
        var tr = document.createElement("tr");
        tr.innerHTML =
          '<td><span class="type-pill ' +
          (TYPE_CLASS[type] || "type-a") +
          '">' +
          escapeHtml(type) +
          '</span></td><td class="record-value">' +
          escapeHtml(value) +
          "</td><td>" +
          (idx === 0 && ttl != null ? escapeHtml(ttl) : "") +
          '</td><td class="muted">' +
          (idx === 0 ? escapeHtml(note || "") : "") +
          "</td>";
        tbody.appendChild(tr);
        rows += 1;
      });
    });

    if (empty) empty.classList.toggle("hidden", rows > 0);
  }

  function renderIp(ip) {
    var grid = $("ip-grid");
    if (!grid) return;
    ip = ip || {};

    grid.innerHTML =
      '<div class="info-tile"><p class="tile-label">Input type</p><p class="tile-value">' +
      escapeHtml(ip.input_type || "—") +
      '</p></div><div class="info-tile"><p class="tile-label">IPv4</p><p class="tile-value">' +
      (ip.ipv4_available ? "Available" : "Not available") +
      '</p></div><div class="info-tile"><p class="tile-label">IPv6</p><p class="tile-value">' +
      (ip.ipv6_available ? "Available" : "Not available") +
      '</p></div><div class="info-tile"><p class="tile-label">Family</p><p class="tile-value">' +
      escapeHtml(ip.address_family || "None") +
      "</p></div>";

    if (ip.ipv4_addresses && ip.ipv4_addresses.length) {
      grid.innerHTML +=
        '<div class="info-tile"><p class="tile-label">IPv4 addresses</p><ul class="addr-list">' +
        ip.ipv4_addresses.map(function (a) {
          return "<li>" + escapeHtml(a) + "</li>";
        }).join("") +
        "</ul></div>";
    }
    if (ip.ipv6_addresses && ip.ipv6_addresses.length) {
      grid.innerHTML +=
        '<div class="info-tile"><p class="tile-label">IPv6 addresses</p><ul class="addr-list">' +
        ip.ipv6_addresses.map(function (a) {
          return "<li>" + escapeHtml(a) + "</li>";
        }).join("") +
        "</ul></div>";
    }
    if (ip.error) {
      grid.innerHTML +=
        '<p class="muted" style="grid-column:1/-1;margin:0">' + escapeHtml(ip.error) + "</p>";
    }
  }

  function renderNetwork(data) {
    var grid = $("network-grid");
    if (!grid) return;
    var conn = data.connectivity || {};
    var tcp = data.tcp || {};
    var http = data.http || {};

    function tile(title, status, detail) {
      return (
        '<div class="info-tile"><div class="layer-top"><span class="layer-name">' +
        escapeHtml(title) +
        '</span><span class="' +
        badgeClass(status) +
        '">' +
        escapeHtml(friendlyStatus(status)) +
        '</span></div><p class="layer-desc">' +
        escapeHtml(detail) +
        "</p></div>"
      );
    }

    var connDetail =
      conn.average_rtt_ms != null
        ? "Avg RTT " + formatMs(conn.average_rtt_ms) + ", loss " + (conn.packet_loss_percent != null ? conn.packet_loss_percent + "%" : "—")
        : conn.error || "Waiting for connectivity module.";

    var tcpDetail = tcp.error || "Port results from TCP module.";
    if (tcp.ports && Object.keys(tcp.ports).length) {
      tcpDetail = Object.keys(tcp.ports)
        .map(function (p) {
          return p + ": " + (tcp.ports[p].state || "unknown");
        })
        .join(", ");
    }

    var httpDetail = http.error || "HTTP/HTTPS module pending.";
    if (http.http && http.http.status_code) {
      httpDetail = "HTTP " + http.http.status_code + " in " + formatMs(http.http.response_time_ms);
    }
    if (http.https && http.https.status_code) {
      httpDetail += " · HTTPS " + http.https.status_code;
    }

    grid.innerHTML =
      tile("Ping / ICMP", conn.status || "skipped", connDetail) +
      tile("TCP ports", tcp.status || "skipped", tcpDetail) +
      tile("HTTP / HTTPS", http.status || "skipped", httpDetail);
  }

  function renderDiagnosis(diag) {
    diag = diag || {};
    var panel = $("diagnosis-panel");
    var list = $("suggestions-list");
    if (panel) {
      var score = diag.health_score != null ? diag.health_score : "—";
      panel.innerHTML =
        '<div class="score-ring" aria-label="Health score">' +
        escapeHtml(score) +
        '</div><div><p class="tile-label">Overall status</p><p class="tile-value">' +
        escapeHtml(diag.status || "Pending") +
        "</p></div>";
    }
    if (list) {
      list.innerHTML = (diag.suggestions || [])
        .map(function (s) {
          return "<li>" + escapeHtml(s) + "</li>";
        })
        .join("");
    }
  }

  function destroyChart(chart) {
    if (chart) chart.destroy();
    return null;
  }

  function renderCharts(data) {
    if (typeof Chart === "undefined") return;

    var dnsMs = data.dns && data.dns.response_time_ms;
    var tcpMs = null;
    var httpMs = null;
    if (data.http && data.http.https && data.http.https.response_time_ms != null) {
      httpMs = data.http.https.response_time_ms;
    } else if (data.http && data.http.http && data.http.http.response_time_ms != null) {
      httpMs = data.http.http.response_time_ms;
    }
    if (data.tcp && data.tcp.ports) {
      var ports = data.tcp.ports;
      Object.keys(ports).some(function (p) {
        if (ports[p].latency_ms != null) {
          tcpMs = ports[p].latency_ms;
          return true;
        }
        return false;
      });
    }

    var labels = [];
    var values = [];
    if (dnsMs != null) {
      labels.push("DNS");
      values.push(dnsMs);
    }
    if (tcpMs != null) {
      labels.push("TCP");
      values.push(tcpMs);
    }
    if (httpMs != null) {
      labels.push("HTTP(S)");
      values.push(httpMs);
    }

    var canvas = $("timing-chart");
    if (canvas) {
      timingChart = destroyChart(timingChart);
      if (labels.length) {
        timingChart = new Chart(canvas, {
          type: "bar",
          data: {
            labels: labels,
            datasets: [
              {
                label: "Response time (ms)",
                data: values,
                backgroundColor: ["rgba(59,130,246,0.7)", "rgba(34,211,238,0.6)", "rgba(167,139,250,0.6)"],
              },
            ],
          },
          options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
              y: { beginAtZero: true, ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.15)" } },
              x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
            },
          },
        });
      }
    }

    var conn = data.connectivity || {};
    var samples = conn.rtt_samples_ms;
    var rttCanvas = $("rtt-chart");
    if (rttCanvas && samples && samples.length) {
      rttCanvas.classList.remove("hidden");
      rttChart = destroyChart(rttChart);
      rttChart = new Chart(rttCanvas, {
        type: "line",
        data: {
          labels: samples.map(function (_, i) {
            return "Probe " + (i + 1);
          }),
          datasets: [
            {
              label: "RTT (ms)",
              data: samples,
              borderColor: "#4ade80",
              tension: 0.3,
            },
          ],
        },
        options: {
          responsive: true,
          scales: {
            y: { ticks: { color: "#94a3b8" }, grid: { color: "rgba(148,163,184,0.15)" } },
            x: { ticks: { color: "#94a3b8" } },
          },
        },
      });
    } else if (rttCanvas) {
      rttCanvas.classList.add("hidden");
      rttChart = destroyChart(rttChart);
    }
  }

  function renderTransport(block) {
    var section = $("dns-transport-section");
    var body = $("dns-transport-body");
    if (!section || !body) return;
    if (!block) {
      section.classList.add("hidden");
      return;
    }
    section.classList.remove("hidden");
    var udp = block.udp || {};
    var tcp = block.tcp || {};
    body.textContent =
      "UDP: " +
      (udp.response_time_ms != null ? formatMs(udp.response_time_ms) : "n/a") +
      " (" +
      (udp.response_code || udp.error || "—") +
      ") · TCP: " +
      (tcp.response_time_ms != null ? formatMs(tcp.response_time_ms) : "n/a") +
      " (" +
      (tcp.response_code || tcp.error || "—") +
      ")";
  }

  function renderAll(data) {
    showResultsNav();
    renderSummary(data);
    renderDns(data.dns);
    renderIp(data.ip_analysis);
    renderNetwork(data);
    renderDiagnosis(data.diagnosis);
    renderCharts(data);
    renderTransport(data.dns_transport);
  }

  /* --- Init --- */

  document.addEventListener("DOMContentLoaded", function () {
    checkBackendHealth();
    var form = $("analyze-form");
    if (form) {
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var target = ($("target-input") && $("target-input").value.trim()) || "";
        if (!target) {
          showFormError("Enter a hostname or IP address.");
          return;
        }
        runAnalysis(target);
      });
    }
  });
})();
