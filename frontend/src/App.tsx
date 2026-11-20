
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  Clock3,
  Download,
  Eye,
  FlaskConical,
  LayoutDashboard,
  Network,
  RadioTower,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";
import "./App.css";

type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

type SecurityAlert = {
  id: string;
  time: string;
  timestamp: string;
  title: string;
  source: string;
  destination: string;
  protocol: string;
  zone: string;
  severity: Severity;
  status: string;
  sourceType: string;
};

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

type ApiAlert = {
  event_id: string;
  timestamp: string;
  title: string;
  source_ip: string;
  destination: string;
  protocol: string;
  zone: string;
  severity: Severity;
  status: string;
  source_type: string;
};

type ApiSummary = {
  total_alerts: number;
  by_severity: Record<Severity, number>;
  demo_events: number;
  non_demo_events: number;
  connected_sensors: number;
  recent_live_sources: number;
  recent_activity_window_seconds: number;
};


type ApiSensor = {
  id: string;
  name: string;
  source_type: string;
  description: string;
  status: "recently_active" | "no_recent_events" | "not_integrated";
  last_seen: string | null;
  seconds_since_last_event: number | null;
};

type ApiSensorsResponse = {
  activity_window_seconds: number;
  sensors: ApiSensor[];
};



const zones = [
  {
    name: "User network",
    id: "VLAN 10",
    subnet: "192.168.10.0/24",
    rule: "Restricted access",
    status: "CONFIGURED",
    note: "USER network configured in pfSense. Access-policy validation is tracked separately.",
    icon: Wifi,
  },
  {
    name: "Server network",
    id: "VLAN 20",
    subnet: "192.168.20.0/24",
    rule: "Application-specific access",
    status: "CONFIGURED",
    note: "SERVER network configured in pfSense. Segmentation blocking has been validated.",
    icon: Server,
  },
  {
    name: "DMZ",
    id: "VLAN 30",
    subnet: "192.168.30.0/24",
    rule: "Public-facing services only",
    status: "CONFIGURED",
    note: "DMZ network configured in pfSense. Additional policy validation remains.",
    icon: Network,
  },
  {
    name: "Management",
    id: "VLAN 40",
    subnet: "192.168.40.0/24",
    rule: "Privileged access only",
    status: "CONFIGURED",
    note: "MANAGEMENT network configured in pfSense. Segmentation blocking has been validated.",
    icon: ShieldCheck,
  },
  {
    name: "Telemetry",
    id: "ZT_TELEMETRY",
    subnet: "192.168.56.0/24",
    rule: "Dedicated security monitoring and log collection",
    status: "CONFIGURED",
    note: "Telemetry network configured. pfSense syslog forwarding to the collector is operational.",
    icon: Network,
  },
];


const navItems = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Alerts", icon: Bell },
  { label: "Network Zones", icon: Network },
  { label: "Sensors", icon: RadioTower },
  { label: "Lab Plan", icon: FlaskConical },
];


function App() {
  const [activePage, setActivePage] = useState("Overview");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [selectedAlert, setSelectedAlert] =
    useState<SecurityAlert | null>(null);

  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [summary, setSummary] = useState<ApiSummary | null>(null);
  const [sensors, setSensors] = useState<ApiSensor[]>([]);
  const [apiConnected, setApiConnected] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const [lastRefresh, setLastRefresh] = useState("Connecting to API...");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadData() {
      try {
        const [alertsResponse, summaryResponse, sensorsResponse] =
          await Promise.all([
            fetch(`${API_BASE}/api/alerts`),
            fetch(`${API_BASE}/api/summary`),
            fetch(`${API_BASE}/api/sensors`),
          ]);


        if (
          !alertsResponse.ok ||
          !summaryResponse.ok ||
          !sensorsResponse.ok
        ) {
          throw new Error("The API returned an unsuccessful response.");
        }

        const apiAlerts = (await alertsResponse.json()) as ApiAlert[];
        const apiSummary = (await summaryResponse.json()) as ApiSummary;
        const apiSensors = (await sensorsResponse.json()) as ApiSensorsResponse;

        if (cancelled) return;

        setAlerts(
          apiAlerts.map((item) => ({
            id: item.event_id,
            time: new Date(item.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            }),
            timestamp: item.timestamp,
            title: item.title,
            source: item.source_ip,
            destination: item.destination,
            protocol: item.protocol,
            zone: item.zone,
            severity: item.severity,
            status: item.status,
            sourceType: item.source_type,
          })),
        );

        setSummary(apiSummary);
        setSensors(apiSensors.sensors);
        setApiConnected(true);
        setLastRefresh(
          `API updated at ${new Date().toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          })}`,
        );
        setNotice("");
      } catch {
        if (!cancelled) {
          setApiConnected(false);
          setLastRefresh("API unavailable");
          setNotice(
            "Cannot reach FastAPI. Check that the backend is running on port 8000.",
          );
        }
      }
    }

    void loadData();

  return () => {
      cancelled = true;
    };
  }, [reloadKey]);

  const integratedSensors = sensors.filter(
    (sensor) => sensor.status !== "not_integrated",
  );

  const activeIntegratedSensors = integratedSensors.filter(
    (sensor) => sensor.status === "recently_active",
  );
  const filteredAlerts = useMemo(() => {
  const term = search.trim().toLowerCase();

  return alerts.filter((alert) => {
    const matchesSearch =
      !term ||
      [
        alert.id,
        alert.title,
        alert.source,
        alert.destination,
        alert.protocol,
        alert.zone,
      ].some((value) => value.toLowerCase().includes(term));

    const matchesSeverity =
      severityFilter === "All" ||
      alert.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });
}, [alerts, search, severityFilter]);

const trafficBars = useMemo(() => {
  const hourMs = 60 * 60 * 1000;
  const currentHour = Math.floor(Date.now() / hourMs) * hourMs;
  const firstHour = currentHour - 23 * hourMs;

  const counts = Array(24).fill(0) as number[];

  for (const alert of alerts) {
    const timestamp = Date.parse(alert.timestamp);

    if (!Number.isFinite(timestamp)) {
      continue;
    }

    const bucketIndex = Math.floor(
      (timestamp - firstHour) / hourMs,
    );

    if (bucketIndex >= 0 && bucketIndex < 24) {
      counts[bucketIndex] += 1;
    }
  }

  const maxCount = Math.max(1, ...counts);

  return counts.map((count) => ({
    count,
    height:
      count === 0
        ? 0
        : Math.max(5, Math.round((count / maxCount) * 100)),
  }));
}, [alerts]);


  const blockedCount = alerts.filter(
    (alert) => alert.status.toLowerCase() === "blocked",
  ).length;


  function refreshData() {
  setNotice("Refreshing data from the FastAPI backend...");
  setReloadKey((value) => value + 1);
  }

  function exportAlerts() {
    const headers = [
      "ID",
      "Time",
      "Title",
      "Data source",
      "Source",
      "Destination",
      "Protocol",
      "Zone",
      "Severity",
      "Status",
    ];

    const rows = filteredAlerts.map((alert) =>
      [
        alert.id,
        alert.time,
        alert.title,
        alert.sourceType,
        alert.source,
        alert.destination,
        alert.protocol,
        alert.zone,
        alert.severity,
        alert.status,
      ].map((value) => `"${value.replace(/"/g, '""')}"`),
    );

    const csv = [headers, ...rows]
      .map((row) => row.join(","))
      .join("\r\n");

    const url = URL.createObjectURL(
      new Blob(["\uFEFF" + csv], {
        type: "text/csv;charset=utf-8;",
      }),
    );

    const link = document.createElement("a");
    link.href = url;
    link.download = "ztshield-security-alerts.csv";
    link.click();
    URL.revokeObjectURL(url);

    const exportedCount = rows.length;
    const isFiltered =
      search.trim() !== "" || severityFilter !== "All";

    setNotice(
      isFiltered
        ? `${exportedCount} filtered security events exported successfully as CSV.`
        : `${exportedCount} security events exported successfully as CSV.`,
    );
  }

  const pageDescriptions: Record<string, string> = {
    Overview: "Monitor your zero-trust network security environment.",
    Alerts: "Search, filter and investigate security events.",
    "Network Zones": "Review network segmentation and access policies.",
    Sensors: "Monitor telemetry integrations and sensor activity.",
    "Lab Plan": "Track implementation progress and remaining integrations.",
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={25} />
          </div>
          <div>
            <div className="brand-name">ZTShield</div>
            <div className="brand-caption">NETWORK DEFENSE</div>
          </div>
        </div>

        <div className="environment-card">
          <span className="environment-dot" />
          <div>
            <div className="environment-title">Local lab</div>
            <div className="environment-subtitle">Live Lab Environment</div>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav className="sidebar-nav">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = activePage === item.label;

            return (
              <button
                key={item.label}
                className={`nav-item ${active ? "active" : ""}`}
                onClick={() => {
                  setActivePage(item.label);
                  setSelectedAlert(null);
                  setNotice("");
                }}
              >
                <Icon size={18} />
                <span>{item.label}</span>
                {item.label === "Alerts" && (
                  <span className="nav-count">
                    {alerts.length.toString().padStart(2, "0")}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-bottom-title">SECURITY POSTURE</div>
          <div className="posture-row">
            <Shield size={16} />
            <span>Policies not yet connected</span>
          </div>
          <p className="sidebar-note">
            Live telemetry is connected. Additional integrations and security
            policies are still being implemented.
          </p>
          <div className="profile">
            <div className="avatar">ZS</div>
            <div className="profile-details">
              <strong>Lab Analyst</strong>
              <span>Local workspace</span>
            </div>
            <CircleDot size={15} className="profile-status" />
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>ZTShield</span>
            <span className="breadcrumb-divider">/</span>
            <strong>{activePage}</strong>
          </div>
          <div className="topbar-right">
            <span className="demo-pill">
              <span className="environment-dot" />
              {apiConnected ? "API CONNECTED" : "API OFFLINE"}
            </span>
            <button
              className="icon-button"
              aria-label="Refresh demo"
              title="Refresh demo"
              onClick={refreshData}
            >
              <RefreshCw size={17} />
            </button>
          </div>
        </header>

        <div className="page-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
              <h1>{activePage}</h1>
              <p>{pageDescriptions[activePage]}</p>
            </div>
            <button className="button-secondary" onClick={exportAlerts}>
              <Download size={16} />
              Export CSV
            </button>
          </section>

          {notice && (
            <div className="notice" role="status">
              <CheckCircle2 size={17} />
              <span>{notice}</span>
              <button
                className="notice-close"
                aria-label="Dismiss message"
                onClick={() => setNotice("")}
              >
                <X size={15} />
              </button>
            </div>
          )}

          {activePage === "Overview" && (
            <>
              <div className="metrics-grid">
                <article className="metric-card">
                  <div className="metric-top">
                    <span>Events in database</span>
                    <div className="metric-icon blue">
                      <Activity size={19} />
                    </div>
                  </div>
                  <div className="metric-value">
                    {summary ? summary.total_alerts.toLocaleString() : "—"}
                  </div>
                  <div className="metric-footer">
                    <span className="muted-note">
                      {summary ? `${summary.demo_events} demo records` : "Waiting for API"}
                    </span>
                    <span className="metric-neutral">
                      <ArrowUpRight size={14} /> Sample
                    </span>
                  </div>
                </article>

                <article className="metric-card">
                  <div className="metric-top">
                    <span>Critical alerts</span>
                    <div className="metric-icon red">
                      <ShieldAlert size={19} />
                    </div>
                  </div>
                  <div className="metric-value">
                    {summary
                      ? String(summary.by_severity.Critical).padStart(2, "0")
                      : "—"}
                  </div>
                  <div className="metric-footer">
                    <span className="muted-note">Requires investigation</span>
                    <span className="metric-danger">
                      <AlertTriangle size={14} /> Review
                    </span>
                  </div>
                </article>

                <article className="metric-card">
                  <div className="metric-top">
                    <span>Blocked events</span>
                    <div className="metric-icon green">
                      <ShieldCheck size={19} />
                    </div>
                  </div>
                  <div className="metric-value">
                    {String(blockedCount).padStart(2, "0")}
                  </div>
                  <div className="metric-footer">
                    <span className="muted-note">
                      {apiConnected ? "Based on stored events" : "Waiting for API"}
                    </span>
                    <span className="metric-good">
                      <ArrowDownRight size={14} /> Recorded
                    </span>
                  </div>
                </article>

                <article className="metric-card">
                  <div className="metric-top">
                    <span>Recently active sources</span>
                    <div className="metric-icon purple">
                      <RadioTower size={19} />
                    </div>
                  </div>
                  <div className="metric-value">
                    {summary ? `${summary.recent_live_sources} / 4` : "— / 4"}
                  </div>
                  <div className="metric-footer">
                    <span className="muted-note">
                      {summary && summary.recent_live_sources > 0
                        ? "Events seen in last 5 min"
                        : "No recent live events"}
                    </span>
                    <span className="metric-neutral">
                      {summary && summary.recent_live_sources > 0
                        ? "Recently active"
                        : "Awaiting events"}
                    </span>
                  </div>
                </article>
              </div>

<section className="panel severity-breakdown-panel">
  <div className="severity-breakdown-header">
    <div>
      <h2>Severity breakdown</h2>
      <p>Distribution of stored security alerts by severity.</p>
    </div>
    <span>
      {summary
        ? `${Object.values(summary.by_severity).reduce(
            (total, count) => total + count,
            0,
          )} events`
        : "Loading..."}
    </span>
  </div>

  <div className="severity-breakdown-grid">
    {(["Critical", "High", "Medium", "Low", "Info"] as Severity[]).map(
      (severity) => {
        const count = summary?.by_severity[severity] ?? 0;
        const total = summary
          ? Object.values(summary.by_severity).reduce(
              (sum, value) => sum + value,
              0,
            )
          : 0;

        const percentage =
          total > 0 ? Math.round((count / total) * 100) : 0;

        return (
          <div
            className={`severity-breakdown-item breakdown-${severity.toLowerCase()}`}
            key={severity}
          >
            <div className="severity-breakdown-top">
              <span>{severity}</span>
              <strong>{count}</strong>
            </div>

            <div
              className="severity-breakdown-track"
              role="progressbar"
              aria-label={`${severity} alerts`}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={percentage}
            >
              <div
                className="severity-breakdown-fill"
                style={{ width: `${percentage}%` }}
              />
            </div>

            <p>{percentage}% of stored events</p>
          </div>
        );
      },
    )}
  </div>
</section>


              <div className="overview-grid">
                <section className="panel traffic-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Network activity</h2>
                      <p>Stored security events per hour · last 24 hours</p>
                    </div>
                    <span className="subtle-badge">LAST 24 HOURS</span>
                  </div>

                  <div className="chart-legend">
                    <span className="legend-dot" />
                    <span>Stored events</span>
                    <span className="chart-note">24 hourly buckets</span>
                  </div>

                  <div
                    className="bar-chart"
                    role="img"
                    aria-label="Bar chart showing stored security event counts by hour over the last 24 hours"
                  >


                    {trafficBars.map(({ height, count }, index) => (
                      <div
                        className="bar-column"
                        key={index}
                        title={`${count} event${count === 1 ? "" : "s"}`}
                      >
                        {count > 0 && (
                          <div
                            className="bar"
                            style={{ height: `${height}%` }}
                          />
                        )}
                      </div>
                    ))}
                  </div>


                  <div className="chart-axis">
                    <span>24h ago</span>
                    <span>18h ago</span>
                    <span>12h ago</span>
                    <span>6h ago</span>
                    <span>Now</span>
                  </div>
                  <p className="chart-footnote">
                    Hourly counts are calculated from stored alert timestamps.
                  </p>
                </section>

                <section className="panel zones-summary">
                  <div className="panel-heading">
                    <div>
                      <h2>Network zones</h2>
                      <p>Configured lab zones</p>
                    </div>
                    <button
                      className="text-button"
                      onClick={() => setActivePage("Network Zones")}
                    >
                      View zones
                    </button>
                  </div>

                  {zones.map((zone) => {
                    const Icon = zone.icon;

                    return (
                      <div className="zone-row" key={zone.id}>
                        <div className="zone-icon">
                          <Icon size={17} />
                        </div>
                        <div className="zone-info">
                          <strong>{zone.name}</strong>
                          <span>{zone.id} · {zone.subnet}</span>
                        </div>
                        <span className="configured-dot" title="Configured in pfSense" />
                      </div>
                    );
                  })}
                  <div className="zone-legend">
                    <span className="configured-dot" />
                    Configured in pfSense; policy validation tracked separately
                  </div>
                </section>
              </div>
            </>
          )}

          {activePage === "Network Zones" && (
            <section className="zone-page-grid">
              {zones.map((zone) => {
                const Icon = zone.icon;

                return (
                  <article className="panel zone-detail-card" key={zone.id}>
                    <div className="zone-detail-top">
                      <div className="zone-icon large">
                        <Icon size={21} />
                      </div>
                      <span className="subtle-badge">{zone.status}</span>
                    </div>
                    <h2>{zone.name}</h2>
                    <span className="zone-vlan">{zone.id}</span>
                    <div className="subnet-block">
                      <span>Subnet</span>
                      <strong>{zone.subnet}</strong>
                    </div>
                    <div className="subnet-block">
                      <span>Access policy</span>
                      <strong>{zone.rule}</strong>
                    </div>
                    <p className="card-help">
                      {zone.note}
                    </p>
                  </article>
                );
              })}
            </section>
          )}


          {activePage === "Sensors" && (
            <section className="sensor-grid">
              {sensors.map((sensor) => {
                const Icon =
                  sensor.id === "pfsense"
                    ? Shield
                    : sensor.id === "suricata"
                      ? Eye
                      : sensor.id === "wireguard"
                        ? Wifi
                        : RadioTower;

                const statusLabels: Record<ApiSensor["status"], string> = {
                  recently_active: "Recently active",
                  no_recent_events: "No recent events",
                  not_integrated: "Not integrated",
                };

                const lastSeen = sensor.last_seen
                  ? new Date(sensor.last_seen).toLocaleString()
                  : "No events recorded";

                const age = sensor.seconds_since_last_event;

                const elapsed =
                  age === null
                    ? "—"
                    : age < 60
                      ? `${age} seconds ago`
                      : age < 3600
                        ? `${Math.floor(age / 60)} minutes ago`
                        : `${Math.floor(age / 3600)} hours ago`;

                return (
                  <article className="panel sensor-card" key={sensor.id}>
                    <div className="sensor-card-top">
                      <div className="metric-icon blue">
                        <Icon size={20} />
                      </div>

                      <span
                        className={`sensor-status sensor-status-${sensor.status.replace(/_/g, "-")}`}
                      >
                        {statusLabels[sensor.status]}
                      </span>
                    </div>

                    <h2>{sensor.name}</h2>
                    <p>{sensor.description}</p>

                    <div className="sensor-phase">
                      <strong>Last event:</strong> {lastSeen}
                    </div>

                    <div className="sensor-phase">
                      <strong>Time since last event:</strong> {elapsed}
                    </div>

                    <div className="sensor-phase">
                      <strong>Source:</strong> {sensor.source_type}
                    </div>
                  </article>
                );
              })}
            </section>
          )}


          {activePage === "Lab Plan" && (
            <section className="panel lab-plan">
              <div className="panel-heading">
                <div>
                  <h2>Implementation roadmap</h2>
                  <p>Remaining validation and integration work</p>
                </div>
                <FlaskConical size={21} className="heading-icon" />
              </div>

              {[
                ["01", "Foundation", "Dashboard, FastAPI, database and tests"],
                ["02", "Network segmentation", "pfSense interfaces, zones and firewall policies"],
                ["03", "Threat detection", "Suricata rules and EVE JSON ingestion"],
                ["04", "Secure remote access", "WireGuard and access-control validation"],
                ["05", "Investigation", "PCAP analysis and honeypot telemetry"],
                ["06", "Verification", "Controlled tests, evidence and final report"],
              ].map(([number, title, description]) => (
                <div className="roadmap-item" key={number}>
                  <span className="roadmap-number">{number}</span>
                  <div>
                    <strong>{title}</strong>
                    <p>{description}</p>
                  </div>
                  <span className="roadmap-status">Planned</span>
                </div>
              ))}
            </section>
          )}

          {(activePage === "Overview" || activePage === "Alerts") && (
            <section className="panel alerts-panel">
              <div className="panel-heading alerts-heading">
                <div>
                  <h2>Security events</h2>
                  <p>
                    {filteredAlerts.length} event
                    {filteredAlerts.length === 1 ? "" : "s"} shown
                  </p>
                </div>
                <div className="refresh-status">
                  <Clock3 size={14} /> {lastRefresh}
                </div>
              </div>

              <div className="table-toolbar">
                <div className="search-box">
                  <Search size={16} />
                  <input
                    aria-label="Search security events"
                    placeholder="Search title, IP, protocol..."
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                  />
                </div>

                <label className="filter-select">
                  <span>Severity</span>
                  <select
                    value={severityFilter}
                    onChange={(event) => setSeverityFilter(event.target.value)}
                    aria-label="Filter by severity"
                  >
                    <option>All</option>
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>
                  <ChevronDown size={14} />
                </label>

                <button className="button-secondary compact" onClick={exportAlerts}>
                  <Download size={15} />
                  Export
                </button>
              </div>

              <div className="table-scroll">
                <table className="alerts-table">
                  <thead>
                    <tr>
                      <th>EVENT</th>
                      <th>SOURCE → DESTINATION</th>
                      <th>DATA SOURCE</th>
                      <th>ZONE</th>
                      <th>SEVERITY</th>
                      <th>STATUS</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {filteredAlerts.map((alert) => (
                      <tr key={alert.id}>
                        <td>
                          <div className="event-title">{alert.title}</div>
                          <div className="event-meta">
                            {alert.id} · {alert.time}
                          </div>
                        </td>
                        <td>
                          <div className="ip-value">{alert.source}</div>
                          <div className="event-meta">
                            → {alert.destination} · {alert.protocol}
                          </div>
                        </td>
                        <td>
                          <span className="zone-tag">
                            {alert.sourceType === "suricata_live"
                              ? "LIVE SURICATA"
                              : alert.sourceType === "suricata_pcap"
                                ? "OFFLINE PCAP"
                                : alert.sourceType === "suricata"
                                  ? "SURICATA — MODE UNKNOWN"
                                  : alert.sourceType.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <span className="zone-tag">{alert.zone}</span>
                        </td>
                        <td>
                          <span
                            className={`severity severity-${alert.severity.toLowerCase()}`}
                          >
                            <span /> {alert.severity}
                          </span>
                        </td>
                        <td>
                          <span
                            className={`status-text ${
                              alert.status === "Blocked" ? "blocked" : ""
                            }`}
                          >
                            {alert.status}
                          </span>
                        </td>
                        <td>
                          <button
                            className="row-action"
                            title="Inspect event"
                            aria-label={`Inspect ${alert.id}`}
                            onClick={() => setSelectedAlert(alert)}
                          >
                            <Eye size={16} />
                          </button>
                        </td>
                      </tr>
                    ))}

                    {filteredAlerts.length === 0 && (
                      <tr>
                        <td colSpan={6} className="empty-state">
                          No demo events match those filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>

              <div className="table-foot">
                <span>
                  <span className="environment-dot" />
                  {apiConnected
                    ? `Telemetry: ${activeIntegratedSensors.length} of ${integratedSensors.length} integrated sensors recently active`
                    : "Telemetry API unavailable"}
                </span>
                <button
                  className="text-button"
                  onClick={() => setActivePage("Alerts")}
                >
                  Open alerts <ArrowUpRight size={14} />
                </button>
              </div>
            </section>
          )}

          <footer className="app-footer">
            <span>ZTShield · Zero-Trust Network Defense</span>
            <span>Prototype v0.1.0 · Local environment</span>
          </footer>
        </div>
      </main>

      {selectedAlert && (
        <div
          className="modal-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSelectedAlert(null);
            }
          }}
        >
          <section className="alert-modal" role="dialog" aria-modal="true" aria-labelledby="detail-title">
            <div className="modal-heading">
              <div>
                <span className="eyebrow">
                  {selectedAlert.sourceType === "demo"
                    ? "DEMO EVENT"
                    : selectedAlert.sourceType === "suricata_live"
                      ? "LIVE SURICATA ALERT"
                      : selectedAlert.sourceType === "pfsense_live"
                        ? "LIVE PFSENSE EVENT"
                        : "STORED SECURITY EVENT"}
                </span>
                <h2 id="detail-title">{selectedAlert.title}</h2>
                <p>{selectedAlert.id} · {selectedAlert.time}</p>
              </div>
              <button
                className="icon-button"
                aria-label="Close details"
                onClick={() => setSelectedAlert(null)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="modal-details">
              <div><span>Source IP</span><strong>{selectedAlert.source}</strong></div>
              <div><span>Destination</span><strong>{selectedAlert.destination}</strong></div>
              <div><span>Protocol</span><strong>{selectedAlert.protocol}</strong></div>
              <div><span>Zone</span><strong>{selectedAlert.zone}</strong></div>
              <div><span>Severity</span><strong>{selectedAlert.severity}</strong></div>
              <div><span>Workflow status</span><strong>{selectedAlert.status}</strong></div>
            </div>
            <p className="modal-disclaimer">
              {selectedAlert.sourceType === "demo"
                ? "This is a demonstration event generated for the ZTShield interface."
                : selectedAlert.sourceType === "suricata_live"
                  ? "This alert was ingested from live Suricata IDS telemetry. The alert metadata is stored; a full packet capture is not attached."
                  : selectedAlert.sourceType === "pfsense_live"
                    ? "This event was ingested from live pfSense firewall telemetry. The firewall event metadata is stored; a full packet capture is not attached."
                    : "This is a stored security event. Its source classification is available, but additional evidence may not be attached."}
            </p>
            <button className="button-primary" onClick={() => setSelectedAlert(null)}>
              Close details
            </button>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;
