import { useState } from "react";

const scenarios = [
  {
    id: 1,
    codename: "Dark Harvest",
    icon: "🕸️",
    theme: "#e74c3c",
    type: "Web Application Compromise",
    victim: "web-srv",
    difficulty: "Todos los niveles",
    killChain: [
      { step: "Reconocimiento", mitre: "T1595", tool: "Nmap/Nikto" },
      { step: "SQLi Exploitation", mitre: "T1190", tool: "SQLMap" },
      { step: "Web Shell Upload", mitre: "T1505.003", tool: "PHP Shell" },
      { step: "Privilege Escalation", mitre: "T1068", tool: "Sudo Exploit" },
      { step: "Data Exfiltration", mitre: "T1048", tool: "mysqldump" },
      { step: "Persistence", mitre: "T1053.003", tool: "Cron Job" },
    ],
    questions: { pup: 3, hunter: 3, alpha: 3, fenrir: 2 },
    wazuhRules: ["31101-31110", "550-553", "5715-5716", "87900+"],
  },
  {
    id: 2,
    codename: "Iron Gate",
    icon: "🏰",
    theme: "#3498db",
    type: "Active Directory Compromise",
    victim: "dc-srv",
    difficulty: "Todos los niveles",
    killChain: [
      { step: "Spearphishing", mitre: "T1566", tool: "Email Payload" },
      { step: "Macro Execution", mitre: "T1059.001", tool: "PowerShell" },
      { step: "Credential Dump", mitre: "T1003.001", tool: "Mimikatz" },
      { step: "Kerberoasting", mitre: "T1558.003", tool: "Rubeus" },
      { step: "Lateral Movement", mitre: "T1021.002", tool: "PSExec" },
      { step: "Ransomware", mitre: "T1486", tool: "Custom Encryptor" },
    ],
    questions: { pup: 3, hunter: 3, alpha: 3, fenrir: 2 },
    wazuhRules: ["60100-60115", "92100-92200", "Custom Sysmon"],
  },
  {
    id: 3,
    codename: "Ghost in the Shell",
    icon: "👻",
    theme: "#2ecc71",
    type: "Linux Server + Rootkit",
    victim: "lnx-srv",
    difficulty: "Todos los niveles",
    killChain: [
      { step: "SSH Brute Force", mitre: "T1110.001", tool: "Hydra" },
      { step: "Valid Credentials", mitre: "T1078", tool: "SSH" },
      { step: "Toolkit Download", mitre: "T1105", tool: "wget/curl" },
      { step: "Rootkit Install", mitre: "T1014", tool: "Kernel Module" },
      { step: "C2 Channel", mitre: "T1571", tool: "Reverse Shell" },
      { step: "Cryptominer", mitre: "T1496", tool: "XMRig" },
    ],
    questions: { pup: 3, hunter: 3, alpha: 3, fenrir: 2 },
    wazuhRules: ["5710-5716", "550-553", "80700-80800", "Custom Auditd"],
  },
  {
    id: 4,
    codename: "Supply Chain Phantom",
    icon: "🔗",
    theme: "#9b59b6",
    type: "Multi-Vector Supply Chain",
    victim: "Todos",
    difficulty: "Solo Alpha + Fenrir",
    killChain: [
      { step: "Dependency Confusion", mitre: "T1195.001", tool: "Malicious NPM" },
      { step: "Post-Install Backdoor", mitre: "T1059.006", tool: "Python Script" },
      { step: "DNS Tunneling C2", mitre: "T1071.004", tool: "dnscat2" },
      { step: "Lateral Movement", mitre: "T1021", tool: "Shared Package" },
      { step: "Data Staging", mitre: "T1074", tool: "tar + encrypt" },
      { step: "Anti-Forensics", mitre: "T1070", tool: "Log Manipulation" },
    ],
    questions: { pup: 0, hunter: 0, alpha: 4, fenrir: 3 },
    wazuhRules: ["Custom DNS", "FIM Rules", "Multi-host Correlation"],
  },
];

const stack = [
  { name: "Wazuh Manager", port: "1514/1515", color: "#00a9e5", desc: "SIEM Core - Recolección y correlación" },
  { name: "Wazuh Indexer", port: "9200", color: "#00a9e5", desc: "OpenSearch - Almacenamiento" },
  { name: "Wazuh Dashboard", port: "5601", color: "#00a9e5", desc: "Interfaz de investigación" },
  { name: "CTFd", port: "8000", color: "#f39c12", desc: "Plataforma CTF - Flags y scoring" },
  { name: "CALDERA", port: "8888", color: "#e74c3c", desc: "Simulación de ataques MITRE" },
  { name: "Nginx", port: "80/443", color: "#27ae60", desc: "Proxy reverso unificado" },
  { name: "MariaDB", port: "3306", color: "#f39c12", desc: "Base de datos CTFd" },
  { name: "Docker Compose", port: "—", color: "#2496ed", desc: "Orquestación completa" },
];

const levels = [
  { name: "Cachorro (Pup)", icon: "🐺", pts: 100, color: "#27ae60", skills: "Dashboard navigation, búsquedas básicas, identificación de alertas" },
  { name: "Cazador (Hunter)", icon: "🐺", pts: 200, color: "#f39c12", skills: "Correlación de eventos, análisis de reglas, investigación" },
  { name: "Alfa (Alpha)", icon: "🐺", pts: 300, color: "#e67e22", skills: "Threat hunting, análisis forense, reglas custom" },
  { name: "Fenrir (Boss)", icon: "🐺", pts: 500, color: "#e74c3c", skills: "Multi-vector, evasión, respuesta completa a incidentes" },
];

const phases = [
  { phase: "Fase 1 — MVP", time: "Mes 1-2", items: ["Docker Compose funcional", "Escenarios 1 & 3", "CTFd + challenges", "Dashboards básicos"] },
  { phase: "Fase 2 — Expansión", time: "Mes 3-4", items: ["Escenarios 2 & 4", "Datasets automatizados", "Branding + certificados", "API externa"] },
  { phase: "Fase 3 — Comunidad", time: "Mes 5-6", items: ["Template system", "Contribuciones community", "Plugin CTFd-Wazuh", "Modo autoguiado"] },
  { phase: "Fase 4 — Enterprise", time: "Mes 7+", items: ["Multi-tenant", "Reporting automático", "Cloud scenarios", "Certificaciones"] },
];

export default function WazuhBOTS() {
  const [activeTab, setActiveTab] = useState("overview");
  const [selectedScenario, setSelectedScenario] = useState(null);

  const tabs = [
    { id: "overview", label: "Visión General", icon: "⚡" },
    { id: "architecture", label: "Arquitectura", icon: "🏗️" },
    { id: "scenarios", label: "Escenarios", icon: "💀" },
    { id: "levels", label: "Niveles", icon: "📊" },
    { id: "roadmap", label: "Roadmap", icon: "🗺️" },
  ];

  const totalQuestions = scenarios.reduce((acc, s) => acc + s.questions.pup + s.questions.hunter + s.questions.alpha + s.questions.fenrir, 0);

  return (
    <div style={{ minHeight: "100vh", background: "#0a0e17", color: "#e0e0e0", fontFamily: "'Segoe UI', system-ui, -apple-system, sans-serif" }}>
      {/* Header */}
      <div style={{ background: "linear-gradient(135deg, #0a0e17 0%, #1a1f35 50%, #0d1525 100%)", borderBottom: "1px solid #1e2a4a", padding: "24px 32px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 8 }}>
          <span style={{ fontSize: 36 }}>🐺</span>
          <div>
            <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800, background: "linear-gradient(90deg, #00a9e5, #00d4aa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              WazuhBOTS
            </h1>
            <p style={{ margin: 0, fontSize: 13, color: "#6b7b9e", letterSpacing: 2, textTransform: "uppercase" }}>
              Boss of the SOC — Powered by Wazuh | by MrHacker
            </p>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 4, marginTop: 16, flexWrap: "wrap" }}>
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => { setActiveTab(tab.id); setSelectedScenario(null); }}
              style={{
                padding: "8px 16px",
                background: activeTab === tab.id ? "rgba(0,169,229,0.15)" : "transparent",
                border: activeTab === tab.id ? "1px solid #00a9e5" : "1px solid transparent",
                borderRadius: 8,
                color: activeTab === tab.id ? "#00d4aa" : "#6b7b9e",
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 600,
                transition: "all 0.2s",
              }}
            >
              {tab.icon} {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div style={{ padding: "24px 32px", maxWidth: 1100, margin: "0 auto" }}>

        {/* OVERVIEW */}
        {activeTab === "overview" && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16, marginBottom: 32 }}>
              {[
                { label: "Escenarios", value: "4", sub: "Attack Scenarios", color: "#e74c3c" },
                { label: "Preguntas", value: totalQuestions + "+", sub: "CTF Challenges", color: "#00a9e5" },
                { label: "Niveles", value: "4", sub: "Dificultad progresiva", color: "#f39c12" },
                { label: "Stack", value: "100%", sub: "Open Source", color: "#2ecc71" },
              ].map((stat, i) => (
                <div key={i} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #1e2a4a", borderRadius: 12, padding: 20, textAlign: "center" }}>
                  <div style={{ fontSize: 32, fontWeight: 800, color: stat.color }}>{stat.value}</div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: "#c0c8d8" }}>{stat.label}</div>
                  <div style={{ fontSize: 11, color: "#6b7b9e", marginTop: 4 }}>{stat.sub}</div>
                </div>
              ))}
            </div>

            <div style={{ background: "rgba(0,169,229,0.05)", border: "1px solid #1e2a4a", borderRadius: 12, padding: 24, marginBottom: 24 }}>
              <h3 style={{ margin: "0 0 12px", color: "#00d4aa", fontSize: 16 }}>🎯 Multi-Propósito</h3>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12 }}>
                {[
                  { icon: "🏢", title: "SOC Training", desc: "Onboarding y evaluación de analistas" },
                  { icon: "🎤", title: "Wazuh Meetups", desc: "Competencias en vivo con scoreboard" },
                  { icon: "📚", title: "Educativo", desc: "Labs autoguiados y cursos" },
                  { icon: "🏆", title: "CTF Público", desc: "Competencia abierta global" },
                ].map((mode, i) => (
                  <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                    <span style={{ fontSize: 24 }}>{mode.icon}</span>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 13, color: "#e0e0e0" }}>{mode.title}</div>
                      <div style={{ fontSize: 12, color: "#6b7b9e" }}>{mode.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid #1e2a4a", borderRadius: 12, padding: 24 }}>
              <h3 style={{ margin: "0 0 16px", color: "#00d4aa", fontSize: 16 }}>⚡ Quick Deploy</h3>
              <div style={{ fontFamily: "monospace", fontSize: 13, lineHeight: 2, color: "#00d4aa", background: "#0d1117", borderRadius: 8, padding: 16 }}>
                <div style={{ color: "#6b7b9e" }}># Clone & Deploy</div>
                <div>$ git clone https://github.com/MrHacker-X/wazuhbots.git</div>
                <div>$ cd wazuhbots</div>
                <div>$ chmod +x scripts/setup.sh && ./scripts/setup.sh</div>
                <div style={{ color: "#6b7b9e", marginTop: 8 }}># Access</div>
                <div>Dashboard → https://localhost:5601</div>
                <div>CTFd     → http://localhost:8000</div>
              </div>
            </div>
          </div>
        )}

        {/* ARCHITECTURE */}
        {activeTab === "architecture" && (
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#00d4aa", marginBottom: 20 }}>🏗️ Stack Tecnológico — 100% Open Source</h2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, marginBottom: 32 }}>
              {stack.map((s, i) => (
                <div key={i} style={{ background: "rgba(255,255,255,0.03)", border: `1px solid ${s.color}33`, borderRadius: 10, padding: 16, borderLeft: `3px solid ${s.color}` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <span style={{ fontWeight: 700, fontSize: 14, color: s.color }}>{s.name}</span>
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: "#6b7b9e", background: "#0d1117", padding: "2px 8px", borderRadius: 4 }}>{s.port}</span>
                  </div>
                  <div style={{ fontSize: 12, color: "#8b95a8" }}>{s.desc}</div>
                </div>
              ))}
            </div>

            <div style={{ background: "#0d1117", borderRadius: 12, padding: 24, border: "1px solid #1e2a4a" }}>
              <h3 style={{ color: "#00a9e5", fontSize: 15, margin: "0 0 16px" }}>📐 Diagrama de Flujo</h3>
              <div style={{ fontFamily: "monospace", fontSize: 11, lineHeight: 1.6, color: "#6b9bc3", whiteSpace: "pre", overflowX: "auto" }}>
{`  Participantes (Browser)
         │
    ┌────▼─────┐
    │  Nginx   │  :80/:443
    │  Proxy   │
    └──┬────┬──┘
       │    │
  ┌────▼─┐ ┌▼──────┐
  │Wazuh │ │ CTFd  │
  │Dashb.│ │  CTF  │
  │:5601 │ │ :8000 │
  └──┬───┘ └───┬───┘
     │         │
  ┌──▼───────┐ ┌▼────────┐
  │ Wazuh    │ │MariaDB  │
  │ Indexer  │ │+ Redis  │
  │ :9200    │ └─────────┘
  └──┬───────┘
     │
  ┌──▼───────┐
  │ Wazuh    │
  │ Manager  │
  │:1514/1515│
  └──┬──┬──┬─┘
     │  │  │
  ┌──▼┐┌▼─┐┌▼──┐
  │WEB││DC ││LNX│  Victim
  │SRV││SRV││SRV│  Machines
  └───┘└───┘└───┘
     ▲  ▲  ▲
  ┌──┴──┴──┴──┐
  │ CALDERA + │
  │ Atomic RT │
  │  Attacks  │
  └───────────┘`}
              </div>
            </div>

            <div style={{ marginTop: 24, background: "rgba(255,255,255,0.03)", border: "1px solid #1e2a4a", borderRadius: 12, padding: 20 }}>
              <h3 style={{ color: "#f39c12", fontSize: 15, margin: "0 0 12px" }}>💻 Requisitos de Hardware</h3>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
                {[
                  { mode: "Local/Dev", cpu: "4 cores", ram: "16 GB", disk: "100 GB" },
                  { mode: "Meetup", cpu: "8 cores", ram: "32 GB", disk: "200 GB" },
                  { mode: "CTF Público", cpu: "16 cores", ram: "64 GB", disk: "500 GB" },
                ].map((r, i) => (
                  <div key={i} style={{ background: "#0d1117", borderRadius: 8, padding: 12, textAlign: "center" }}>
                    <div style={{ fontWeight: 700, color: "#f39c12", fontSize: 13, marginBottom: 6 }}>{r.mode}</div>
                    <div style={{ fontSize: 11, color: "#8b95a8" }}>{r.cpu} • {r.ram} • {r.disk}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* SCENARIOS */}
        {activeTab === "scenarios" && (
          <div>
            {!selectedScenario ? (
              <>
                <h2 style={{ fontSize: 20, fontWeight: 700, color: "#00d4aa", marginBottom: 20 }}>💀 Escenarios de Ataque</h2>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
                  {scenarios.map((s) => (
                    <div
                      key={s.id}
                      onClick={() => setSelectedScenario(s)}
                      style={{
                        background: "rgba(255,255,255,0.03)",
                        border: `1px solid ${s.theme}44`,
                        borderRadius: 12,
                        padding: 20,
                        cursor: "pointer",
                        transition: "all 0.2s",
                        borderTop: `3px solid ${s.theme}`,
                      }}
                      onMouseEnter={(e) => { e.currentTarget.style.background = `${s.theme}11`; e.currentTarget.style.transform = "translateY(-2px)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.03)"; e.currentTarget.style.transform = "none"; }}
                    >
                      <div style={{ fontSize: 32, marginBottom: 8 }}>{s.icon}</div>
                      <div style={{ fontWeight: 800, fontSize: 16, color: s.theme, marginBottom: 4 }}>
                        Escenario {s.id}
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 14, color: "#e0e0e0", marginBottom: 8 }}>
                        "{s.codename}"
                      </div>
                      <div style={{ fontSize: 12, color: "#6b7b9e", marginBottom: 12 }}>{s.type}</div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                        <span style={{ color: "#8b95a8" }}>Víctima: <span style={{ color: "#00d4aa" }}>{s.victim}</span></span>
                        <span style={{ color: "#8b95a8" }}>{s.killChain.length} pasos</span>
                      </div>
                      <div style={{ marginTop: 8, fontSize: 11, color: s.theme }}>{s.difficulty}</div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <>
                <button
                  onClick={() => setSelectedScenario(null)}
                  style={{ background: "none", border: "1px solid #1e2a4a", color: "#6b7b9e", padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12, marginBottom: 20 }}
                >
                  ← Volver a escenarios
                </button>
                <div style={{ borderTop: `3px solid ${selectedScenario.theme}`, background: "rgba(255,255,255,0.03)", borderRadius: 12, padding: 24, border: `1px solid ${selectedScenario.theme}33` }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
                    <span style={{ fontSize: 40 }}>{selectedScenario.icon}</span>
                    <div>
                      <h2 style={{ margin: 0, color: selectedScenario.theme, fontSize: 22 }}>Operation: {selectedScenario.codename}</h2>
                      <p style={{ margin: 0, color: "#6b7b9e", fontSize: 13 }}>{selectedScenario.type} — Víctima: {selectedScenario.victim}</p>
                    </div>
                  </div>

                  <h3 style={{ color: "#00d4aa", fontSize: 15, marginBottom: 12 }}>🔗 Kill Chain</h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, marginBottom: 24 }}>
                    {selectedScenario.killChain.map((step, i) => (
                      <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                        <div style={{ width: 28, height: 28, borderRadius: "50%", background: selectedScenario.theme, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 800, color: "#fff", flexShrink: 0 }}>
                          {i + 1}
                        </div>
                        {i < selectedScenario.killChain.length - 1 && (
                          <div style={{ position: "absolute", left: 45, top: 28, width: 2, height: 20, background: `${selectedScenario.theme}44` }} />
                        )}
                        <div style={{ background: "#0d1117", borderRadius: 8, padding: "8px 14px", flex: 1, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 4 }}>
                          <span style={{ fontWeight: 600, fontSize: 13, color: "#e0e0e0" }}>{step.step}</span>
                          <div style={{ display: "flex", gap: 8 }}>
                            <span style={{ fontFamily: "monospace", fontSize: 11, color: selectedScenario.theme, background: `${selectedScenario.theme}15`, padding: "2px 8px", borderRadius: 4 }}>{step.mitre}</span>
                            <span style={{ fontSize: 11, color: "#6b7b9e" }}>{step.tool}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  <h3 style={{ color: "#00d4aa", fontSize: 15, marginBottom: 12 }}>🎯 Preguntas por Nivel</h3>
                  <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
                    {[
                      { key: "pup", label: "Cachorro", color: "#27ae60" },
                      { key: "hunter", label: "Cazador", color: "#f39c12" },
                      { key: "alpha", label: "Alfa", color: "#e67e22" },
                      { key: "fenrir", label: "Fenrir", color: "#e74c3c" },
                    ].map((l) => (
                      <div key={l.key} style={{ background: `${l.color}15`, border: `1px solid ${l.color}33`, borderRadius: 8, padding: "10px 18px", textAlign: "center" }}>
                        <div style={{ fontSize: 22, fontWeight: 800, color: l.color }}>{selectedScenario.questions[l.key]}</div>
                        <div style={{ fontSize: 11, color: "#8b95a8" }}>{l.label}</div>
                      </div>
                    ))}
                  </div>

                  <h3 style={{ color: "#00d4aa", fontSize: 15, marginBottom: 8 }}>🛡️ Reglas Wazuh Relevantes</h3>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {selectedScenario.wazuhRules.map((r, i) => (
                      <span key={i} style={{ fontFamily: "monospace", fontSize: 12, background: "#0d1117", border: "1px solid #1e2a4a", padding: "4px 10px", borderRadius: 6, color: "#00a9e5" }}>
                        {r}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* LEVELS */}
        {activeTab === "levels" && (
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#00d4aa", marginBottom: 20 }}>📊 Sistema de Niveles Progresivos</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {levels.map((l, i) => (
                <div key={i} style={{ background: "rgba(255,255,255,0.03)", border: `1px solid ${l.color}33`, borderLeft: `4px solid ${l.color}`, borderRadius: 12, padding: 20, display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
                  <div style={{ textAlign: "center", minWidth: 80 }}>
                    <div style={{ fontSize: 28 }}>{l.icon}</div>
                    <div style={{ fontWeight: 800, fontSize: 20, color: l.color }}>{l.pts} pts</div>
                  </div>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <div style={{ fontWeight: 700, fontSize: 16, color: l.color, marginBottom: 4 }}>
                      Nivel {i + 1}: {l.name}
                    </div>
                    <div style={{ fontSize: 13, color: "#8b95a8" }}>{l.skills}</div>
                  </div>
                  <div style={{ background: `${l.color}15`, borderRadius: 8, padding: "4px 12px" }}>
                    <span style={{ fontSize: 11, color: l.color, fontWeight: 600 }}>
                      {i === 0 ? "N1 / Estudiante" : i === 1 ? "Analista N2" : i === 2 ? "Threat Hunter" : "Experto / Red Team"}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 24, background: "rgba(255,255,255,0.03)", border: "1px solid #1e2a4a", borderRadius: 12, padding: 20 }}>
              <h3 style={{ color: "#f39c12", fontSize: 15, margin: "0 0 12px" }}>🏅 Scoring Dinámico</h3>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 12 }}>
                {[
                  { label: "Decay", value: "50% mín", desc: "Puntos decrecen con solves" },
                  { label: "First Blood", value: "+20%", desc: "Bonus primer solve" },
                  { label: "Time Bonus", value: "+10%", desc: "En la primera hora" },
                  { label: "Hints", value: "-25/50%", desc: "Costo de pistas" },
                ].map((s, i) => (
                  <div key={i} style={{ textAlign: "center", background: "#0d1117", borderRadius: 8, padding: 12 }}>
                    <div style={{ fontWeight: 800, fontSize: 18, color: "#f39c12" }}>{s.value}</div>
                    <div style={{ fontWeight: 600, fontSize: 12, color: "#c0c8d8" }}>{s.label}</div>
                    <div style={{ fontSize: 10, color: "#6b7b9e" }}>{s.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ROADMAP */}
        {activeTab === "roadmap" && (
          <div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#00d4aa", marginBottom: 20 }}>🗺️ Roadmap del Proyecto</h2>
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {phases.map((p, i) => {
                const colors = ["#00a9e5", "#2ecc71", "#f39c12", "#e74c3c"];
                return (
                  <div key={i} style={{ background: "rgba(255,255,255,0.03)", border: `1px solid ${colors[i]}33`, borderLeft: `4px solid ${colors[i]}`, borderRadius: 12, padding: 20 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
                      <h3 style={{ margin: 0, color: colors[i], fontSize: 16 }}>{p.phase}</h3>
                      <span style={{ fontSize: 12, color: "#6b7b9e", background: "#0d1117", padding: "4px 10px", borderRadius: 4 }}>{p.time}</span>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 8 }}>
                      {p.items.map((item, j) => (
                        <div key={j} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "#c0c8d8" }}>
                          <span style={{ color: colors[i], fontSize: 10 }}>▸</span> {item}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "24px 32px", borderTop: "1px solid #1e2a4a", marginTop: 32 }}>
        <p style={{ fontSize: 12, color: "#4a5568", margin: 0 }}>
          🐺 WazuhBOTS — Created by MrHacker (Kevin Muñoz) | Wazuh Technology Ambassador | 100% Open Source
        </p>
      </div>
    </div>
  );
}
