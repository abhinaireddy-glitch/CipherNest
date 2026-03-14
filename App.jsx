import { useState, useEffect, useRef, useCallback } from "react";

/* ─── CICIDS2017 Static Dataset ───────────────────────────────────────────── */
const DS = {
  attackDistribution:[
    {label:"DDoS",        count:128027,color:"#ff3b5c"},
    {label:"Brute Force", count:13835, color:"#ffb830"},
    {label:"PortScan",    count:158930,color:"#00d4ff"},
    {label:"Web Attack",  count:2180,  color:"#00ff9d"},
    {label:"Infiltration",count:36,    color:"#a78bfa"},
  ],
  attackIPs:[
    {ip:"172.16.0.1",    reason:"DDoS Flood",        attempts:847, since:"02:14:08",duration:"3h 22m"},
    {ip:"192.168.10.50", reason:"Brute Force Login",  attempts:312, since:"03:41:22",duration:"1h 55m"},
    {ip:"205.174.165.73",reason:"SQL Injection",      attempts:119, since:"04:07:55",duration:"1h 28m"},
    {ip:"192.168.10.19", reason:"Malware Beacon",     attempts:64,  since:"04:55:10",duration:"0h 41m"},
    {ip:"205.174.165.68",reason:"Port Scan",          attempts:28,  since:"05:12:38",duration:"0h 23m"},
    {ip:"172.16.0.11",   reason:"Brute Force Login",  attempts:1203,since:"01:30:00",duration:"4h 06m"},
    {ip:"192.168.10.51", reason:"DDoS Flood",         attempts:589, since:"02:58:14",duration:"2h 37m"},
    {ip:"205.174.165.80",reason:"Port Scan",          attempts:17,  since:"05:44:01",duration:"0h 08m"},
    {ip:"192.168.10.3",  reason:"Web Attack XSS",     attempts:44,  since:"05:58:22",duration:"0h 06m"},
    {ip:"172.16.0.5",    reason:"Web Attack SQLi",    attempts:73,  since:"06:01:10",duration:"0h 04m"},
  ],
  networkLatency:[12,14,13,18,22,45,88,134,176,210,198,165,132,98,72,55,44,38,32,28,26,30,34,41,53,67,82,110,143,165,148,120,95,74,58,46,40,36,34,32],
  errorRatio:    [0.01,0.01,0.02,0.04,0.08,0.18,0.34,0.52,0.61,0.57,0.48,0.36,0.24,0.14,0.08,0.05,0.04,0.03,0.03,0.03,0.02,0.03,0.04,0.06,0.09,0.13,0.19,0.29,0.41,0.48,0.43,0.33,0.22,0.14,0.08,0.05,0.04,0.03,0.02,0.02],
  requestRate:   [0.4,0.4,0.5,0.7,1.1,2.0,3.4,4.2,4.8,4.6,4.1,3.5,2.8,2.0,1.4,1.0,0.8,0.7,0.6,0.5,0.5,0.6,0.7,0.9,1.2,1.6,2.2,3.0,3.8,4.3,4.0,3.3,2.6,1.8,1.2,0.9,0.7,0.6,0.5,0.5],
  connDuration:  [14,13,12,10,7,4,2,1,1,1,2,3,4,6,8,10,11,12,13,13,14,13,12,11,9,7,5,3,2,1,2,3,5,7,9,11,12,13,13,14],
  uploadHistory: [38,40,41,43,48,58,72,89,104,115,112,103,92,80,68,57,49,44,41,39,38,40,42,46,53,63,76,92,108,118,114,104,93,81,70,60,51,45,42,40,39,41,43,47,55,66,79,95,110,120,116,106,95,83,72,62,53,47,43,41,40,38],
  downloadHistory:[65,68,70,75,84,97,115,138,158,172,168,155,140,125,110,96,84,76,71,67,65,68,72,78,88,102,120,144,164,176,172,159,143,128,113,99,87,79,73,68,66,69,74,81,92,107,126,150,170,180,175,162,146,130,115,101,89,81,75,69,67,65],
  ntpHosts:[
    {ip:"10.0.0.10",  host:"srv-web-01",   stratum:2,offset:0.124, lastSync:5,  status:"synced"},
    {ip:"10.0.0.11",  host:"srv-db-02",    stratum:2,offset:-0.312,lastSync:8,  status:"synced"},
    {ip:"10.0.0.12",  host:"srv-api-03",   stratum:3,offset:1.204, lastSync:12, status:"synced"},
    {ip:"10.0.1.5",   host:"wks-fin-07",   stratum:3,offset:-4.821,lastSync:45, status:"drifting"},
    {ip:"10.0.1.6",   host:"wks-hr-12",    stratum:3,offset:0.088, lastSync:7,  status:"synced"},
    {ip:"10.0.0.14",  host:"srv-mail-04",  stratum:2,offset:-0.540,lastSync:10, status:"synced"},
    {ip:"10.0.0.15",  host:"srv-proxy-05", stratum:2,offset:0.211, lastSync:6,  status:"synced"},
    {ip:"10.0.2.20",  host:"cam-lobby-01", stratum:4,offset:11.33, lastSync:180,status:"offline"},
    {ip:"10.0.2.21",  host:"cam-floor2-03",stratum:4,offset:7.940, lastSync:95, status:"drifting"},
    {ip:"10.0.1.9",   host:"wks-dev-09",   stratum:3,offset:-0.177,lastSync:14, status:"synced"},
    {ip:"10.0.0.16",  host:"srv-auth-06",  stratum:2,offset:0.033, lastSync:4,  status:"synced"},
    {ip:"10.0.1.2",   host:"wks-exec-02",  stratum:3,offset:-1.620,lastSync:30, status:"synced"},
    {ip:"10.0.3.5",   host:"iot-hvac-01",  stratum:4,offset:-9.401,lastSync:220,status:"offline"},
    {ip:"10.0.1.15",  host:"wks-ops-15",   stratum:3,offset:0.558, lastSync:18, status:"synced"},
    {ip:"10.0.0.18",  host:"srv-backup-08",stratum:2,offset:-0.092,lastSync:9,  status:"synced"},
  ],
  logEvents:[
    {sev:"CRITICAL",ev:"DDoS LOIT Flood",        proto:"UDP",  action:"blocked",ip:"172.16.0.1",     dest:"192.168.10.50",details:"2847 pkt/s Flood"},
    {sev:"CRITICAL",ev:"SSH Brute Force Login",   proto:"SSH",  action:"blocked",ip:"192.168.10.19",  dest:"192.168.10.3", details:"341 failed auths"},
    {sev:"CRITICAL",ev:"Heartbleed Exploit",      proto:"TLS",  action:"blocked",ip:"205.174.165.73", dest:"10.0.0.12",    details:"CVE-2014-0160"},
    {sev:"CRITICAL",ev:"FTP Brute Force",         proto:"FTP",  action:"blocked",ip:"192.168.10.50",  dest:"192.168.10.3", details:"211 failed auths"},
    {sev:"CRITICAL",ev:"DoS Slowloris",           proto:"HTTP", action:"blocked",ip:"205.174.165.68", dest:"192.168.10.50",details:"Socket exhaust"},
    {sev:"WARNING", ev:"PortScan SYN Sweep",      proto:"TCP",  action:"monitor",ip:"172.16.0.11",    dest:"192.168.10.0/24",details:"Ports 1-65535"},
    {sev:"WARNING", ev:"Web Attack XSS",          proto:"HTTPS",action:"blocked",ip:"192.168.10.51",  dest:"192.168.10.50",details:"Reflected XSS"},
    {sev:"WARNING", ev:"Web Attack SQL Injection",proto:"HTTPS",action:"blocked",ip:"205.174.165.80", dest:"192.168.10.50",details:"UNION SELECT"},
    {sev:"WARNING", ev:"GoldenEye HTTP Flood",    proto:"HTTP", action:"blocked",ip:"172.16.0.5",     dest:"192.168.10.50",details:"Random headers"},
    {sev:"WARNING", ev:"DoS Hulk",                proto:"HTTP", action:"blocked",ip:"192.168.10.3",   dest:"192.168.10.50",details:"800+ conn/s"},
    {sev:"INFO",    ev:"Normal HTTPS Traffic",    proto:"HTTPS",action:"allowed",ip:"203.0.113.45",   dest:"192.168.10.50",details:"GET /api/v1"},
    {sev:"INFO",    ev:"DNS Lookup",              proto:"DNS",  action:"allowed",ip:"192.168.10.100", dest:"10.0.0.1",     details:"A record query"},
    {sev:"INFO",    ev:"NTP Sync",                proto:"NTP",  action:"allowed",ip:"10.0.0.10",      dest:"10.0.0.1",     details:"Stratum 2 sync"},
    {sev:"WARNING", ev:"Infiltration Attempt",    proto:"SMTP", action:"monitor",ip:"205.174.165.73", dest:"10.0.0.14",    details:"Covert channel"},
    {sev:"CRITICAL",ev:"Botnet C2 Beacon",        proto:"IRC",  action:"blocked",ip:"192.168.10.8",   dest:"172.16.0.1",   details:"Known C2 IP"},
  ],
  alerts:[
    {type:"DDoS LOIT Flood",         sev:"CRITICAL",ip:"172.16.0.1",     time:"06:14:08"},
    {type:"SSH Brute Force",         sev:"CRITICAL",ip:"192.168.10.19",  time:"06:10:22"},
    {type:"Heartbleed Exploit",      sev:"CRITICAL",ip:"205.174.165.73", time:"06:07:55"},
    {type:"FTP Brute Force",         sev:"CRITICAL",ip:"192.168.10.50",  time:"06:05:10"},
    {type:"DoS Slowloris",           sev:"CRITICAL",ip:"205.174.165.68", time:"05:58:38"},
    {type:"Botnet C2 Beacon",        sev:"CRITICAL",ip:"192.168.10.8",   time:"05:44:01"},
    {type:"Web Attack SQL Injection",sev:"WARNING", ip:"205.174.165.80", time:"05:36:14"},
    {type:"PortScan SYN Sweep",      sev:"WARNING", ip:"172.16.0.11",    time:"05:22:30"},
    {type:"Web Attack XSS",          sev:"WARNING", ip:"192.168.10.51",  time:"05:15:44"},
    {type:"GoldenEye HTTP Flood",    sev:"WARNING", ip:"172.16.0.5",     time:"05:07:55"},
    {type:"DoS Hulk",                sev:"WARNING", ip:"192.168.10.3",   time:"04:58:20"},
    {type:"Infiltration Attempt",    sev:"WARNING", ip:"205.174.165.73", time:"04:41:10"},
    {type:"PortScan UDP Sweep",      sev:"WARNING", ip:"172.16.0.11",    time:"04:35:02"},
    {type:"Repeated Auth Failure",   sev:"WARNING", ip:"192.168.10.19",  time:"04:28:55"},
    {type:"DDoS Fragmentation",      sev:"CRITICAL",ip:"172.16.0.1",     time:"04:14:08"},
    {type:"Web Attack Brute Force",  sev:"CRITICAL",ip:"205.174.165.68", time:"04:07:22"},
    {type:"DoS SlowHTTPTest",        sev:"WARNING", ip:"192.168.10.51",  time:"03:58:11"},
    {type:"Covert Channel Detected", sev:"CRITICAL",ip:"192.168.10.9",   time:"03:44:30"},
  ],
  agents:[
    {name:"SENTINEL-01",role:"Intrusion Detection",load:72,tasks:14},
    {name:"GUARDIAN-02",role:"Firewall Manager",   load:48,tasks:8},
    {name:"ORACLE-03",  role:"Log Analyzer",       load:91,tasks:31},
    {name:"WARDEN-04",  role:"ACL Controller",     load:33,tasks:5},
    {name:"NEXUS-05",   role:"Threat Intelligence",load:60,tasks:18},
    {name:"CIPHER-06",  role:"Packet Inspector",   load:85,tasks:22},
    {name:"NEXUS-07",   role:"AI Threat Engine",   load:55,tasks:11},
    {name:"RECON-08",   role:"Port Monitor",       load:20,tasks:3},
  ],
  topThreat:{ip:"172.16.0.1",geo:"Unknown — Tor Exit Node",firstSeen:"02:14:08",attempts:847},
  metrics:{alerts:18,ips:47,events:13,load:62},
};

const THREAT_CONFIG={
  "All Traffic":    {conf:89,cve:"CVE-2024-3182",  response:"IP automatically blocked — ACL rule applied at perimeter firewall. Admin notified via SIEM alert #7841.",explain:"Detected statistically anomalous request pattern: 340 req/s from single source, deviation 6.2σ above baseline. Matching known DDoS signature."},
  "Login Attack":   {conf:95,cve:"CVE-2023-48795", response:"SSH access suspended for source IP. MFA enforcement triggered. Account lockout applied after 5 consecutive failures.",explain:"CICIDS2017 SSH Brute Force pattern: 341 failed auths in 4 min. Inter-arrival time 1.2 ms — automated tooling (Hydra/Medusa) detected."},
  "Network Attack": {conf:97,cve:"CVE-2024-21762", response:"BGP null-route advertised for attacker prefix. Upstream provider notified. Scrubbing centre activated.",explain:"CICIDS2017 DDoS LOIT pattern: 2847 pkt/s UDP flood, avg packet size 60B, high inter-arrival variance (std 0.004 ms). Classic amplification vector."},
  "Port Scan":      {conf:82,cve:"CVE-2024-0682",  response:"Scan source added to firewall denylist. IDS rule R-112 triggered. Network segment isolated pending investigation.",explain:"CICIDS2017 PortScan SYN sweep: 65535 ports probed in 38s. RST/ACK ratio 0.96 — stealth SYN scan. Source 172.16.0.11 matches known recon actor."},
  "Malware":        {conf:93,cve:"CVE-2023-44487", response:"C2 channel severed via DNS sinkhole. Infected endpoint quarantined (VLAN 999). IR team dispatched.",explain:"CICIDS2017 Infiltration signature: periodic beacon interval 60s, small encrypted payload 128B, IRC tunnel over port 6667. Known botnet fingerprint."},
};

/* ─── CSS ─────────────────────────────────────────────────────────────────── */
const CSS=`
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');
:root{--bg:#020409;--surface:#070d18;--border:#0e2040;--accent:#00d4ff;--accent2:#00ff9d;--danger:#ff3b5c;--warn:#ffb830;--muted:#2a4060;--text:#c8dff5;--dim:#4a6a90;}
.cn *{box-sizing:border-box;margin:0;padding:0;}
.cn{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;font-size:15px;min-height:100vh;overflow-x:hidden;position:relative;}
.cn::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.013) 2px,rgba(0,212,255,.013) 4px);pointer-events:none;z-index:999;}
.cn::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,212,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,.035) 1px,transparent 1px);background-size:60px 60px;pointer-events:none;z-index:0;}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes shieldPulse{0%,100%{filter:drop-shadow(0 0 8px #00d4ff)}50%{filter:drop-shadow(0 0 22px #00d4ff) drop-shadow(0 0 40px #00ff9d)}}
@keyframes threatPulse{0%,100%{box-shadow:none}50%{box-shadow:0 0 16px rgba(255,59,92,.4)}}
@keyframes rowIn{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
@keyframes confFill{from{width:0}}
@keyframes simPulse{0%,100%{box-shadow:0 0 0 0 rgba(0,255,157,.4)}50%{box-shadow:0 0 0 8px rgba(0,255,157,0)}}
@keyframes scanLine{0%{top:0}100%{top:100%}}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

/* HEADER */
.cn-hdr{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:0 32px;height:64px;background:rgba(2,4,9,.95);border-bottom:1px solid var(--border);backdrop-filter:blur(12px);}
.cn-logo{font-family:'Orbitron',monospace;font-size:19px;font-weight:900;letter-spacing:5px;color:var(--accent);text-shadow:0 0 30px var(--accent);display:flex;align-items:center;gap:12px;}
.logo-hex{width:34px;height:34px;flex-shrink:0;background:linear-gradient(135deg,var(--accent),var(--accent2));clip-path:polygon(50% 0%,93% 25%,93% 75%,50% 100%,7% 75%,7% 25%);animation:shieldPulse 2s ease-in-out infinite;}
.logo-sub{font-family:'Share Tech Mono',monospace;font-size:8px;letter-spacing:3px;color:var(--dim);margin-top:2px;}
.hdr-right{display:flex;align-items:center;gap:16px;flex-wrap:wrap;}
.nav-tabs{display:flex;gap:4px;}
.nav-tab{padding:6px 14px;border:1px solid var(--muted);border-radius:2px;background:transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;cursor:pointer;transition:all .2s;text-transform:uppercase;}
.nav-tab.active,.nav-tab:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,.07);}
.sim-toggle-wrap{display:flex;align-items:center;gap:8px;padding:5px 12px;border:1px solid var(--muted);border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--dim);cursor:pointer;transition:all .2s;user-select:none;}
.sim-toggle-wrap.active{border-color:var(--accent2);color:var(--accent2);background:rgba(0,255,157,.07);}
.sim-toggle-track{width:34px;height:18px;border-radius:9px;border:1px solid var(--muted);background:var(--muted);position:relative;transition:all .25s;}
.sim-toggle-wrap.active .sim-toggle-track{background:rgba(0,255,157,.3);border-color:var(--accent2);}
.sim-toggle-thumb{position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:var(--dim);transition:all .25s;}
.sim-toggle-wrap.active .sim-toggle-thumb{left:18px;background:var(--accent2);box-shadow:0 0 6px var(--accent2);}
.status-pill{display:flex;align-items:center;gap:8px;padding:6px 14px;border:1px solid var(--accent2);border-radius:2px;font-size:12px;letter-spacing:2px;color:var(--accent2);font-family:'Share Tech Mono',monospace;}
.sdot{width:8px;height:8px;border-radius:50%;background:var(--accent2);box-shadow:0 0 8px var(--accent2);animation:blink 1.2s ease infinite;}
.clock{font-family:'Share Tech Mono',monospace;font-size:13px;color:var(--dim);letter-spacing:2px;}
.threat-badge{padding:6px 14px;background:rgba(255,59,92,.12);border:1px solid var(--danger);border-radius:2px;font-size:12px;letter-spacing:2px;color:var(--danger);font-family:'Share Tech Mono',monospace;animation:threatPulse 2s ease infinite;}

/* SIM MODE BANNER */
.sim-banner{background:rgba(0,255,157,.06);border-bottom:1px solid rgba(0,255,157,.25);padding:6px 32px;display:flex;align-items:center;gap:12px;font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;color:var(--accent2);}
.sim-banner-dot{width:8px;height:8px;border-radius:50%;background:var(--accent2);animation:simPulse 1.2s infinite;}

/* MAIN */
.cn-main{position:relative;z-index:1;padding:28px 32px;display:flex;flex-direction:column;gap:24px;}
.sec-title{font-family:'Orbitron',monospace;font-size:11px;letter-spacing:4px;color:var(--dim);text-transform:uppercase;margin-bottom:16px;display:flex;align-items:center;gap:12px;}
.sec-title::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent);}
.metrics-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;}
.mcard{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:22px 24px;position:relative;overflow:hidden;transition:border-color .3s,transform .3s;}
.mcard:hover{border-color:var(--accent);transform:translateY(-2px);}
.mcard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.6;}
.mcard.danger::before{background:linear-gradient(90deg,transparent,var(--danger),transparent);}
.mcard.warn::before{background:linear-gradient(90deg,transparent,var(--warn),transparent);}
.mcard.green::before{background:linear-gradient(90deg,transparent,var(--accent2),transparent);}
.mc-lbl{font-size:11px;letter-spacing:3px;color:var(--dim);text-transform:uppercase;font-family:'Share Tech Mono',monospace;}
.mc-val{font-family:'Orbitron',monospace;font-size:32px;font-weight:700;margin:8px 0 4px;color:var(--accent);}
.mcard.danger .mc-val{color:var(--danger);}
.mcard.warn .mc-val{color:var(--warn);}
.mcard.green .mc-val{color:var(--accent2);}
.mc-delta{font-size:12px;letter-spacing:1px;color:var(--dim);}
.mc-delta.up{color:var(--danger);}
.mc-delta.down{color:var(--accent2);}
.mc-icon{position:absolute;right:20px;top:50%;transform:translateY(-50%);font-size:40px;opacity:.06;}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:24px;}
.three-col{display:grid;grid-template-columns:2fr 1fr;gap:24px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:24px;position:relative;}
.pc{position:absolute;width:12px;height:12px;border-color:var(--accent);border-style:solid;}
.pc.tl{top:-1px;left:-1px;border-width:2px 0 0 2px;}
.pc.tr{top:-1px;right:-1px;border-width:2px 2px 0 0;}
.pc.bl{bottom:-1px;left:-1px;border-width:0 0 2px 2px;}
.pc.br{bottom:-1px;right:-1px;border-width:0 2px 2px 0;}
.mode-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px;}
.tab{padding:7px 16px;border:1px solid var(--muted);border-radius:2px;background:transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;cursor:pointer;text-transform:uppercase;transition:all .2s;}
.tab:hover,.tab.active{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,.07);box-shadow:0 0 12px rgba(0,212,255,.15);}
.ai-box{border:1px solid var(--border);border-radius:3px;padding:16px;margin-bottom:12px;position:relative;}
.ai-lbl{position:absolute;top:-10px;left:12px;background:var(--surface);padding:0 8px;font-size:10px;letter-spacing:3px;font-family:'Share Tech Mono',monospace;color:var(--dim);}
.ai-box.detected{border-color:var(--danger);}.ai-box.detected .ai-lbl{color:var(--danger);}
.ai-box.response{border-color:var(--warn);}.ai-box.response .ai-lbl{color:var(--warn);}
.ai-box.explain{border-color:var(--accent2);}.ai-box.explain .ai-lbl{color:var(--accent2);}
.ai-box p{font-size:13px;color:var(--text);line-height:1.6;}
.conf-bar{height:4px;background:var(--muted);border-radius:2px;margin-top:10px;overflow:hidden;}
.conf-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,var(--danger),var(--warn));animation:confFill 1.2s cubic-bezier(.4,0,.2,1) both;}
.ip-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;}
.ip-cell{background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:3px;padding:12px;}
.ip-cell-lbl{font-size:10px;letter-spacing:2px;color:var(--dim);font-family:'Share Tech Mono',monospace;}
.ip-cell-val{font-family:'Orbitron',monospace;font-size:14px;color:var(--accent);margin-top:4px;}
.speed-ro{background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:4px;padding:16px;}
.speed-dir{font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:3px;margin-bottom:6px;}
.speed-big{font-family:'Orbitron',monospace;font-size:36px;font-weight:700;line-height:1;transition:color .3s;}
.speed-unit{font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;color:var(--dim);margin-bottom:10px;}
.sbar-wrap{height:4px;background:var(--muted);border-radius:2px;overflow:hidden;margin-bottom:8px;}
.sbar{height:100%;border-radius:2px;transition:width .6s cubic-bezier(.4,0,.2,1);}
.speed-sub{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:1px;color:var(--dim);}
.sspeed-stat{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:3px;padding:10px 12px;}
.ss-lbl{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);margin-bottom:4px;}
.ss-val{font-family:'Orbitron',monospace;font-size:13px;font-weight:700;}
.ntp-badge{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--accent2);border:1px solid var(--accent2);padding:4px 10px;border-radius:2px;display:flex;align-items:center;gap:6px;}
.nb{animation:blink 1s infinite;}
.ntp-sum{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px;}
.ntp-sc{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:3px;padding:10px 12px;text-align:center;}
.ntp-sl{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);margin-bottom:4px;}
.ntp-sv{font-family:'Orbitron',monospace;font-size:20px;font-weight:700;}
.ntp-sv.a2{color:var(--accent2);}.ntp-sv.warn{color:var(--warn);}.ntp-sv.danger{color:var(--danger);}
.ntp-hdr{display:grid;grid-template-columns:120px 1fr 70px 100px 90px 90px;gap:8px;padding:6px 10px;background:rgba(0,212,255,.04);border:1px solid var(--border);border-radius:3px 3px 0 0;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;margin-bottom:2px;}
.ntp-feed{display:flex;flex-direction:column;gap:2px;max-height:240px;overflow-y:auto;}
.ntp-feed::-webkit-scrollbar{width:3px;}.ntp-feed::-webkit-scrollbar-thumb{background:var(--muted);}
.ntp-row{display:grid;grid-template-columns:120px 1fr 70px 100px 90px 90px;gap:8px;align-items:center;padding:8px 10px;border:1px solid transparent;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:11px;transition:background .2s;animation:rowIn .3s ease both;}
.ntp-row:hover{background:rgba(0,212,255,.04);border-color:var(--border);}
.ntp-st{padding:2px 7px;border-radius:2px;font-size:9px;letter-spacing:2px;text-align:center;white-space:nowrap;}
.ntp-st.synced{background:rgba(0,255,157,.12);color:var(--accent2);border:1px solid var(--accent2);}
.ntp-st.drifting{background:rgba(255,184,48,.12);color:var(--warn);border:1px solid var(--warn);}
.ntp-st.offline{background:rgba(255,59,92,.12);color:var(--danger);border:1px solid var(--danger);}
.ov.good{color:var(--accent2);}.ov.warn{color:var(--warn);}.ov.bad{color:var(--danger);}
.log-filter{padding:4px 10px;border:1px solid var(--muted);border-radius:2px;background:transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;cursor:pointer;transition:all .2s;}
.log-filter:hover,.log-filter.active{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,.07);}
.log-hdr{display:grid;grid-template-columns:88px 90px 1fr 130px 130px 90px 90px 1fr;gap:8px;padding:7px 12px;background:rgba(0,212,255,.04);border:1px solid var(--border);border-radius:3px 3px 0 0;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;margin-bottom:2px;}
.log-feed{display:flex;flex-direction:column;gap:2px;max-height:420px;overflow-y:auto;}
.log-feed::-webkit-scrollbar{width:3px;}.log-feed::-webkit-scrollbar-thumb{background:var(--muted);}
.log-row{display:grid;grid-template-columns:88px 90px 1fr 130px 130px 90px 90px 1fr;gap:8px;align-items:center;padding:7px 12px;border:1px solid transparent;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:11px;transition:background .15s;animation:rowIn .25s ease both;}
.log-row:hover{background:rgba(0,212,255,.03);border-color:rgba(0,212,255,.15);}
.log-row.crit{border-left:2px solid rgba(255,59,92,.5);background:rgba(255,59,92,.02);}
.log-row.warn{border-left:2px solid rgba(255,184,48,.4);background:rgba(255,184,48,.015);}
.log-row.info{border-left:2px solid rgba(14,32,64,.9);}
.sev{padding:3px 8px;border-radius:2px;font-size:10px;letter-spacing:2px;text-align:center;font-weight:600;}
.sev.CRITICAL{background:rgba(255,59,92,.15);color:#d94f65;border:1px solid rgba(255,59,92,.5);}
.sev.WARNING{background:rgba(255,184,48,.12);color:#c8962a;border:1px solid rgba(255,184,48,.45);}
.sev.INFO{background:rgba(0,212,255,.1);color:#2a90a8;border:1px solid rgba(0,212,255,.35);}
.apill{padding:2px 7px;border-radius:2px;font-size:9px;letter-spacing:1px;text-align:center;font-weight:600;}
.apill.blocked{background:rgba(255,59,92,.12);color:#b84055;border:1px solid rgba(255,59,92,.4);}
.apill.allowed{background:rgba(0,255,157,.1);color:#2a9968;border:1px solid rgba(0,255,157,.35);}
.apill.monitor{background:rgba(255,184,48,.1);color:#b08030;border:1px solid rgba(255,184,48,.4);}
.status-bar{display:flex;align-items:center;gap:32px;padding:14px 24px;background:var(--surface);border:1px solid var(--border);border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--dim);letter-spacing:2px;}
.si{display:flex;align-items:center;gap:8px;}
.sdot-sm{width:6px;height:6px;border-radius:50%;background:var(--accent2);box-shadow:0 0 6px var(--accent2);}
.sdot-sm.warn{background:var(--warn);box-shadow:0 0 6px var(--warn);}
.rbtn{display:flex;align-items:center;gap:8px;padding:9px 12px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;cursor:pointer;transition:all .2s;width:100%;background:rgba(0,0,0,.3);}
.rbtn.primary{border:1px solid rgba(0,212,255,.35);color:#2a8aaa;}
.rbtn.primary:hover{background:rgba(0,212,255,.08);border-color:rgba(0,212,255,.6);color:#4ab0cc;}
.rbtn.danger{border:1px solid rgba(255,59,92,.35);color:#904050;}
.rbtn.danger:hover{background:rgba(255,59,92,.08);border-color:rgba(255,59,92,.6);color:#c05060;}
.rbtn.warn{border:1px solid rgba(255,184,48,.35);color:#886830;}
.rbtn.warn:hover{background:rgba(255,184,48,.08);border-color:rgba(255,184,48,.6);color:#b08840;}
.rbtn.muted{border:1px solid rgba(42,64,96,.8);color:#3a5878;}
.rbtn.muted:hover{background:rgba(0,212,255,.04);color:#4a7090;}
.rbtn:active{transform:scale(.97);}
.ubp-wrap{display:grid;grid-template-columns:280px 1fr 300px;gap:20px;padding:24px 32px;min-height:calc(100vh - 64px);}
.alert-feed{display:flex;flex-direction:column;gap:6px;overflow-y:auto;max-height:calc(100vh - 260px);}
.alert-feed::-webkit-scrollbar{width:3px;}.alert-feed::-webkit-scrollbar-thumb{background:var(--muted);}
.alert-item{padding:10px 12px;border-radius:3px;border:1px solid transparent;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:.5px;animation:rowIn .3s ease both;cursor:default;transition:background .2s;}
.alert-item:hover{background:rgba(0,212,255,.03);}
.alert-item.crit{border-color:rgba(255,59,92,.25);background:rgba(255,59,92,.04);}
.alert-item.warn{border-color:rgba(255,184,48,.2);background:rgba(255,184,48,.03);}
.aih{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;}
.agent-feed{display:flex;flex-direction:column;gap:8px;overflow-y:auto;max-height:calc(100vh - 280px);}
.agent-feed::-webkit-scrollbar{width:3px;}.agent-feed::-webkit-scrollbar-thumb{background:var(--muted);}
.agent-card{padding:12px 14px;border-radius:3px;border:1px solid var(--border);background:rgba(0,0,0,.25);animation:rowIn .3s ease both;transition:border-color .2s;}
.agent-card:hover{border-color:rgba(0,212,255,.25);}
.act{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;}
.an{font-family:'Orbitron',monospace;font-size:11px;color:var(--text);letter-spacing:1px;}
.asb{padding:2px 8px;border-radius:2px;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;}
.asb.online{background:rgba(0,255,157,.1);color:#2a9968;border:1px solid rgba(0,255,157,.3);}
.asb.busy{background:rgba(255,184,48,.1);color:#886830;border:1px solid rgba(255,184,48,.3);}
.asb.offline{background:rgba(255,59,92,.1);color:#904050;border:1px solid rgba(255,59,92,.3);}
.ameta{font-family:'Share Tech Mono',monospace;font-size:9px;color:var(--dim);line-height:1.7;}
.abw{height:3px;background:var(--muted);border-radius:2px;margin-top:8px;overflow:hidden;}
.ab{height:100%;border-radius:2px;transition:width 1.2s ease;}
.ubp-stat{background:rgba(0,0,0,.3);border-radius:3px;padding:10px;text-align:center;border:1px solid var(--border);}
.ubp-stat.danger{border-color:rgba(255,59,92,.25);}.ubp-stat.warn{border-color:rgba(255,184,48,.25);}.ubp-stat.green{border-color:rgba(0,255,157,.2);}
.usv{font-family:'Orbitron',monospace;font-size:22px;font-weight:700;}
.ubp-stat.danger .usv{color:#904050;}.ubp-stat.warn .usv{color:#886830;}.ubp-stat.green .usv{color:#2a9968;}
.usl{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);margin-top:3px;}
.ub-hdr{display:grid;grid-template-columns:70px 130px 1fr 80px 100px 80px 90px;gap:8px;padding:6px 12px;background:rgba(0,212,255,.03);border:1px solid var(--border);border-radius:3px 3px 0 0;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);margin-bottom:2px;}
.ub-list{display:flex;flex-direction:column;gap:2px;max-height:420px;overflow-y:auto;}
.ub-list::-webkit-scrollbar{width:3px;}.ub-list::-webkit-scrollbar-thumb{background:var(--muted);}
.ub-row{display:grid;grid-template-columns:70px 130px 1fr 80px 100px 80px 90px;gap:8px;align-items:center;padding:9px 12px;border:1px solid rgba(255,59,92,.15);border-left:2px solid rgba(255,59,92,.45);border-radius:3px;background:rgba(255,59,92,.03);font-family:'Share Tech Mono',monospace;font-size:11px;animation:rowIn .25s ease both;transition:background .15s;}
.ub-row:hover{background:rgba(255,59,92,.06);}
.ub-filter{padding:5px 10px;border:1px solid var(--muted);border-radius:2px;background:transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:1.5px;cursor:pointer;transition:all .2s;text-transform:uppercase;}
.ub-filter.active,.ub-filter:hover{border-color:var(--accent);color:var(--accent);background:rgba(0,212,255,.07);}
.utag{padding:2px 7px;border-radius:2px;font-size:9px;letter-spacing:2px;background:rgba(255,59,92,.12);color:#904050;border:1px solid rgba(255,59,92,.35);}
.ubbtn{padding:4px 10px;border:1px solid rgba(0,255,157,.3);border-radius:2px;background:rgba(0,255,157,.06);color:#2a9968;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;cursor:pointer;transition:all .2s;white-space:nowrap;}
.ubbtn:hover{background:rgba(0,255,157,.12);border-color:rgba(0,255,157,.6);color:#44bb88;}
.ub-input{flex:1;background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:1px;padding:8px 12px;outline:none;transition:border-color .2s;}
.ub-input::placeholder{color:var(--dim);}
.ub-input:focus{border-color:rgba(0,212,255,.4);}
.ub-submit{padding:8px 14px;border:1px solid rgba(0,212,255,.35);border-radius:3px;background:rgba(0,212,255,.07);color:#2a8aaa;font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;cursor:pointer;transition:all .2s;white-space:nowrap;}
.ub-submit:hover{background:rgba(0,212,255,.12);border-color:rgba(0,212,255,.6);color:#4ab0cc;}

/* INCIDENT REPORT page */
.ir-wrap{padding:24px 32px;display:flex;flex-direction:column;gap:24px;min-height:calc(100vh - 64px);}
.ir-tabs{display:flex;gap:6px;flex-wrap:wrap;}
.ir-tab{padding:8px 18px;border:1px solid var(--muted);border-radius:2px;background:transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:11px;letter-spacing:2px;cursor:pointer;text-transform:uppercase;transition:all .2s;}
.ir-tab.active,.ir-tab:hover{border-color:var(--accent2);color:var(--accent2);background:rgba(0,255,157,.06);}
.ir-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;}
.ir-stat{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:18px 20px;position:relative;overflow:hidden;}
.ir-stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;}
.ir-stat.d::before{background:var(--danger);}
.ir-stat.w::before{background:var(--warn);}
.ir-stat.g::before{background:var(--accent2);}
.ir-stat.a::before{background:var(--accent);}
.ir-sv{font-family:'Orbitron',monospace;font-size:28px;font-weight:700;margin:6px 0 4px;}
.ir-stat.d .ir-sv{color:var(--danger);}
.ir-stat.w .ir-sv{color:var(--warn);}
.ir-stat.g .ir-sv{color:var(--accent2);}
.ir-stat.a .ir-sv{color:var(--accent);}
.ir-sl{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;}
.ir-timeline{display:flex;flex-direction:column;gap:4px;max-height:360px;overflow-y:auto;}
.ir-timeline::-webkit-scrollbar{width:3px;}.ir-timeline::-webkit-scrollbar-thumb{background:var(--muted);}
.ir-ev{display:grid;grid-template-columns:80px 80px 1fr 100px 120px;gap:10px;align-items:center;padding:9px 12px;border:1px solid transparent;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:11px;transition:all .15s;animation:fadeIn .3s ease both;}
.ir-ev.c{border-left:2px solid rgba(255,59,92,.5);background:rgba(255,59,92,.025);}
.ir-ev.w{border-left:2px solid rgba(255,184,48,.4);background:rgba(255,184,48,.015);}
.ir-ev.i{border-left:2px solid rgba(0,212,255,.25);background:rgba(0,212,255,.008);}
.ir-ev:hover{background:rgba(0,212,255,.03);border-color:rgba(0,212,255,.15);}
.ir-hdr{display:grid;grid-template-columns:80px 80px 1fr 100px 120px;gap:10px;padding:7px 12px;background:rgba(0,212,255,.04);border:1px solid var(--border);border-radius:3px 3px 0 0;font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);text-transform:uppercase;margin-bottom:3px;}
.dl-btn{display:flex;align-items:center;justify-content:center;gap:10px;padding:12px 28px;border:1px solid rgba(0,255,157,.35);border-radius:3px;background:rgba(0,255,157,.07);color:var(--accent2);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px;cursor:pointer;transition:all .25s;text-transform:uppercase;}
.dl-btn:hover{background:rgba(0,255,157,.14);border-color:var(--accent2);box-shadow:0 0 16px rgba(0,255,157,.2);}
.dl-btn:active{transform:scale(.97);}
.report-preview{background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:3px;padding:20px;font-family:'Share Tech Mono',monospace;font-size:11px;color:var(--dim);line-height:1.9;max-height:340px;overflow-y:auto;}
.report-preview::-webkit-scrollbar{width:3px;}.report-preview::-webkit-scrollbar-thumb{background:var(--muted);}
.rp-head{color:var(--accent);font-size:13px;letter-spacing:3px;margin-bottom:12px;font-family:'Orbitron',monospace;}
.rp-section{color:var(--accent2);margin-top:10px;margin-bottom:4px;letter-spacing:2px;}
.speed-analysis{display:flex;flex-direction:column;gap:10px;margin-top:16px;padding-top:16px;border-top:1px solid var(--border);}
.sa-row{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:rgba(0,0,0,.2);border:1px solid var(--border);border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:11px;}
.sa-lbl{color:var(--dim);letter-spacing:1px;}
.sa-val{font-family:'Orbitron',monospace;font-size:13px;font-weight:700;}
.sa-bar-wrap{width:120px;height:4px;background:var(--muted);border-radius:2px;overflow:hidden;margin:0 12px;}
.sa-bar{height:100%;border-radius:2px;}

/* SIMULATION PAGE */
.sim-wrap{padding:24px 32px;display:flex;flex-direction:column;gap:24px;}
.sim-controls{display:grid;grid-template-columns:1fr 1fr;gap:20px;}
.sim-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:20px;position:relative;overflow:hidden;}
.sim-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--accent2),transparent);}
.sform-lbl{font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--dim);margin-bottom:6px;text-transform:uppercase;}
.sform-input{width:100%;background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:'Share Tech Mono',monospace;font-size:12px;padding:8px 12px;outline:none;transition:border-color .2s;margin-bottom:12px;}
.sform-input:focus{border-color:rgba(0,212,255,.4);}
.sform-select{width:100%;background:rgba(7,13,24,.95);border:1px solid var(--border);border-radius:3px;color:var(--text);font-family:'Share Tech Mono',monospace;font-size:12px;padding:8px 12px;outline:none;transition:border-color .2s;margin-bottom:12px;cursor:pointer;}
.sform-select:focus{border-color:rgba(0,212,255,.4);}
.sform-range{width:100%;accent-color:var(--accent);margin-bottom:12px;cursor:pointer;}
.sim-run-btn{width:100%;padding:12px;border:1px solid rgba(0,255,157,.35);border-radius:3px;background:rgba(0,255,157,.07);color:var(--accent2);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px;cursor:pointer;transition:all .2s;text-transform:uppercase;display:flex;align-items:center;justify-content:center;gap:10px;}
.sim-run-btn:hover{background:rgba(0,255,157,.14);border-color:var(--accent2);}
.sim-run-btn:active{transform:scale(.98);}
.sim-run-btn.running{border-color:var(--warn);color:var(--warn);background:rgba(255,184,48,.07);animation:simPulse 1s infinite;}
.sim-stop-btn{width:100%;padding:12px;border:1px solid rgba(255,59,92,.35);border-radius:3px;background:rgba(255,59,92,.07);color:var(--danger);font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px;cursor:pointer;transition:all .2s;text-transform:uppercase;display:flex;align-items:center;justify-content:center;gap:10px;}
.sim-stop-btn:hover{background:rgba(255,59,92,.14);}
.sim-stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
.sim-stat{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:3px;padding:14px;text-align:center;}
.sim-stat-val{font-family:'Orbitron',monospace;font-size:22px;font-weight:700;color:var(--accent2);}
.sim-stat-lbl{font-family:'Share Tech Mono',monospace;font-size:9px;letter-spacing:2px;color:var(--dim);margin-top:4px;}
.sim-log{background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:3px;padding:12px;height:220px;overflow-y:auto;font-family:'Share Tech Mono',monospace;font-size:11px;}
.sim-log::-webkit-scrollbar{width:3px;}.sim-log::-webkit-scrollbar-thumb{background:var(--muted);}
.sim-log-line{margin-bottom:4px;line-height:1.6;}
.upload-zone{border:2px dashed var(--muted);border-radius:4px;padding:32px;text-align:center;transition:all .3s;cursor:pointer;position:relative;}
.upload-zone:hover,.upload-zone.drag{border-color:var(--accent);background:rgba(0,212,255,.04);}
.upload-zone.has-file{border-color:var(--accent2);background:rgba(0,255,157,.04);}
.upload-icon{font-size:32px;margin-bottom:8px;opacity:.5;}
.upload-title{font-family:'Share Tech Mono',monospace;font-size:12px;letter-spacing:2px;color:var(--dim);margin-bottom:6px;}
.upload-sub{font-size:11px;color:var(--dim);opacity:.6;}
.upload-input{position:absolute;inset:0;opacity:0;cursor:pointer;}
.upload-progress{height:4px;background:var(--muted);border-radius:2px;margin-top:12px;overflow:hidden;}
.upload-bar{height:100%;background:linear-gradient(90deg,var(--accent2),var(--accent));border-radius:2px;transition:width .4s;}
.attack-type-pills{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;}
.at-pill{padding:5px 12px;border:1px solid var(--muted);border-radius:2px;background:transparent;color:var(--dim);font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:1.5px;cursor:pointer;transition:all .2s;text-transform:uppercase;}
.at-pill.active{border-color:var(--danger);color:var(--danger);background:rgba(255,59,92,.08);}
.sim-progress-wrap{background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:4px;padding:20px;}
.sim-prog-bar-wrap{height:8px;background:var(--muted);border-radius:4px;overflow:hidden;margin:12px 0;}
.sim-prog-bar{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--accent2),var(--accent));transition:width .3s;}
`;

/* ─── Chart helpers ─────────────────────────────────────────────────────── */
function useChartJS(){
  const [r,setR]=useState(!!window.Chart);
  useEffect(()=>{if(window.Chart){setR(true);return;}const s=document.createElement("script");s.src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js";s.onload=()=>setR(true);document.head.appendChild(s);},[]);
  return r;
}
function ChartCanvas({id,height=200,init,update,deps=[]}){
  const cRef=useRef(null),chRef=useRef(null);
  useEffect(()=>{if(!window.Chart||!cRef.current)return;if(chRef.current)chRef.current.destroy();chRef.current=init(cRef.current.getContext("2d"));return()=>{if(chRef.current)chRef.current.destroy();};},[]);
  useEffect(()=>{if(chRef.current&&update)update(chRef.current);},deps);
  return <canvas ref={cRef} id={id} height={height}/>;
}
function DonutChart(){
  const d=DS.attackDistribution;
  return <ChartCanvas id="cnDon" height={220} init={ctx=>new window.Chart(ctx,{type:"doughnut",data:{labels:d.map(x=>x.label),datasets:[{data:d.map(x=>x.count),backgroundColor:d.map(x=>x.color+"33"),borderColor:d.map(x=>x.color),borderWidth:2,hoverOffset:8}]},options:{cutout:"68%",plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${c.label}: ${c.parsed.toLocaleString()} events`}}},animation:{duration:600}}})}/>;
}
function NetChart({offset}){
  const ds=DS,len=ds.networkLatency.length;
  const sl=arr=>{const s=offset%len;return[...arr.slice(s),...arr.slice(0,s)];};
  return <ChartCanvas id="cnNet" height={120}
    init={ctx=>new window.Chart(ctx,{type:"line",data:{labels:Array.from({length:len},(_,i)=>i),datasets:[{label:"Latency (ms)",data:sl(ds.networkLatency),borderColor:"#ffb830",backgroundColor:"rgba(255,184,48,.06)",tension:.4,borderWidth:2,pointRadius:0,fill:true},{label:"Error Ratio",data:sl(ds.errorRatio),borderColor:"#ff3b5c",backgroundColor:"rgba(255,59,92,.06)",tension:.4,borderWidth:2,pointRadius:0,fill:true},{label:"Request Rate",data:sl(ds.requestRate),borderColor:"#00d4ff",backgroundColor:"rgba(0,212,255,.06)",tension:.4,borderWidth:2,pointRadius:0,fill:true},{label:"Conn Duration",data:sl(ds.connDuration),borderColor:"#00ff9d",backgroundColor:"rgba(0,255,157,.06)",tension:.4,borderWidth:2,pointRadius:0,fill:true}]},options:{responsive:true,animation:{duration:0},scales:{x:{display:false},y:{grid:{color:"rgba(14,32,64,.8)"},ticks:{color:"#4a6a90",font:{family:"Share Tech Mono",size:10}}}},plugins:{legend:{labels:{color:"#4a6a90",font:{family:"Share Tech Mono",size:10},boxWidth:12}}}}})}
    update={c=>{c.data.datasets[0].data=sl(ds.networkLatency);c.data.datasets[1].data=sl(ds.errorRatio);c.data.datasets[2].data=sl(ds.requestRate);c.data.datasets[3].data=sl(ds.connDuration);c.update("none");}}
    deps={[offset]}/>;
}
function SpeedChart({idx}){
  const up=DS.uploadHistory,dn=DS.downloadHistory;
  const win=(arr,i)=>Array.from({length:60},(_,j)=>arr[(i+j)%arr.length]);
  return <ChartCanvas id="cnSpd" height={140}
    init={ctx=>new window.Chart(ctx,{type:"line",data:{labels:Array(60).fill(""),datasets:[{label:"Send (Mbps)",data:win(up,idx),borderColor:"#00ff9d",backgroundColor:"rgba(0,255,157,.08)",borderWidth:2,pointRadius:0,tension:.35,fill:true},{label:"Receive (Mbps)",data:win(dn,idx),borderColor:"#00d4ff",backgroundColor:"rgba(0,212,255,.08)",borderWidth:2,pointRadius:0,tension:.35,fill:true}]},options:{responsive:true,animation:{duration:0},scales:{x:{display:false},y:{min:0,max:200,grid:{color:"rgba(14,32,64,.7)"},ticks:{color:"#4a6a90",font:{family:"Share Tech Mono",size:10},callback:v=>v+"M"}}},plugins:{legend:{labels:{color:"#4a6a90",font:{family:"Share Tech Mono",size:10},boxWidth:10}}}}})}
    update={c=>{c.data.datasets[0].data=win(up,idx);c.data.datasets[1].data=win(dn,idx);c.update("none");}}
    deps={[idx]}/>;
}
function OffsetChart(){
  const bkts=["<-8","-8:-4","-4:-2","-2:0","0:2","2:4","4:8",">8"];
  const data=()=>{const b=Array(8).fill(0);DS.ntpHosts.forEach(c=>{const o=c.offset;if(o<-8)b[0]++;else if(o<-4)b[1]++;else if(o<-2)b[2]++;else if(o<0)b[3]++;else if(o<2)b[4]++;else if(o<4)b[5]++;else if(o<8)b[6]++;else b[7]++;});return b;};
  return <ChartCanvas id="cnOff" height={60} init={ctx=>new window.Chart(ctx,{type:"bar",data:{labels:bkts,datasets:[{data:data(),backgroundColor:bkts.map((_,i)=>i===3||i===4?"rgba(0,255,157,.5)":i===2||i===5?"rgba(255,184,48,.5)":"rgba(255,59,92,.5)"),borderColor:bkts.map((_,i)=>i===3||i===4?"#00ff9d":i===2||i===5?"#ffb830":"#ff3b5c"),borderWidth:1,borderRadius:2}]},options:{responsive:true,scales:{x:{grid:{display:false},ticks:{color:"#4a6a90",font:{family:"Share Tech Mono",size:8}}},y:{grid:{color:"rgba(14,32,64,.7)"},ticks:{color:"#4a6a90",font:{family:"Share Tech Mono",size:9},stepSize:1}}},plugins:{legend:{display:false}}}})}/>;
}

/* ─── DASHBOARD PAGE (unchanged) ────────────────────────────────────────── */
function DashboardPage({onNav,simMode}){
  const chartReady=useChartJS();
  const [mode,setMode]=useState("All Traffic");
  const [logFilter,setLogFilter]=useState("ALL");
  const [netOff,setNetOff]=useState(0);
  const [spdIdx,setSpdIdx]=useState(0);
  const [logIdx,setLogIdx]=useState(0);
  const [reqStatus,setReqStatus]=useState(null);
  const [simMetrics,setSimMetrics]=useState({alerts:18,ips:47,events:13,load:62});

  useEffect(()=>{const t=setInterval(()=>setNetOff(p=>p+1),1500);return()=>clearInterval(t);},[]);
  useEffect(()=>{const t=setInterval(()=>setSpdIdx(p=>p+1),500);return()=>clearInterval(t);},[]);
  useEffect(()=>{const t=setInterval(()=>setLogIdx(p=>p+1),1200);return()=>clearInterval(t);},[]);
  useEffect(()=>{
    if(!simMode)return;
    const t=setInterval(()=>setSimMetrics(p=>({alerts:Math.max(10,Math.min(35,p.alerts+Math.round((Math.random()-.4)*2))),ips:Math.max(30,Math.min(70,p.ips+Math.round((Math.random()-.4)*3))),events:Math.max(5,Math.min(25,p.events+Math.round((Math.random()-.4)*2))),load:Math.max(40,Math.min(95,p.load+Math.round((Math.random()-.4)*5)))})),800);
    return()=>clearInterval(t);
  },[simMode]);

  const tc=THREAT_CONFIG[mode];
  const evLen=DS.logEvents.length;
  const visLogs=Array.from({length:30},(_,i)=>{const ev=DS.logEvents[(logIdx-i+evLen*100)%evLen];const d=new Date(Date.now()-i*1200);return{...ev,t:d.toTimeString().slice(0,8),id:`${logIdx}-${i}`};});
  const filteredLogs=logFilter==="ALL"?visLogs:visLogs.filter(l=>l.sev===logFilter);
  const up=DS.uploadHistory,dn=DS.downloadHistory;
  const upVal=up[spdIdx%up.length],dnVal=dn[spdIdx%dn.length];
  const peakUp=Math.max(...up),peakDn=Math.max(...dn);
  const avgUp=(up.reduce((a,b)=>a+b,0)/up.length).toFixed(1);
  const avgDn=(dn.reduce((a,b)=>a+b,0)/dn.length).toFixed(1);
  const totUp=(up.reduce((a,b)=>a+b,0)*.5/8/1000).toFixed(3);
  const totDn=(dn.reduce((a,b)=>a+b,0)*.5/8/1000).toFixed(3);
  const threat=DS.topThreat;
  const m=simMode?simMetrics:DS.metrics;

  const showRS=(msg,type)=>{setReqStatus({msg,type});setTimeout(()=>setReqStatus(null),5000);};
  const handleIR=type=>{
    if(type==="investigation"){onNav("incident");showRS("◈ Ticket INC-2847 opened — navigating to Incident Report…","primary");}
    else if(type==="report"){onNav("incident");showRS("◈ Generating CICIDS2017 PDF report — redirecting…","warn");}
    else if(type==="lockdown"){showRS("⊗ LOCKDOWN INITIATED — Perimeter ACLs enforced. All inbound blocked.","danger");}
    else{showRS("▲ ESCALATED TO SOC — Priority 1 alert raised. On-call team notified.","muted");}
  };

  const RSC={primary:{bg:"rgba(0,212,255,.1)",bd:"rgba(0,212,255,.35)",c:"#2a8aaa"},warn:{bg:"rgba(255,184,48,.1)",bd:"rgba(255,184,48,.35)",c:"#886830"},danger:{bg:"rgba(255,59,92,.1)",bd:"rgba(255,59,92,.35)",c:"#904050"},muted:{bg:"rgba(0,212,255,.07)",bd:"rgba(42,64,96,.8)",c:"#3a5878"}};

  return (
    <main className="cn-main">
      {/* metrics */}
      <div>
        <div className="sec-title">OPERATIONAL METRICS — CICIDS2017{simMode&&<span style={{color:"var(--accent2)",fontSize:10,marginLeft:8}}>[ SIMULATION ACTIVE ]</span>}</div>
        <div className="metrics-row">
          <div className="mcard danger"><div className="mc-icon">⚠</div><div className="mc-lbl">Active Alerts</div><div className="mc-val">{m.alerts}</div><div className="mc-delta up">↑ +12% vs last hour</div></div>
          <div className="mcard warn"><div className="mc-icon">🚫</div><div className="mc-lbl">Blocked IPs</div><div className="mc-val">{m.ips}</div><div className="mc-delta up">↑ +8 in last 5 min</div></div>
          <div className="mcard"><div className="mc-icon">◉</div><div className="mc-lbl">Anomalous Events</div><div className="mc-val">{m.events}</div><div className="mc-delta down">↓ −3% vs baseline</div></div>
          <div className="mcard green"><div className="mc-icon">≋</div><div className="mc-lbl">Network Load</div><div className="mc-val">{m.load}%</div><div className="mc-delta">{simMode?"SIMULATING…":"Stable — normal range"}</div></div>
        </div>
      </div>

      {/* threat engine + donut */}
      <div className="three-col">
        <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
          <div className="sec-title">AI THREAT ENGINE — CICIDS2017</div>
          <div className="mode-tabs">{Object.keys(THREAT_CONFIG).map(m2=>(<button key={m2} className={`tab${mode===m2?" active":""}`} onClick={()=>setMode(m2)}>{m2}</button>))}</div>
          <div className="ai-box detected"><span className="ai-lbl">THREAT DETECTED</span>
            <p>Attack Type: <strong style={{color:"var(--danger)"}}>{mode}</strong></p>
            <p style={{marginTop:6}}>Confidence: <strong style={{color:"var(--warn)"}}>{tc.conf}%</strong></p>
            <div className="conf-bar"><div className="conf-fill" style={{width:`${tc.conf}%`}}/></div>
          </div>
          <div className="ai-box response"><span className="ai-lbl">AUTOMATED RESPONSE</span><p>{tc.response}</p></div>
          <div className="ai-box explain"><span className="ai-lbl">AI EXPLANATION — CICIDS2017</span><p>{tc.explain} <strong style={{color:"var(--accent2)"}}>{tc.cve}</strong>.</p></div>
          <div className="ip-grid">
            <div className="ip-cell"><div className="ip-cell-lbl">THREAT IP</div><div className="ip-cell-val">{threat.ip}</div></div>
            <div className="ip-cell"><div className="ip-cell-lbl">GEO ORIGIN</div><div className="ip-cell-val" style={{fontSize:11}}>{threat.geo}</div></div>
            <div className="ip-cell"><div className="ip-cell-lbl">FIRST SEEN</div><div className="ip-cell-val">{threat.firstSeen}</div></div>
            <div className="ip-cell"><div className="ip-cell-lbl">ATTEMPTS</div><div className="ip-cell-val">{threat.attempts}</div></div>
          </div>
          <div style={{marginTop:16,borderTop:"1px solid var(--border)",paddingTop:16}}>
            <div style={{fontFamily:"Share Tech Mono",fontSize:9,letterSpacing:3,color:"var(--dim)",marginBottom:10}}>INCIDENT RESPONSE</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8}}>
              <button className="rbtn primary" onClick={()=>handleIR("investigation")}><span>⚑</span><span>Request Investigation</span></button>
              <button className="rbtn danger"  onClick={()=>handleIR("lockdown")}><span>⊗</span><span>Force Lockdown</span></button>
              <button className="rbtn warn"    onClick={()=>handleIR("report")}><span>◈</span><span>Generate Report</span></button>
              <button className="rbtn muted"   onClick={()=>handleIR("escalate")}><span>▲</span><span>Escalate to SOC</span></button>
            </div>
            {reqStatus&&<div style={{marginTop:10,padding:"8px 12px",borderRadius:3,fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:1,background:RSC[reqStatus.type]?.bg,border:`1px solid ${RSC[reqStatus.type]?.bd}`,color:RSC[reqStatus.type]?.c}}>{reqStatus.msg}</div>}
          </div>
        </div>

        <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
          <div className="sec-title">ATTACK DISTRIBUTION</div>
          {chartReady&&<DonutChart/>}
          <div style={{display:"flex",flexWrap:"wrap",gap:10,marginTop:16}}>
            {DS.attackDistribution.map(d=>(<div key={d.label} style={{display:"flex",alignItems:"center",gap:6,fontSize:11,fontFamily:"Share Tech Mono",color:d.color,letterSpacing:1}}><div style={{width:8,height:8,borderRadius:1,background:d.color}}/>{d.label}</div>))}
          </div>
          {/* Speed Analysis below pie */}
          <div className="speed-analysis">
            <div style={{fontFamily:"Share Tech Mono",fontSize:9,letterSpacing:3,color:"var(--dim)",marginBottom:4}}>SPEED ANALYSIS REPORT</div>
            {[
              {l:"Peak Upload",v:`${Math.max(...DS.uploadHistory)} Mbps`,pct:Math.max(...DS.uploadHistory)/200,c:"#00ff9d"},
              {l:"Peak Download",v:`${Math.max(...DS.downloadHistory)} Mbps`,pct:Math.max(...DS.downloadHistory)/200,c:"#00d4ff"},
              {l:"Avg Upload",v:`${(DS.uploadHistory.reduce((a,b)=>a+b)/DS.uploadHistory.length).toFixed(1)} Mbps`,pct:(DS.uploadHistory.reduce((a,b)=>a+b)/DS.uploadHistory.length)/200,c:"#00ff9d"},
              {l:"Avg Download",v:`${(DS.downloadHistory.reduce((a,b)=>a+b)/DS.downloadHistory.length).toFixed(1)} Mbps`,pct:(DS.downloadHistory.reduce((a,b)=>a+b)/DS.downloadHistory.length)/200,c:"#00d4ff"},
              {l:"Total Transferred",v:`${((DS.uploadHistory.reduce((a,b)=>a+b)+DS.downloadHistory.reduce((a,b)=>a+b))*.5/8/1000).toFixed(2)} GB`,pct:.62,c:"#ffb830"},
            ].map(s=>(<div key={s.l} className="sa-row">
              <span className="sa-lbl">{s.l}</span>
              <div className="sa-bar-wrap"><div className="sa-bar" style={{width:`${s.pct*100}%`,background:s.c}}/></div>
              <span className="sa-val" style={{color:s.c}}>{s.v}</span>
            </div>))}
          </div>
        </div>
      </div>

      {/* network chart */}
      <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div className="sec-title">NETWORK PERFORMANCE — CICIDS2017 REPLAY</div>
        {chartReady&&<NetChart offset={netOff}/>}
      </div>

      {/* throughput + ntp */}
      <div className="two-col">
        <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
          <div className="sec-title">LIVE DATA THROUGHPUT</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16,marginBottom:20}}>
            <div className="speed-ro">
              <div className="speed-dir" style={{color:"var(--accent2)"}}>▲ SEND</div>
              <div className="speed-big" style={{color:upVal>120?"var(--danger)":"var(--accent2)"}}>{upVal.toFixed(2)}</div>
              <div className="speed-unit">Mbps</div>
              <div className="sbar-wrap"><div className="sbar" style={{background:"var(--accent2)",width:`${upVal/200*100}%`}}/></div>
              <div className="speed-sub">Total: {totUp} GB</div>
            </div>
            <div className="speed-ro">
              <div className="speed-dir" style={{color:"var(--accent)"}}>▼ RECEIVE</div>
              <div className="speed-big" style={{color:dnVal>160?"var(--danger)":"var(--accent)"}}>{dnVal.toFixed(2)}</div>
              <div className="speed-unit">Mbps</div>
              <div className="sbar-wrap"><div className="sbar" style={{background:"var(--accent)",width:`${dnVal/200*100}%`}}/></div>
              <div className="speed-sub">Total: {totDn} GB</div>
            </div>
          </div>
          {chartReady&&<SpeedChart idx={spdIdx}/>}
          <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginTop:16}}>
            <div className="sspeed-stat"><div className="ss-lbl">PEAK ▲</div><div className="ss-val" style={{color:"var(--accent2)"}}>{peakUp}M</div></div>
            <div className="sspeed-stat"><div className="ss-lbl">AVG ▲</div><div className="ss-val" style={{color:"var(--accent2)"}}>{avgUp}M</div></div>
            <div className="sspeed-stat"><div className="ss-lbl">PEAK ▼</div><div className="ss-val" style={{color:"var(--accent)"}}>{peakDn}M</div></div>
            <div className="sspeed-stat"><div className="ss-lbl">AVG ▼</div><div className="ss-val" style={{color:"var(--accent)"}}>{avgDn}M</div></div>
          </div>
        </div>

        <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
            <div className="sec-title" style={{marginBottom:0,flex:1}}>TIME SERVER CLIENTS</div>
            <div className="ntp-badge"><span className="nb">●</span> NTP SYNC</div>
          </div>
          <div className="ntp-sum">
            {[{l:"TOTAL",v:DS.ntpHosts.length,c:"a2"},{l:"SYNCED",v:DS.ntpHosts.filter(c=>c.status==="synced").length,c:"a2"},{l:"DRIFTING",v:DS.ntpHosts.filter(c=>c.status==="drifting").length,c:"warn"},{l:"OFFLINE",v:DS.ntpHosts.filter(c=>c.status==="offline").length,c:"danger"}].map(s=>(<div key={s.l} className="ntp-sc"><div className="ntp-sl">{s.l}</div><div className={`ntp-sv ${s.c}`}>{s.v}</div></div>))}
          </div>
          <div className="ntp-hdr"><span>CLIENT IP</span><span>HOSTNAME</span><span>STRATUM</span><span>OFFSET (ms)</span><span>LAST SYNC</span><span>STATUS</span></div>
          <div className="ntp-feed">
            {DS.ntpHosts.map((c,i)=>{
              const oc=Math.abs(c.offset)<2?"good":Math.abs(c.offset)<8?"warn":"bad";
              const ss=c.lastSync<60?c.lastSync+"s ago":Math.floor(c.lastSync/60)+"m ago";
              return(<div key={i} className="ntp-row">
                <span style={{color:"var(--accent)"}}>{c.ip}</span>
                <span>{c.host}</span>
                <span style={{color:"var(--dim)",textAlign:"center"}}>{c.stratum}</span>
                <span className={`ov ${oc}`}>{c.offset>0?"+":""}{c.offset.toFixed(3)}</span>
                <span style={{color:"var(--dim)"}}>{ss}</span>
                <span className={`ntp-st ${c.status}`}>{c.status.toUpperCase()}</span>
              </div>);
            })}
          </div>
          <div style={{marginTop:16}}>
            <div style={{fontFamily:"Share Tech Mono",fontSize:9,letterSpacing:2,color:"var(--dim)",marginBottom:8}}>OFFSET DISTRIBUTION</div>
            {chartReady&&<OffsetChart/>}
          </div>
        </div>
      </div>

      {/* log */}
      <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
          <div className="sec-title" style={{marginBottom:0,flex:1}}>LIVE SECURITY EVENT LOG — CICIDS2017</div>
          <div style={{display:"flex",gap:8,alignItems:"center"}}>
            <span style={{fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:2,color:"var(--dim)"}}>FILTER:</span>
            {["ALL","CRITICAL","WARNING","INFO"].map(f=>(<button key={f} className={`log-filter${logFilter===f?" active":""}`} onClick={()=>setLogFilter(f)}>{f}</button>))}
          </div>
        </div>
        <div className="log-hdr"><span>SEVERITY</span><span>TIMESTAMP</span><span>EVENT TYPE</span><span>SOURCE IP</span><span>DESTINATION</span><span>PROTOCOL</span><span>ACTION</span><span>DETAILS</span></div>
        <div className="log-feed">
          {filteredLogs.map(l=>{
            const sc=l.sev==="CRITICAL"?"crit":l.sev==="WARNING"?"warn":"info";
            const ec=l.sev==="CRITICAL"?"#b85060":l.sev==="WARNING"?"#a87830":"#7aaec8";
            const ic=l.sev==="CRITICAL"?"#a84050":l.sev==="WARNING"?"#9a7228":"#2a7a96";
            return(<div key={l.id} className={`log-row ${sc}`}>
              <span className={`sev ${l.sev}`}>{l.sev}</span>
              <span style={{color:"#5a8ab0",letterSpacing:1}}>{l.t}</span>
              <span style={{color:ec,fontWeight:600}}>{l.ev}</span>
              <span style={{color:ic,fontWeight:700}}>{l.ip}</span>
              <span style={{color:"#4a7090"}}>{l.dest}</span>
              <span style={{color:"#00b8d9",letterSpacing:1}}>{l.proto}</span>
              <span className={`apill ${l.action}`}>{l.action.toUpperCase()}</span>
              <span style={{color:"#3a6080"}}>{l.details}</span>
            </div>);
          })}
        </div>
      </div>

      <div className="status-bar">
        <div className="si"><div className="sdot-sm"/>CIPHERNEST ENGINE ONLINE</div>
        <div className="si"><div className="sdot-sm"/>CICIDS2017 STREAM ACTIVE</div>
        <div className="si"><div className="sdot-sm warn"/>3 AGENTS ELEVATED</div>
        <div className="si"><div className="sdot-sm"/>SOC DASHBOARD SYNCED</div>
        {simMode&&<div className="si"><div className="sdot-sm" style={{background:"var(--accent2)",animation:"simPulse 1s infinite"}}/>SIMULATION MODE ACTIVE</div>}
        <div style={{marginLeft:"auto",color:"var(--dim)"}}>v3.2.0 — CICIDS2017 DATASET</div>
      </div>
    </main>
  );
}

/* ─── UNBLOCK PAGE (unchanged) ───────────────────────────────────────────── */
function UnblockPage(){
  const [blocked,setBlocked]=useState(DS.attackIPs.map(e=>({...e})));
  const [ubF,setUbF]=useState("ALL");
  const [inp,setInp]=useState("");
  const [ubs,setUbs]=useState(null);
  const lp=[72,48,91,33,60,85,55,20,75,50,88,30,65,80,58,22];
  const [pi,setPi]=useState(0);
  const [agents,setAgents]=useState(DS.agents.map(a=>({...a,status:a.load>80?"busy":a.load<10?"offline":"online"})));

  useEffect(()=>{
    const t=setInterval(()=>{
      setPi(p=>p+1);
      setAgents(prev=>prev.map((a,i)=>{const base=DS.agents[i].load;const v=lp[(pi+i*3)%lp.length]-50;const load=Math.max(5,Math.min(98,Math.round(base+v*.2)));return{...a,load,tasks:Math.max(0,Math.round(load/5)),status:load>82?"busy":load<8?"offline":"online"};}));
    },6000);return()=>clearInterval(t);
  },[pi]);

  const USS={success:{bg:"rgba(0,255,157,.08)",bd:"rgba(0,255,157,.3)",c:"#2a9968"},error:{bg:"rgba(255,59,92,.08)",bd:"rgba(255,59,92,.3)",c:"#904050"},warn:{bg:"rgba(255,184,48,.08)",bd:"rgba(255,184,48,.3)",c:"#886830"}};
  const showS=(msg,type)=>{setUbs({msg,type});setTimeout(()=>setUbs(null),4000);};
  const unblockOne=idx=>{const e=blocked[idx];setBlocked(p=>p.filter((_,i)=>i!==idx));showS(`✓ ${e.ip} unblocked — ACL rule removed.`,"success");};
  const unblockAll=r=>{if(r==="ALL"){const c=blocked.length;setBlocked([]);showS(`✓ All ${c} IPs unblocked.`,"success");}else{const b=blocked.length;const a=blocked.filter(e=>!e.reason.toLowerCase().includes(r.toLowerCase()));setBlocked(a);showS(`✓ ${b-a.length} IP(s) cleared.`,"success");}};
  const submit=()=>{const v=inp.trim();if(!v){showS("⚠ Enter a valid IP address.","warn");return;}if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(v)||v.split(".").some(n=>+n>255)){showS("✗ Invalid IP format.","error");return;}const idx=blocked.findIndex(e=>e.ip===v);if(idx===-1){showS(`✗ ${v} not found in blocklist.`,"error");}else{unblockOne(idx);}setInp("");};
  const filtered=ubF==="ALL"?blocked:blocked.filter(e=>e.reason.toLowerCase().includes(ubF.toLowerCase()));
  const crits=DS.alerts.filter(a=>a.sev==="CRITICAL").length,warns=DS.alerts.filter(a=>a.sev==="WARNING").length;
  const online=agents.filter(a=>a.status==="online").length,busy=agents.filter(a=>a.status==="busy").length,offline=agents.filter(a=>a.status==="offline").length;

  return(
    <div className="ubp-wrap">
      <div className="panel">
        <div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div className="sec-title">ACTIVE ALERTS</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:16}}>
          <div className="ubp-stat danger"><div className="usv">{crits}</div><div className="usl">CRITICAL</div></div>
          <div className="ubp-stat warn"><div className="usv">{warns}</div><div className="usl">WARNING</div></div>
        </div>
        <div className="alert-feed">{DS.alerts.map((a,i)=>(<div key={i} className={`alert-item ${a.sev==="CRITICAL"?"crit":"warn"}`} style={{animationDelay:`${i*.03}s`}}><div className="aih"><span style={{fontWeight:700,letterSpacing:1,color:a.sev==="CRITICAL"?"#a84050":"#886830"}}>{a.type}</span><span style={{color:"var(--dim)",fontSize:9}}>{a.time}</span></div><div style={{color:"var(--dim)",fontSize:9,marginTop:2}}>SRC: {a.ip} · {a.sev}</div></div>))}</div>
      </div>

      <div className="panel">
        <div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20}}>
          <div className="sec-title" style={{marginBottom:0,flex:1}}>IP UNBLOCK MANAGER — CICIDS2017</div>
          <div style={{fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:2,color:"var(--dim)"}}>{blocked.length} BLOCKED</div>
        </div>
        <div style={{display:"flex",gap:8,marginBottom:16}}>
          <input className="ub-input" value={inp} onChange={e=>setInp(e.target.value)} placeholder="Enter CICIDS2017 IP (e.g. 172.16.0.1)..." onKeyDown={e=>e.key==="Enter"&&submit()}/>
          <button className="ub-submit" onClick={submit}>⊘ UNBLOCK</button>
        </div>
        <div style={{display:"flex",gap:6,marginBottom:12,flexWrap:"wrap"}}>
          {["ALL","DDoS","Brute Force","SQL","Port Scan","Malware"].map(f=>(<button key={f} className={`ub-filter${ubF===f?" active":""}`} onClick={()=>setUbF(f)}>{f}</button>))}
        </div>
        <div className="ub-hdr"><span>STATUS</span><span>IP ADDRESS</span><span>REASON</span><span>ATTEMPTS</span><span>BLOCKED SINCE</span><span>DURATION</span><span>ACTION</span></div>
        <div className="ub-list">
          {filtered.length===0?<div style={{fontFamily:"Share Tech Mono",fontSize:10,color:"var(--dim)",padding:16,textAlign:"center",letterSpacing:2}}>NO ENTRIES MATCH FILTER</div>
          :filtered.map(entry=>{const gi=blocked.indexOf(entry);return(<div key={entry.ip} className="ub-row"><span className="utag">BLOCKED</span><span style={{color:"#a84050",fontWeight:700,letterSpacing:1}}>{entry.ip}</span><span>{entry.reason}</span><span style={{color:"#886830"}}>{entry.attempts.toLocaleString()}</span><span style={{color:"var(--dim)"}}>{entry.since}</span><span style={{color:"var(--dim)"}}>{entry.duration}</span><button className="ubbtn" onClick={()=>unblockOne(gi)}>✓ UNBLOCK</button></div>);})}
        </div>
        {ubs&&<div style={{marginTop:12,padding:"9px 14px",borderRadius:3,fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:1,background:USS[ubs.type]?.bg,border:`1px solid ${USS[ubs.type]?.bd}`,color:USS[ubs.type]?.c}}>{ubs.msg}</div>}
        <div style={{marginTop:16,borderTop:"1px solid var(--border)",paddingTop:14,display:"flex",alignItems:"center",gap:10}}>
          <span style={{fontFamily:"Share Tech Mono",fontSize:9,letterSpacing:2,color:"var(--dim)"}}>BULK:</span>
          <button className="rbtn warn" style={{width:"auto",padding:"7px 14px"}} onClick={()=>unblockAll("Port Scan")}><span>⊘</span> Clear Port Scans</button>
          <button className="rbtn muted" style={{width:"auto",padding:"7px 14px"}} onClick={()=>unblockAll("ALL")}><span>⊘</span> Unblock All</button>
        </div>
      </div>

      <div className="panel">
        <div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div className="sec-title">ACTIVE AGENTS</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:8,marginBottom:16}}>
          <div className="ubp-stat green"><div className="usv">{online}</div><div className="usl">ONLINE</div></div>
          <div className="ubp-stat warn"><div className="usv">{busy}</div><div className="usl">BUSY</div></div>
          <div className="ubp-stat danger"><div className="usv">{offline}</div><div className="usl">OFFLINE</div></div>
        </div>
        <div className="agent-feed">{agents.map((a,i)=>{const bc=a.load>80?"#904050":a.load>60?"#886830":"#2a9968";return(<div key={a.name} className="agent-card" style={{animationDelay:`${i*.04}s`}}><div className="act"><div className="an">{a.name}</div><span className={`asb ${a.status}`}>{a.status.toUpperCase()}</span></div><div className="ameta">ROLE: {a.role}<br/>LOAD: {a.load}% · TASKS: {a.tasks}</div><div className="abw"><div className="ab" style={{width:`${a.load}%`,background:bc}}/></div></div>);})}</div>
      </div>
    </div>
  );
}

/* ─── INCIDENT REPORT PAGE (NEW) ─────────────────────────────────────────── */
function IncidentPage(){
  const [irTab,setIrTab]=useState("summary");
  const [dlStatus,setDlStatus]=useState(null);
  const now=new Date();

  const incidents=DS.alerts.map((a,i)=>({
    id:`INC-${2847+i}`,
    sev:a.sev,
    type:a.type,
    ip:a.ip,
    time:a.time,
    status:i<3?"OPEN":i<8?"INVESTIGATING":"RESOLVED",
    agent:DS.agents[i%DS.agents.length].name,
  }));

  const crits=incidents.filter(a=>a.sev==="CRITICAL").length;
  const warns=incidents.filter(a=>a.sev==="WARNING").length;
  const open=incidents.filter(a=>a.status==="OPEN").length;
  const resolved=incidents.filter(a=>a.status==="RESOLVED").length;

  const reportText=`CIPHERNEST — CICIDS2017 INCIDENT REPORT
═══════════════════════════════════════════
REPORT ID  : RPT-${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")}-001
GENERATED  : ${now.toUTCString()}
DATASET    : CICIDS2017 (Canadian Institute for Cybersecurity)
PLATFORM   : CipherNest AI Cyber Defense Platform v3.2.0

EXECUTIVE SUMMARY
─────────────────
Total Incidents   : ${incidents.length}
Critical Alerts   : ${crits}
Warning Alerts    : ${warns}
Open Cases        : ${open}
Resolved Cases    : ${resolved}
Blocked IPs       : ${DS.metrics.ips}
Network Load      : ${DS.metrics.load}%

TOP THREAT ACTOR
─────────────────
IP Address   : ${DS.topThreat.ip}
Geo Origin   : ${DS.topThreat.geo}
First Seen   : ${DS.topThreat.firstSeen}
Attempts     : ${DS.topThreat.attempts}

ATTACK BREAKDOWN (CICIDS2017)
──────────────────────────────
${DS.attackDistribution.map(d=>`${d.label.padEnd(16)}: ${d.count.toLocaleString()} events`).join("\n")}

ML MODEL PERFORMANCE
──────────────────────
Random Forest     : 97.4% accuracy
XGBoost           : 98.1% accuracy
Isolation Forest  : 97.0% anomaly detection
Ensemble Voter    : 98.6% accuracy (AUC 0.998)

RECOMMENDED ACTIONS
────────────────────
1. Block IP range 172.16.0.0/24 at BGP level
2. Enable MFA on all SSH endpoints immediately
3. Deploy WAF rules for SQLi/XSS signatures
4. Isolate VLAN segments with Botnet C2 traffic
5. Schedule full penetration test within 72h

AGENT STATUS AT TIME OF REPORT
───────────────────────────────
${DS.agents.map(a=>`${a.name.padEnd(14)}: ${a.role.padEnd(22)} LOAD ${a.load}%`).join("\n")}
`;

  function downloadPDF(){
    setDlStatus("generating");
    setTimeout(()=>{
      try{
        const blob=new Blob([reportText],{type:"text/plain"});
        const url=URL.createObjectURL(blob);
        const a=document.createElement("a");
        a.href=url;a.download=`CipherNest_IncidentReport_${now.toISOString().slice(0,10)}.txt`;
        document.body.appendChild(a);a.click();document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setDlStatus("done");
        setTimeout(()=>setDlStatus(null),3000);
      }catch(e){setDlStatus("error");}
    },1200);
  }

  const sevColor=s=>s==="CRITICAL"?"var(--danger)":s==="WARNING"?"var(--warn)":"var(--accent)";
  const statusColor=s=>s==="OPEN"?"var(--danger)":s==="INVESTIGATING"?"var(--warn)":"var(--accent2)";

  return(
    <div className="ir-wrap">
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",flexWrap:"wrap",gap:12}}>
        <div>
          <div className="sec-title" style={{marginBottom:4}}>INCIDENT REPORT — CICIDS2017</div>
          <div style={{fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:2,color:"var(--dim)"}}>REPORT AGENT OUTPUT · {now.toUTCString()}</div>
        </div>
        <button className="dl-btn" onClick={downloadPDF} disabled={dlStatus==="generating"}>
          {dlStatus==="generating"?<><span style={{animation:"blink .6s infinite"}}>⏳</span> GENERATING…</>:dlStatus==="done"?<><span>✓</span> DOWNLOADED</>:<><span>⬇</span> DOWNLOAD REPORT (TXT/PDF)</>}
        </button>
      </div>

      {/* sub-tabs */}
      <div className="ir-tabs">
        {[["summary","SUMMARY"],["timeline","INCIDENT TIMELINE"],["agents","AGENT REPORT"],["preview","REPORT PREVIEW"]].map(([k,l])=>(<button key={k} className={`ir-tab${irTab===k?" active":""}`} onClick={()=>setIrTab(k)}>{l}</button>))}
      </div>

      {irTab==="summary"&&(
        <>
          <div className="ir-grid">
            {[{l:"Total Incidents",v:incidents.length,c:"a"},{l:"Critical Alerts",v:crits,c:"d"},{l:"Warning Alerts",v:warns,c:"w"},{l:"Open Cases",v:open,c:"d"},{l:"Resolved",v:resolved,c:"g"},{l:"Blocked IPs",v:DS.metrics.ips,c:"w"}].map(s=>(<div key={s.l} className={`ir-stat ${s.c}`}><div className="ir-sl">{s.l}</div><div className="ir-sv">{s.v}</div></div>))}
          </div>
          <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
            <div className="sec-title">ATTACK DISTRIBUTION — CICIDS2017 DATASET</div>
            {DS.attackDistribution.map(d=>(<div key={d.label} style={{display:"flex",alignItems:"center",gap:12,marginBottom:10}}>
              <span style={{fontFamily:"Share Tech Mono",fontSize:11,color:"var(--dim)",minWidth:120,letterSpacing:1}}>{d.label}</span>
              <div style={{flex:1,height:6,background:"var(--muted)",borderRadius:2,overflow:"hidden"}}><div style={{height:"100%",background:d.color,width:`${d.count/Math.max(...DS.attackDistribution.map(x=>x.count))*100}%`,transition:"width 1s"}}/></div>
              <span style={{fontFamily:"Share Tech Mono",fontSize:11,color:d.color,minWidth:80,textAlign:"right"}}>{d.count.toLocaleString()}</span>
            </div>))}
            <div style={{marginTop:16,padding:"12px 16px",background:"rgba(0,0,0,.2)",border:"1px solid var(--border)",borderRadius:3,fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:1,color:"var(--dim)",lineHeight:2}}>
              <strong style={{color:"var(--accent2)"}}>RECOMMENDED ACTIONS: </strong>
              Block 172.16.0.0/24 at BGP level · Enable MFA on SSH endpoints · Deploy WAF for SQLi/XSS · Isolate VLAN with C2 traffic · Schedule pentest within 72h
            </div>
          </div>
        </>
      )}

      {irTab==="timeline"&&(
        <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
          <div className="sec-title">FULL INCIDENT TIMELINE</div>
          <div className="ir-hdr"><span>ID</span><span>TIME</span><span>INCIDENT TYPE</span><span>SEVERITY</span><span>STATUS</span></div>
          <div className="ir-timeline">
            {incidents.map((inc,i)=>{
              const sc=inc.sev==="CRITICAL"?"c":inc.sev==="WARNING"?"w":"i";
              return(<div key={i} className={`ir-ev ${sc}`} style={{animationDelay:`${i*.02}s`}}>
                <span style={{color:"var(--accent)",fontWeight:700}}>{inc.id}</span>
                <span style={{color:"var(--dim)"}}>{inc.time}</span>
                <span style={{color:sevColor(inc.sev)}}>{inc.type}</span>
                <span className={`sev ${inc.sev}`} style={{fontSize:9,padding:"2px 6px"}}>{inc.sev}</span>
                <span style={{color:statusColor(inc.status),fontWeight:700,letterSpacing:1}}>{inc.status}</span>
              </div>);
            })}
          </div>
        </div>
      )}

      {irTab==="agents"&&(
        <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(280px,1fr))",gap:16}}>
          {DS.agents.map((a,i)=>{const bc=a.load>80?"var(--danger)":a.load>60?"var(--warn)":"var(--accent2)";return(
            <div key={a.name} className="panel" style={{animationDelay:`${i*.05}s`}}><div className="pc tl"/><div className="pc br"/>
              <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
                <div style={{fontFamily:"Orbitron,monospace",fontSize:12,color:"var(--text)",letterSpacing:1}}>{a.name}</div>
                <span className={`asb ${a.load>80?"busy":"online"}`}>{a.load>80?"BUSY":"ONLINE"}</span>
              </div>
              <div style={{fontFamily:"Share Tech Mono",fontSize:10,color:"var(--dim)",lineHeight:2}}>
                ROLE: {a.role}<br/>LOAD: <span style={{color:bc}}>{a.load}%</span> · ACTIVE TASKS: {a.tasks}
              </div>
              <div className="abw" style={{marginTop:10}}><div className="ab" style={{width:`${a.load}%`,background:bc}}/></div>
              <div style={{marginTop:10,padding:"8px 10px",background:"rgba(0,0,0,.2)",border:"1px solid var(--border)",borderRadius:3,fontFamily:"Share Tech Mono",fontSize:10,color:"var(--dim)"}}>
                LAST ACTION: {DS.logEvents[i%DS.logEvents.length].ev}<br/>
                PROTOCOL: {DS.logEvents[i%DS.logEvents.length].proto} · {DS.logEvents[i%DS.logEvents.length].action.toUpperCase()}
              </div>
            </div>
          );})}
        </div>
      )}

      {irTab==="preview"&&(
        <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
          <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16}}>
            <div className="sec-title" style={{marginBottom:0}}>REPORT PREVIEW</div>
            <button className="dl-btn" style={{padding:"8px 18px",fontSize:11}} onClick={downloadPDF}>⬇ DOWNLOAD</button>
          </div>
          <div className="report-preview">
            <div className="rp-head">CIPHERNEST INCIDENT REPORT</div>
            {reportText.split("\n").map((l,i)=>(
              <div key={i} style={{color:l.startsWith("═")||l.startsWith("─")||l.startsWith("─")?"var(--border)":l.startsWith("CIPHERNEST")||l.endsWith("──────────────")?"var(--accent)":l.includes(":")?"var(--text)":"var(--dim)"}}>{l||<br/>}</div>
            ))}
          </div>
          {dlStatus&&<div style={{marginTop:12,padding:"8px 14px",borderRadius:3,fontFamily:"Share Tech Mono",fontSize:10,letterSpacing:1,background:dlStatus==="done"?"rgba(0,255,157,.08)":"rgba(0,212,255,.08)",border:`1px solid ${dlStatus==="done"?"rgba(0,255,157,.3)":"rgba(0,212,255,.3)"}`,color:dlStatus==="done"?"var(--accent2)":"var(--accent)"}}>{dlStatus==="done"?"✓ Report downloaded successfully!":"⏳ Generating report…"}</div>}
        </div>
      )}
    </div>
  );
}

/* ─── SIMULATION + LOAD TEST PAGE (NEW) ─────────────────────────────────── */
const SIM_ATTACK_TYPES=["DDoS LOIT Flood","SSH Brute Force","SQL Injection","Port Scan","Heartbleed","GoldenEye","DoS Slowloris","XSS Web Attack","Botnet C2","FTP Brute Force"];
const SIM_LOG_MSGS=[
  t=>`[${t}] MONITOR    → Flow ingested: ${Math.floor(Math.random()*4000+1000)} pkt/s`,
  t=>`[${t}] ANALYZER   → Anomaly score: ${(Math.random()*.4+.6).toFixed(3)} — flagged for ML`,
  t=>`[${t}] THREAT     → Signature match: ${SIM_ATTACK_TYPES[Math.floor(Math.random()*SIM_ATTACK_TYPES.length)]}`,
  t=>`[${t}] ML-ENGINE  → RF prediction: MALICIOUS (conf ${Math.floor(Math.random()*20+80)}%)`,
  t=>`[${t}] DECISION   → Score > 0.85 — AUTO-BLOCK triggered`,
  t=>`[${t}] RESPONSE   → Firewall rule added: DROP ${["172.16.0","192.168.10","205.174.165"][Math.floor(Math.random()*3)]}.${Math.floor(Math.random()*254)+1}`,
  t=>`[${t}] LEARNING   → Sample queued for retraining (total: ${Math.floor(Math.random()*200+400)})`,
  t=>`[${t}] REPORT     → Incident #INC-${Math.floor(Math.random()*9000+1000)} logged to SIEM`,
];

function SimPage(){
  const [running,setRunning]=useState(false);
  const [progress,setProgress]=useState(0);
  const [simLogs,setSimLogs]=useState([]);
  const [stats,setStats]=useState({flows:0,threats:0,blocked:0,accuracy:0});
  const [attackTypes,setAttackTypes]=useState(["DDoS LOIT Flood","SSH Brute Force"]);
  const [intensity,setIntensity]=useState(50);
  const [duration,setDuration]=useState(30);
  const [uploadFile,setUploadFile]=useState(null);
  const [uploadProgress,setUploadProgress]=useState(0);
  const [dragOver,setDragOver]=useState(false);
  const [loadTestRunning,setLoadTestRunning]=useState(false);
  const [loadTestResults,setLoadTestResults]=useState(null);
  const [ltConcurrent,setLtConcurrent]=useState(100);
  const [ltDuration,setLtDuration]=useState(10);
  const simRef=useRef(null);
  const logRef=useRef(null);

  function toggleAttack(t){setAttackTypes(p=>p.includes(t)?p.filter(x=>x!==t):[...p,t]);}

  function addLog(msg,color="#c8dff5"){
    setSimLogs(p=>{const next=[...p,{msg,color,id:Date.now()+Math.random()}];return next.slice(-80);});
    setTimeout(()=>{if(logRef.current)logRef.current.scrollTop=logRef.current.scrollHeight;},50);
  }

  function startSim(){
    if(running)return;
    setRunning(true);setProgress(0);setSimLogs([]);
    setStats({flows:0,threats:0,blocked:0,accuracy:0});
    const total=duration*1000;const start=Date.now();
    addLog(`▶ Simulation started — ${attackTypes.length} attack type(s) · intensity ${intensity}% · duration ${duration}s`,"#00ff9d");
    addLog(`  Dataset: ${uploadFile?uploadFile.name:"CICIDS2017 (built-in)"}  Mode: ${uploadFile?"Custom Upload":"Synthetic"}`,"#4a6a90");
    simRef.current=setInterval(()=>{
      const elapsed=Date.now()-start;const pct=Math.min(100,elapsed/total*100);setProgress(pct);
      const t=new Date().toTimeString().slice(0,8);
      const fn=SIM_LOG_MSGS[Math.floor(Math.random()*SIM_LOG_MSGS.length)];
      const isBlock=Math.random()>.6;
      addLog(fn(t),isBlock?"#ff3b5c":Math.random()>.5?"#ffb830":"#4a9090");
      setStats(p=>({
        flows:p.flows+Math.floor(Math.random()*intensity*2+20),
        threats:p.threats+(Math.random()>.55?1:0),
        blocked:p.blocked+(Math.random()>.7?1:0),
        accuracy:Math.round(95+Math.random()*4),
      }));
      if(elapsed>=total){clearInterval(simRef.current);setRunning(false);setProgress(100);addLog(`■ Simulation complete.`,"#00ff9d");}
    },300);
  }
  function stopSim(){clearInterval(simRef.current);setRunning(false);addLog(`■ Simulation stopped by user.`,"#ffb830");}
  useEffect(()=>()=>clearInterval(simRef.current),[]);

  function handleFile(file){
    if(!file)return;
    setUploadFile(file);setUploadProgress(0);
    addLog(`📂 Loading dataset: ${file.name} (${(file.size/1024).toFixed(1)} KB)`,"#00d4ff");
    let p=0;const t=setInterval(()=>{p+=Math.random()*15+5;setUploadProgress(Math.min(100,p));if(p>=100){clearInterval(t);addLog(`✓ Dataset loaded: ${file.name}`,"#00ff9d");}},120);
  }

  function runLoadTest(){
    setLoadTestRunning(true);setLoadTestResults(null);
    addLog(`⚡ Load test started — ${ltConcurrent} concurrent · ${ltDuration}s`,"#ffb830");
    setTimeout(()=>{
      const r={rps:Math.floor(ltConcurrent*Math.random()*800+400),p50:Math.floor(Math.random()*20+5),p95:Math.floor(Math.random()*80+40),p99:Math.floor(Math.random()*200+100),errors:Math.floor(Math.random()*ltConcurrent*.05),throughput:(ltConcurrent*Math.random()*1.2+0.5).toFixed(2)};
      setLoadTestResults(r);setLoadTestRunning(false);
      addLog(`✓ Load test complete — ${r.rps} req/s · p95 ${r.p95}ms · errors ${r.errors}`,"#00ff9d");
    },ltDuration*1000/3);
  }

  return(
    <div className="sim-wrap">
      <div className="sec-title">SIMULATION MODE & LOAD TEST — CICIDS2017</div>

      {/* Dataset upload */}
      <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div className="sec-title">DATASET UPLOAD</div>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:20}}>
          <div>
            <div
              className={`upload-zone${uploadFile?" has-file":""}${dragOver?" drag":""}`}
              onDragOver={e=>{e.preventDefault();setDragOver(true);}}
              onDragLeave={()=>setDragOver(false)}
              onDrop={e=>{e.preventDefault();setDragOver(false);const f=e.dataTransfer.files[0];if(f)handleFile(f);}}
            >
              <input className="upload-input" type="file" accept=".csv,.pcap,.txt,.json" onChange={e=>handleFile(e.target.files[0])}/>
              <div className="upload-icon">{uploadFile?"✓":"⬆"}</div>
              <div className="upload-title">{uploadFile?uploadFile.name:"DRAG & DROP DATASET"}</div>
              <div className="upload-sub">{uploadFile?`${(uploadFile.size/1024).toFixed(1)} KB loaded`:"Supports CICIDS CSV · PCAP · JSON · TXT"}</div>
              {uploadFile&&<div className="upload-progress"><div className="upload-bar" style={{width:`${uploadProgress}%`}}/></div>}
            </div>
          </div>
          <div>
            <div className="sform-lbl">SUPPORTED FORMATS</div>
            {[{f:"CICIDS2017/2018 CSV",d:"Original feature export from ISCX"},
              {f:"PCAP Network Capture",d:"Raw packet data for replay"},
              {f:"Custom JSON",d:"Pre-labelled flow records"},
              {f:"Plain Text Logs",d:"Syslog / IDS log format"},
            ].map(r=>(<div key={r.f} style={{display:"flex",justifyContent:"space-between",padding:"7px 10px",background:"rgba(0,0,0,.2)",border:"1px solid var(--border)",borderRadius:3,marginBottom:6,fontFamily:"Share Tech Mono",fontSize:10}}>
              <span style={{color:"var(--accent)",letterSpacing:1}}>{r.f}</span>
              <span style={{color:"var(--dim)"}}>{r.d}</span>
            </div>))}
            {!uploadFile&&<div style={{marginTop:8,padding:"8px 12px",background:"rgba(0,212,255,.05)",border:"1px solid rgba(0,212,255,.15)",borderRadius:3,fontFamily:"Share Tech Mono",fontSize:10,color:"var(--dim)"}}>No file loaded — using CICIDS2017 built-in dataset</div>}
          </div>
        </div>
      </div>

      {/* Sim controls */}
      <div className="sim-controls">
        <div className="sim-card">
          <div className="sec-title">SIMULATION PARAMETERS</div>
          <div className="sform-lbl">ATTACK TYPES TO SIMULATE</div>
          <div className="attack-type-pills">
            {SIM_ATTACK_TYPES.map(t=>(<button key={t} className={`at-pill${attackTypes.includes(t)?" active":""}`} onClick={()=>toggleAttack(t)}>{t}</button>))}
          </div>
          <div className="sform-lbl">INTENSITY — {intensity}%</div>
          <input type="range" className="sform-range" min={10} max={100} value={intensity} onChange={e=>setIntensity(+e.target.value)}/>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:16}}>
            <div>
              <div className="sform-lbl">DURATION (seconds)</div>
              <input className="sform-input" type="number" min={5} max={120} value={duration} onChange={e=>setDuration(+e.target.value)}/>
            </div>
            <div>
              <div className="sform-lbl">DATASET SOURCE</div>
              <select className="sform-select" value={uploadFile?"custom":"builtin"} onChange={()=>{}}>
                <option value="builtin">CICIDS2017 Built-in</option>
                {uploadFile&&<option value="custom">{uploadFile.name}</option>}
              </select>
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
            <button className={`sim-run-btn${running?" running":""}`} onClick={startSim} disabled={running}>{running?<><span style={{animation:"blink .5s infinite"}}>●</span> SIMULATING…</>:<><span>▶</span> RUN SIMULATION</>}</button>
            <button className="sim-stop-btn" onClick={stopSim} disabled={!running}><span>■</span> STOP</button>
          </div>
        </div>

        <div className="sim-card">
          <div className="sec-title">LOAD TEST</div>
          <div className="sform-lbl">CONCURRENT CONNECTIONS — {ltConcurrent}</div>
          <input type="range" className="sform-range" min={10} max={1000} value={ltConcurrent} onChange={e=>setLtConcurrent(+e.target.value)}/>
          <div className="sform-lbl">TEST DURATION (seconds) — {ltDuration}s</div>
          <input type="range" className="sform-range" min={5} max={60} value={ltDuration} onChange={e=>setLtDuration(+e.target.value)}/>
          <div className="sform-lbl">PROTOCOL MIX</div>
          <select className="sform-select">
            <option>HTTP/HTTPS Mixed (realistic)</option>
            <option>UDP Flood (DDoS simulation)</option>
            <option>TCP SYN Flood</option>
            <option>ICMP Ping Flood</option>
            <option>DNS Amplification</option>
          </select>
          <button className={`sim-run-btn${loadTestRunning?" running":""}`} style={{marginBottom:12}} onClick={runLoadTest} disabled={loadTestRunning}>
            {loadTestRunning?<><span style={{animation:"blink .5s infinite"}}>●</span> RUNNING LOAD TEST…</>:<><span>⚡</span> RUN LOAD TEST</>}
          </button>
          {loadTestResults&&(
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
              {[{l:"REQ/S",v:loadTestResults.rps,c:"var(--accent2)"},{l:"P50 ms",v:loadTestResults.p50,c:"var(--accent)"},{l:"P95 ms",v:loadTestResults.p95,c:"var(--warn)"},{l:"P99 ms",v:loadTestResults.p99,c:"var(--danger)"},{l:"ERRORS",v:loadTestResults.errors,c:"var(--danger)"},{l:"GBPS",v:loadTestResults.throughput,c:"var(--accent2)"}].map(r=>(<div key={r.l} style={{background:"rgba(0,0,0,.3)",border:"1px solid var(--border)",borderRadius:3,padding:"10px 8px",textAlign:"center"}}><div style={{fontFamily:"Orbitron,monospace",fontSize:16,fontWeight:700,color:r.c}}>{r.v}</div><div style={{fontFamily:"Share Tech Mono",fontSize:9,letterSpacing:1.5,color:"var(--dim)",marginTop:3}}>{r.l}</div></div>))}
            </div>
          )}
        </div>
      </div>

      {/* live stats */}
      {(running||stats.flows>0)&&(
        <div>
          <div className="sec-title">LIVE SIMULATION METRICS</div>
          <div className="sim-stats-grid">
            {[{l:"FLOWS PROCESSED",v:stats.flows.toLocaleString(),c:"var(--accent)"},{l:"THREATS DETECTED",v:stats.threats,c:"var(--danger)"},{l:"IPS BLOCKED",v:stats.blocked,c:"var(--warn)"},{l:"ML ACCURACY",v:`${stats.accuracy}%`,c:"var(--accent2)"}].map(s=>(<div key={s.l} className="sim-stat"><div className="sim-stat-val" style={{color:s.c}}>{s.v}</div><div className="sim-stat-lbl">{s.l}</div></div>))}
          </div>
          {running&&(<div className="sim-progress-wrap" style={{marginTop:12}}><div style={{display:"flex",justifyContent:"space-between",marginBottom:4,fontFamily:"Share Tech Mono",fontSize:10,color:"var(--dim)"}}><span>SIMULATION PROGRESS</span><span style={{color:"var(--accent2)"}}>{Math.round(progress)}%</span></div><div className="sim-prog-bar-wrap"><div className="sim-prog-bar" style={{width:`${progress}%`}}/></div></div>)}
        </div>
      )}

      {/* log output */}
      <div className="panel"><div className="pc tl"/><div className="pc tr"/><div className="pc bl"/><div className="pc br"/>
        <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:12}}>
          <div className="sec-title" style={{marginBottom:0}}>AGENT PIPELINE LOG</div>
          <button onClick={()=>setSimLogs([])} style={{padding:"4px 10px",border:"1px solid var(--muted)",borderRadius:2,background:"transparent",color:"var(--dim)",fontFamily:"Share Tech Mono",fontSize:9,letterSpacing:2,cursor:"pointer"}}>CLEAR</button>
        </div>
        <div ref={logRef} className="sim-log">
          {simLogs.length===0?(<div style={{color:"var(--dim)",letterSpacing:2}}>// Waiting for simulation to start…</div>):simLogs.map(l=>(<div key={l.id} className="sim-log-line" style={{color:l.color}}>{l.msg}</div>))}
        </div>
      </div>
    </div>
  );
}

/* ─── ROOT APP ────────────────────────────────────────────────────────────── */
export default function App(){
  const [page,setPage]=useState("dashboard");
  const [clock,setClock]=useState("");
  const [simMode,setSimMode]=useState(false);

  useEffect(()=>{const t=setInterval(()=>setClock(new Date().toTimeString().slice(0,8)+" UTC"),1000);setClock(new Date().toTimeString().slice(0,8)+" UTC");return()=>clearInterval(t);},[]);

  const PAGES=[["dashboard","DASHBOARD"],["unblock","UNBLOCK MANAGER"],["incident","INCIDENT REPORT"],["simulation","SIMULATION & LOAD TEST"]];

  return(
    <div className="cn">
      <style>{CSS}</style>

      <header className="cn-hdr">
        <div className="cn-logo">
          <div className="logo-hex"/>
          <div>CIPHERNEST<div className="logo-sub">AI CYBER DEFENSE PLATFORM</div></div>
        </div>
        <div className="hdr-right">
          <div className="nav-tabs">
            {PAGES.map(([k,l])=>(<button key={k} className={`nav-tab${page===k?" active":""}`} onClick={()=>setPage(k)}>{l}</button>))}
          </div>
          {/* Simulation toggle */}
          <div className={`sim-toggle-wrap${simMode?" active":""}`} onClick={()=>setSimMode(p=>!p)}>
            <div className="sim-toggle-track"><div className="sim-toggle-thumb"/></div>
            SIM MODE
          </div>
          <div className="status-pill"><div className="sdot"/>ALL SYSTEMS NOMINAL</div>
          <div className="clock">{clock}</div>
          <div className="threat-badge">THREAT LEVEL: HIGH</div>
        </div>
      </header>

      {simMode&&(
        <div className="sim-banner">
          <div className="sim-banner-dot"/>
          SIMULATION MODE ACTIVE — Live metrics are synthetically generated · CICIDS2017 dataset replay engaged
        </div>
      )}

      {page==="dashboard"  &&<DashboardPage onNav={setPage} simMode={simMode}/>}
      {page==="unblock"    &&<UnblockPage/>}
      {page==="incident"   &&<IncidentPage/>}
      {page==="simulation" &&<SimPage/>}
    </div>
  );
}
