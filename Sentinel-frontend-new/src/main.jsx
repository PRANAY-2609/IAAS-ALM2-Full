import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = "http://127.0.0.1:5000";
function App() {
  const [rules,setRules]=useState([]), [alerts,setAlerts]=useState([]), [stats,setStats]=useState({total_events:0,total_alerts:0,sources:[]});
  const [kind,setKind]=useState("HTTP"), [ip,setIp]=useState("10.0.0.10"), [action,setAction]=useState("block"), [ruleIp,setRuleIp]=useState("*"), [port,setPort]=useState("*"), [protocol,setProtocol]=useState("*"), [description,setDescription]=useState("Custom firewall rule");
  const [traffic,setTraffic]=useState([]), [threats,setThreats]=useState([]), [error,setError]=useState(""), [notice,setNotice]=useState("");
  async function api(path,options={}) {
    const r=await fetch(API+path,{...options,headers:{"Content-Type":"application/json",...(options.headers||{})}});
    const d=await r.json(); if(!r.ok) throw new Error(d.error||"Request failed"); return d;
  }
  async function refresh(){
    try { const [r,a,s,t,e]=await Promise.all([api("/api/rules"),api("/api/alerts"),api("/api/stats"),api("/api/threats"),api("/api/events").catch(()=>[])]);
      setRules(r);setAlerts(a);setStats(s);setThreats(t);setTraffic(e);
    } catch { setError("Cannot reach backend. Start the Flask API on port 5000."); }
  }
  // Event endpoint is intentionally defined below by using the local list updated from each traffic response.
  useEffect(()=>{refresh();},[]);
  async function addRule(ev){
    ev.preventDefault();setError("");setNotice("");
    try{await api("/api/rules",{method:"POST",body:JSON.stringify({action,source_ip:ruleIp,port,protocol,description})});setNotice("Firewall rule added.");await refresh();}
    catch(e){setError(e.message);}
  }
  async function deleteRule(id){try{await api(`/api/rules/${id}`,{method:"DELETE"});setNotice("Rule deleted.");await refresh();}catch(e){setError(e.message);}}
  async function generate(){
    setError("");setNotice("");
    try{const d=await api("/api/traffic",{method:"POST",body:JSON.stringify({kind,source_ip:ip})});setTraffic(old=>[d.packet,...old].slice(0,30));setNotice(`Simulated ${kind} traffic: ${d.packet.firewall_action.toUpperCase()}.`);await refresh();}
    catch(e){setError(e.message);}
  }
  async function reset(){try{await api("/api/reset",{method:"POST",body:"{}"});setTraffic([]);setNotice("Traffic and alerts cleared.");await refresh();}catch(e){setError(e.message);}}
  return <main>
    <header><div className="eyebrow">ALM-2 · PROJECT 3</div><h1>🛡️ Sentinel</h1><p>Firewall and intrusion-detection simulator</p></header>
    {error&&<div className="error">{error}</div>}{notice&&<div className="notice">{notice}</div>}
    <div className="metrics"><div><small>Simulated packets</small><b>{stats.total_events}</b></div><div><small>IDS / firewall alerts</small><b>{stats.total_alerts}</b></div><div><small>Active firewall rules</small><b>{rules.length}</b></div></div>
    <section className="panel"><h2>Traffic generator</h2><p className="muted">Generate sample traffic locally; no real packets are sent.</p>
      <div className="formgrid"><label>Traffic type<select value={kind} onChange={e=>setKind(e.target.value)}><option>HTTP</option><option>SSH_SUCCESS</option><option>SSH_FAIL</option><option>TELNET</option><option>UDP</option><option>PORT_SCAN</option></select></label><label>Simulated source IP<input value={ip} onChange={e=>setIp(e.target.value)} /></label></div>
      <div className="actions"><button className="primary" onClick={generate}>Generate traffic</button><button onClick={reset}>Clear events & alerts</button></div>
    </section>
    <section className="panel"><h2>Firewall rule manager</h2><form onSubmit={addRule}>
      <div className="formgrid"><label>Action<select value={action} onChange={e=>setAction(e.target.value)}><option value="block">Block</option><option value="allow">Allow</option></select></label><label>Source IP or *<input value={ruleIp} onChange={e=>setRuleIp(e.target.value)} required/></label><label>Port or *<input value={port} onChange={e=>setPort(e.target.value)} required/></label><label>Protocol<select value={protocol} onChange={e=>setProtocol(e.target.value)}><option>*</option><option>TCP</option><option>UDP</option><option>ICMP</option></select></label></div>
      <label>Description<input value={description} onChange={e=>setDescription(e.target.value)} required/></label><button className="primary" type="submit">+ Add rule</button>
    </form>
    <div className="tablewrap"><table><thead><tr><th>Action</th><th>Source IP</th><th>Port</th><th>Protocol</th><th>Description</th><th></th></tr></thead><tbody>{rules.map(r=><tr key={r.id}><td><span className={`tag ${r.action}`}>{r.action}</span></td><td>{r.source_ip}</td><td>{r.port}</td><td>{r.protocol}</td><td>{r.description}</td><td><button className="small" onClick={()=>deleteRule(r.id)}>Delete</button></td></tr>)}</tbody></table></div>
      <p className="hint">Rules are evaluated from top to bottom. First matching rule wins; unmatched traffic defaults to allow in this demo.</p>
    </section>
    <section className="panel"><div className="section-title"><h2>IDS alert feed</h2><span className="pill">LATEST FIRST</span></div>
      {alerts.length===0?<p className="muted">No alerts yet. Try five SSH_FAIL events from the same IP, or generate TELNET traffic.</p>:<div className="alerts">{alerts.map(a=><article className="alert" key={a.id}><div><b>{a.type}</b><span className={`severity ${a.severity.toLowerCase()}`}>{a.severity}</span></div><p>{a.message}</p><small>{a.time} · Source {a.source_ip}</small></article>)}</div>}
    </section>
    <section className="panel"><h2>Recent simulated traffic</h2>{traffic.length===0?<p className="muted">Generate traffic to see events here.</p>:<div className="tablewrap"><table><thead><tr><th>Time</th><th>Type</th><th>Source IP</th><th>Port</th><th>Firewall</th><th>Matched rule</th></tr></thead><tbody>{traffic.map((e,i)=><tr key={i}><td>{e.time}</td><td>{e.kind}</td><td>{e.source_ip}</td><td>{e.port}</td><td><span className={`tag ${e.firewall_action}`}>{e.firewall_action}</span></td><td>{e.matched_rule}</td></tr>)}</tbody></table></div>}</section>
    <section className="panel"><h2>Threat encyclopedia</h2><p className="muted">Conceptual reference: common malware types and defenses.</p><div className="threatgrid">{threats.map(t=><article className="threat" key={t.name}><span className="pill">{t.type}</span><h3>{t.name}</h3><p>{t.description}</p><b>Countermeasures</b><p>{t.countermeasure}</p></article>)}</div></section>
    <footer>Educational simulation only · Does not inspect or block real network traffic</footer>
  </main>;
}
createRoot(document.getElementById("root")).render(<App />);
