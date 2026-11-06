import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = "http://127.0.0.1:5000";
function App() {
  const [protocol, setProtocol] = useState("tls");
  const [steps, setSteps] = useState([]);
  const [index, setIndex] = useState(-1);
  const [auth, setAuth] = useState(true);
  const [session, setSession] = useState(null);
  const [mode, setMode] = useState("transport");
  const [packet, setPacket] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setIndex(-1); setSession(null); setError("");
    fetch(`${API}/api/handshake/${protocol}`)
      .then(r => r.json()).then(d => setSteps(d.steps || []))
      .catch(() => setError("Cannot reach backend. Start the Flask API on port 5000."));
  }, [protocol]);

  async function startSession() {
    try {
      const r = await fetch(`${API}/api/session-demo`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({authenticated:auth})});
      setSession(await r.json());
    } catch { setError("Backend is not running."); }
  }
  async function showPacket() {
    try {
      const r = await fetch(`${API}/api/ipsec`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({mode})});
      setPacket(await r.json());
    } catch { setError("Backend is not running."); }
  }

  const current = steps[index];
  return <main>
    <header><div className="eyebrow">ALM-2 · PROJECT 2</div><h1>🔐 SecureTunnel</h1><p>Explore how secure channels are negotiated.</p></header>
    {error && <div className="error">{error}</div>}
    <section className="panel">
      <div className="section-title"><h2>Handshake visualizer</h2><span className="pill">SIMULATION</span></div>
      <div className="tabs">
        <button className={protocol==="tls"?"active":""} onClick={()=>setProtocol("tls")}>TLS / SSL</button>
        <button className={protocol==="ssh"?"active":""} onClick={()=>setProtocol("ssh")}>SSH</button>
      </div>
      <div className="parties"><div className="party"><span>💻</span><b>Client</b><small>Browser / user</small></div><div className="wire">⇄</div><div className="party"><span>🖥️</span><b>Server</b><small>Remote service</small></div></div>
      <div className="step-list">{steps.map((s,i)=><div key={s.title} className={`step ${i===index?"selected":i<index?"done":""}`}><span className="number">{i<index?"✓":i+1}</span><div><b>{s.title}</b><small>{s.from} → {s.to}</small></div></div>)}</div>
      <div className="detail">{current ? <><h3>{current.title}</h3><p>{current.detail}</p></> : <p>Choose <b>Next step</b> to reveal the handshake sequence one stage at a time.</p>}</div>
      <div className="actions"><button className="primary" onClick={()=>setIndex(v=>Math.min(v+1,steps.length-1))} disabled={index>=steps.length-1}>Next step →</button><button onClick={()=>setIndex(-1)}>Reset</button></div>
      {index===steps.length-1 && <div className="success">Handshake walkthrough complete.</div>}
    </section>
    <section className="panel">
      <h2>SSH user-authentication demo</h2><p className="muted">Choose a simulated authentication result.</p>
      <label className="check"><input type="checkbox" checked={auth} onChange={e=>setAuth(e.target.checked)}/> Simulate successful user authentication</label>
      <button className="primary" onClick={startSession}>Run session demo</button>
      {session && <div className={session.authenticated?"success":"error"}>{session.authenticated?"Secure channel established":"Authentication failed — channel not established"}{session.demo_session_id && <p>Demo session ID: <code>{session.demo_session_id}</code></p>}<small>{session.note}</small></div>}
    </section>
    <section className="panel">
      <h2>IPsec / ESP packet overview</h2><p className="muted">Compare how Transport Mode and Tunnel Mode organize a packet.</p>
      <div className="tabs"><button className={mode==="transport"?"active":""} onClick={()=>{setMode("transport");setPacket(null)}}>Transport Mode</button><button className={mode==="tunnel"?"active":""} onClick={()=>{setMode("tunnel");setPacket(null)}}>Tunnel Mode</button></div>
      <button className="primary" onClick={showPacket}>Visualize packet</button>
      {packet && <><div className="packet">{[packet.outer_ip_header,packet.esp_header,packet.payload,packet.esp_trailer].map((x,i)=><div key={i} className={`packet-part p${i}`}>{x}</div>)}</div><p>{packet.explanation}</p></>}
    </section>
    <footer>Educational demo only · Not a production security implementation</footer>
  </main>;
}
createRoot(document.getElementById("root")).render(<App />);
