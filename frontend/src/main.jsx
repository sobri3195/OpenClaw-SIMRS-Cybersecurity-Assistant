import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function App() {
  const [dashboard, setDashboard] = useState({});
  const [assets, setAssets] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [report, setReport] = useState('');
  const [form, setForm] = useState({ name: 'Server SIMRS Lab', target: '127.0.0.1', category: 'SIMRS', environment: 'lab', owner: '', notes: '' });

  async function refresh() {
    setDashboard(await fetch(`${API}/dashboard`).then(r => r.json()));
    setAssets(await fetch(`${API}/assets`).then(r => r.json()));
  }
  useEffect(() => { refresh(); }, []);

  async function createAsset(e) {
    e.preventDefault();
    await fetch(`${API}/assets`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
    refresh();
  }

  async function runScan(assetId) {
    if (!confirm('Pastikan Anda berwenang memindai target ini. Scan bersifat passive/light dan non-destruktif. Lanjutkan?')) return;
    const scan = await fetch(`${API}/assets/${assetId}/scan`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ safety_acknowledged: true }) }).then(r => r.json());
    setSelectedScan(scan);
    const md = await fetch(`${API}/scans/${scan.id}/report.md`).then(r => r.text());
    setReport(md);
    refresh();
  }

  return <main>
    <h1>OpenClaw SIMRS Cybersecurity Assistant</h1>
    <section className="cards">
      <div>Total Asset <strong>{dashboard.total_assets ?? 0}</strong></div>
      <div>High Risk Findings <strong>{dashboard.total_high_risk_findings ?? 0}</strong></div>
      <div>Port Baru Terbuka <strong>{dashboard.new_open_ports ?? 0}</strong></div>
      <div>Target Terakhir <strong>{dashboard.last_scanned_target ?? '-'}</strong></div>
    </section>

    <section className="grid">
      <div>
        <h2>Asset List</h2>
        <form onSubmit={createAsset} className="asset-form">
          <input value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="Nama aset" />
          <input value={form.target} onChange={e => setForm({...form, target: e.target.value})} placeholder="IP/domain lokal" />
          <input value={form.environment} onChange={e => setForm({...form, environment: e.target.value})} placeholder="Environment" />
          <button>Add Asset</button>
        </form>
        {assets.map(asset => <article key={asset.id} className="asset">
          <h3>{asset.name}</h3>
          <p>{asset.target} · {asset.environment}</p>
          <button onClick={() => runScan(asset.id)}>Run passive/light scan</button>
        </article>)}
      </div>
      <div>
        <h2>Scan Result Detail</h2>
        {selectedScan ? <>
          <p>Status: <strong>{selectedScan.status}</strong></p>
          <table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Risk</th></tr></thead><tbody>
            {(selectedScan.ports || []).map(p => <tr key={`${p.protocol}-${p.port}`}><td>{p.port}/{p.protocol}</td><td>{p.service_name}</td><td>{p.product} {p.version}</td><td>{p.risk_level}</td></tr>)}
          </tbody></table>
          <h2>Report Viewer</h2><pre>{report}</pre>
        </> : <p>Pilih aset lalu jalankan scan untuk melihat detail, comparison, dan report.</p>}
      </div>
    </section>
  </main>;
}

createRoot(document.getElementById('root')).render(<App />);
