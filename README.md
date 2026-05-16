# OpenClaw SIMRS Cybersecurity Assistant

OpenClaw SIMRS Cybersecurity Assistant adalah Proof of Concept aplikasi lokal/on-premise untuk membantu fasilitas kesehatan memantau exposure port/service SIMRS secara aman, non-destruktif, dan mudah dipahami manajemen.

> **Batasan keselamatan:** OpenClaw bukan exploit framework, bukan alat brute force, bukan alat DoS, dan bukan alat bypass/evasion. Default scan memakai `nmap -sV -Pn -T2 --open -oX output.xml TARGET` dan hanya diizinkan untuk target private/local network kecuali operator mengaktifkan `ALLOW_PUBLIC_SCAN=true` untuk aset yang benar-benar diotorisasi.

## Fitur PoC

- FastAPI backend dengan SQLite.
- Asset CRUD: nama aset, IP/domain lokal, kategori, environment, owner, notes.
- Manual scan menggunakan Nmap passive/light command.
- Guardrails: validasi target private/local, legal authorization acknowledgement, timeout, rate limiting per aset, audit log, no credentials.
- Parser Nmap XML untuk host, port, protocol, state, service, product, version, extra info, timestamp.
- Risk rule engine untuk port prioritas healthcare/SIMRS: SMB, database, DICOM/PACS, RDP, SSH, HTTP/HTTPS.
- Local CVE matching berbasis `backend/local_cve_db.json` tanpa API eksternal.
- Comparison scan untuk port baru, port tertutup, service/version/risk berubah.
- Markdown/JSON/CSV report export.
- Optional local AI summary via Ollama (`OLLAMA_ENABLED=true`), tanpa API cloud.
- Optional honeypot log parser lokal untuk T-Pot/HoneyDrive-style JSON/plain logs.
- Frontend React minimal: dashboard, asset list, scan detail, comparison/report viewer.

## Struktur

```text
backend/app/main.py                    # API FastAPI dan orchestration scan/report
backend/app/scanner/safety.py          # validasi private/local target, rate limit, audit helper
backend/app/scanner/nmap_runner.py     # safe Nmap command builder/runner
backend/app/scanner/nmap_parser.py     # XML parser
backend/app/risk/rules.py              # rule engine defensif
backend/app/risk/cve_matcher.py        # local CVE matcher
backend/app/comparison/diff_engine.py  # scan diff engine
backend/app/reports/markdown_report.py # report Markdown
backend/app/reports/csv_export.py      # export CSV
backend/app/ai/ollama_summary.py       # optional Ollama adapter
backend/app/honeypot/log_parser.py     # optional local honeypot log parser
frontend/src/main.jsx                  # UI minimal
examples/sample_nmap_output.xml        # sample parser input
examples/sample_report.md              # contoh report
```

## Menjalankan Backend Lokal

Persyaratan:

- Python 3.11+
- Nmap terinstal di host (`nmap --version`)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Buka API docs: <http://127.0.0.1:8000/docs>

## Menjalankan Frontend Lokal

```bash
cd frontend
npm install
VITE_API_URL=http://127.0.0.1:8000 npm run dev
```

Buka UI: <http://127.0.0.1:5173>

## Menjalankan dengan Docker Compose

```bash
docker compose up --build
```

- Backend: <http://localhost:8000>
- Frontend: <http://localhost:5173>
- SQLite disimpan pada volume `openclaw-data`.
- Container tidak memakai privileged mode.

## Contoh Workflow Aman di Lab/Dummy

1. Tambah aset lab private/local:

```bash
curl -X POST http://127.0.0.1:8000/assets \
  -H 'Content-Type: application/json' \
  -d '{"name":"Server SIMRS Lab","target":"127.0.0.1","category":"SIMRS","environment":"lab","owner":"IT RS","notes":"Dummy local target"}'
```

2. Jalankan scan manual dengan acknowledgement legal/authorization:

```bash
curl -X POST http://127.0.0.1:8000/assets/1/scan \
  -H 'Content-Type: application/json' \
  -d '{"safety_acknowledged":true,"authorized_deep_check":false}'
```

3. Lihat riwayat scan:

```bash
curl http://127.0.0.1:8000/assets/1/scans
```

4. Export report Markdown dan CSV:

```bash
curl http://127.0.0.1:8000/scans/1/report.md -o report.md
curl http://127.0.0.1:8000/scans/1/export.csv -o ports.csv
```

## Konfigurasi Keselamatan

Environment variables backend:

| Variable | Default | Keterangan |
|---|---:|---|
| `ALLOW_PUBLIC_SCAN` | `false` | Blokir target public IP/domain secara default. Aktifkan hanya untuk aset yang diotorisasi. |
| `ENABLE_VULN_SCRIPT` | `false` | NSE vuln script tidak aktif default. Jika aktif, runner tetap hanya memakai seleksi `vuln and safe` dan memblokir kata kunci intrusive/offensive. |
| `SCAN_TIMEOUT_SECONDS` | `120` | Timeout per scan agar tidak mengganggu layanan 24 jam. |
| `MIN_SECONDS_BETWEEN_SCANS_PER_ASSET` | `300` | Rate limit scan per aset. |
| `OLLAMA_ENABLED` | `false` | Aktifkan summary lokal via Ollama. |
| `OLLAMA_URL` | `http://ollama:11434/api/generate` | Endpoint Ollama lokal/on-prem. |
| `OLLAMA_MODEL` | `llama3` | Model lokal default. |

## Optional Ollama Local Summary

Jalankan Ollama di host/on-prem, lalu set:

```bash
export OLLAMA_ENABLED=true
export OLLAMA_URL=http://127.0.0.1:11434/api/generate
export OLLAMA_MODEL=llama3
```

Data report JSON dikirim hanya ke endpoint Ollama yang dikonfigurasi. Jangan arahkan endpoint ke layanan cloud jika kebijakan RS melarang data keluar.

## Optional Honeypot Log Integration

OpenClaw tidak deploy honeypot otomatis. Parser hanya membaca file log lokal:

```bash
curl -X POST 'http://127.0.0.1:8000/honeypot/parse?path=/path/to/local/honeypot.log'
```

## Testing

```bash
cd backend
PYTHONPATH=. pytest -q
```

Unit test mencakup parser Nmap XML, risk rule engine, dan comparison engine.

## Catatan Produksi

PoC ini ditujukan untuk lab/internal baseline. Sebelum produksi, tambahkan authentication/authorization aplikasi, role-based access control, TLS, secret management, hardening deployment, scheduled worker nyata, backup database, dan review compliance internal RS.
