# SIMRS Cybersecurity Passive Assessment Report

## Executive Summary
Ditemukan 2 layanan berisiko tinggi pada Server SIMRS Lab. Prioritaskan segmentasi jaringan, pembatasan akses, dan validasi kebutuhan bisnis layanan terbuka.

## Target Information
- Name: Server SIMRS Lab
- Target: 192.168.56.10
- Environment: lab
- Scan Time: 2024-07-01T00:00:00Z

## Open Ports and Services
| Port | Protocol | Service | Product | Version | Risk | Notes |
|---:|---|---|---|---|---|---|
| 22 | tcp | ssh | OpenSSH | 7.6p1 Ubuntu | Medium | SSH administrative service detected; restrict access to trusted management networks. |
| 445 | tcp | microsoft-ds | Samba smbd | 4.7.6 | High | SMB exposure can enable ransomware lateral movement and unsafe file sharing. |
| 3306 | tcp | mysql | MySQL | 5.7.31 | High | MySQL exposure may risk unauthorized access to patient databases. |

## New Findings Since Last Scan
- Tidak ada perubahan signifikan dari scan sebelumnya.

## High Risk Findings
- **High-risk service exposed on 445/MICROSOFT-DS**: SMB exposure can enable ransomware lateral movement and unsafe file sharing. Recommendation: Restrict SMB to required internal subnets, disable legacy SMB versions, and audit file share permissions.
- **High-risk service exposed on 3306/MYSQL**: MySQL exposure may risk unauthorized access to patient databases. Recommendation: Bind database services to application hosts only, enforce firewall rules, and verify database access logs.

## Possible CVE Matches
| CVE ID | Severity | Product | Version | Summary | Recommendation |
|---|---|---|---|---|---|
| CVE-POC-0001 | Medium | OpenSSH | 7.6p1 Ubuntu | Dummy PoC entry for older OpenSSH versions requiring patch review. | Verify vendor patch level and restrict SSH to management subnet. |
| CVE-POC-0003 | High | MySQL | 5.7.31 | Dummy PoC entry for older MySQL-compatible database versions. | Plan database upgrade, restrict network access, and verify backups. |

## Recommended Actions
- 1 hari: Validasi owner layanan high risk, batasi akses firewall untuk SMB/RDP/database/DICOM, dan review exposure baru.
- 7 hari: Verifikasi patch level, dokumentasikan baseline port yang disetujui, dan aktifkan monitoring log administratif.
- 30 hari: Terapkan segmentasi jaringan SIMRS/PACS/database, review kebijakan backup ransomware, dan perbarui local CVE database.

## Safety Note
Scan dilakukan menggunakan mode passive/light non-destruktif. Sistem ini tidak melakukan exploit, brute force, credential guessing, bypass, evasion, DoS, fuzzing, atau payload ofensif.
