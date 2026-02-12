# LabSentinel

LabSentinel — secure-by-default posture scanning for Proxmox home labs.

## What it does

- Proxmox API authentication and inventory discovery (nodes, VMs, CTs)
- LAN exposure scan against the Proxmox host (common admin/service ports)
- Service exposure hints based on guest naming patterns
- Best-effort firewall status checks for datacenter and nodes
- JSON export for automation pipelines

## Quick Start

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
labsentinel --mode api --host 192.168.1.10 --user root --realm pam --password "YOUR_PASSWORD"
```

### Linux/macOS

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
labsentinel --mode api --host 192.168.1.10 --user root --realm pam --password 'YOUR_PASSWORD'
```

## Usage

Show all options:

```bash
labsentinel --help
```

API mode:

```bash
labsentinel --mode api --host 192.168.1.10 --user root@pam --password 'YOUR_PASSWORD'
```

Local mode:

```bash
labsentinel --mode local
```

JSON export:

```bash
labsentinel --mode api --host 192.168.1.10 --user root@pam --password 'YOUR_PASSWORD' --json
```

## Agent Facts (optional)

Collect local host facts on the Proxmox node and pass them to LabSentinel for extra checks.

On the Proxmox host:

```bash
python3 labsentinel_agent/collect_facts.py > agent_facts.json
```

From the scanning machine:

```bash
labsentinel --mode api --host 192.168.1.10 --user root@pam --password 'YOUR_PASSWORD' --agent-facts agent_facts.json
```

Using stdin:

```bash
python3 labsentinel_agent/collect_facts.py | labsentinel --mode api --host 192.168.1.10 --user root@pam --password 'YOUR_PASSWORD' --agent-facts -
```

Do not share agent fact files publicly; they may contain sensitive host metadata.

## Example output

```text
LabSentinel v0.1
================================================================
Score: 85/100
Risk Level: Low
================================================================
Top Risks
- [WARNING] impact 5 - Remote Admin Port Open: Remote admin port open on LAN (22).
- [WARNING] impact 5 - Reverse proxy detected; ensure TLS, auth, and WAF/rate limit if internet-facing.
----------------------------------------------------------------
Findings
WARNING
  - Remote Admin Port Open: Remote admin port open on LAN (22). Ensure access is restricted...
  - Reverse proxy detected; ensure TLS, auth, and WAF/rate limit if internet-facing. Guest: traefik (ID 105).
INFO
  - Datacenter Firewall Status Unknown: Firewall options are not explicitly set...
----------------------------------------------------------------
Recommended Next Steps
- Restrict SSH (22) to mgmt VLAN/VPN; disable password auth.
- Ensure reverse proxy enforces TLS + auth; consider rate limiting.
----------------------------------------------------------------
Tip: use --json to export results
```

## How scoring works

- Score starts at `100`.
- Each finding can subtract score using explicit `impact` when present.
- If no explicit impact exists, severity defaults are used.
- Risk levels:
  - `85-100` = Low
  - `65-84` = Moderate
  - `40-64` = High
  - `<40` = Critical

## Security & privacy

- Do not paste credentials in screenshots, logs, or issue reports.
- LabSentinel is read-only and does not modify Proxmox configuration.

## Roadmap

- Proxmox API token authentication
- Optional agent mode for deeper host checks
- Improved firewall-state detection
- Packaging and release to PyPI

## Contributing

Issues and pull requests are welcome. Please include clear reproduction steps and expected behavior.

## License

MIT — see [LICENSE](LICENSE).
