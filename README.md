# Automated SOC Incident Response System — Milestone 1

A small, defensive Python pipeline that analyzes local Linux SSH authentication logs and creates JSON incident records for repeated failed logins. It is designed as a lab project: it does **not** block IPs, disable accounts, call APIs, or change third-party systems.

## What it does

1. Parses recognized `sshd` success and failure lines from an `auth.log` file.
2. Groups failed logins by source IP in a rolling time window.
3. Creates a detection when an IP reaches the configured failure threshold.
4. Applies transparent, explainable risk scoring.
5. Classifies incidents as `low`, `medium`, or `high`.
6. Writes one self-contained JSON incident record per detection under `incidents/`.

## Project structure

```text
soc-incident-response/
├── data/
│   └── auth.log          # synthetic lab authentication events
├── incidents/            # generated incident JSON records (ignored by Git)
├── parser.py             # SSH auth.log parser and normalized event model
├── detector.py           # repeated-failed-login detection
├── risk.py               # explainable risk score and severity
├── main.py               # command-line pipeline
├── dashboard.py          # local browser dashboard for incident records
├── requirements.txt      # standard-library-only milestone
└── README.md
```

## Run it

Python 3.10+ is recommended. No package installation is needed for this milestone.

```powershell
cd soc-incident-response
python main.py
```

The included synthetic data produces two local incidents:

- `203.0.113.50`: three failed attempts against invalid account names, rated **high**.
- `198.51.100.73`: three failed attempts against `root`, rated **medium**.

Generated records use names such as `incidents/INC-20260911-AB12CD34.json` and contain the evidence, time window, risk reasons, and an analyst-oriented next step.

## View the local dashboard

After generating incidents, start the local browser dashboard:

```powershell
python dashboard.py
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser. The dashboard shows severity totals, recent risk scores, and expandable incident evidence. It binds to `127.0.0.1` by default and reads only local JSON files; it does not send data, block IPs, or perform containment actions. Press `Ctrl+C` in the terminal to stop it.

## Analyze another local log file

```powershell
python main.py --log C:\lab\logs\auth.log --threshold 5 --window-minutes 15
```

`auth.log` syslog-style timestamps do not contain a year, so supply one when analyzing archived logs:

```powershell
python main.py --log C:\lab\logs\auth.log --year 2025
```

## Risk scoring

The first milestone deliberately uses simple, inspectable rules:

- 15 points per failed login, capped at 60.
- 20 points when the repeated-login threshold is met.
- 20 points if invalid usernames were targeted.
- Severity: `high` at 80+, `medium` at 50–79, and `low` below 50.

Scores guide analyst triage; they do not prove malicious activity. Future milestones can add test coverage, threat-intelligence enrichment, case management, alerting, and safe, authorized lab-only response workflows.
