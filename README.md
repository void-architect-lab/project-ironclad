# 🛠️ PROJECT IRONCLAD

Stop shipping vulnerabilities: Ironclad is the self-hosted, modular auditing engine that ruthlessly hunts down flaws in your Dockerfiles and infrastructure configurations before they ever reach production.

## ⚡ The Architecture of Total Control
You don't hand your core application logic over to unvetted third-party SaaS scanners. Why would you do it with your infrastructure?
Project Ironclad is built on a decoupled, paranoid-by-design architecture tailored for elite engineering teams:

* **The Engine (Backend):** A blisteringly fast, proprietary FastAPI backend that you self-host. It runs in your VPC, behind your firewall, completely sandboxed. Zero telemetry. Zero data exfiltration.
* **The Weapon (CLI):** A beautiful, rich, terminal-native CLI client. It provides real-time, color-coded vulnerability matrices and actionable remediation steps right where you work.

## 🚀 Quick Start: From Zero to Secure in 60 Seconds
No bloated onboarding. Spin up the engine, equip the weapon, and pull the trigger.

### 1. Ignite the Engine
Clone the repository and bring up the Ironclad backend using Docker Compose. This maps the FastAPI analysis engine to your local environment.

```bash
git clone [https://github.com/void-architect-lab/project-ironclad.git](https://github.com/void-architect-lab/project-ironclad.git)
cd project-ironclad/backend
cp .env.example .env
docker compose up -d