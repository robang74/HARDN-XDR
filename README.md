# HARDN
---
A single **Debian** tool to fully secure an OS using  automation, monitoring, heuristics and keep availability high.
---
# Table of Contents
## Table of Contents
- [Overview](##Overview)
- [Tools](##Tools)
- [How it works](##How_it_Works)
- [Getting Started](##Getting_Started)
- [Goals](##Goals)
- [Contributing](#contributing)
- [License](#license)
---
# **Overview**  

In the development of this repo, we aim to include all facets of **kernel hardening**, **penetration testing**, and **OS security** for Debian Linux systems, ensuring both security and stability.

We will always take suggestions and mentioning of how to keep Linux secure and productivity high. 

This document outlines the pre-release activities that need to be completed before finalizing the project release.

These tasks are designed to reinforce security, improve performance, and streamline user management.

By following these guidelines, you will enhance system security, maintain stability, and optimize Debian-based systems for performance and resilience.

---

## Tools

- Lynis,Security auditing tool for Unix-based systems.
- Fail2Ban,Protects against brute-force attacks.
- UFW,Easy-to-configure firewall utility.
- Lynis Audit- to keep the base secure posture validated
- AppArmor,Mandatory Access Control (MAC) for enforcing policies.
- ESET_Nod32,(Soon to be replaced by Legion) Open-source antivirus software.
- Firejail,Sandboxing tool for application isolation.
- Cron, to keep it all omaintenance**:  

1. **HARDN the System** – Applies firewall rules, intrusion detection, malware protection, and access control automatically.  
2. **Monitor & Defend** – Uses heuristic analysis, security audits, and automated updates to **stay ahead of threats**.  (LEGION to come)
3. **Stay Updated** – Built-in automation via `cron` ensures **constant updates and maintenance** without user intervention.  

Once installed, **HARDN runs in the background**—keeping your system tight **without slowing you down**.

we are working on a 'headless' option to remove the gui, for server functionality. 
---

## **Getting Started**  

### Clone the Repository**  
```bash
git clone https://github.com/opensource-for-freedom/HARDN.git
cd hardn
```
### Youll need Python 3 
```bash
pip install -r requirements.txt
```
### Install hardn system wide
```bash
pip install -e .
```
### HARDN
```bash
hardn
```
## To update system
rerun
```bash
sudo ./setup.sh
```
---
## Goals
- Replacing ESET with `Legion` – A dedicated malware scanner optimized for Linux.
- Integrating Wazuh SIEM – Expanding system-wide monitoring for better incident response.
- Expanding container security – Locking down VMs and containers without affecting performance.
- Making it easier to use – Simplifying configurations for both end-users and professionals.
---
## Contributing
- Please do 🙂
---

## License

- MIT License