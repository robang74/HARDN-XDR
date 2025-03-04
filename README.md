         ██░ ██  ▄▄▄       ██▀███  ▓█████▄  ███▄    █ 
        ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▒██▀ ██▌ ██ ▀█   █ 
        ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒░██   █▌▓██  ▀█ ██▒
        ░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█▄   ▌▓██▒  ▐▌██▒
        ░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▓ ▒██░   ▓██░
         ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ▒▒▓  ▒ ░ ▒░   ▒ ▒ 
         ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ▒  ▒ ░ ░░   ░ ▒░
         ░  ░░ ░  ░   ▒     ░░   ░  ░ ░  ░    ░   ░ ░ 
         ░  ░  ░      ░  ░   ░        ░             ░ 
                            ░                 
                    The Linux Security Project
   


# HARDN
---
A single **Debian** tool to fully secure an OS using  automation, monitoring, heuristics and availability.
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
# **Overview and Reciept of Mission**  

- Kernel Hardening – Fortifying the Linux kernel to block exploits, enforce strict access controls, and minimize attack surfaces.

- Penetration Testing – Proactively scanning and testing for vulnerabilities to find weaknesses before attackers do.

- Automation – Reducing manual security tasks with scripts and tools that streamline system protection and performance tuning.

- OS Security – Locking down vulnerabilities while ensuring stability, speed, and reliability for Debian systems

---

## Tools

- Lynis,Security auditing tool for Unix-based systems.
- Fail2Ban,Protects against brute-force attacks.
- SELinux, a security feature in Linux that enforces strict access controls to protect the system from unauthorized actions, even by compromised or malicious processes.
- UFW,Easy-to-configure firewall utility.
- TCP wrappers, to bundle outbound/ inbound and predefined rules monitoring tool, host based. 
- Lynis Audit- to keep the base secure posture validated
- AppArmor,Mandatory Access Control (MAC) for enforcing policies.
- ESET_Nod32,(Soon to be replaced by Legion) Open-source antivirus software.
- Firejail,Sandboxing tool for application isolation.
- Cron, to keep it all omaintenance**
- Pex*, used for GRUB password hash automation 

1. **Secure the System** – Applies firewall rules, intrusion detection, malware protection, and access control automatically.  
2. **Monitor & Defend** – Uses heuristic analysis, security audits, and automated updates to **stay ahead of threats**.  (LEGION)
3. **Stay Updated** – Built-in automation via `cron` ensures **constant updates and maintenance** without user intervention.  

Once installed, **HARDN runs in the background**—keeping your system tight **without slowing you down**.

> we are working on a 'headless' option to remove the gui, for server functionality. 
> We are working on server and container compatibility.
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
> [LEGION](https://github.com/opensource-for-freedom/LEGION.git)
- Integrating Wazuh SIEM – Expanding system-wide monitoring for better incident response.
- Expanding container security – Locking down VMs and containers without affecting performance.
- Making it easier to use – Simplifying configurations for both end-users and professionals.
---
## Contributing
- Contact directly for access 
---

## License

- MIT License
