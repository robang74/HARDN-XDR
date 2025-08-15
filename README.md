# HARDN-XDR
      
A single UX based **Debian** tool to fully secure an OS using automation, monitoring, heuristics and availability

- Assist the open source community in building a Debian based "**golden image**" system.
- To empower IT administrators and users with the tools they need to ensure endpoint security, optimize performance, and maintain compliance across their organization.
- A robust and secure endpoint management solution designed to simplify and enhance the management of devices in your network. 
- Advanced features for monitoring, securing, and maintaining endpoints efficiently.
- Compliance with Security Technical Information Guides [STIG](https://www.cyber.mil/stigs) provided by the DoD Cyber Exchange.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Goals](#goals)
- [Tools](#tools)
- [How it Works](#how-it-works)
- [Quick Start](#quick-start)
- [Contributing](#contributing)
- [File Structure](#file-structure)
- [License](#license)

---

### Overview

HARDN Endpoint is a robust and secure endpoint management solution designed to simplify and enhance the management of devices in your network. It provides advanced features for monitoring, securing, and maintaining endpoints efficiently.

- **Kernel Hardening** – Fortifying the Linux kernel to block exploits, enforce strict access controls, and minimize attack surfaces.
- **Penetration Testing** – Proactively scanning and testing for vulnerabilities to find weaknesses before attackers do.
- **Automation** – Reducing manual security tasks with scripts and tools that streamline system protection and performance tuning.
- **OS Security** – Locking down vulnerabilities while ensuring stability, speed, and reliability for Debian systems

#### Purpose

The purpose of HARDN Endpoint is to empower IT administrators with the tools they need to ensure endpoint security, optimize performance, and maintain compliance across their organization.

---

### Features

- **Comprehensive Monitoring**: Real-time insights into endpoint performance and activity.
- **Enhanced Security**: Protect endpoints with advanced security protocols.
- **Scalability**: Manage endpoints across small to large-scale networks.
- **User-Friendly Interface**: Intuitive design for seamless navigation and management.
- **STIG Compliance**: This release brings the utmost security for Debian Government based information systems.

---

### Goals

Once installed, **HARDN runs in the background**—keeping your system tight **without slowing you down**.

> We are working on a 'headless' option to remove the gui, for server functionality.<br>
> We are also working on server and container compatibility.

---

### Tools

- Lynis,Security auditing tool for Unix-based systems.
- Fail2Ban,Protects against brute-force attacks.
- SELinux, a security feature in Linux that enforces strict access controls to protect the system from unauthorized actions, even by compromised or malicious processes.
- UFW,Easy-to-configure firewall utility.
- TCP wrappers, to bundle outbound/ inbound and predefined rules monitoring tool, host based. 
- Lynis Audit- to keep the base secure posture validated, and priovide a systems score.
- AppArmor,Mandatory Access Control (MAC) for enforcing policies.
- LMD (MALDETECT),(Soon to be replaced by Legion) Open-source antivirus software.
- Firejail,Sandboxing tool for application isolation.
- Cron, to keep it all updates maintenanced
- Pex&ast;, used for GRUB password hash automation

---

### How it Works

1. **Secure the System** – Applies firewall rules, intrusion detection, malware protection, and access control automatically.  
2. **Monitor & Defend** – Soon to use heuristic analysis, security audits, and automated updates to **stay ahead of threats**.  (`Legion`)
3. **Stay Updated** – Built-in automation via `cron` ensures **constant updates and maintenance** without user intervention.  

---

### Quick Start

#### Github Installation

1.  **One command**

    ```bash
    curl -LO https://raw.$url/HARDN-XDR/$ver/install.sh \
        && sudo chmod +x install.sh && sudo ./install.sh
    ```

#### Debian Installation

1. Download the `.deb` package from the [Releases](https://github.com/opensource-for-freedom/HARDN/releases) page.
2. Install the package using the following command:
    ```bash
    sudo dpkg -i hardn-endpoint.deb
    ```
3. Resolve any missing dependencies:
    ```bash
    sudo apt-get install -f
    ```
4. Follow the setup instructions in the [Installation Guide](./INSTALL.md).

#### Installation Notes

- HARDN-XDR is currently being developed and tested for **BARE-METAL installs of Debian based distributions and Virtual Machines**.
- Ensure you have the latest version of **Debian 12** or **Ubuntu 24.04**.
- By installing HARDN-XDR with the commands listed in the installation process, the following changes will be made to your system:
> - A collection of security focused packages will be installed.
> - Security tools and services will be enabled.
> - System hardening and STIG settings will be applied.
> - A malware and signature detection and response system will be set up.
> - A monitoring and reporting system will be activated. 
- For a detailed list of all that will be changed, please refer to [HARDN.md](docs/HARDN.md).
- For an overview of HARDN-Debian STIG Compliance, please refer to [deb_stig.md](docs/deb_stig.md).

---

### Contributing

We welcome contributions! Please see our [Contributing Guidelines](./CONTRIBUTING.md) for more details.

#### Support Contact

- [support@hardnLinux.com](mailto:support@hardnLinux.com)

#### Project Partner

- [office@cybersynapse.ro](mailto:office@cybersynapse.ro)

---

### File Structure

```bash
HARDN-XDR/
├── changelog.md                 # Documents version history and changes
├── docs                         # Documentation directory
│   ├── assets                   # Images and visual resources
│   │   ├── cybersynapse.png     # Partner logo
│   │   └── HARDN(1).png         # Project logo
│   ├── CODE_OF_CONDUCT.md       # Community guidelines and expectations
│   ├── deb_stig.md              # Debian STIG compliance documentation
│   ├── hardn-main-sh-review.md  # Review of the main script functionality
│   ├── HARDN.md                 # Detailed project documentation
│   ├── hardn-security-tools.md  # Security tools documentation
│   └── TODO.md                  # Planned features and improvements
├── install.sh                   # Main installation script
├── LICENSE                      # MIT License file
├── progs.csv                    # List of programs and packages to be installed
├── README.md                    
└── src                          
    └── setup                    
        ├── hardn-main.sh        
        └── hardn-uninstall.sh
```

---

### License

- This project is licensed under the MIT [license](./LICENSE).

