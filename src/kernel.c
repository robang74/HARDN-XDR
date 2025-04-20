use std::process::Command;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// HARDN kernel sysctl hardening configuration + STIG
pub struct KernelConfig {
    pub parameter: String,
    pub value: String,
}

impl KernelConfig {
    pub fn apply(&self) -> io::Result<()> {
        let output = Command::new("sysctl")
            .arg("-w")
            .arg(format!("{}={}", self.parameter, self.value))
            .output()?;

        if output.status.success() {
            log_action(&format!("Applied: {}={}", self.parameter, self.value))?;
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            eprintln!("Failed to apply {}: {}", self.parameter, err);
            log_action(&format!("Failed: {}={} => {}", self.parameter, self.value, err))?;
        }
        Ok(())
    }

    pub fn persist(&self, file: &mut fs::File) -> io::Result<()> {
        writeln!(file, "{} = {}", self.parameter, self.value)?;
        Ok(())
    }
}

pub fn log_action(action: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/hardn.log")?;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    writeln!(file, "[{}] {}", ts, action)?;
    Ok(())
}

pub fn monitor_kernel_logs(log_file: &str) -> io::Result<()> {
    if !std::path::Path::new(log_file).exists() {
        eprintln!("Log file not found: {}", log_file);
        return Ok(());
    }

    let logs = fs::read_to_string(log_file)?;
    for line in logs.lines() {
        if line.contains("error") || line.contains("warn") || line.contains("critical") {
            println!("Kernel alert: {}", line);
            log_action(&format!("Kernel log alert: {}", line))?;
        }
    }
    Ok(())
}

pub fn get_kernel_version() -> io::Result<String> {
    let output = Command::new("uname").arg("-r").output()?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Failed to get kernel version"))
    }
}

fn persist_sysctl_config(configs: &[KernelConfig]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .open("/etc/sysctl.d/hardn.conf")?;
    for cfg in configs {
        cfg.persist(&mut file)?;
    }

    Command::new("sysctl")
        .arg("--system")
        .status()
        .expect("Failed to reload sysctl system");

    log_action("Persisted kernel hardening to /etc/sysctl.d/hardn.conf")?;
    Ok(())
}

fn blacklist_kernel_modules() -> io::Result<()> {
    let blacklist = vec![
        "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf", "usb-storage"
    ];

    let path = "/etc/modprobe.d/hardn-blacklist.conf";
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .open(path)?;

    for module in blacklist {
        writeln!(file, "install {} /bin/false", module)?;
    }

    log_action("Blacklisted unnecessary kernel modules in hardn-blacklist.conf")?;
    Ok(())
}

fn whitelist_hardn_binaries() -> io::Result<()> {
    let whitelist_path = "/etc/apparmor.d/local/hardn.whitelist";
    let hardn_bins = vec![
        "/usr/local/bin/hardn",
        "/usr/local/bin/kernel",
        "/usr/local/bin/setup.sh",
        "/usr/local/bin/packages.sh",
        "/usr/local/bin/gui/main.py"
    ];

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .open(whitelist_path)?;

    for path in hardn_bins {
        writeln!(file, "/{} rix,", path.trim_start_matches('/'))?;
    }

    log_action("Whitelisted HARDN runtime binaries via AppArmor local override")?;
    Ok(())
}

fn reload_apparmor_profiles() -> io::Result<()> {
    let status = Command::new("apparmor_parser")
        .arg("-r")
        .arg("/etc/apparmor.d/local/hardn.whitelist")
        .status()?;

    if status.success() {
        println!("[+] AppArmor profile for HARDN reloaded.");
        log_action("Reloaded AppArmor profile: hardn.whitelist")?;
    } else {
        eprintln!("[-] Failed to reload AppArmor profile.");
        log_action("Failed to reload AppArmor profile: hardn.whitelist")?;
    }

    let output = Command::new("aa-status")
        .output()
        .expect("Failed to check AppArmor status");

    let status_out = String::from_utf8_lossy(&output.stdout);
    if status_out.contains("enforce mode") && status_out.contains("hardn") {
        println!("[+] HARDN AppArmor profiles are enforced.");
        log_action("HARDN AppArmor profiles are enforced.")?;
    } else {
        println!("[-] HARDN AppArmor profiles not enforced.");
        log_action("HARDN AppArmor profiles NOT enforced.")?;
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let configs = vec![
        KernelConfig { parameter: "kernel.randomize_va_space".into(), value: "2".into() },
        KernelConfig { parameter: "net.ipv4.ip_forward".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.conf.all.rp_filter".into(), value: "1".into() },
        KernelConfig { parameter: "net.ipv4.conf.default.rp_filter".into(), value: "1".into() },
        KernelConfig { parameter: "net.ipv4.conf.all.accept_source_route".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.conf.default.accept_source_route".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.conf.all.accept_redirects".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.conf.default.accept_redirects".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.conf.all.send_redirects".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.conf.default.send_redirects".into(), value: "0".into() },
        KernelConfig { parameter: "net.ipv4.tcp_syncookies".into(), value: "1".into() },
        KernelConfig { parameter: "kernel.sysrq".into(), value: "0".into() },
        KernelConfig { parameter: "fs.suid_dumpable".into(), value: "0".into() },
    ];

    println!("Applying STIG kernel parameters...");
    for config in &configs {
        config.apply()?;
    }

    persist_sysctl_config(&configs)?;
    blacklist_kernel_modules()?;
    whitelist_hardn_binaries()?;
    reload_apparmor_profiles()?;

    println!("Monitoring kernel logs...");
    monitor_kernel_logs("/var/log/kern.log")?;

    let version = get_kernel_version()?;
    println!("Current kernel version: {}", version);
    log_action(&format!("Kernel version: {}", version))?;

    Ok(())
}