use clap::{App, Arg};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, exit};
use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;
use std::time::Duration;

const LOG_FILE: &str = "/var/log/hardn.log";
const SYSTEMD_UNIT: &str = "/etc/systemd/system/hardn.service";

fn validate_environment() {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("This script must be run as root. Please use 'sudo'.");
        log::error!("This script must be run as root. Please use 'sudo'.");
        exit(1);
    }
    println!("Environment validated successfully.");
    log::info!("Environment validated successfully.");
}

fn set_executable_permissions(base_dir: &str) {
    let files_to_chmod = vec![
        format!("{}/setup/setup.sh", base_dir),
        format!("{}/setup/packages.sh", base_dir),
        format!("{}/kernel.c", base_dir),
        format!("{}/gui/main.py", base_dir),
    ];

    for file in files_to_chmod {
        if Path::new(&file).exists() {
            let mut perms = fs::metadata(&file).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&file, perms).unwrap();
            println!("Set executable permissions for {}", file);
            log::info!("Set executable permissions for {}", file);
        } else {
            eprintln!("Warning: {} does not exist. Skipping.", file);
            log::warn!("Warning: {} does not exist. Skipping.", file);
        }
    }
}

fn run_script(script_name: &str) {
    if !Path::new(script_name).exists() {
        eprintln!("Error: script {} not found!", script_name);
        log::error!("Missing script: {}", script_name);
        exit(1);
    }

    println!("Running {}...", script_name);
    log::info!("Running {}...", script_name);

    let status = Command::new("/bin/bash")
        .arg(script_name)
        .status()
        .expect("Failed to execute script");

    if !status.success() {
        eprintln!("Error running {}: {}", script_name, status);
        log::error!("Error running {}: {:?}", script_name, status);
        exit(1);
    }

    println!("{} executed successfully.", script_name);
    log::info!("{} executed successfully.", script_name);
}

fn run_kernel(base_dir: &str) {
    println!("Compiling and running kernel hardening (kernel.c)...");
    log::info!("Compiling and running kernel hardening (kernel.c)...");

    let kernel_file = format!("{}/kernel.c", base_dir);
    let output_file = format!("{}/kernel", base_dir);

    let compile_status = Command::new("gcc")
        .arg(&kernel_file)
        .arg("-o")
        .arg(&output_file)
        .status()
        .expect("Failed to compile kernel.c");

    if !compile_status.success() {
        eprintln!("Error compiling kernel.c: {:?}", compile_status);
        log::error!("Error compiling kernel.c: {:?}", compile_status);
        exit(1);
    }

    let run_status = Command::new(&output_file)
        .status()
        .expect("Failed to execute kernel hardening");

    if !run_status.success() {
        eprintln!("Error running kernel: {:?}", run_status);
        log::error!("Error running kernel: {:?}", run_status);
        exit(1);
    }

    println!("Kernel hardening completed successfully.");
    log::info!("Kernel hardening completed successfully.");
}

fn launch_gui(base_dir: &str) {
    println!("Launching GUI...");
    log::info!("Launching GUI...");

    let gui_file = format!("{}/gui/main.py", base_dir);

    let status = Command::new("python3")
        .arg(&gui_file)
        .status()
        .expect("Failed to launch GUI");

    if !status.success() {
        eprintln!("Error launching GUI: {:?}", status);
        log::error!("Error launching GUI: {:?}", status);
        exit(1);
    }

    println!("GUI launched successfully.");
    log::info!("GUI launched successfully.");
}

fn monitor_system() {
    println!("Monitoring system for changes...");
    log::info!("Monitoring system for changes...");

    let (tx, rx) = channel();
    let mut watcher = watcher(tx, Duration::from_secs(10)).expect("Failed to initialize watcher");

    watcher.watch("/", RecursiveMode::Recursive).expect("Failed to watch root directory");

    loop {
        match rx.recv() {
            Ok(event) => {
                println!("Detected system change: {:?}", event);
                log::info!("Detected system change: {:?}", event);
            }
            Err(e) => {
                eprintln!("Watch error: {:?}", e);
                log::error!("Watch error: {:?}", e);
            }
        }
    }
}

fn create_systemd_service(exec_path: &str) {
    println!("Creating systemd service: {}", SYSTEMD_UNIT);
    log::info!("Creating systemd service");

    let unit_contents = format!(
        "[Unit]
Description=HARDN Orchestration Service
After=network.target auditd.service
Requires=network.target

[Service]
Type=simple
ExecStart={} --all
Restart=on-failure
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
", exec_path);

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(SYSTEMD_UNIT)
        .expect("Failed to create systemd unit file");

    file.write_all(unit_contents.as_bytes()).expect("Failed to write systemd unit file");

    Command::new("systemctl")
        .args(&["daemon-reload"])
        .status()
        .expect("Failed to reload systemd");

    Command::new("systemctl")
        .args(&["enable", "--now", "hardn.service"])
        .status()
        .expect("Failed to enable/start HARDN systemd service");

    println!("Systemd service created and started.");
    log::info!("Systemd service created and started.");
}

fn main() {
    env_logger::init();

    let matches = App::new("HARDN Orchestration Script")
        .version("1.0")
        .author("Tim")
        .about("Orchestrates the HARDN project")
        .arg(Arg::with_name("setup").long("setup").help("Run setup scripts"))
        .arg(Arg::with_name("kernel").long("kernel").help("Run kernel hardening"))
        .arg(Arg::with_name("gui").long("gui").help("Launch the GUI"))
        .arg(Arg::with_name("monitor").long("monitor").help("Monitor the system for changes"))
        .arg(Arg::with_name("all").long("all").help("Run all steps (default)"))
        .arg(Arg::with_name("install-service").long("install-service").help("Create and enable systemd service"))
        .get_matches();

    let base_dir = env::current_dir()
        .expect("Failed to read current directory")
        .canonicalize()
        .expect("Failed to resolve full path")
        .to_str()
        .unwrap()
        .to_string();

    validate_environment();
    set_executable_permissions(&base_dir);

    if matches.is_present("install-service") {
        let binary_path = std::env::current_exe().unwrap();
        create_systemd_service(binary_path.to_str().unwrap());
        return;
    }

    if matches.is_present("setup") || matches.is_present("all") {
        run_script(&format!("{}/setup/setup.sh", base_dir));
        run_script(&format!("{}/setup/packages.sh", base_dir));
    }

    if matches.is_present("kernel") || matches.is_present("all") {
        run_kernel(&base_dir);
    }

    if matches.is_present("gui") || matches.is_present("all") {
        launch_gui(&base_dir);
    }

    if matches.is_present("monitor") || matches.is_present("all") {
        monitor_system();
    }

    println!("HARDN orchestration completed successfully.");
    log::info!("HARDN orchestration completed successfully.");
}