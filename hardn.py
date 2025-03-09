import os
import subprocess
import sys
import threading
import shutil
import tkinter as tk
from tkinter import ttk, messagebox  
from datetime import datetime
import pexpect

def ensure_root():
    if os.geteuid() != 0:
        print("Restarting as root...")
        try:
            subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate to root: {e}")
        sys.exit(0)

ensure_root()

def exec_command(command, args, status_gui=None):
    try:
        if status_gui:
            status_gui.update_status(f"Executing: {command} {' '.join(args)}")
        print(f"Executing: {command} {' '.join(args)}")
        if command == "apt" and "update" in args:
            process = subprocess.run([command, "update"], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        elif command == "apt" and "upgrade" in args:
            process = subprocess.run([command, "upgrade", "-y"], check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        else:
            process = subprocess.run([command] + args, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
        if status_gui:
            status_gui.update_status(f"Completed: {command} {' '.join(args)}")
        print(process.stdout)
    except subprocess.CalledProcessError as e:
        if status_gui:
            status_gui.update_status(f"Error executing '{command} {' '.join(args)}': {e.stderr}")
        print(f"Error executing command '{command} {' '.join(args)}': {e.stderr}")
    except subprocess.TimeoutExpired:
        if status_gui:
            status_gui.update_status(f"Command timed out: {command} {' '.join(args)}")
        print(f"Command timed out: {command} {' '.join(args)}")
    except Exception as e:
        if status_gui:
            status_gui.update_status(f"Unexpected error: {str(e)}")
        print(f"Unexpected error: {str(e)}")

def print_ascii_art():
    art = """
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
                "HARDN" - The Linux Security Project
                ----------------------------------------
                "A single Debian tool to fully secure an 
               OS using automation, monitoring, heuristics 
                           and availability.
                           
                         DEV: Tim "Tank" Burns
                             License: MIT
                ----------------------------------------
    """
    return art

# GET DIR
script_dir = os.path.dirname(os.path.abspath(__file__))

# FILE PATH - to dependents 
HARDN_DARK_PATH = os.path.join(script_dir, "HARDN_dark.py")

print("HARDN_DARK_PATH:", HARDN_DARK_PATH)

# GUI
class StatusGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HARDN")
        self.root.geometry("800x600")
        self.root.configure(bg='#333333')

        self.canvas = tk.Canvas(self.root, width=800, height=600, bg='#333333', highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.progress = ttk.Progressbar(self.root, length=700, mode="determinate")
        self.progress_window = self.canvas.create_window(400, 550, window=self.progress)

        self.status_text = tk.StringVar()
        self.status_label = ttk.Label(self.root, textvariable=self.status_text, background='#333333', foreground='white')
        self.status_label_window = self.canvas.create_window(400, 580, window=self.status_label)

        self.log_text = tk.Text(self.root, height=10, width=90, bg='#222222', fg='white', highlightthickness=0)
        self.log_text_window = self.canvas.create_window(400, 400, window=self.log_text)

        self.task_count = 0
        self.total_tasks = 15  

        self.display_ascii_art()

    def display_ascii_art(self):
        ascii_art = print_ascii_art()
        self.canvas.create_text(400, 200, text=ascii_art, fill="white", font=("Courier", 8), anchor="center")

    def update_status(self, message):
        self.task_count += 1
        self.progress["value"] = (self.task_count / self.total_tasks) * 100
        self.status_text.set(message)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def complete(self, lynis_score=None):
        self.progress["value"] = 100
        if lynis_score:
            self.status_text.set(f"Hardening complete! Lynis score: {lynis_score}")
        else:
            self.status_text.set("Hardening complete!")
        self.log_text.insert(tk.END, f"Lynis score: {lynis_score}\n")
        self.log_text.see(tk.END)
        
        # Parse and prompt user for fixes from Lynis logs
        fixes = parse_lynis_output()
        prompt_user_for_fixes(fixes)

    def run(self):
        self.root.mainloop()

    def get_grub_password(self):
        self.password_window = tk.Toplevel(self.root)
        self.password_window.title("Enter GRUB Password")
        self.password_window.geometry("300x150")
        self.password_window.configure(bg='#333333')

        self.password_label = ttk.Label(self.password_window, text="Enter GRUB Password:", background='#333333', foreground='white')
        self.password_label.pack(pady=10)

        self.password_entry = ttk.Entry(self.password_window, show="*")
        self.password_entry.pack(pady=10)

        self.submit_button = ttk.Button(self.password_window, text="Submit", command=self.submit_password)
        self.submit_button.pack(pady=10)

    def submit_password(self):
        self.grub_password = self.password_entry.get()
        self.password_window.destroy()
        secure_grub(self)

# SECURITY HARDENING FUNCTIONS
def configure_apparmor():
    status_gui.update_status("Configuring AppArmor for Mandatory Access Control...")
    exec_command("apt", ["install", "-y", "apparmor", "apparmor-profiles", "apparmor-utils"], status_gui)
    exec_command("systemctl", ["enable", "--now", "apparmor"], status_gui)

def configure_firejail():
    status_gui.update_status("Configuring Firejail for Application Sandboxing...")
    exec_command("apt", ["install", "-y", "firejail"], status_gui)
    exec_command("firejail", ["--list"], status_gui)
    
def enforce_password_policies():
    exec_command("apt", ["install", "-y", "libpam-pwquality"], status_gui)
    exec_command("sh", ["-c", "echo 'password requisite pam_pwquality.so retry=3 minlen=12 difok=3' >> /etc/pam.d/common-password"], status_gui)
    
    
# SECURITY TOOLS
def remove_clamav():
    status_gui.update_status("Removing ClamAV...")
    exec_command("apt", ["remove", "--purge", "-y", "clamav", "clamav-daemon"], status_gui)
    exec_command("rm", ["-rf", "/var/lib/clamav"], status_gui)
    
def install_rkhunter():
    status_gui.update_status("Installing Rootkit Hunter (rkhunter)...")
    exec_command("apt", ["install", "-y", "rkhunter"], status_gui)
    exec_command("rkhunter", ["--update"], status_gui)
    exec_command("rkhunter", ["--propupd"], status_gui)
    
def install_maldetect():
    status_gui.update_status("Installing Linux Malware Detect (Maldetect)...")
    exec_command("apt", ["install", "-y", "maldetect"], status_gui)
    exec_command("maldet", ["-u"], status_gui)
    

def setup_auto_updates():
    status_gui.update_status("Configuring Auto-Update for Security Packages...")
    cron_jobs = [
        "0 3 * * * /opt/eset/esets/sbin/esets_update",
        "0 2 * * * apt update && apt upgrade -y",
        "0 1 * * * lynis audit system --cronjob >> /var/log/lynis_cron.log 2>&1"
    ]
    for job in cron_jobs:
        exec_command("sh", ["-c", f"(crontab -l 2>/null; echo '{job}') | crontab -"], status_gui)

def configure_tcp_wrappers(): # thank you Kiukcat :)
    status_gui.update_status("Configuring TCP Wrappers...")
    exec_command("apt", ["install", "-y", "tcpd"], status_gui)

def configure_fail2ban():
    status_gui.update_status("Setting up Fail2Ban...")
    exec_command("apt", ["install", "-y", "fail2ban"], status_gui)
    exec_command("systemctl", ["restart", "fail2ban"], status_gui)
    exec_command("systemctl", ["enable", "--now", "fail2ban"], status_gui)
    
def run_lynis_audit(status_gui):
    status_gui.update_status("Running Lynis security audit...")
    result = subprocess.run(["lynis", "audit", "system", "--profile", "/etc/lynis/custom.prf"], capture_output=True, text=True)
    with open("/var/log/lynis.log", "w") as log_file:
        log_file.write(result.stdout)
    lynis_score = None
    for line in result.stdout.split("\n"):
        if "Hardening index" in line:
            lynis_score = line.split(":")[1].strip()
            break
    if lynis_score:
        status_gui.update_status(f"Lynis score: {lynis_score}")
        print(f"Lynis score: {lynis_score}")
    return lynis_score

import shutil
import subprocess
import pexpect
# Added VM compatibility in case it's running boot loader or EFI- thanks Alex :)
def configure_grub():
    status_gui.update_status("Configuring GRUB Security Settings...")
    
    # Check if GRUB is available - Alex pointed it out running it on Oracle VM
    grub_cmd = shutil.which("update-grub") or shutil.which("grub-mkconfig")

    if grub_cmd:
        try:
            subprocess.run([grub_cmd, "-o", "/boot/grub/grub.cfg"], check=True, timeout=120)
        except subprocess.TimeoutExpired:
            status_gui.update_status("Command timed out: update-grub")
    else:
        print("Warning: GRUB update command not found. Skipping GRUB update.")
        print("If running inside a VM, this may not be necessary.")

def configure_firewall(status_gui): # simplified for use, not most secure version at this time
    status_gui.update_status("Configuring Firewall...")
    exec_command("ufw", ["default", "deny", "incoming"], status_gui)
    exec_command("ufw", ["default", "allow", "outgoing"], status_gui)
    exec_command("ufw", ["allow", "out", "80,443/tcp"], status_gui)
    exec_command("ufw", ["--force", "enable"], status_gui)
    exec_command("ufw", ["reload"], status_gui)
    
def secure_grub(status_gui):
    status_gui.update_status("Configuring GRUB Secure Boot Password...")
    grub_password = status_gui.grub_password
    child = pexpect.spawn("grub-mkpasswd-pbkdf2")
    child.expect("Enter password: ")
    child.sendline(grub_password)
    child.expect("Reenter password: ")
    child.sendline(grub_password)
    child.expect(pexpect.EOF)
    output = child.before.decode()
    
    hashed_password = ""
    for line in output.split("\n"):
        if "PBKDF2 hash of your password is" in line:
            hashed_password = line.split("is ")[1].strip()
            break
    
    if not hashed_password:
        status_gui.update_status("Failed to generate GRUB password hash.")
        return
    
    grub_config = f"set superusers=\"admin\"\npassword_pbkdf2 admin {hashed_password}\n"
    with open("/etc/grub.d/00_password", "w") as f:
        f.write(grub_config)
    
    exec_command("update-grub", [], status_gui)
    
def enable_aide(status_gui):
    status_gui.update_status("Installing and configuring AIDE...")
    exec_command("apt", ["install", "-y", "aide", "aide-common"], status_gui)
    status_gui.update_status("Initializing AIDE database (this may take a while)...")
    threading.Thread(target=run_aideinit, args=(status_gui,)).start()

def run_aideinit(status_gui):
    try:
        exec_command("aideinit", [], status_gui)
        exec_command("mv", ["/var/lib/aide/aide.db.new", "/var/lib/aide/aide.db"], status_gui)
    except subprocess.TimeoutExpired:
        status_gui.update_status("Command timed out: aideinit && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db")

def harden_sysctl(status_gui):
    exec_command("sysctl", ["-w", "net.ipv4.conf.all.accept_redirects=0"], status_gui)
    exec_command("sysctl", ["-w", "net.ipv4.conf.all.send_redirects=0"], status_gui)    

def disable_usb(status_gui): # We can set this to just put in monitor mode*
    status_gui.update_status("Locking down USB devices...")
    exec_command("sh", ["-c", "echo 'blacklist usb-storage' >> /etc/modprobe.d/usb-storage.conf"], status_gui)
    exec_command("modprobe", ["-r", "usb-storage"], status_gui)
# if usb is in use it won't allow any changes 
def software_integrity_check(status_gui):
    status_gui.update_status("Software Integrity Check...")
    exec_command("debsums", ["-s"], status_gui)

def run_audits(status_gui):
    status_gui.update_status("Running Security Audits...")
    exec_command("lynis", ["audit", "system", "--quick"], status_gui)

def scan_with_eset(status_gui):
    status_gui.update_status("Scanning system with ESET NOD32 (ES32) Antivirus...")
    exec_command("/opt/eset/esets/sbin/esets_scan", ["/home"], status_gui)

def configure_postfix(status_gui):
    status_gui.update_status("Configuring Postfix to hide mail_name...")
    exec_command("postconf", ["-e", "smtpd_banner=$myhostname ESMTP $mail_name"], status_gui)
    exec_command("systemctl", ["restart", "postfix"], status_gui)

def purge_old_packages(status_gui):
    status_gui.update_status("Purging old/removed packages...")
    exec_command("aptitude", ["purge", "~c"], status_gui)

def configure_password_hashing_rounds(status_gui):
    status_gui.update_status("Configuring password hashing rounds...")
    exec_command("sed", ["-i", "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/", "/etc/login.defs"], status_gui)
    exec_command("sed", ["-i", "s/^SHA_CRYPT_MIN_ROUNDS.*/SHA_CRYPT_MIN_ROUNDS 5000/", "/etc/login.defs"], status_gui)
    exec_command("sed", ["-i", "s/^SHA_CRYPT_MAX_ROUNDS.*/SHA_CRYPT_MAX_ROUNDS 5000/", "/etc/login.defs"], status_gui)

def add_legal_banners(status_gui):
    status_gui.update_status("Adding legal banners...")
    with open("/etc/issue", "w") as f:
        f.write("Authorized uses only. All activity may be monitored and reported.\n")
    with open("/etc/issue.net", "w") as f:
        f.write("Authorized uses only. All activity may be monitored and reported.\n")



# CHECK ALL -  we needed this in the parent file
def check_and_install_dependencies():
    dependencies = [
        "apparmor", "apparmor-profiles", "apparmor-utils", "firejail", "libpam-pwquality",
        "tcpd", "fail2ban", "rkhunter", "aide", "aide-common", "ufw", "postfix", "debsums", "python3-pexpect", "python3-tk"
    ]
    
    for package in dependencies:
        try:
            status_gui.update_status(f"Checking for {package}...")
            result = subprocess.run(f"dpkg -s {package}", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if "install ok installed" not in result.stdout.decode():
                status_gui.update_status(f"{package} not found. Installing...")
                exec_command("apt", ["install", "-y", package], status_gui)
            else:
                status_gui.update_status(f"{package} is already installed.")
        except subprocess.CalledProcessError:
            status_gui.update_status(f"{package} not found. Installing...")
            exec_command("apt", ["install", "-y", package], status_gui)

# START HARDENING PROCESS
def start_hardening():
    def run_tasks():
        check_and_install_dependencies()
        exec_command("apt", ["update"], status_gui)
        exec_command("apt", ["upgrade", "-y"], status_gui)
        enforce_password_policies()
        exec_command("apt", ["install", "-y", "fail2ban"], status_gui)
        exec_command("systemctl", ["enable", "--now", "fail2ban"], status_gui)
        configure_firewall(status_gui)
        exec_command("apt", ["install", "-y", "rkhunter"], status_gui)
        exec_command("rkhunter", ["--update"], status_gui)
        exec_command("rkhunter", ["--propupd"], status_gui)
        install_maldetect()
        exec_command("apt", ["install", "-y", "libpam-pwquality"], status_gui)
        enable_aide(status_gui)
        harden_sysctl(status_gui)
        disable_usb(status_gui)
        exec_command("apt", ["install", "-y", "apparmor", "apparmor-profiles", "apparmor-utils"], status_gui)
        exec_command("systemctl", ["enable", "--now", "apparmor"], status_gui)
        configure_postfix(status_gui)
        exec_command("apt", ["autoremove", "-y"], status_gui)  # Use apt autoremove instead of aptitude
        configure_password_hashing_rounds(status_gui)
        add_legal_banners(status_gui)
        lynis_score = run_lynis_audit(status_gui)
        fixes = parse_lynis_output()
        prompt_user_for_fixes(fixes)
        status_gui.complete(lynis_score)
    
    threading.Thread(target=run_tasks, daemon=True).start()

# MAIN
def main():
    global status_gui  # global
    status_gui = StatusGUI()  
    status_gui.root.after(100, start_hardening)
    status_gui.run()

if __name__ == "__main__":
    main()