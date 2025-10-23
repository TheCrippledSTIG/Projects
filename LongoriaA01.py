# LongoriaA01.py
import socket
import sys
import time
from pathlib import Path

'''
Alexander Logan Longoria
CIS 41A Fall 2024
Assignment 1

Use the classes as described to be used in the main program. 

Create a top level menu for the program that gives three options
    Network Tools
    Forensics Tools
    Quit 

Under the Network tools have a sub-menu with two options.
    Port Scanning
    Main menu

Under the Forensics Tools similarly have two options.
    LogFileScanning
    Main Menu 

Under the PortScanningsubmenu have another submenu with the necessary options for port scanning
???

Under the LogFileScanning submenu have the necessary options for LogFileScanning.
???

The last option on each of these submenus should be to go back to the previous menu.


'''

def name_log_output_file(prefix = 'assignment_1_output_'):
    output_file_name = time.strftime("logFile_%Y-%m-%d-%H-%M-%S.txt")
    return f'{prefix}_{output_file_name}'

def default_log_name(prefix="log"):
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    return f"{prefix}_{ts}.txt"

def write_text_file(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

#--------------------------------------------------------------------------------------------------------------------------------
def notify(msg: str):
    '''
    Simple notification function to print messages during scans to update the user.
    '''
    print(f"{msg}")

def notify_periodic(current: int, total: int, every: int, label: str):
    """Print 'checked X/Y' every `every` items (and at the end)."""
    if total <= 0:
        return
    if current % every == 0 or current == total:
        print(f"COMPLETE! {label}: checked {current}/{total}")

#--------------------------------------------------------------------------------------------------------------------------------

class MenuItem:
    def __init__(self, label, action):
        self.label = label
        self.action = action

#--------------------------------------------------------------------------------------------------------------------------------

class longoria_menu_class:
    '''
    Simple menu builder class to display different menus throughout the code.
    '''
    def __init__(self, title):
        self.title = title
        self.menu_options = []

    def add_menu_option(self, label, action):
        self.menu_options.append(MenuItem(label, action))

    def run(self):
        while True:
            print(f"------------------")
            print(f"{self.title}")
            print(f"------------------")
            for index, item in enumerate(self.menu_options, start=1):
                print(f"{index}.{item.label}")
            choice = input("Please select one of the menu options:\n")
            if not choice.isdigit():
                print("Invalid input. Please enter a number.")
                continue
            choice_i = int(choice)
            if 1 <= choice_i <= len(self.menu_options):
                self.menu_options[choice_i - 1].action()
                break
            else:
                print("Choice out of range, try again.")
#--------------------------------------------------------------------------------------------------------------------------------

class PortScanner:
    '''
    Port scanning functionality. Reads IPs/ports from keyboard or file,
    supports configurable timeout, and can save results.
    '''

    def __init__(self, timeout_sec = 5):
        self.timeout = timeout_sec

    def port_knocker(self, ip, port):
        '''
        Check if a port is open (returns True if open).
        '''
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            if self.timeout < 5:
                print(f"Timeout set to {self.timeout} seconds. This may be too fast for some ports. "
                      "If there are no results try increasing the timeout to at least 5 seconds.")
            result = s.connect_ex((ip, port))
            return result == 0  # Returns True if port is open

    # --- Unified file reader (replaces read_lines_from_file + read_lines_file_02) ---
    def read_lines_file(self, file_path):
        """
        Read non-empty, stripped lines from a text file.
        Accepts either a str path or a pathlib.Path.
        Uses UTF-8 and returns [] on any error (with a helpful message).
        """
        try:
            p = Path(file_path)
            with p.open('r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return []
        except Exception as e:
            print(f"An error occurred while reading {file_path}: {e}")
            return []

    def gather_ips(self):
        '''
        Gathers IP addresses from a file or manual input.
        '''
        print(f'Where would you like to get the IP addresses from?')
        print(f'1. Manual Input')
        print(f'2. File')
        user_input = input('Please enter one of the options:')
        if user_input == '1':
            user_provided_ip = input('Please enter IP address/addresses. (ex. xxx.xxx.xxx.xxx, xxx.xxx.xxx.xxx,):')
            return [ip for ip in user_provided_ip.replace(',', ' ').split() if ip]
        elif user_input == '2':
            file_name = input('Please enter the file name containing IP addresses: ')
            return self.read_lines_file(file_name)  # <— unified call
        else:
            print("Invalid option selected.")
            return []

    def _gather_ports(self):
        '''
        Gathers port numbers from user input or a file (supports ranges like "20-25").
        '''
        print("\nPort input source:")
        print("1) Keyboard Input (e.g., 22 80 443 or ranges like 20-25)")
        print("2) Input file (one port per line; ranges allowed 'start-end')")
        src = input("Choose 1 or 2: ").strip()
        if src == "2":
            p = input("Enter path to port list file: ").strip()
            tokens = self.read_lines_file(p)  # <— unified call
        else:
            raw = input("Enter ports/ranges: ")
            tokens = [tok for tok in raw.replace(",", " ").split() if tok]

        ports = []
        for tok in tokens:
            if "-" in tok:
                try:
                    start, end = tok.split("-", 1)
                    start_i, end_i = int(start), int(end)
                    if start_i <= 0 or end_i <= 0 or end_i < start_i:
                        print(f"Skipping invalid range: {tok}")
                        continue
                    ports.extend(range(start_i, end_i + 1))
                except ValueError:
                    print(f"Skipping invalid token: {tok}")
            else:
                try:
                    pnum = int(tok)
                    if pnum > 0:
                        ports.append(pnum)
                except ValueError:
                    print(f"Skipping invalid port: {tok}")

        #sort
        return sorted(set(ports))

    def configure_timeout(self):
        '''
        Configures the timeout for network operations.
        '''
        try:
            timeout_input = input("Enter timeout in seconds (recommended is 5): ").strip()
            if timeout_input:
                timeout_value = int(timeout_input)
                if timeout_value > 0:
                    self.timeout = timeout_value
                else:
                    print("Timeout must be a positive integer. Using default of 5 seconds.")
        except ValueError:
            print("Invalid input. Using default timeout of 5 seconds.")
            self.timeout = 5

    def run_port_scan(self):
        '''
        Runs the port scanning process with lightweight notifications.
        '''
        print(f"--- Port Scan ---")
        print(f"Current timeout is {self.timeout} seconds.")
        ips = self.gather_ips()
        if not ips:
            print("No valid IP addresses provided. Exiting scan.")
            return
        ports = self._gather_ports()
        if not ports:
            print("No valid ports provided. Exiting scan.")
            return

        total_ports = len(ports)
        lines = []

        notify(f"Beginning port scan. {len(ips)} IP(s), {total_ports} port(s) each. Timeout={self.timeout}s.")

        for ip_index, ip in enumerate(ips, start=1):
            notify(f"Starting scan for {ip} ({ip_index}/{len(ips)}) with {total_ports} port(s).")
            open_count = closed_count = err_count = 0

            tick = max(1, total_ports // 10)

            for idx, port in enumerate(ports, start=1):
                try:
                    is_open = self.port_knocker(ip, port)
                    status = "Open" if is_open else "Closed"
                    if is_open:
                        open_count += 1
                    else:
                        closed_count += 1
                except Exception as e:
                    status = f"Error: {e}"
                    err_count += 1

                line = f"ip: {ip}, port: {port}, status: {status}"
                if status == "Open":
                    print(line)
                lines.append(line)

                notify_periodic(idx, total_ports, tick, f"{ip}")

            notify(f"Finished {ip}. Open: {open_count}, Closed: {closed_count}, Errors: {err_count}")

        self.offer_save(lines)

    def offer_save(self, lines):
        '''
        Offers to save the scan results to a file.
        '''
        save_option = input("Would you like to save the results to a file? (y/n): ").strip().lower()
        if save_option == 'y':
            default_name = default_log_name("port_scan_results")
            file_name = input(f"Enter output file name (default: {default_name}): ").strip()
            if not file_name:
                file_name = default_name
            try:
                with open(file_name, 'w') as f:
                    for line in lines:
                        f.write(line + "\n")
                print(f"Results saved to {file_name}")
            except Exception as e:
                print(f"Failed to save results: {e}")
        else:
            print("Results not saved.")

#--------------------------------------------------------------------------------------------------------------------------------
class FileLogScanningClass:
    '''
    Scans a text/log file for user-provided words (case-insensitive) with lightweight notifications.
    '''
    def __init__(self, file_path=None, separator=","):
        self.file_path = Path(file_path) if file_path else None
        self.separator = separator  # default separator for multiple words can be changed by user

    def _read_lines(self):
        if not self.file_path or not self.file_path.exists():
            raise FileNotFoundError("Log file not set or does not exist.")
        return self.file_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    def choose_file(self):
        p = input("Enter path to log/text file: ").strip()
        p = Path(p)
        if not p.exists():
            print("File not found.")
            return
        self.file_path = p
        print(f"Log file set to: {self.file_path}")

    def set_separator(self):
        sep = input(f"Enter word separator (current '{self.separator}'): ").strip()
        if sep:
            self.separator = sep

    def _collect_terms(self):
        raw = input(f"Enter words separated by '{self.separator}': ").strip()
        terms = [t.strip() for t in raw.split(self.separator) if t.strip()]
        return terms

    def scan(self):
        if not self.file_path:
            self.choose_file()
            if not self.file_path:
                return
        terms = self._collect_terms()
        if not terms:
            print("No search terms provided.")
            return

        lines = self._read_lines()
        total_lines = len(lines)
        result_lines = []
        hits_total = 0

        notify(f"Scanning file: {self.file_path}  (lines: {total_lines})")
        # roughly updates across the file
        tick = max(50, total_lines // 20) if total_lines > 0 else 1

        for idx, line in enumerate(lines, start=1):
            found = [t for t in terms if t.lower() in line.lower()]
            if found:
                hits_total += 1
                all_words = ", ".join(sorted(set(found), key=str.lower))
                out = f"[{idx}] {line}\n    -> found: {all_words}"
                print(out)
                result_lines.append(out)

            notify_periodic(idx, total_lines, tick, "File scan")

        notify(f"Scan complete. Matches on {hits_total} line(s) out of {total_lines}.")

        header = [
            f"File: {self.file_path}",
            f"Separator: '{self.separator}'",
            "Search terms: " + ", ".join(terms),
            f"Matching lines: {hits_total}",
            "-" * 60,
        ]
        content = "\n".join(header + result_lines)
        self._offer_save(content)

    def _offer_save(self, content):
        print("\nSave output?")
        print("1) Yes, default timestamped name")
        print("2) Yes, specify filename")
        print("3) No")
        choice = input("Choose 1/2/3: ").strip()
        if choice == "1":
            path = default_log_name("logscan")
            write_text_file(path, content)
            print(f"Saved to {path}")
        elif choice == "2":
            path = input("Enter output path: ").strip()
            if not path:
                path = default_log_name("logscan")
            write_text_file(path, content)
            print(f"Saved to {path}")
        else:
            print("Not saved.")

#--------------------------------------------------------------------------------------------------------------------------------

def main():
    '''
    Main program where most pf the work is done.
    
    '''
    port_scanner = PortScanner()
    log_scanner = FileLogScanningClass()

    def menu_network_tools():
        submenu = longoria_menu_class("Network Tools")
        submenu.add_menu_option("Port Scanning", port_scanner_menu)
        submenu.add_menu_option("Go To Main Menu", lambda: None)
        submenu.run()

    def port_scanner_menu():
        ps = longoria_menu_class("Port Scanning")
        ps.add_menu_option("Run Scan", port_scanner.run_port_scan)
        ps.add_menu_option("Configure Timeout", port_scanner.configure_timeout)
        ps.add_menu_option("Back", lambda: None)
        ps.run()

    def menu_forensics_tools():
        submenu = longoria_menu_class("Forensics Tools")
        submenu.add_menu_option("LogFileScanning", log_scanner_menu)
        submenu.add_menu_option("Go To Main Menu", lambda: None)
        submenu.run()

    def log_scanner_menu():
        ls = longoria_menu_class("Log File Scanning")
        ls.add_menu_option("Choose Log File", log_scanner.choose_file)
        ls.add_menu_option("Set Word Separator", log_scanner.set_separator)
        ls.add_menu_option("Scan for Words", log_scanner.scan)
        ls.add_menu_option("Back", lambda: None)
        ls.run()

    while True:
        root = longoria_menu_class("Main Menu")
        root.add_menu_option("Network Tools", menu_network_tools)
        root.add_menu_option("Forensics Tools", menu_forensics_tools)
        root.add_menu_option("Quit", lambda: sys.exit(0))
        root.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
