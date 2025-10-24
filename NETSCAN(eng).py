import sys                 # to read command-line arguments
import socket              # for IP/port operations and conversions
import ipaddress           # handling IP addresses and networks
import concurrent.futures  # to run tasks in parallel
import platform            # to detect the operating system
import subprocess          # to run system commands
import re                  # regex pattern matching


def print_app_name():
    print("""

 _   _      _   _____                                 
| \\ | |    | | /  ___|                                
|  \\| | ___| |_\\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| . ` |/ _ \\ __|`--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|
| |\\  |  __/ |_/\\__/ / (_| (_| | | | | | | |  __/ |   
\\_| \\_/\\___|\\__\\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   

         Welcome to a (simple) Network Scanner                                                    
                                                      

          """)


def get_ip_and_mask():
    """
    Detects the local IP address and subnet mask.
    Tries several methods in order of reliability:
      1) socket to get outbound IP
      2) 'ip addr' on Linux
      3) 'ifconfig' as a fallback
      4) assume /24 if it can't find the mask
      5) return loopback as a last resort
    """
    system = platform.system().lower()
    if system == "windows":
        try:
            output = subprocess.check_output("ipconfig", universal_newlines=True)
            ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)
            mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)
            if ip_match and mask_match:
                return ip_match.group(1), mask_match.group(1)
        except Exception:
            pass

    local_ip = None
    # 1) tries to get the outbound IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    # 2) tries 'ip addr' on Linux
    try:
        output = subprocess.check_output(["ip", "addr"], universal_newlines=True)
        matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)(?: .*scope (\w+))?', output)
        chosen_ip = None
        chosen_cidr = None

        if local_ip:
            for ip, cidr, scope in matches:
                if ip == local_ip and not ip.startswith("127."):
                    chosen_ip = ip
                    chosen_cidr = int(cidr)
                    break

        if not chosen_ip:
            for ip, cidr, scope in matches:
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    chosen_ip = ip
                    chosen_cidr = int(cidr)
                    break

        if chosen_ip and chosen_cidr is not None:
            mask = socket.inet_ntoa((0xffffffff << (32 - chosen_cidr) & 0xffffffff).to_bytes(4, "big"))
            return chosen_ip, mask

    except Exception:
        pass

    # 3) fallback to ifconfig
    try:
        output = subprocess.check_output("ifconfig", shell=True, universal_newlines=True)
        m = re.search(r'inet (?:addr:)?([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
        if m:
            ip = m.group(1)
            mask = m.group(2)
            if mask.startswith("0x"):
                mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
            return ip, mask
    except Exception:
        pass

    # 4) if we only have the IP, it assumes it's /24
    if local_ip:
        return local_ip, "255.255.255.0"

    # 5) final fallback
    return "127.0.0.1", "255.255.255.255"


def mask_to_cidr(mask):
    """
    Converts a subnet mask (e.g. 255.255.255.0) to CIDR notation (e.g. 24).
    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))


def parse_network(arg=None):
    """
    Parses the network argument and return an ipaddress.ip_network object.

    Supports:
      - no argument (auto-detect IP and mask)
      - full CIDR (e.g. 192.168.1.0/24)
      - partial IP (e.g. 192.168.1 -> 192.168.1.0/24)
      - single IP (e.g. 192.168.1.10 -> /32)
    """
    if not arg:
        ip, mask = get_ip_and_mask()
        cidr = mask_to_cidr(mask)
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)

    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)

    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)

    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/32', strict=False)

    else:
        raise ValueError("Invalid network format")


def ping(ip):
    """
    Runs a single ping and returns the IP if reachable, otherwise None.
    """
    ip = str(ip)
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=2
        )
        if result.returncode == 0:
            return ip
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def scan_network(network):
    """
    Scans all hosts in the network in parallel and returns the list of online ones.
    """
    print(f"Scanning network: {network}")
    online = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    online.append(result)

    except KeyboardInterrupt:
        print("\nScan interrupted by user. Showing results so far ...")

    return online


def show_help():
    """
    prints usage and examples
    """
    print(
        "Usage: netscan [network]\n"
        "Scan a network for online devices.\n\n"
        "Options:\n"
        "  -h, --help     Show this help message\n"
        "Examples:\n"
        "  netscan                 # Scan current local network\n"
        "  netscan 192.168.1.0     # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1       # Scan 192.168.1.0/24\n"
        "  netscan 192.168.1.0/24  # Scan 192.168.1.0/24"
    )


def main():
    """
    handles arguments, runs the scan and shows results.
    """
    print_app_name()
    
    args = sys.argv[1:]

    if len(args) == 1 and args[0] in ("-h", "--help"):
        show_help()
        return
    
    if not args:
        try:
            network = parse_network()
        except Exception as e:
            print(f"Error: {e}")
            show_help()
            return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])
        except Exception as e:
            print(f"Error: {e}")
            return
    
    try:
        online_hosts = scan_network(network)
        print("\nOnline hosts:")
        if not online_hosts:
            print("No hosts online")
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    
    print("\n--help or -h to show help message\n")


if __name__ == "__main__":
    main()
