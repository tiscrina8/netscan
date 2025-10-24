import sys                 # per leggere argomenti da riga di comando
import socket              # per operazioni su IP e porte
import ipaddress           # gestione reti e indirizzi IP
import concurrent.futures  # per eseguire task in parallelo
import platform            # per rilevare il sistema operativo
import subprocess          # per eseguire comandi di sistema
import re                  # per pattern matching con regex


def print_app_name():
    print("""
 _   _      _   _____                                 
| \\ | |    | | /  ___|                                
|  \\| | ___| |_\\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| . ` |/ _ \\ __|`--. \\/ __/ _` | '_ \\| '_ \\ / _ \\ '__|
| |\\  |  __/ |_/\\__/ / (_| (_| | | | | | | |  __/ |   
\\_| \\_/\\___|\\__\\____/ \\___\\__,_|_| |_|_| |_|\\___|_|   

     Benvenuto in un (semplice) Network Scanner
          
          
    """)


def get_ip_and_mask():
    """
    Rileva l'indirizzo IP locale e la subnet mask.
    Tenta diversi metodi in ordine di affidabilità:
      1) socket per ottenere l'IP di uscita
      2) 'ip addr' su Linux
      3) 'ifconfig' come fallback
      4) assume /24 se non trova la mask
      5) ritorna loopback come ultima risorsa
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
    # 1) prova a ottenere l'IP di uscita
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

    # 2) tenta con 'ip addr' su Linux
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

    # 3) fallback su ifconfig
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

    # 4) se abbiamo solo l'IP, assumiamo /24
    if local_ip:
        return local_ip, "255.255.255.0"

    # 5) fallback finale
    return "127.0.0.1", "255.255.255.255"


def mask_to_cidr(mask):
    """
    Converte una subnet mask (es. 255.255.255.0) in notazione CIDR (es. 24).
    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))


def parse_network(arg=None):
    """
    Analizza l'argomento di rete e ritorna un oggetto ipaddress.ip_network.

    Supporta:
      - nessun argomento (auto-detect IP e mask)
      - CIDR completo (es. 192.168.1.0/24)
      - IP parziale (es. 192.168.1 -> 192.168.1.0/24)
      - IP singolo (es. 192.168.1.10 -> /32)
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
    Esegue un singolo ping e ritorna l'IP se raggiungibile, altrimenti None.
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
    Scansiona tutti gli host nella rete in parallelo e restituisce la lista di quelli online.
    """
    print(f"Scansione della rete: {network}")
    online = []

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    online.append(result)

    except KeyboardInterrupt:
        print("\nScansione interrotta dall'utente. Mostro i risultati finora...")

    return online


def show_help():
    """
    stampa l'utilizzo e esempi
    """
    print(
        "Uso: netscan [rete]\n"
        "Scansiona una rete per dispositivi raggiungibili.\n\n"
        "Opzioni:\n"
        "  -h, --help     Mostra questo messaggio di aiuto\n"
        "Esempi:\n"
        "  netscan                 # Scansiona la rete locale corrente\n"
        "  netscan 192.168.1.0     # Scansiona 192.168.1.0/24\n"
        "  netscan 192.168.1       # Scansiona 192.168.1.0/24\n"
        "  netscan 192.168.1.0/24  # Scansiona 192.168.1.0/24"
    )


def main():
    """
    gestisce argomenti, esegue la scansione e mostra i risultati.
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
            print(f"Errore: {e}")
            show_help()
            return
    elif len(args) == 1:
        try:
            network = parse_network(args[0])
        except Exception as e:
            print(f"Errore: {e}")
            return
    
    try:
        online_hosts = scan_network(network)
        print("\nHost online:")
        if not online_hosts:
            print("Nessun host online")
        for host in sorted(online_hosts, key=lambda x: tuple(map(int, x.split('.')))):
            print(host)

    except KeyboardInterrupt:
        print("\nScansione interrotta dall'utente")
    
    print("\n--help o -h per mostrare il messaggio di aiuto\n")


if __name__ == "__main__":
    main()
