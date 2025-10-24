# Network Scanner

A lightweight Python network scanner that detects online devices on a local or specified network.  
Works on Windows and Linux.



## How it works

1. Detects your local IP and subnet mask using multiple methods:
      - socket (reliable)
      - ip addr (Linux)
      - ifconfig (fallback)

2. Converts subnet mask to CIDR if needed.

3. Pings all hosts in the target network in parallel.

4. Displays a sorted list of online hosts.

## Notes

- Requires network permissions to send ping requests.
- Large networks may take longer to scan.
- Works best with IPv4 networks.

## License
This project is licensed under the MIT License.
