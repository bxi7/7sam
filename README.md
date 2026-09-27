# 7sam — Local Network Scanner

7sam is a beginner-friendly IPv4 network scanner for Windows and Linux. It shows the local IP address, network range, discovered devices, available hostnames and MAC addresses, and open TCP ports. The web interface starts in English and includes an English/Arabic language toggle.

## Requirements

- Python 3.9 or newer
- A local network you own or are authorized to scan

7sam uses only Python's standard library; no extra packages are required.

## Get the project on Linux

Clone it once:

```bash
git clone https://github.com/bxi7/7sam.git
cd 7sam
```

Update an existing checkout to the latest version:

```bash
cd ~/7sam
git pull origin main
```

After updating, stop the running copy with `Ctrl+C` and start it again with the command below.

## Start the web interface

Keep `7sam.py` and `7sam.html` in the same directory.

**Linux:**

```bash
python3 7sam.py
```

**Windows (PowerShell or Command Prompt):**

```powershell
py 7sam.py
```

If `py` is not available, use `python 7sam.py`.

Open the URL printed in the terminal, usually `http://127.0.0.1:8765`, then click **Start scan**. Enter `common` for the common port list or a comma-separated list such as `22,80,443`. Export results as CSV from the table.

## Set the interface language

English is the default. Choose a language when starting the web server:

```bash
python3 7sam.py --language en
python3 7sam.py --language ar
```

On Windows, replace `python3` with `py` (or `python`). You can also switch English/Arabic with the language button in the interface.

## Scan from the terminal

Automatically detect the local network and scan common ports:

```bash
python3 7sam.py --scan
```

Specify a network and ports:

```bash
python3 7sam.py --scan --network 192.168.1.0/24 --ports 22,80,443
```

Scan every TCP port from 1 to 65535 on discovered devices:

```bash
python3 7sam.py --scan --network 192.168.1.0/24 --ports all
```

On Windows, use `py 7sam.py --scan` or `python 7sam.py --scan`. Full port scans take considerably longer. A scan is limited to 4096 IPv4 addresses; choose a smaller CIDR range if needed.

## Notes

- Discovery uses ping and the operating system's ARP/neighbor table. Firewalls may prevent some devices from appearing.
- MAC addresses may be unavailable outside the local subnet or when the operating system has no neighbor entry.
- Hostnames depend on reverse DNS and may be shown as `Unknown`.
- Open ports are TCP ports that accepted a connection during the scan. Results depend on firewalls and network settings.
- The web server binds to `127.0.0.1` by default and is available only on the computer running 7sam.
- Only scan networks and devices you own or have explicit permission to assess.
