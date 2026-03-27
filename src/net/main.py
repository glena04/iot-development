import sys
import subprocess
import ipaddress
import urllib.request
import typer

app = typer.Typer()


def _get_mac(ip: str):
    result = subprocess.run(
        ["arp", "-n", ip],
        capture_output=True,
        text=True,
        timeout=5
    )
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == ip:
                mac = parts[2]
                if mac != "(incomplete)" and mac != "--":
                    return mac
    return None


def _get_vendor(mac_addr: str):
    url = f"https://api.macvendors.com/{mac_addr}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        elif e.code == 429:
            raise Exception("Too many requests.")
        else:
            raise Exception(f"HTTP {e.code} {e.reason}")
    except Exception as e:
        raise Exception(f"{e}")


@app.command()
def scan(netmask: str = typer.Argument(..., help="Netmask to scan")):
    """Scan the network for active IP addresses."""
    typer.secho(f"Scanning network: {netmask}...", err=True)
    try:
        network = ipaddress.ip_network(netmask, strict=False)
    except ValueError as e:
        print(f"Error: Invalid netmask '{netmask}'. {e}")
        raise typer.Exit(code=1)
    try:
        for ip in network:
            ip_str = str(ip)
            try:
                result = subprocess.run(
                    ["ping", "-n", "-c", "1", "-W", "2", ip_str],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if result.returncode == 0:
                    print(ip_str)
                else:
                    error_msg = result.stderr.strip()
                    output = f"{ip_str} (error: {error_msg})" if error_msg else ip_str
                    typer.secho(output, fg=typer.colors.RED, err=True)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                raise
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Exiting...")
        raise typer.Exit(code=0)


@app.command()
def mac(ip: str | None = typer.Argument(None, help="IP address to look up MAC for")):
    """Look up the MAC address for a given IP address."""
    ips = sys.stdin.read().splitlines() if ip is None else [ip]
    for addr in ips:
        addr = addr.strip()
        if not addr:
            continue
        mac_addr = _get_mac(addr)
        if mac_addr:
            typer.echo(mac_addr)
        else:
            typer.secho(f"Could not find MAC for {addr}", fg=typer.colors.RED, err=True)


@app.command()
def ispi(
    mac_addr: str | None = typer.Argument(None, help="MAC address to check"),
    ip: str | None = typer.Argument(None, help="IP address (optional)"),
):
    """Check whether a MAC address belongs to a Raspberry Pi."""
    macs = sys.stdin.read().splitlines() if mac_addr is None else [mac_addr]
    for m in macs:
        m = m.strip()
        if not m:
            continue
        try:
            vendor = _get_vendor(m)
        except Exception as e:
            typer.secho(f"Vendor lookup failed for {m}: {e}", fg=typer.colors.RED, err=True)
            continue
        is_pi = vendor is not None and "raspberry pi" in vendor.lower()
        subject = f"{m} {ip}" if ip else m
        if is_pi:
            typer.secho(f"Yes, {subject} is a Raspberry Pi address.", fg=typer.colors.GREEN)
        else:
            typer.secho(f"No, {subject} is not a known Raspberry Pi address.", fg=typer.colors.RED)


if __name__ == "__main__":
    app()
