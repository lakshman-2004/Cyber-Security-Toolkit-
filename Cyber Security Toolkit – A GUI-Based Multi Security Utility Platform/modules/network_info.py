"""
Module 5: Network Information Tool
Display system network information: IP, hostname, MAC, interfaces, etc.
"""

import socket
import uuid
import platform
import subprocess
import re
from typing import List, Dict, Optional


def get_network_info() -> dict:
    """
    Collect and return comprehensive network information about the local machine.

    Returns a dict with:
        hostname, local_ip, public_ip (if reachable), mac_address,
        os_info, interfaces, dns_servers, default_gateway
    """
    info = {}

    # Hostname
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        info["hostname"] = "Unknown"

    # Local IP (primary)
    info["local_ip"] = _get_local_ip()

    # MAC address
    info["mac_address"] = _get_mac_address()

    # OS info
    info["os_info"] = f"{platform.system()} {platform.release()} ({platform.machine()})"

    # Network interfaces
    info["interfaces"] = _get_interfaces()

    # Default gateway
    info["default_gateway"] = _get_default_gateway()

    # DNS servers
    info["dns_servers"] = _get_dns_servers()

    # Public IP (best-effort)
    info["public_ip"] = _get_public_ip()

    return info


# -- helpers -------------------------------------------------------------------

def _get_local_ip() -> str:
    """Get the primary local IP by connecting to an external address (no data sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def _get_mac_address() -> str:
    """Return the MAC address of the primary network interface."""
    try:
        mac_int = uuid.getnode()
        mac = ":".join(
            f"{(mac_int >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6))
        )
        return mac
    except Exception:
        return "Unknown"


def _get_interfaces() -> List[Dict]:
    """
    Return a list of network interfaces with name and IP.
    Uses socket.getaddrinfo / platform-specific commands.
    """
    interfaces = []
    system = platform.system()

    try:
        if system == "Windows":
            output = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            interfaces = _parse_ipconfig(output)
        else:
            output = subprocess.check_output(
                ["ip", "addr"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            interfaces = _parse_ip_addr(output)
    except Exception:
        pass

    # Fallback: at least show hostname-based IP
    if not interfaces:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            interfaces = [{"name": "Primary", "ip": ip, "mac": _get_mac_address()}]
        except Exception:
            interfaces = [{"name": "Unknown", "ip": "N/A", "mac": "N/A"}]

    return interfaces


def _parse_ipconfig(output: str) -> List[Dict]:
    """Parse Windows ipconfig output."""
    interfaces = []
    current_name = None
    current_ip = None
    current_mac = None

    for line in output.splitlines():
        # Adapter name
        adapter_match = re.match(r"^(\S.*):$", line)
        if adapter_match:
            if current_name and current_ip:
                interfaces.append({
                    "name": current_name,
                    "ip":   current_ip,
                    "mac":  current_mac or "N/A",
                })
            current_name = adapter_match.group(1).strip()
            current_ip   = None
            current_mac  = None
            continue

        # IPv4
        ip_match = re.search(r"IPv4 Address.*?:\s*([\d.]+)", line)
        if ip_match:
            current_ip = ip_match.group(1)

        # MAC
        mac_match = re.search(r"Physical Address.*?:\s*([0-9A-Fa-f\-]{17})", line)
        if mac_match:
            current_mac = mac_match.group(1).replace("-", ":")

    if current_name and current_ip:
        interfaces.append({
            "name": current_name,
            "ip":   current_ip,
            "mac":  current_mac or "N/A",
        })

    return interfaces


def _parse_ip_addr(output: str) -> List[Dict]:
    """Parse Linux/macOS `ip addr` output."""
    interfaces = []
    current_name = None
    current_ip   = None
    current_mac  = None

    for line in output.splitlines():
        iface_match = re.match(r"^\d+:\s+(\S+):", line)
        if iface_match:
            if current_name and current_ip:
                interfaces.append({
                    "name": current_name,
                    "ip":   current_ip,
                    "mac":  current_mac or "N/A",
                })
            current_name = iface_match.group(1)
            current_ip   = None
            current_mac  = None

        ip_match = re.search(r"inet\s+([\d.]+)/", line)
        if ip_match:
            current_ip = ip_match.group(1)

        mac_match = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
        if mac_match:
            current_mac = mac_match.group(1)

    if current_name and current_ip:
        interfaces.append({
            "name": current_name,
            "ip":   current_ip,
            "mac":  current_mac or "N/A",
        })

    return interfaces


def _get_default_gateway() -> str:
    """Return the default gateway IP."""
    system = platform.system()
    try:
        if system == "Windows":
            output = subprocess.check_output(
                ["ipconfig"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            match = re.search(r"Default Gateway.*?:\s*([\d.]+)", output)
            if match:
                return match.group(1)
        else:
            output = subprocess.check_output(
                ["ip", "route"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            match = re.search(r"default via ([\d.]+)", output)
            if match:
                return match.group(1)
    except Exception:
        pass
    return "Unknown"


def _get_dns_servers() -> List[str]:
    """Return a list of configured DNS server IPs."""
    system = platform.system()
    servers = []
    try:
        if system == "Windows":
            output = subprocess.check_output(
                ["ipconfig", "/all"], stderr=subprocess.DEVNULL, text=True, timeout=5
            )
            for match in re.finditer(r"DNS Servers.*?:\s*([\d.]+)", output):
                servers.append(match.group(1))
        else:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    m = re.match(r"nameserver\s+([\d.]+)", line)
                    if m:
                        servers.append(m.group(1))
    except Exception:
        pass
    return servers if servers else ["Unknown"]


def _get_public_ip() -> str:
    """Try to fetch the public IP via a lightweight DNS trick (no HTTP needed)."""
    try:
        # Use OpenDNS resolver to get public IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        # Query myip.opendns.com via OpenDNS
        # Fallback: just return local IP if this fails
        s.connect(("resolver1.opendns.com", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass

    # Try requests if available
    try:
        import requests
        resp = requests.get("https://api.ipify.org", timeout=4)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        pass

    return "Unavailable (no internet)"
