"""
Module 1: Port Scanner
Scans a target IP to detect open ports and running services.
"""

import socket
import threading
from PyQt5.QtCore import QThread, pyqtSignal


# Common port-to-service mapping
PORT_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD/LPR",
    587: "SMTP (TLS)",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MS SQL Server",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2181: "ZooKeeper",
    2375: "Docker",
    2376: "Docker SSL",
    3000: "Node.js / Grafana",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4000: "ICQ",
    4444: "Metasploit",
    5000: "Flask / UPnP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    6667: "IRC",
    7001: "WebLogic",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "Jupyter Notebook",
    9000: "PHP-FPM",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    27017: "MongoDB",
    27018: "MongoDB",
    27019: "MongoDB",
}


def get_service_name(port):
    """Return service name for a given port number."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return "Unknown"


class PortScannerThread(QThread):
    """Worker thread for port scanning to keep GUI responsive."""
    result_signal = pyqtSignal(int, str, str)   # port, status, service
    progress_signal = pyqtSignal(int)            # progress percentage
    finished_signal = pyqtSignal(str)            # summary message
    error_signal = pyqtSignal(str)               # error message

    def __init__(self, target, start_port, end_port, timeout=0.5):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self._is_running = True
        self.open_ports = []
        self.lock = threading.Lock()

    def stop(self):
        self._is_running = False

    def scan_port(self, port):
        """Scan a single port and emit result."""
        if not self._is_running:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                service = get_service_name(port)
                with self.lock:
                    self.open_ports.append(port)
                self.result_signal.emit(port, "Open", service)
        except Exception:
            pass

    def run(self):
        """Run the port scan in a thread pool."""
        try:
            # Resolve hostname to IP
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                self.error_signal.emit(f"Cannot resolve hostname: {self.target}")
                return

            total_ports = self.end_port - self.start_port + 1
            scanned = 0
            threads = []
            batch_size = 50  # Scan 50 ports at a time

            port_range = range(self.start_port, self.end_port + 1)

            for i in range(0, total_ports, batch_size):
                if not self._is_running:
                    break
                batch = list(port_range)[i:i + batch_size]
                batch_threads = []
                for port in batch:
                    if not self._is_running:
                        break
                    t = threading.Thread(target=self.scan_port, args=(port,))
                    t.daemon = True
                    t.start()
                    batch_threads.append(t)

                for t in batch_threads:
                    t.join()

                scanned += len(batch)
                progress = int((scanned / total_ports) * 100)
                self.progress_signal.emit(progress)

            if self._is_running:
                count = len(self.open_ports)
                summary = f"Scan complete. Found {count} open port(s) on {ip}"
                self.finished_signal.emit(summary)
            else:
                self.finished_signal.emit("Scan stopped by user.")

        except Exception as e:
            self.error_signal.emit(f"Scan error: {str(e)}")
