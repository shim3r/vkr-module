from datetime import datetime, timezone
from typing import Dict, List, Tuple

# (payload, delay_after_seconds)
AttackSeq = List[Tuple[Dict, float]]

def _nowz() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def vpn_bruteforce() -> AttackSeq:
    src = "10.0.0.9"
    user = "user1"
    seq: AttackSeq = []
    for _ in range(6):
        seq.append(({
            "source_type": "firewall",
            "format": "cef",
            "data": f"CEF:0|NGFW|Vendor|1.0|100|VPN_LOGIN_FAIL|8|src={src} dst=10.0.0.1 suser={user}",
        }, 0.25))
    return seq

def vpn_compromise() -> AttackSeq:
    seq = vpn_bruteforce()
    src = "10.0.0.9"
    user = "user1"
    seq.append(({
        "source_type": "firewall",
        "format": "cef",
        "data": f"CEF:0|NGFW|Vendor|1.0|100|VPN_LOGIN_SUCCESS|5|src={src} dst=10.0.0.1 suser={user}",
    }, 0.1))
    return seq

def portscan() -> AttackSeq:
    src = "10.0.0.77"
    ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    seq: AttackSeq = []
    for p in ports:
        seq.append(({
            "source_type": "firewall",
            "format": "cef",
            "data": f"CEF:0|NGFW|Vendor|1.0|101|PORTSCAN|6|src={src} dst=10.0.0.1 dpt={p}",
        }, 0.12))
    return seq

def lateral() -> AttackSeq:
    user = "user1"
    hosts = ["pc1", "pc2", "pc3", "pc4"]
    nowz = _nowz()
    seq: AttackSeq = []
    for h in hosts:
        seq.append(({
            "source_type": "iam",
            "format": "csv",
            "data": f"{nowz},{user},LOGIN_SUCCESS,host={h},ip=10.0.0.9",
        }, 0.2))
    return seq

def malware() -> AttackSeq:
    host = "pc7"
    return [({
        "source_type": "av",
        "format": "cef",
        "data": f"CEF:0|EndpointAV|Vendor|1.0|200|AV_DETECT|7|host={host} file=sample.exe action=quarantine",
    }, 0.1)]

ATTACKS = {
    "vpn_bruteforce": vpn_bruteforce,
    "vpn_compromise": vpn_compromise,
    "portscan": portscan,
    "lateral": lateral,
    "malware": malware,
}