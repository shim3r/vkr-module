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


# IAM/AD and Endpoints attacks
def iam_password_spray() -> AttackSeq:
    """Multiple auth failures from one src IP across several users."""
    src_ip = "10.0.0.9"
    host = "dc1"
    users = ["user1", "user2", "user3", "user4", "admin"]
    seq: AttackSeq = []
    for u in users:
        seq.append(({
            "source_type": "iam",
            "format": "cef",
            "data": (
                "CEF:0|IAM|AD|1.0|400|IAM_AUTH_FAIL|6|"
                f"host={host} suser={u} src={src_ip} outcome=failure auth=kerberos"
            ),
        }, 0.10))
    return seq


def iam_auth_success() -> AttackSeq:
    """A successful authentication event (useful for chains)."""
    src_ip = "10.0.0.9"
    host = "dc1"
    user = "user1"
    return [({
        "source_type": "iam",
        "format": "cef",
        "data": (
            "CEF:0|IAM|AD|1.0|401|IAM_AUTH_SUCCESS|4|"
            f"host={host} suser={user} src={src_ip} outcome=success auth=kerberos"
        ),
    }, 0.10)]


def iam_admin_group_change() -> AttackSeq:
    """Privilege escalation style event: add a user to Domain Admins."""
    host = "dc1"
    actor = "admin"
    target = "user1"
    return [({
        "source_type": "iam",
        "format": "cef",
        "data": (
            "CEF:0|IAM|AD|1.0|402|IAM_GROUP_CHANGE|8|"
            f"host={host} suser={actor} target={target} group=DomainAdmins action=add"
        ),
    }, 0.10)]


def endpoint_login_fail() -> AttackSeq:
    """Endpoint OS auth failures (e.g., RDP brute)"""
    host = "pc5"
    user = "user1"
    src_ip = "10.0.0.9"
    seq: AttackSeq = []
    for _ in range(6):
        seq.append(({
            "source_type": "endpoints",
            "format": "cef",
            "data": (
                "CEF:0|EndpointOS|Windows|1.0|500|ENDPOINT_LOGIN_FAIL|5|"
                f"host={host} suser={user} src={src_ip} outcome=failure logon_type=RDP"
            ),
        }, 0.12))
    return seq


def endpoint_powershell_encoded() -> AttackSeq:
    """Endpoint suspicious process start (PowerShell -enc)."""
    host = "pc5"
    user = "user1"
    return [({
        "source_type": "endpoints",
        "format": "cef",
        "data": (
            "CEF:0|EndpointOS|Windows|1.0|501|ENDPOINT_PROCESS_START|7|"
            f"host={host} suser={user} process=powershell.exe cmd=\"powershell -enc AAAA\""
        ),
    }, 0.10)]


def endpoint_service_create() -> AttackSeq:
    """Endpoint remote service creation (often lateral movement indicator)."""
    host = "pc4"
    user = "user1"
    src_host = "pc2"
    return [({
        "source_type": "endpoints",
        "format": "cef",
        "data": (
            "CEF:0|EndpointOS|Windows|1.0|502|ENDPOINT_SERVICE_CREATE|8|"
            f"host={host} suser={user} service=PSEXESVC src_host={src_host} action=create"
        ),
    }, 0.10)]

def malware() -> AttackSeq:
    host = "pc7"
    return [({
        "source_type": "av",
        "format": "cef",
        "data": f"CEF:0|EndpointAV|Vendor|1.0|200|AV_DETECT|7|host={host} file=sample.exe action=quarantine",
    }, 0.1)]

def av_disabled() -> AttackSeq:
    host = "pc7"
    user = "user1"
    return [({
        "source_type": "av",
        "format": "cef",
        "data": f"CEF:0|EndpointAV|Vendor|1.0|201|AV_DISABLED|9|host={host} suser={user} action=disabled reason=tamper",
    }, 0.1)]


def av_clean_fail() -> AttackSeq:
    host = "pc7"
    return [({
        "source_type": "av",
        "format": "cef",
        "data": f"CEF:0|EndpointAV|Vendor|1.0|202|AV_CLEAN_FAIL|8|host={host} file=payload.dll malware=Trojan.Generic action=clean_failed",
    }, 0.1)]


def av_quarantine() -> AttackSeq:
    host = "pc7"
    return [({
        "source_type": "av",
        "format": "cef",
        "data": f"CEF:0|EndpointAV|Vendor|1.0|203|AV_QUARANTINE|6|host={host} file=invoice.exe action=quarantine",
    }, 0.1)]


def edr_suspicious_process() -> AttackSeq:
    host = "pc3"
    user = "user1"
    return [({
        "source_type": "edr",
        "format": "cef",
        "data": (
            "CEF:0|EDR|Vendor|1.0|300|EDR_SUSPICIOUS_PROCESS|7|"
            f"host={host} suser={user} process=powershell.exe cmd=\"powershell -enc AAAA\""
        ),
    }, 0.1)]


def edr_credential_dump() -> AttackSeq:
    host = "pc2"
    user = "user1"
    return [({
        "source_type": "edr",
        "format": "cef",
        "data": (
            "CEF:0|EDR|Vendor|1.0|301|EDR_CREDENTIAL_DUMP|9|"
            f"host={host} suser={user} technique=LSASS_DUMP tool=mimikatz action=blocked"
        ),
    }, 0.1)]


def edr_lateral_tool() -> AttackSeq:
    src_host = "pc2"
    dst_host = "pc4"
    user = "user1"
    seq: AttackSeq = []
    seq.append(({
        "source_type": "edr",
        "format": "cef",
        "data": (
            "CEF:0|EDR|Vendor|1.0|302|EDR_LATERAL_TOOL|8|"
            f"host={src_host} dhost={dst_host} suser={user} tool=psexec action=detected"
        ),
    }, 0.12))
    seq.append(({
        "source_type": "edr",
        "format": "cef",
        "data": (
            "CEF:0|EDR|Vendor|1.0|303|EDR_REMOTE_SERVICE_CREATE|8|"
            f"host={dst_host} suser={user} service=PSEXESVC src={src_host} action=blocked"
        ),
    }, 0.12))
    return seq


def edr_ransomware_behavior() -> AttackSeq:
    host = "pc7"
    user = "user1"
    seq: AttackSeq = []
    # burst of file modifications typical for ransomware
    for i in range(8):
        seq.append(({
            "source_type": "edr",
            "format": "cef",
            "data": (
                "CEF:0|EDR|Vendor|1.0|304|EDR_RANSOMWARE_BEHAVIOR|9|"
                f"host={host} suser={user} process=unknown.exe files_modified={10+i} action=blocked"
            ),
        }, 0.10))
    return seq

ATTACKS = {
    "vpn_bruteforce": vpn_bruteforce,
    "vpn_compromise": vpn_compromise,
    "portscan": portscan,
    "lateral": lateral,

    # IAM/AD
    "iam_password_spray": iam_password_spray,
    "iam_auth_success": iam_auth_success,
    "iam_admin_group_change": iam_admin_group_change,

    # Endpoints
    "endpoint_login_fail": endpoint_login_fail,
    "endpoint_powershell": endpoint_powershell_encoded,
    "endpoint_service_create": endpoint_service_create,

    # Antivirus (AV)
    "malware": malware,
    "av_quarantine": av_quarantine,
    "av_clean_fail": av_clean_fail,
    "av_disabled": av_disabled,

    # EDR
    "edr_suspicious_process": edr_suspicious_process,
    "edr_credential_dump": edr_credential_dump,
    "edr_lateral_tool": edr_lateral_tool,
    "edr_ransomware": edr_ransomware_behavior,
}