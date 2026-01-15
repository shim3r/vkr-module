from __future__ import annotations

import argparse
import asyncio
import random
from datetime import datetime, timezone
from typing import Dict, List

import httpx

from app.simulator.generator import append_to_live_file, pick_event


def _isoz_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _rand_ip(prefix: str = "10.0.0") -> str:
    # prefix like "10.0.0" -> "10.0.0.X"
    return f"{prefix}.{random.randint(2, 254)}"


def make_vpn_event(event_type: str, src_ip: str, dst_ip: str, user: str, severity: int) -> Dict:
    data = (
        f"CEF:0|NGFW|Vendor|1.0|100|{event_type}|{severity}|"
        f"src={src_ip} dst={dst_ip} suser={user}"
    )
    return {"source_type": "firewall", "format": "cef", "data": data}


def make_portscan_event(src_ip: str, dst_ip: str, dpt: int) -> Dict:
    data = (
        "CEF:0|NGFW|Vendor|1.0|101|PORTSCAN|6|"
        f"src={src_ip} dst={dst_ip} dpt={dpt}"
    )
    return {"source_type": "firewall", "format": "cef", "data": data}


def make_lateral_login_event(user: str, host: str, ip: str) -> Dict:
    return {
        "source_type": "iam",
        "format": "csv",
        "data": f"{_isoz_now()},{user},LOGIN_SUCCESS,host={host},ip={ip}",
    }


def make_malware_event(host: str = "pc7") -> Dict:
    data = (
        "CEF:0|EndpointAV|Vendor|1.0|200|AV_DETECT|7|"
        f"host={host} file=sample.exe action=quarantine"
    )
    return {"source_type": "av", "format": "cef", "data": data}


async def _post(client: httpx.AsyncClient, url: str, payload: Dict) -> None:
    try:
        await client.post(url, json=payload)
    except Exception as e:
        print(f"[WARN] send failed: {e}")


async def _run_normal(client: httpx.AsyncClient, ingest_url: str, eps: float) -> None:
    delay = 1.0 / max(eps, 0.1)
    while True:
        payload = pick_event()
        append_to_live_file(payload)
        await _post(client, ingest_url, payload)
        await asyncio.sleep(delay)


async def _run_vpn(
    client: httpx.AsyncClient,
    ingest_url: str,
    count: int,
    window_seconds: float,
    cooldown_seconds: float,
    src_ip: str,
    dst_ip: str,
    user: str,
    randomize_src: bool,
    include_success: bool,
    once: bool,
) -> None:
    while True:
        burst_src = _rand_ip("10.0.0") if randomize_src else src_ip
        n = max(1, int(count))
        window = max(0.1, float(window_seconds))
        per_event_delay = window / n

        mode = "vpn_compromise" if include_success else "vpn_bruteforce"
        print(f"[ATTACK] mode={mode} sending {n} VPN_LOGIN_FAIL from src={burst_src} user={user}")

        for _ in range(n):
            payload = make_vpn_event("VPN_LOGIN_FAIL", burst_src, dst_ip, user, 8)
            append_to_live_file(payload)
            await _post(client, ingest_url, payload)
            await asyncio.sleep(per_event_delay)

        if include_success:
            success = make_vpn_event("VPN_LOGIN_SUCCESS", burst_src, dst_ip, user, 5)
            append_to_live_file(success)
            await _post(client, ingest_url, success)

        if once:
            return

        await asyncio.sleep(max(0.1, float(cooldown_seconds)))


async def _run_portscan(
    client: httpx.AsyncClient,
    ingest_url: str,
    count: int,
    window_seconds: float,
    cooldown_seconds: float,
    src_ip: str,
    dst_ip: str,
    randomize_src: bool,
    once: bool,
) -> None:
    ports: List[int] = [22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900, 8080]

    while True:
        burst_src = _rand_ip("10.0.0") if randomize_src else src_ip
        n = max(10, int(count))
        window = max(0.5, float(window_seconds))
        per_event_delay = window / n

        print(f"[ATTACK] mode=portscan sending {n} events from src={burst_src} across many ports")

        for i in range(n):
            dpt = ports[i % len(ports)]
            payload = make_portscan_event(burst_src, dst_ip, dpt)
            append_to_live_file(payload)
            await _post(client, ingest_url, payload)
            await asyncio.sleep(per_event_delay)

        if once:
            return

        await asyncio.sleep(max(0.1, float(cooldown_seconds)))


async def _run_lateral(
    client: httpx.AsyncClient,
    ingest_url: str,
    count: int,
    window_seconds: float,
    cooldown_seconds: float,
    user: str,
    src_ip: str,
    randomize_src: bool,
    once: bool,
) -> None:
    while True:
        n = max(6, int(count))
        window = max(0.5, float(window_seconds))
        per_event_delay = window / n

        print(f"[ATTACK] mode=lateral sending {n} LOGIN_SUCCESS for user={user} across multiple hosts")

        for i in range(n):
            host = f"pc{(i % 6) + 1}"
            ip = _rand_ip("10.0.0") if randomize_src else src_ip
            payload = make_lateral_login_event(user, host, ip)
            append_to_live_file(payload)
            await _post(client, ingest_url, payload)
            await asyncio.sleep(per_event_delay)

        if once:
            return

        await asyncio.sleep(max(0.1, float(cooldown_seconds)))


async def _run_malware(
    client: httpx.AsyncClient,
    ingest_url: str,
    cooldown_seconds: float,
    once: bool,
) -> None:
    while True:
        payload = make_malware_event(host=f"pc{random.randint(1, 30)}")
        print("[ATTACK] mode=malware sending AV_DETECT")
        append_to_live_file(payload)
        await _post(client, ingest_url, payload)

        if once:
            return

        await asyncio.sleep(max(0.1, float(cooldown_seconds)))


async def main() -> None:
    parser = argparse.ArgumentParser(description="VKR generator/attacks runner (sends events to SIEM API)")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="SIEM base URL")

    parser.add_argument(
        "--mode",
        choices=["normal", "vpn_bruteforce", "vpn_compromise", "portscan", "lateral", "malware"],
        default="normal",
    )

    parser.add_argument("--eps", type=float, default=2.0)
    parser.add_argument("--attack-count", type=int, default=6)
    parser.add_argument("--attack-window-seconds", type=float, default=2.0)
    parser.add_argument("--attack-cooldown-seconds", type=float, default=10.0)
    parser.add_argument("--attack-src-ip", default="10.0.0.9")
    parser.add_argument("--attack-dst-ip", default="10.0.0.1")
    parser.add_argument("--attack-user", default="user1")
    parser.add_argument("--attack-randomize-src", action="store_true")
    parser.add_argument("--once", action="store_true")

    args = parser.parse_args()

    ingest_url = f"{args.url.rstrip('/')}/api/ingest"

    async with httpx.AsyncClient(timeout=10) as client:
        if args.mode == "normal":
            await _run_normal(client, ingest_url, eps=args.eps)
            return

        if args.mode == "vpn_bruteforce":
            await _run_vpn(
                client,
                ingest_url,
                count=args.attack_count,
                window_seconds=args.attack_window_seconds,
                cooldown_seconds=args.attack_cooldown_seconds,
                src_ip=args.attack_src_ip,
                dst_ip=args.attack_dst_ip,
                user=args.attack_user,
                randomize_src=args.attack_randomize_src,
                include_success=False,
                once=args.once,
            )
            return

        if args.mode == "vpn_compromise":
            await _run_vpn(
                client,
                ingest_url,
                count=args.attack_count,
                window_seconds=args.attack_window_seconds,
                cooldown_seconds=args.attack_cooldown_seconds,
                src_ip=args.attack_src_ip,
                dst_ip=args.attack_dst_ip,
                user=args.attack_user,
                randomize_src=args.attack_randomize_src,
                include_success=True,
                once=args.once,
            )
            return

        if args.mode == "portscan":
            await _run_portscan(
                client,
                ingest_url,
                count=args.attack_count,
                window_seconds=args.attack_window_seconds,
                cooldown_seconds=args.attack_cooldown_seconds,
                src_ip=args.attack_src_ip,
                dst_ip=args.attack_dst_ip,
                randomize_src=args.attack_randomize_src,
                once=args.once,
            )
            return

        if args.mode == "lateral":
            await _run_lateral(
                client,
                ingest_url,
                count=args.attack_count,
                window_seconds=args.attack_window_seconds,
                cooldown_seconds=args.attack_cooldown_seconds,
                user=args.attack_user,
                src_ip=args.attack_src_ip,
                randomize_src=args.attack_randomize_src,
                once=args.once,
            )
            return

        if args.mode == "malware":
            await _run_malware(client, ingest_url, cooldown_seconds=args.attack_cooldown_seconds, once=args.once)
            return

        raise SystemExit(f"Unknown mode: {args.mode}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass