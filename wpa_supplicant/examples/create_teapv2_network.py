#!/usr/bin/env python3
"""
Create a single machine-only TEAPv2 network in wpa_supplicant through wpa_cli.
"""

from __future__ import annotations

import argparse
import shlex
import shutil
import subprocess
import sys
from typing import List, Optional


class ProvisionError(RuntimeError):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a machine-only TEAPv2 wpa_supplicant network."
    )
    parser.add_argument("--ssid", required=True, help="SSID for the new network")
    parser.add_argument(
        "--ca-cert",
        required=True,
        help="CA certificate path for server validation",
    )
    parser.add_argument(
        "--identity",
        required=True,
        help="Machine identity used for TEAPv2",
    )
    parser.add_argument(
        "--password",
        help="Optional inner-method password; omitted by default for machine-only TEAPv2",
    )
    parser.add_argument(
        "--anonymous-identity",
        help="Optional anonymous identity for the outer exchange",
    )
    parser.add_argument(
        "--client-cert",
        help="Optional client certificate path for certificate-based authentication",
    )
    parser.add_argument(
        "--private-key",
        help="Private key path associated with --client-cert",
    )
    parser.add_argument(
        "--private-key-passwd",
        help="Optional password for --private-key",
    )
    parser.add_argument("--interface", default="wlan0", help="wpa_supplicant interface")
    parser.add_argument(
        "--ctrl-path",
        help="Optional ctrl_interface path passed to wpa_cli with -p",
    )
    parser.add_argument(
        "--phase2",
        help="Optional Phase 2 method string; omitted by default for machine-only TEAPv2",
    )
    parser.add_argument(
        "--phase1",
        default="",
        help="Optional phase1 string for TEAPv2",
    )
    parser.add_argument("--key-mgmt", default="WPA-EAP", help="key_mgmt value")
    parser.add_argument("--proto", default="WPA2", help="proto value")
    parser.add_argument("--pairwise", default="CCMP", help="pairwise cipher value")
    parser.add_argument("--group", default="CCMP", help="group cipher value")
    parser.add_argument("--priority", type=int, help="Optional network priority")
    parser.add_argument(
        "--save-config",
        action="store_true",
        help="Run SAVE_CONFIG after creating the network",
    )
    parser.add_argument(
        "--select",
        action="store_true",
        help="Select the newly created network immediately",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Show the wpa_cli commands that would be run without executing them",
    )
    return parser.parse_args()


def require_binary(name: str) -> None:
    if shutil.which(name) is None:
        raise ProvisionError(f"required executable not found: {name}")


def shell_join(argv: List[str]) -> str:
    return " ".join(shlex.quote(arg) for arg in argv)


def quote_value(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def wpa_cli_cmd(args: argparse.Namespace, *extra: str) -> List[str]:
    cmd = ["wpa_cli"]
    if args.ctrl_path:
        cmd.extend(["-p", args.ctrl_path])
    cmd.extend(["-i", args.interface])
    cmd.extend(extra)
    return cmd


def run_wpa_cli(args: argparse.Namespace, *extra: str) -> str:
    cmd = wpa_cli_cmd(args, *extra)
    if args.dry_run:
        print(shell_join(cmd))
        if extra and extra[0] == "add_network":
            return "0"
        if extra and extra[0] in {"set_network", "enable_network", "select_network", "save_config"}:
            return "OK"
        if extra and extra[0] in {"list_networks", "get_network"}:
            return ""
        return ""
    proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        raise ProvisionError(
            f"{shell_join(cmd)} failed with exit code {proc.returncode}: "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return proc.stdout.strip()


def set_network(args: argparse.Namespace, network_id: str, field: str, value: str) -> None:
    out = run_wpa_cli(args, "set_network", network_id, field, value)
    if out != "OK":
        raise ProvisionError(
            f"failed to set network {network_id} field {field}: {out or '<empty>'}"
        )


def list_networks(args: argparse.Namespace) -> List[dict]:
    out = run_wpa_cli(args, "list_networks")
    lines = [line for line in out.splitlines() if line.strip()]
    networks = []
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        networks.append(
            {
                "id": parts[0],
                "ssid": parts[1],
            }
        )
    return networks


def get_network_field(args: argparse.Namespace, network_id: str, field: str) -> Optional[str]:
    out = run_wpa_cli(args, "get_network", network_id, field)
    if out in {"FAIL", ""}:
        return None
    return out


def find_existing_teapv2_network(args: argparse.Namespace, ssid: str) -> Optional[str]:
    for network in list_networks(args):
        if network["ssid"] != ssid:
            continue
        if get_network_field(args, network["id"], "eap") == "TEAPV2":
            return network["id"]
    return None


def main() -> int:
    args = parse_args()
    if not args.dry_run:
        require_binary("wpa_cli")
    if bool(args.client_cert) != bool(args.private_key):
        raise ProvisionError("--client-cert and --private-key must be provided together")

    existing = find_existing_teapv2_network(args, args.ssid)
    if existing is not None:
        print(f"SSID {args.ssid!r} already mapped to TEAPV2 network {existing}")
        return 0

    network_id = run_wpa_cli(args, "add_network")
    if not network_id.isdigit():
        raise ProvisionError(f"unexpected add_network response: {network_id!r}")

    set_network(args, network_id, "ssid", quote_value(args.ssid))
    set_network(args, network_id, "key_mgmt", args.key_mgmt)
    set_network(args, network_id, "proto", args.proto)
    set_network(args, network_id, "pairwise", args.pairwise)
    set_network(args, network_id, "group", args.group)
    set_network(args, network_id, "eap", "TEAPV2")
    set_network(args, network_id, "identity", quote_value(args.identity))
    set_network(args, network_id, "ca_cert", quote_value(args.ca_cert))

    if args.anonymous_identity:
        set_network(
            args,
            network_id,
            "anonymous_identity",
            quote_value(args.anonymous_identity),
        )
    if args.client_cert:
        set_network(args, network_id, "client_cert", quote_value(args.client_cert))
        set_network(args, network_id, "private_key", quote_value(args.private_key))
    if args.private_key_passwd:
        set_network(
            args,
            network_id,
            "private_key_passwd",
            quote_value(args.private_key_passwd),
        )
    if args.phase1:
        set_network(args, network_id, "phase1", quote_value(args.phase1))
    if args.password:
        set_network(args, network_id, "password", quote_value(args.password))
    if args.phase2:
        set_network(args, network_id, "phase2", quote_value(args.phase2))
    if args.priority is not None:
        set_network(args, network_id, "priority", str(args.priority))

    out = run_wpa_cli(args, "enable_network", network_id)
    if out != "OK":
        raise ProvisionError(f"failed to enable network {network_id}: {out or '<empty>'}")

    if args.select:
        out = run_wpa_cli(args, "select_network", network_id)
        if out != "OK":
            raise ProvisionError(
                f"failed to select network {network_id}: {out or '<empty>'}"
            )

    if args.save_config:
        out = run_wpa_cli(args, "save_config")
        if out != "OK":
            raise ProvisionError(f"failed to save config: {out or '<empty>'}")

    print(f"Created TEAPV2 network {network_id} for SSID {args.ssid!r}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProvisionError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
