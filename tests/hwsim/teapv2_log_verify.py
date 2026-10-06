#!/usr/bin/env python3
"""Verify TEAPv2 key derivation and Crypto-Binding values in debug logs.

The calculations follow draft-ietf-emu-teapv2-00, Sections 3.3 and 3.4.
Only Python's standard library is required.

The TLS exporter used to derive each RoundKey and CMK cannot be reproduced
unless its exporter secret is logged.  This program therefore:

* independently derives the final MSK and EMSK from the Final RoundSeed;
* independently calculates each MSK Compound MAC from the logged CMK/BUFFER;
* validates RoundSeed/PrevRoundKey chaining and Crypto-Binding encoding; and
* compares exporter-derived values between logs for the same TLS session.

TEAP version-number differences are intentionally ignored.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional


DRAFT_URL = "https://www.ietf.org/archive/id/draft-ietf-emu-teapv2-00.html"
MSK_LABEL = b"Session Key Generating Function"
EMSK_LABEL = b"Extended Session Key Generating Function"
ZERO32 = bytes(32)

HEX_RE = re.compile(
    r"EAP-TEAPV2: (?P<label>.*?) - hexdump\(len=(?P<length>\d+)\):"
    r"\s*(?P<data>(?:[0-9a-fA-F]{2}(?:\s+|$))*)"
)
CIPHER_RE = re.compile(r"EAP-TEAPV2: TLS cipher suite 0x([0-9a-fA-F]+)")


@dataclass
class Value:
    data: bytes
    line: int


@dataclass
class Round:
    seed: Value
    cmk: Optional[Value] = None
    updated_prev: Optional[Value] = None


@dataclass
class Compound:
    cmk: Value
    buffer: Optional[Value] = None
    macs: list[tuple[str, Value]] = field(default_factory=list)


@dataclass
class Session:
    path: Path
    number: int
    initial_prev: Value
    cipher_suite: Optional[int]
    rounds: list[Round] = field(default_factory=list)
    final_seed: Optional[Value] = None
    final_msk: Optional[Value] = None
    final_emsk: Optional[Value] = None
    compounds: list[Compound] = field(default_factory=list)
    bindings: list[Value] = field(default_factory=list)

    @property
    def name(self) -> str:
        return f"{self.path}:session-{self.number}"


class Reporter:
    def __init__(self, quiet: bool = False) -> None:
        self.quiet = quiet
        self.passed = 0
        self.warned = 0
        self.failed = 0

    def pass_(self, where: str, message: str) -> None:
        self.passed += 1
        if not self.quiet:
            print(f"PASS {where}: {message}")

    def warn(self, where: str, message: str) -> None:
        self.warned += 1
        print(f"WARN {where}: {message}")

    def fail(self, where: str, message: str) -> None:
        self.failed += 1
        print(f"FAIL {where}: {message}")


def short_hex(value: bytes) -> str:
    text = value.hex()
    return text if len(text) <= 48 else text[:48] + "..."


def tls_prf(
    secret: bytes, label: bytes, length: int, digestmod: Callable = hashlib.sha256
) -> bytes:
    """TLS 1.2 P_hash, as used by the draft's TLS-PRF construction."""
    result = bytearray()
    a = hmac.new(secret, label, digestmod).digest()
    while len(result) < length:
        result.extend(hmac.new(secret, a + label, digestmod).digest())
        a = hmac.new(secret, a, digestmod).digest()
    return bytes(result[:length])


def cipher_hash(suite: Optional[int]) -> Optional[Callable]:
    # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
    # TLS_CHACHA20_POLY1305_SHA256, and the two TLS_AES_CCM suites.
    return {
        0x1301: hashlib.sha256,
        0x1302: hashlib.sha384,
        0x1303: hashlib.sha256,
        0x1304: hashlib.sha256,
        0x1305: hashlib.sha256,
    }.get(suite)


def read_hexdump(match: re.Match[str], path: Path, line: int) -> bytes:
    declared = int(match.group("length"))
    data = bytes.fromhex(match.group("data"))
    if len(data) != declared:
        raise ValueError(
            f"{path}:{line}: declared hexdump length {declared}, parsed {len(data)}"
        )
    return data


def parse_log(path: Path) -> list[Session]:
    sessions: list[Session] = []
    current: Optional[Session] = None
    pending_cipher: Optional[int] = None
    pending_mac: Optional[tuple[str, Value]] = None

    with path.open("r", encoding="utf-8", errors="replace") as log:
        for line_number, line in enumerate(log, 1):
            cipher_match = CIPHER_RE.search(line)
            if cipher_match:
                pending_cipher = int(cipher_match.group(1), 16)
                continue

            match = HEX_RE.search(line)
            if not match:
                continue
            label = match.group("label")
            data = read_hexdump(match, path, line_number)
            value = Value(data, line_number)

            if label == "session_key_seed (initial PrevRoundKey)":
                current = Session(
                    path=path,
                    number=len(sessions) + 1,
                    initial_prev=value,
                    cipher_suite=pending_cipher,
                )
                sessions.append(current)
                pending_mac = None
                continue
            if current is None:
                continue

            if label == "RoundSeed":
                current.rounds.append(Round(seed=value))
            elif label == "CMK" and current.rounds:
                current.rounds[-1].cmk = value
            elif label == "Updated PrevRoundKey" and current.rounds:
                current.rounds[-1].updated_prev = value
            elif label == "Final RoundSeed":
                current.final_seed = value
            elif label == "Derived key (MSK)":
                current.final_msk = value
            elif label == "Derived key (EMSK)":
                current.final_emsk = value
            elif label == "CMK for Compound MAC calculation":
                compound = Compound(cmk=value)
                if pending_mac is not None:
                    compound.macs.append(pending_mac)
                    pending_mac = None
                current.compounds.append(compound)
            elif label == "BUFFER for Compound MAC calculation":
                if current.compounds:
                    current.compounds[-1].buffer = value
            elif label in {
                "MSK Compound MAC",
                "Received MSK Compound MAC",
                "Calculated MSK Compound MAC",
            }:
                if label != "MSK Compound MAC" and current.compounds:
                    current.compounds[-1].macs.append((label, value))
                elif (
                    current.compounds
                    and current.compounds[-1].buffer is not None
                    and not current.compounds[-1].macs
                ):
                    current.compounds[-1].macs.append((label, value))
                else:
                    # A received TLV's plain "MSK Compound MAC" is logged
                    # before hostapd constructs the zeroed verification BUFFER.
                    pending_mac = (label, value)
            elif label == "Crypto-Binding TLV":
                current.bindings.append(value)

    return sessions


def check_length(
    reporter: Reporter, where: str, what: str, value: Value, wanted: int
) -> bool:
    if len(value.data) != wanted:
        reporter.fail(
            f"{where}:{value.line}", f"{what} is {len(value.data)} bytes, expected {wanted}"
        )
        return False
    return True


def validate_outer_tlvs(reporter: Reporter, where: str, data: bytes) -> None:
    offset = 0
    count = 0
    while offset < len(data):
        if len(data) - offset < 4:
            reporter.fail(where, f"truncated outer TLV header at offset {offset}")
            return
        _, length = struct.unpack("!HH", data[offset : offset + 4])
        end = offset + 4 + length
        if end > len(data):
            reporter.fail(
                where,
                f"outer TLV at offset {offset} declares {length} value bytes, "
                f"but only {len(data) - offset - 4} remain",
            )
            return
        count += 1
        offset = end
    reporter.pass_(where, f"BUFFER contains {count} well-formed outer TLV(s)")


def validate_buffer(reporter: Reporter, where: str, value: Value) -> bool:
    data = value.data
    if len(data) < 81:
        reporter.fail(where, f"BUFFER is {len(data)} bytes, expected at least 81")
        return False

    tlv_type, tlv_length = struct.unpack("!HH", data[:4])
    ok = True
    if not (tlv_type & 0x8000) or (tlv_type & 0x3FFF) != 12:
        reporter.fail(
            where,
            f"BUFFER starts with TLV type 0x{tlv_type:04x}, expected mandatory type 12",
        )
        ok = False
    if tlv_length != 76:
        reporter.fail(where, f"Crypto-Binding TLV length is {tlv_length}, expected 76")
        ok = False
    if data[40:80] != bytes(40):
        reporter.fail(where, "Compound MAC fields were not zeroed in MAC input BUFFER")
        ok = False
    if ok:
        reporter.pass_(where, "Crypto-Binding header and zeroed MAC fields are correct")
    validate_outer_tlvs(reporter, where, data[81:])
    return ok


def binding_parts(data: bytes) -> tuple[int, int, int, int, bytes, bytes, bytes]:
    version = data[1]
    received_version = data[2]
    flags = data[3] >> 4
    subtype = data[3] & 0x0F
    return (
        version,
        received_version,
        flags,
        subtype,
        data[4:36],
        data[36:56],
        data[56:76],
    )


def canonical_binding(data: bytes) -> bytes:
    header = struct.pack("!HH", 0x800C, 76)
    return header + data[:36] + bytes(40)


def validate_binding(
    reporter: Reporter,
    session: Session,
    binding: Value,
    compound_results: list[tuple[Compound, bytes]],
    strict_should: bool,
) -> None:
    where = f"{session.name}:{binding.line}"
    if not check_length(reporter, session.name, "Crypto-Binding TLV", binding, 76):
        return
    data = binding.data
    _, _, flags, subtype, _, emsk_mac, msk_mac = binding_parts(data)

    if data[0] != 0:
        reporter.fail(where, f"reserved octet is 0x{data[0]:02x}, expected 0")
    else:
        reporter.pass_(where, "reserved octet is zero")

    if flags != 2:
        reporter.fail(where, f"Flags value is {flags}, expected 2")
    else:
        reporter.pass_(where, "Flags value is 2")
    if subtype not in (0, 1):
        reporter.fail(where, f"Sub-Type is {subtype}, expected 0 (request) or 1 (response)")
    else:
        reporter.pass_(where, f"Sub-Type {subtype} is valid")

    if emsk_mac != bytes(20):
        message = "EMSK Compound MAC is nonzero; draft -00 says it SHOULD be zero"
        (reporter.fail if strict_should else reporter.warn)(where, message)
    else:
        reporter.pass_(where, "EMSK Compound MAC is zero")

    canonical = canonical_binding(data)
    matches = [
        expected
        for compound, expected in compound_results
        if compound.buffer is not None
        and compound.buffer.data[:80] == canonical
    ]
    if not matches:
        reporter.warn(where, "no matching logged MAC-input BUFFER was found")
    elif msk_mac not in matches:
        reporter.fail(
            where,
            f"MSK Compound MAC {short_hex(msk_mac)} does not match calculated "
            f"{short_hex(matches[0])}",
        )
    else:
        reporter.pass_(where, "encoded MSK Compound MAC matches draft calculation")


def validate_session(
    reporter: Reporter,
    session: Session,
    strict_should: bool,
    require_complete: bool,
) -> None:
    where = session.name
    check_length(reporter, where, "initial PrevRoundKey", session.initial_prev, 40)

    digestmod = cipher_hash(session.cipher_suite)
    if digestmod is None:
        suite = (
            "not logged"
            if session.cipher_suite is None
            else f"0x{session.cipher_suite:04x}"
        )
        reporter.fail(where, f"cannot select PRF/MAC hash: TLS cipher suite {suite}")
    else:
        reporter.pass_(
            where,
            f"cipher suite 0x{session.cipher_suite:04x} selects {digestmod().name}",
        )

    expected_prev = session.initial_prev.data
    for index, round_ in enumerate(session.rounds, 1):
        round_where = f"{where}:round-{index}"
        if check_length(reporter, round_where, "RoundSeed", round_.seed, 104):
            if round_.seed.data[:40] != expected_prev:
                reporter.fail(
                    f"{round_where}:{round_.seed.line}",
                    "RoundSeed does not start with the preceding PrevRoundKey",
                )
            else:
                reporter.pass_(round_where, "RoundSeed starts with preceding PrevRoundKey")
        if round_.cmk is None:
            reporter.warn(round_where, "CMK is not present in the log")
        else:
            check_length(reporter, round_where, "CMK", round_.cmk, 32)
        if round_.updated_prev is None:
            reporter.warn(round_where, "updated PrevRoundKey is not present in the log")
        elif check_length(
            reporter, round_where, "updated PrevRoundKey", round_.updated_prev, 40
        ):
            expected_prev = round_.updated_prev.data

    calculated_final: Optional[bytes] = None
    if session.rounds and len(session.rounds[-1].seed.data) == 104:
        calculated_final = expected_prev + session.rounds[-1].seed.data[40:]
    elif not session.rounds and len(session.initial_prev.data) == 40:
        calculated_final = session.initial_prev.data + ZERO32 + ZERO32

    if session.final_seed is None:
        message = (
            "Final RoundSeed is not logged; using the draft-defined composition "
            "from the round records"
        )
        (reporter.fail if require_complete else reporter.warn)(where, message)
    else:
        final = session.final_seed
        if check_length(reporter, where, "Final RoundSeed", final, 104):
            if calculated_final is not None and final.data != calculated_final:
                reporter.fail(
                    f"{where}:{final.line}",
                    "Final RoundSeed is not updated PrevRoundKey || MSK[0:32] || "
                    "EMSK[0:32]",
                )
            else:
                reporter.pass_(where, "Final RoundSeed has the draft-defined composition")
            calculated_final = final.data

    if calculated_final is not None and digestmod is not None:
        expected_msk = tls_prf(calculated_final, MSK_LABEL, 64, digestmod)
        expected_emsk = tls_prf(calculated_final, EMSK_LABEL, 64, digestmod)
        verify_final_key(
            reporter, where, "MSK", session.final_msk, expected_msk, require_complete
        )
        verify_final_key(
            reporter,
            where,
            "EMSK",
            session.final_emsk,
            expected_emsk,
            require_complete,
        )

    compound_results: list[tuple[Compound, bytes]] = []
    for index, compound in enumerate(session.compounds, 1):
        compound_where = f"{where}:binding-{index}"
        cmk_ok = check_length(reporter, compound_where, "CMK", compound.cmk, 32)
        if compound.buffer is None:
            reporter.fail(compound_where, "MAC-input BUFFER is not present")
            continue
        buffer_ok = validate_buffer(reporter, compound_where, compound.buffer)
        if digestmod is None or not cmk_ok or not buffer_ok:
            continue
        expected = hmac.new(
            compound.cmk.data, compound.buffer.data, digestmod
        ).digest()[:20]
        compound_results.append((compound, expected))
        if not compound.macs:
            message = "no logged Compound MAC result follows this BUFFER"
            (reporter.fail if require_complete else reporter.warn)(compound_where, message)
        for label, logged in compound.macs:
            if not check_length(reporter, compound_where, label, logged, 20):
                continue
            if hmac.compare_digest(logged.data, expected):
                reporter.pass_(compound_where, f"{label} matches draft calculation")
            else:
                reporter.fail(
                    f"{compound_where}:{logged.line}",
                    f"{label} {short_hex(logged.data)} != calculated "
                    f"{short_hex(expected)}",
                )

    if not session.compounds:
        message = "no Compound MAC inputs are present"
        (reporter.fail if require_complete else reporter.warn)(where, message)

    for binding in session.bindings:
        validate_binding(
            reporter,
            session,
            binding,
            compound_results,
            strict_should,
        )


def verify_final_key(
    reporter: Reporter,
    where: str,
    name: str,
    logged: Optional[Value],
    expected: bytes,
    require_complete: bool,
) -> None:
    if logged is None:
        message = f"derived {name} is not present in the log"
        (reporter.fail if require_complete else reporter.warn)(where, message)
        return
    if not check_length(reporter, where, f"derived {name}", logged, 64):
        return
    if hmac.compare_digest(logged.data, expected):
        reporter.pass_(where, f"derived {name} matches draft TLS-PRF calculation")
    else:
        reporter.fail(
            f"{where}:{logged.line}",
            f"derived {name} {short_hex(logged.data)} != calculated "
            f"{short_hex(expected)}",
        )


def compare_values(
    reporter: Reporter,
    where: str,
    name: str,
    left: Optional[Value],
    right: Optional[Value],
) -> None:
    if left is None or right is None:
        return
    if left.data == right.data:
        reporter.pass_(where, f"peer/server {name} values agree")
    else:
        reporter.fail(
            where,
            f"peer/server {name} values differ "
            f"({short_hex(left.data)} != {short_hex(right.data)})",
        )


def compare_sessions(reporter: Reporter, sessions: list[Session]) -> None:
    by_seed: dict[bytes, list[Session]] = {}
    for session in sessions:
        by_seed.setdefault(session.initial_prev.data, []).append(session)

    for seed, matching in by_seed.items():
        paths = {session.path for session in matching}
        if len(paths) < 2:
            continue
        base = matching[0]
        for other in matching[1:]:
            if other.path == base.path:
                continue
            where = (
                f"cross-log:{base.path.name}:session-{base.number}<->"
                f"{other.path.name}:session-{other.number}"
            )
            if base.cipher_suite != other.cipher_suite:
                reporter.fail(where, "TLS cipher suites differ")
            else:
                reporter.pass_(where, "TLS cipher suites agree")
            if len(base.rounds) != len(other.rounds):
                reporter.fail(
                    where,
                    f"round counts differ ({len(base.rounds)} != {len(other.rounds)})",
                )
            for index, (left, right) in enumerate(
                zip(base.rounds, other.rounds), 1
            ):
                compare_values(reporter, where, f"round-{index} seed", left.seed, right.seed)
                compare_values(reporter, where, f"round-{index} CMK", left.cmk, right.cmk)
                compare_values(
                    reporter,
                    where,
                    f"round-{index} updated PrevRoundKey",
                    left.updated_prev,
                    right.updated_prev,
                )
            compare_values(
                reporter, where, "Final RoundSeed", base.final_seed, other.final_seed
            )
            compare_values(reporter, where, "final MSK", base.final_msk, other.final_msk)
            compare_values(reporter, where, "final EMSK", base.final_emsk, other.final_emsk)


def contains_teapv2(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as stream:
            for line in stream:
                if "EAP-TEAPV2:" in line:
                    return True
    except (OSError, UnicodeError):
        return False
    return False


def expand_paths(arguments: Iterable[str]) -> list[Path]:
    paths: list[Path] = []
    for argument in arguments:
        path = Path(argument)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and contains_teapv2(child):
                    paths.append(child)
        else:
            paths.append(path)
    return paths


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check TEAPv2 MSK, EMSK, RoundSeed chaining, and Crypto-Binding "
            "Compound MACs in hostap debug logs."
        ),
        epilog=f"Specification: {DRAFT_URL}",
    )
    parser.add_argument(
        "logs",
        nargs="+",
        metavar="LOG",
        help="log file, or a directory whose TEAPv2-containing files are checked",
    )
    parser.add_argument(
        "--strict-should",
        action="store_true",
        help="treat draft SHOULD violations (such as nonzero EMSK MAC) as failures",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="fail when final keys or Compound MAC inputs are absent from a session",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="show successful checks in addition to warnings and failures",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    paths = expand_paths(args.logs)
    reporter = Reporter(quiet=not args.debug)
    all_sessions: list[Session] = []

    if not paths:
        print("ERROR: no log files found", file=sys.stderr)
        return 2
    for path in paths:
        if not path.is_file():
            print(f"ERROR: not a readable file: {path}", file=sys.stderr)
            return 2
        try:
            sessions = parse_log(path)
        except (OSError, ValueError) as error:
            print(f"ERROR: {error}", file=sys.stderr)
            return 2
        if not sessions:
            reporter.warn(str(path), "no TEAPv2 sessions with session_key_seed found")
            continue
        all_sessions.extend(sessions)
        for session in sessions:
            validate_session(
                reporter,
                session,
                args.strict_should,
                args.require_complete,
            )

    compare_sessions(reporter, all_sessions)
    print(
        f"SUMMARY: {reporter.passed} passed, {reporter.warned} warnings, "
        f"{reporter.failed} failed across {len(all_sessions)} session(s)"
    )
    return 1 if reporter.failed else 0


if __name__ == "__main__":
    sys.exit(main())
