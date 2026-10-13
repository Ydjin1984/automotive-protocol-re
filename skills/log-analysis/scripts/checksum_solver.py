#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""checksum_solver.py — подбор чексуммы/CRC по корпусу кадров.

Проверяет модели на ВСЕХ переданных кадрах (последние 1 или 2 байта — чексумма):
  * 1 байт: XOR8, сумма mod 256, -sum (two's complement), 0xFF-sum (инверсия),
            CRC8: poly 0x07 / 0x1D(+init 0xFF, xorout 0xFF) / 0x31 (reflected)
  * 2 байта: CRC16: CCITT-FALSE, XMODEM, MODBUS, X25, KERMIT, reflected-init0 (стиль BMS46)

Примеры:
  python checksum_solver.py --frame "12 04 00 16" --frame "12 2E A0 ..."
  python checksum_solver.py --file capture.log --framing ds2
  python checksum_solver.py --selftest
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import Callable, Dict, List, Optional, Tuple


def _reflect(v: int, bits: int) -> int:
    r = 0
    for i in range(bits):
        if v & (1 << i):
            r |= 1 << (bits - 1 - i)
    return r


def crc_generic(data: bytes, width: int, poly: int, init: int,
                refin: bool, refout: bool, xorout: int) -> int:
    """Канонический битовый CRC (проверяется по контрольным значениям в --selftest)."""
    top = 1 << (width - 1)
    mask = (1 << width) - 1
    crc = init
    for b in data:
        if refin:
            b = _reflect(b, 8)
        crc ^= (b << (width - 8)) & mask
        for _ in range(8):
            if crc & top:
                crc = ((crc << 1) ^ poly) & mask
            else:
                crc = (crc << 1) & mask
    if refout:
        crc = _reflect(crc, width)
    return (crc ^ xorout) & mask


# ---------------------------------------------------------------- модели (1 байт)

def _m_xor8(body: bytes) -> int:
    x = 0
    for b in body:
        x ^= b
    return x


def _m_sum8(body: bytes) -> int:
    return sum(body) & 0xFF


def _m_neg8(body: bytes) -> int:
    return (-sum(body)) & 0xFF


def _m_inv8(body: bytes) -> int:
    return (0xFF - (sum(body) & 0xFF)) & 0xFF


def _m_crc8_07(body: bytes) -> int:
    return crc_generic(body, 8, 0x07, 0x00, False, False, 0x00)


def _m_crc8_j1850(body: bytes) -> int:
    return crc_generic(body, 8, 0x1D, 0xFF, False, False, 0xFF)


def _m_crc8_maxim(body: bytes) -> int:
    return crc_generic(body, 8, 0x31, 0x00, True, True, 0x00)


CHECKS_1: Dict[str, Callable[[bytes], int]] = {
    "xor8": _m_xor8,
    "sum8": _m_sum8,
    "neg8_2c": _m_neg8,
    "inv8": _m_inv8,
    "crc8_p07": _m_crc8_07,
    "crc8_j1850": _m_crc8_j1850,
    "crc8_maxim": _m_crc8_maxim,
}

# ---------------------------------------------------------------- модели (2 байта)

def _mk16(name: str, poly: int, init: int, refin: bool, refout: bool, xorout: int):
    return name, (lambda body: crc_generic(body, 16, poly, init, refin, refout, xorout))


CHECKS_2: Dict[str, Callable[[bytes], int]] = dict([
    _mk16("crc16_ccitt_false", 0x1021, 0xFFFF, False, False, 0x0000),
    _mk16("crc16_xmodem", 0x1021, 0x0000, False, False, 0x0000),
    _mk16("crc16_modbus", 0x8005, 0xFFFF, True, True, 0x0000),
    _mk16("crc16_x25", 0x1021, 0xFFFF, True, True, 0xFFFF),
    _mk16("crc16_kermit", 0x1021, 0x0000, True, True, 0x0000),
    _mk16("crc16_ref_init0", 0x1021, 0x0000, True, True, 0x0000),   # стиль BMS46 (init 0)
])

# CRC32 — на случай прошивочных контрольных сумм
CHECKS_4: Dict[str, Callable[[bytes], int]] = {
    "crc32_zlib": lambda body: __import__("zlib").crc32(body) & 0xFFFFFFFF,
}


# ---------------------------------------------------------------- ввод кадров

def frame_from_line(line: str) -> Optional[bytes]:
    """Из строки лога вытащить hex-байты кадра (или строку чистого hex)."""
    line = line.strip()
    if not line or line.startswith(("#", "//", ";")):
        return None
    m = re.search(r":\s*([0-9A-Fa-f ]+?)\s*$", line)      # Frida-диалект
    if not m:
        m = re.search(r"(?:TX|RX|EH|INPUT|OUTPUT)\s*:?\s*([0-9A-Fa-f ]+?)\s*$", line)
    if not m:
        m = re.match(r"^([0-9A-Fa-f ]+)$", line)          # чистый hex
    if not m:
        return None
    hexs = re.findall(r"[0-9A-Fa-f]{2}", m.group(1))
    if not hexs:
        return None
    return bytes(int(x, 16) for x in hexs)


# ---------------------------------------------------------------- ядро

def solve(frames: List[bytes], cks_len: int, endian: str, verbose: bool = False) -> List[Tuple[str, int, int]]:
    """Для каждой модели — сколько кадров совпало. Возврат: [(model, ok, total)]."""
    results: List[Tuple[str, int, int]] = []
    if cks_len in (1, 0):
        for name, fn in CHECKS_1.items():
            ok = 0
            for f in frames:
                if len(f) < 2:
                    continue
                if fn(f[:-1]) == f[-1]:
                    ok += 1
            results.append((name, ok, len(frames)))
    if cks_len in (2, 0):
        for name, fn in CHECKS_2.items():
            ok = 0
            for f in frames:
                if len(f) < 3:
                    continue
                v = fn(f[:-2])
                tail = f[-2:]
                be = (tail[0] << 8) | tail[1]
                le = (tail[1] << 8) | tail[0]
                hit = (v == be) if endian == "be" else ((v == le) if endian == "le" else (v in (be, le)))
                if hit:
                    ok += 1
            results.append((name + ("" if endian != "auto" else ""), ok, len(frames)))
    if cks_len in (4,):
        for name, fn in CHECKS_4.items():
            ok = 0
            for f in frames:
                if len(f) < 5:
                    continue
                tail = int.from_bytes(f[-4:], "big")
                if fn(f[:-4]) == tail:
                    ok += 1
            results.append((name, ok, len(frames)))
    results.sort(key=lambda r: -r[1])
    if verbose:
        for name, ok, total in results:
            print(f"  {name:<22} {ok}/{total}")
    return results


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    # Контрольные значения каталога CRC ("123456789")
    data = b"123456789"
    check("crc8 p07/F4", crc_generic(data, 8, 0x07, 0x00, False, False, 0x00) == 0xF4)
    check("crc8 j1850/4B", crc_generic(data, 8, 0x1D, 0xFF, False, False, 0xFF) == 0x4B)
    check("crc8 maxim/A1", crc_generic(data, 8, 0x31, 0x00, True, True, 0x00) == 0xA1)
    check("crc16 ccitt-false/29B1", crc_generic(data, 16, 0x1021, 0xFFFF, False, False, 0) == 0x29B1)
    check("crc16 modbus/4B37", crc_generic(data, 16, 0x8005, 0xFFFF, True, True, 0) == 0x4B37)
    check("crc16 x25/906E", crc_generic(data, 16, 0x1021, 0xFFFF, True, True, 0xFFFF) == 0x906E)
    check("crc16 kermit/2189", crc_generic(data, 16, 0x1021, 0x0000, True, True, 0) == 0x2189)

    def mk(payload: bytes, fn, tail_len: int, endian: str = "be") -> bytes:
        v = fn(payload)
        tail = v.to_bytes(tail_len, {"be": "big", "le": "little"}[endian])
        return payload + tail

    # xor8
    frames = [mk(bytes([0x12, 0x04, 0x00]), _m_xor8, 1),
              mk(bytes([0x12, 0x05, 0xA0, 0x42]), _m_xor8, 1)]
    best = solve(frames, 1, "be")[0]
    check("solver: xor8 найден на 2/2", best[0] == "xor8" and best[1] == 2)

    # sum8
    frames = [mk(bytes([0x68, 0x6A, 0xF1, 0x01, 0x00]), _m_sum8, 1),
              mk(bytes([0x81, 0x10, 0xF1, 0x81]), _m_sum8, 1)]
    best = solve(frames, 1, "be")[0]
    check("solver: sum8 найден на 2/2", best[0] == "sum8" and best[1] == 2)

    # crc16 modbus (LE на линии)
    frames = [mk(bytes([0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]), CHECKS_2["crc16_modbus"], 2, "le"),
              mk(bytes([0x10, 0x20, 0x30, 0x40]), CHECKS_2["crc16_modbus"], 2, "le")]
    best = solve(frames, 2, "le")[0]
    check("solver: crc16_modbus (LE) найден", best[0] == "crc16_modbus" and best[1] == 2)

    # строка лога -> кадр
    f = frame_from_line("[+94.086s] TX ftd2xx FT_Write rc=0 len=4 n=4 : 12 04 00 16")
    check("frame_from_line: frida", f == bytes([0x12, 0x04, 0x00, 0x16]))
    f = frame_from_line("12 04 00 16")
    check("frame_from_line: чистый hex", f == bytes([0x12, 0x04, 0x00, 0x16]))

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


# ---------------------------------------------------------------- main

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Подбор чексуммы/CRC по корпусу кадров")
    ap.add_argument("--frame", action="append", default=[], help="кадр hex-строкой (можно повторять)")
    ap.add_argument("--file", help="лог/файл с кадрами (по строке)")
    ap.add_argument("--cks-len", type=int, default=0, choices=[0, 1, 2, 4],
                    help="0=авто (1 и 2), иначе длина чексуммы в байтах")
    ap.add_argument("--endian", default="auto", choices=["auto", "be", "le"])
    ap.add_argument("--verbose", action="store_true", help="печатать все модели")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    frames: List[bytes] = []
    for s in args.frame:
        f = frame_from_line(s)
        if f:
            frames.append(f)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                f = frame_from_line(line)
                if f:
                    frames.append(f)

    if not frames:
        print("нет кадров: передай --frame или --file", file=sys.stderr)
        return 2

    print(f"кадров: {len(frames)}")
    results = solve(frames, args.cks_len, args.endian)
    total = len(frames)
    winners = [r for r in results if r[1] == total]
    if winners:
        print("\nПОДХОДЯТ (100% кадров):")
        for name, ok, tot in winners:
            print(f"  {name:<22} {ok}/{tot}")
    else:
        print("\nни одна модель не объясняет все кадры; лучшие:")
        for name, ok, tot in results[:5]:
            print(f"  {name:<22} {ok}/{tot}")
        print("\nподсказка: возможно, чексумма табличная (CRC в образе) или составная;")
        print("смотри log-analysis/references/methodology.md §2.5")
    if args.verbose:
        print("\nвсе модели:")
        for name, ok, tot in results:
            print(f"  {name:<22} {ok}/{tot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
