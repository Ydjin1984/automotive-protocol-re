#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mine_telegrams.py — поиск каталогов телеграмм внутри EXE/бинарей.

Ищет последовательности вида [addr][len][payload…][cks], где len — полная длина
кадра, а cks — XOR (или сумма) всех предыдущих байт. Так в реальном проекте был
найден литеральный каталог 23 телеграмм внутри флешера (кросс-валидирован по
известным командам).

Примеры:
  python mine_telegrams.py --file app.exe --addr 0x12
  python mine_telegrams.py --file dll.dll --all-addr --cks xor --cluster
  python mine_telegrams.py --selftest
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from typing import List, Optional, Tuple


def _xor(bs: bytes) -> int:
    x = 0
    for b in bs:
        x ^= b
    return x


def scan(data: bytes, addr: Optional[int], min_len: int, max_len: int, cks: str) -> List[Tuple[int, bytes]]:
    hits: List[Tuple[int, bytes]] = []
    n = len(data)
    for i in range(n - min_len + 1):
        a = data[i]
        if addr is not None and a != addr:
            continue
        ln = data[i + 1]
        if ln < min_len or ln > max_len or i + ln > n:
            continue
        frame = data[i:i + ln]
        if cks == "xor":
            if _xor(frame[:-1]) != frame[-1]:
                continue
        elif cks == "sum8":
            if (sum(frame[:-1]) & 0xFF) != frame[-1]:
                continue
        hits.append((i, frame))
    return hits


def clusters(hits: List[Tuple[int, bytes]], window: int = 0x800) -> List[List[Tuple[int, bytes]]]:
    out: List[List[Tuple[int, bytes]]] = []
    for h in hits:
        if out and h[0] - out[-1][-1][0] <= window:
            out[-1].append(h)
        else:
            out.append([h])
    return out


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    def tg(payload: bytes, addr: int = 0x12) -> bytes:
        ln = 2 + len(payload) + 1
        body = bytes([addr, ln]) + payload
        return body + bytes([_xor(body)])

    t1 = tg(bytes([0x00]))                 # 12 04 00 16
    t2 = tg(bytes([0x0B, 0x03]))           # 12 05 0B 03 ...
    t3 = tg(bytes([0x43, 0xFF, 0xFF]))     # 12 06 43 FF FF ...
    blob = os.urandom(64) + t1 + os.urandom(32) + t2 + t3 + os.urandom(16)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(blob)
        path = f.name
    try:
        data = open(path, "rb").read()
        hits = scan(data, 0x12, 4, 64, "xor")
        check("mine: найдено 3 XOR-телеграммы", len(hits) == 3)
        check("mine: кадр 12 04 00 16 найден дословно", any(h[1] == b"\x12\x04\x00\x16" for h in hits))
        check("mine: offset корректен", any(h[0] == 64 for h in hits))

        cl = clusters(hits, 0x800)
        check("mine: все 3 в одном кластере", len(cl) == 1 and len(cl[0]) == 3)

        # сумма-чексумма
        body = bytes([0x12, 0x05, 0x0B, 0x03])
        t4 = body + bytes([sum(body) & 0xFF])
        hits_sum = scan(t4 + os.urandom(8), 0x12, 4, 64, "sum8")
        check("mine: sum8-телеграмма найдена", len(hits_sum) == 1)

        # случайные данные не должны давать ложных срабатываний на addr
        hits_rand = scan(os.urandom(4096), 0x12, 4, 64, "xor")
        check("mine: ложные срабатывания редки (<3 на 4 КБ)", len(hits_rand) < 3)
    finally:
        os.unlink(path)

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


# ---------------------------------------------------------------- main

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Поиск каталогов телеграмм в бинарях")
    ap.add_argument("--file", help="EXE/DLL/BIN")
    ap.add_argument("--addr", default="0x12", help="адрес ЭБУ (hex), по умолчанию 0x12 (DME BMW)")
    ap.add_argument("--all-addr", action="store_true", help="любой первый байт (шире, ложно-положительнее)")
    ap.add_argument("--cks", default="xor", choices=["xor", "sum8"])
    ap.add_argument("--min-len", type=int, default=4)
    ap.add_argument("--max-len", type=int, default=64)
    ap.add_argument("--from", dest="from_off", default=None, help="начало диапазона (hex)")
    ap.add_argument("--to", dest="to_off", default=None, help="конец диапазона (hex)")
    ap.add_argument("--cluster", action="store_true", help="сгруппировать находки в каталоги")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.file:
        print("нужен --file", file=sys.stderr)
        return 2
    data = open(args.file, "rb").read()
    off0 = int(args.from_off, 16) if args.from_off else 0
    off1 = int(args.to_off, 16) if args.to_off else len(data)
    data = data[off0:off1]

    addr = None if args.all_addr else int(args.addr, 16)
    hits = scan(data, addr, args.min_len, args.max_len, args.cks)
    print(f"# {args.file}: телеграмм найдено: {len(hits)} (cks={args.cks}, "
          f"{'any addr' if addr is None else f'addr=0x{addr:02X}'})")
    for off, frame in hits:
        hexs = " ".join(f"{b:02X}" for b in frame)
        print(f"0x{off0 + off:08X}  len={len(frame):<3} {hexs}")
    if args.cluster:
        cl = clusters(hits)
        print(f"\n# каталогов (кластеров): {len(cl)}")
        for k, c in enumerate(cl, 1):
            print(f"  кластер {k}: {len(c)} записей, offset 0x{off0 + c[0][0]:08X}..0x{off0 + c[-1][0]:08X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
