#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""telegram_parse.py — нарезка сырого лога обмена с ЭБУ на кадры (телеграммы).

Понимает "диалекты" логов:
  * канон/HwProbe:  [16:39:35.698] TX 12 04 00 16
  * относительный:  [+1.234s] TX 12 04 00 16
  * Frida-логгер:   [+94.086s] TX ftd2xx FT_Write rc=0 len=4 n=4 : 12 04 00 16
  * EDIABAS trc:    _STD      OUTPUT: 12 04 00 16      (OUTPUT=TX тестера, INPUT=RX от ЭБУ)

Framing:
  ds2        : [addr][полная длина][payload][xor]  (BMW DS2)
  kwp        : FMT(A1A0+L5..L0) [+Len] payload CS  (KWP2000/ISO14230)
  gap:MS     : кадр = байты, между которыми нет паузы > MS (ISO9141-2, KWP1281)
  line       : одна строка лога = один кадр

Примеры:
  python telegram_parse.py --framing ds2 --cks auto < capture.log
  python telegram_parse.py --file win.log --framing gap:25 --out decoded.txt
  python telegram_parse.py --selftest
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional

RE_ABS = re.compile(r"^\[(?P<ts>\d{1,2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\]\s+(?P<dir>TX|RX|EH)\b(?P<rest>.*)$")
RE_REL = re.compile(r"^\[\+(?P<rel>\d+(?:\.\d+)?)s\]\s+(?P<rest>.+)$")
RE_EDIABAS = re.compile(r"^\S+\s+(?P<dir>INPUT|OUTPUT):\s*(?P<hex>[0-9A-Fa-f ]+?)\s*$")
RE_HEXRUN = re.compile(r"(?P<hex>(?:[0-9A-Fa-f]{2})(?:[ ,]+[0-9A-Fa-f]{2})+|[0-9A-Fa-f]{2})")
RE_TRAILING_HEX = re.compile(r":\s*([0-9A-Fa-f ]+?)\s*$")


@dataclass
class Record:
    t: Optional[float]          # секунды (относительные) либо None
    clock: Optional[str]        # wall-clock как в файле
    direction: str              # 'tx' | 'rx'
    data: bytes
    src: str = ""               # источник строки: text|rel|frida|ediabas
    note: str = ""


def _hex_to_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in re.findall(r"[0-9A-Fa-f]{2}", s))


def _clock_to_seconds(ts: str) -> Optional[float]:
    try:
        ts = ts.replace(",", ".")
        h, m, s = ts.split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)
    except Exception:
        return None


def parse_lines(lines: Iterable[str]) -> List[Record]:
    out: List[Record] = []
    base_clock: Optional[float] = None
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith(("#", "//", ";")):
            continue

        m = RE_ABS.match(line)
        if m:
            hm = _clock_to_seconds(m.group("ts"))
            if base_clock is None:
                base_clock = hm
            t = (hm - base_clock) if (hm is not None and base_clock is not None) else None
            d = m.group("dir").lower()
            direction = "tx" if d == "tx" else "rx"
            note = "echo" if d == "eh" else ""
            data = _hex_to_bytes(m.group("rest"))
            if data:
                out.append(Record(t, m.group("ts"), direction, data, "text", note))
            continue

        m = RE_REL.match(line)
        if m:
            t = float(m.group("rel"))
            rest = m.group("rest")
            dm = re.search(r"\b(TX|RX)\b", rest)
            if not dm:
                continue
            direction = "tx" if dm.group(1) == "TX" else "rx"
            src = "frida" if ("ftd2xx" in rest or "VCP" in rest) else "rel"
            hexm = RE_TRAILING_HEX.search(rest) or RE_HEXRUN.search(rest)
            if not hexm:
                continue
            data = _hex_to_bytes(hexm.group(1))
            if data:
                out.append(Record(t, None, direction, data, src))
            continue

        m = RE_EDIABAS.match(line)
        if m:
            direction = "tx" if m.group("dir") == "OUTPUT" else "rx"
            data = _hex_to_bytes(m.group("hex"))
            if data:
                out.append(Record(None, None, direction, data, "ediabas"))
            continue
    return out


# ---------------------------------------------------------------- нарезка кадров

@dataclass
class Frame:
    index: int
    t: Optional[float]
    direction: str
    data: bytes
    cks: str = "?"
    note: str = ""

    def to_text(self, prev_t: Optional[float]) -> str:
        dt = "" if (self.t is None or prev_t is None) else f" dt=+{self.t - prev_t:.3f}s"
        hexs = " ".join(f"{b:02X}" for b in self.data)
        tail = f"  ; {self.note}" if self.note else ""
        return f"#{self.index:<5} {self.direction.upper()} len={len(self.data):<4}{dt:<14} {hexs}  [{self.cks}]{tail}"


def _xor(bs: bytes) -> int:
    x = 0
    for b in bs:
        x ^= b
    return x


def _cks_check(frame: bytes, mode: str) -> str:
    if mode == "none" or len(frame) < 2:
        return "none"
    body, cks = frame[:-1], frame[-1]
    ok_xor = (_xor(body) ^ cks) == 0
    ok_sum = (sum(body) & 0xFF) == cks
    if mode == "xor":
        return "ok:xor" if ok_xor else "bad"
    if mode == "sum8":
        return "ok:sum8" if ok_sum else "bad"
    if ok_xor:
        return "ok:xor"
    if ok_sum:
        return "ok:sum8"
    return "bad"


def _concat(records: List[Record]):
    """Раздельные потоки байт TX и RX с таймстампом на каждый байт."""
    tx_b, tx_t, rx_b, rx_t = [], [], [], []
    for r in records:
        tgt_b, tgt_t = (tx_b, tx_t) if r.direction == "tx" else (rx_b, rx_t)
        tgt_b.extend(r.data)
        tgt_t.extend([r.t] * len(r.data))
    return tx_b, tx_t, rx_b, rx_t


def _frame_stream(data: List[int], times: List[Optional[float]], direction: str,
                  framing: str, cks: str) -> List[Frame]:
    frames: List[Frame] = []
    i = 0
    n = len(data)

    def push(end: int, note: str = "") -> None:
        body = bytes(data[i:end])
        frames.append(Frame(0, times[i] if i < n else None, direction, body, _cks_check(body, cks), note))

    if framing.startswith("gap"):
        thresh = float(framing.split(":", 1)[1]) if ":" in framing else 25.0
        while i < n:
            j = i + 1
            while j < n:
                t0, t1 = times[j - 1], times[j]
                if t0 is not None and t1 is not None and (t1 - t0) * 1000.0 > thresh:
                    break
                j += 1
            push(j)
            i = j
        return frames

    if framing == "ds2":
        while i + 2 <= n:
            ln = data[i + 1]
            if ln < 4 or ln > 250 or i + ln > n:
                frames.append(Frame(0, times[i], direction, bytes(data[i:i + 2]), "?",
                                    f"unparsed at offset {i}: " +
                                    " ".join(f"{b:02X}" for b in data[i:i + 8])))
                i += 1
                continue
            push(i + ln)
            i += ln
        return frames

    if framing == "kwp":
        while i + 5 <= n:
            fmt = data[i]
            a = fmt >> 6
            if a not in (0b10, 0b11):
                frames.append(Frame(0, times[i], direction, bytes(data[i:i + 1]), "?",
                                    f"unparsed FMT=0x{fmt:02X} at offset {i}"))
                i += 1
                continue
            l6 = fmt & 0x3F
            if l6 == 0:
                if i + 5 > n:
                    break
                total = 4 + data[i + 3] + 1   # Fmt Tgt Src Len → data-поле Len байт → CS
            else:
                total = 3 + l6 + 1
            if i + total > n:
                break
            push(i + total)
            i += total
        return frames

    raise SystemExit(f"неизвестный framing: {framing}")


def parse(records: List[Record], framing: str, cks: str) -> List[Frame]:
    if framing == "line":
        return [Frame(0, r.t, r.direction, r.data, _cks_check(r.data, cks), r.note) for r in records]

    tx_b, tx_t, rx_b, rx_t = _concat(records)
    frames: List[Frame] = []
    for direction, data, times in (("tx", tx_b, tx_t), ("rx", rx_b, rx_t)):
        if data:
            frames.extend(_frame_stream(data, times, direction, framing, cks))

    if any(f.t is not None for f in frames):
        frames.sort(key=lambda f: (f.t is None, f.t if f.t is not None else 0.0))
    for k, f in enumerate(frames, 1):
        f.index = k
    return frames


# ---------------------------------------------------------------- отчёт

def report(frames: List[Frame], out) -> None:
    prev = None
    tx = rx = bad = 0
    for f in frames:
        out.write(f.to_text(prev) + "\n")
        if f.t is not None:
            prev = f.t
        if f.direction == "tx":
            tx += 1
        else:
            rx += 1
        if f.cks in ("bad", "?"):
            bad += 1
    out.write(f"\n# frames={len(frames)} tx={tx} rx={rx} cks_problems={bad}\n")


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    # DS2: запрос, эхо отдельной строкой, эхо+ответ склеены в одну строку.
    # Кадр ответа: 12 05 A0 42 F5  (len=5, xor: 12^05^A0^42=F5)
    frames = parse(parse_lines([
        "[10:00:00.100] TX 12 04 00 16",
        "[10:00:00.240] RX 12 04 00 16",
        "[10:00:00.245] RX 12 04 00 16 12 05 A0 42 F5",
    ]), "ds2", "auto")
    check("DS2: 4 кадра (tx + 2 эхо + ответ)", len(frames) == 4)
    check("DS2: чексуммы ok", all(f.cks.startswith("ok") for f in frames))
    check("DS2: длины 4/4/4/5", [len(f.data) for f in frames] == [4, 4, 4, 5])
    check("DS2: направления tx,rx,rx,rx", [f.direction for f in frames] == ["tx", "rx", "rx", "rx"])
    check("DS2: порядок по времени", [round(f.t, 3) for f in frames] == [0.0, 0.14, 0.145, 0.145])

    # KWP2000
    frames = parse(parse_lines([
        "[10:00:01.000] TX 81 10 F1 81 03",
        "[10:00:01.050] RX 83 F1 10 C1 EA 8F BE",
        "[10:00:01.100] RX C2 33 F1 01 00 E7",
    ]), "kwp", "sum8")
    check("KWP: 3 кадра", len(frames) == 3)
    check("KWP: sum8 ok", all(f.cks == "ok:sum8" for f in frames))
    check("KWP: длины 5/7/6", [len(f.data) for f in frames] == [5, 7, 6])

    # KWP с явным Len-байтом (канонический пример EU 2016/799)
    frames = parse(parse_lines(["[10:00:02.000] RX 80 F0 EE 03 C1 EA 8F 9B"]), "kwp", "sum8")
    check("KWP Len-байт: len=8 и sum8 ok",
          len(frames) == 1 and len(frames[0].data) == 8 and frames[0].cks == "ok:sum8")

    # gap-фрейминг: две пачки подряд + одна после паузы
    recs = parse_lines([
        "[10:00:03.000] RX 55 01 8A 75",
        "[10:00:03.005] RX 03 FC 02 FD 09 F6 03",
        "[10:00:03.600] RX 09 F6",
    ])
    frames = parse(recs, "gap:50", "none")
    check("GAP: 2 кадра (пачка 11 Б + 2 Б)",
          len(frames) == 2 and len(frames[0].data) == 11 and len(frames[1].data) == 2)
    frames2 = parse(recs, "gap:5000", "none")
    check("GAP: с порогом 5 с один кадр 13 Б", len(frames2) == 1 and len(frames2[0].data) == 13)

    # EDIABAS-диалект: OUTPUT=TX, INPUT=RX
    recs = parse_lines([
        "_STD      OUTPUT: 12 04 00 ",
        "_STD      INPUT: 12 2E A0 31 39 9F ",
        "_STD      ERROR: NO ERROR",
    ])
    check("EDIABAS: 2 записи tx/rx",
          len(recs) == 2 and recs[0].direction == "tx" and recs[1].direction == "rx")

    # Frida-диалект
    recs = parse_lines([
        "[+94.086s] TX ftd2xx FT_Write rc=0 len=4 n=4 : 12 04 00 16",
        "[+94.241s] RX ftd2xx FT_Read rc=0 want=2 n=2 : 12 2e",
        "[+70.537s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b",
    ])
    check("Frida: 3 записи, tx/rx/tx",
          len(recs) == 3 and [r.direction for r in recs] == ["tx", "rx", "tx"])
    check("Frida: байты", recs[1].data == bytes([0x12, 0x2E]))
    check("Frida: сортировка по времени", recs[0].t == 94.086 and recs[2].t == 70.537)

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


# ---------------------------------------------------------------- main

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Нарезка логов обмена с ЭБУ на кадры")
    ap.add_argument("--file", help="входной лог (по умолчанию stdin)")
    ap.add_argument("--framing", default="ds2", help="ds2 | kwp | gap:MS | line")
    ap.add_argument("--cks", default="auto", help="auto | xor | sum8 | none")
    ap.add_argument("--out", help="файл вывода (по умолчанию stdout)")
    ap.add_argument("--json", help="дополнительно выгрузить кадры в JSON")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            records = parse_lines(f)
    else:
        records = parse_lines(sys.stdin)

    frames = parse(records, args.framing, args.cks)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as out:
            report(frames, out)
    else:
        report(frames, sys.stdout)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([{"i": f.index, "t": f.t, "dir": f.direction,
                        "hex": " ".join(f"{b:02X}" for b in f.data),
                        "cks": f.cks, "note": f.note} for f in frames],
                      f, ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
