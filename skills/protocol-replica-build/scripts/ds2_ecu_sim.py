#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ds2_ecu_sim.py — минимальный симулятор ЭБУ BMW DS2 по TCP для офлайн-тестов реплики.

Зачем: тестировать клиент/флешер без железа — эхо, строгие ACK, авторизации,
«мёртвое окно» после старта сессии, commit с busy-статусами.

Использование (два терминала):
  python ds2_ecu_sim.py --port 5555 --erase-delay-ms 800
  python ../deep-log-capture/scripts/ftdi_kline_logger.py --tcp 127.0.0.1:5555 --probe-ds2

Проверка самого симулятора без сети: python ds2_ecu_sim.py --selftest
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from typing import Optional

DEFAULT_ID = "14309406100A76050" "98010213510" "F0000001" "11832"   # 42 ASCII (wire-verified layout)


def _xor(bs: bytes) -> int:
    x = 0
    for b in bs:
        x ^= b
    return x


def build(addr: int, payload: bytes) -> bytes:
    """Кадр DS2: [addr][LEN = полная длина][payload][xor]  (пример: 12 04 00 16)."""
    body = bytes([addr, 3 + len(payload)]) + payload
    return body + bytes([_xor(body)])


class Ds2Ecu:
    """Минимальная DS2-личность: команды из wire-verified таблицы (BMS46)."""

    def __init__(self, addr: int = 0x12, ident: str = DEFAULT_ID,
                 image: bytes = b"", erase_delay_ms: int = 800, busy_first: int = 1):
        self.addr = addr
        self.ident = (ident.encode("ascii", "replace") + b" " * 42)[:42]
        self.image = image
        self.erase_delay_ms = erase_delay_ms
        self.busy_first = busy_first
        self._busy_left = 0
        self._session_open = False
        self._first_auth_seen = False

    # ---- обработка одного кадра (без сети) -> list[bytes] ответов

    def handle(self, frame: bytes) -> list[bytes]:
        if len(frame) < 4 or frame[0] != self.addr:
            return []
        ln = frame[1]
        if ln != len(frame):
            return []
        if _xor(frame[:-1]) != frame[-1]:
            return [build(self.addr, bytes([0xC0]))]          # ошибка чексуммы
        p = frame[2:-1]
        cmd = p[0]

        if cmd == 0x00:                                        # IDENT
            return [build(self.addr, bytes([0xA0]) + self.ident)]
        if cmd == 0x04 and len(p) >= 2:
            if p[1] == 0x00:
                return [build(self.addr, bytes([0xA0, 0x0A, 0xFF, 0xFF, 0xFF, 0xFF]))]
            if p[1] == 0x0D:                                   # AIF
                return [build(self.addr, bytes([0xA0]) + bytes(73))]
            return [build(self.addr, bytes([0xA0]) + bytes(20))]
        if cmd == 0x06 and len(p) >= 6:                        # READ MEMORY: 06 <addr32 BE> <len8>
            a = (p[1] << 24) | (p[2] << 16) | (p[3] << 8) | p[4]
            n = p[5]
            if n > 0x60:
                return [build(self.addr, bytes([0xB0]))]
            if self.image and a + n <= len(self.image):
                return [build(self.addr, bytes([0xA0]) + self.image[a:a + n])]
            if not self.image:
                return [build(self.addr, bytes([0xA0]) + bytes([0xFF] * n))]
            return [build(self.addr, bytes([0xB0]))]
        if cmd == 0x05:
            return [build(self.addr, bytes([0xA0]))]
        if cmd == 0x43:
            return [build(self.addr, bytes([0xA0]))]
        if cmd == 0x6D:
            return [build(self.addr, bytes([0xA2]))]
        if cmd == 0x9F:
            return [build(self.addr, bytes([0xA0]))]
        if cmd == 0x90:                                        # BMW-авторизации
            if len(p) >= 5 and p[1:4] == bytes([0x42, 0x4D, 0x57]):     # "BMW"
                phase = p[4]
                if phase == 0x04 and not self._first_auth_seen:
                    self._first_auth_seen = True
                    return [build(self.addr, bytes([0xA0]) + self.ident)]   # ответ = строка ID (verified)
                return [build(self.addr, bytes([0xA0, 0x00]))]
            if len(p) >= 5 and p[1:4] == bytes([0x9A, 0x9B, 0x9C]):
                return [build(self.addr, bytes([0xA0, 0x00]))]
            return [build(self.addr, bytes([0xA2]))]
        if cmd == 0x0A:                                        # открыть/коммит сессии
            if not self._session_open:
                self._session_open = True
                if self.erase_delay_ms:
                    time.sleep(self.erase_delay_ms / 1000.0)   # «прогрев» сессии
                self._busy_left = self.busy_first
            if self._busy_left > 0:
                self._busy_left -= 1
                return [build(self.addr, bytes([0xA1]))]       # busy — повторить
            return [build(self.addr, bytes([0xA0, 0x00]))]
        if cmd == 0x07 and len(p) >= 2:
            sub = p[1]
            if sub == 0x06:                                     # старт сессии: пауза + ответ
                if self.erase_delay_ms:
                    time.sleep(self.erase_delay_ms / 1000.0)
                return [build(self.addr, bytes([0xA2]))]
            if sub == 0x0F:                                     # валидация → 01
                return [build(self.addr, bytes([0xA0, 0x01]))]
            if sub == 0x02:                                     # запись блока: ACK addr24/len
                return [build(self.addr, bytes([0xA0, 0x02]) + p[2:6] + bytes([0x01]))]
        return [build(self.addr, bytes([0xB0]))]                # неизвестное — отказ


# ---------------------------------------------------------------- сервер

def serve(host: str, port: int, ecu: Ds2Ecu, echo: bool, verbose: bool) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    print(f"[sim] DS2 ECU на {host}:{port} (addr=0x{ecu.addr:02X}, echo={'on' if echo else 'off'})")
    while True:
        conn, peer = srv.accept()
        print(f"[sim] connect {peer}")
        conn.settimeout(30.0)
        buf = bytearray()
        try:
            while True:
                try:
                    chunk = conn.recv(1024)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                for b in chunk:
                    buf.append(b)
                    # кадр DS2: [addr][len]; длину знаем после 2 байт
                    while len(buf) >= 2 and buf[0] == ecu.addr:
                        ln = buf[1]
                        if len(buf) < ln:
                            break
                        frame = bytes(buf[:ln])
                        del buf[:ln]
                        responses = ecu.handle(frame)          # вызываем РОВНО один раз
                        if echo:
                            conn.sendall(frame)                # эхо (raw FT232R-стиль)
                        if verbose:
                            print(f"[sim] RX {frame.hex(' ')} -> " +
                                  (" | ".join(r.hex(' ') for r in responses) if responses else "(нет)"))
                        for resp in responses:
                            time.sleep(0.002)
                            conn.sendall(resp)
                    if len(buf) >= 2 and buf[0] != ecu.addr:
                        if verbose:
                            print("[sim] drop byte", hex(buf[0]))
                        del buf[:1]
        finally:
            conn.close()
            print(f"[sim] disconnect {peer}")


# ---------------------------------------------------------------- selftest

def selftest() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    ecu = Ds2Ecu()

    def q(payload: bytes) -> bytes:
        return ecu.handle(build(0x12, payload))[0]

    r = q(bytes([0x00]))
    check("ident: A0 + 42 ASCII", r[2] == 0xA0 and len(r) == 2 + 1 + 42 + 1 and b"1430940" in r)

    r = q(bytes([0x04, 0x00]))
    check("dtc count: A0 0A FF*4", r[2] == 0xA0 and r[3] == 0x0A)

    r = q(bytes([0x06, 0x00, 0x00, 0x30, 0x00, 0x04]))
    check("read memory: A0 + 4 байта", r[2] == 0xA0 and len(r) == 2 + 1 + 4 + 1)

    r = q(bytes([0x06, 0x00, 0x00, 0x30, 0x00, 0x61]))
    check("read >0x60: B0", r[2] == 0xB0)

    r = q(bytes([0x90, 0x42, 0x4D, 0x57, 0x04]))
    check("auth #1: ответ = ID", r[2] == 0xA0 and b"1430940" in r)
    r = q(bytes([0x90, 0x9A, 0x9B, 0x9C, 0xA3]))
    check("auth #2: A0 00", r[2] == 0xA0 and r[3] == 0x00)

    r = ecu.handle(build(0x12, bytes([0x07, 0x02, 0x00, 0x80, 0x40, 0x10])))[0]
    check("write ack: содержит addr24/len", r[2] == 0xA0 and r[3] == 0x02 and r[4:8] == bytes([0x00, 0x80, 0x40, 0x10]))

    r = q(bytes([0x07, 0x0F, 0x03, 0x00, 0x00, 0x00]))
    check("final validate: 01", r[2] == 0xA0 and r[3] == 0x01)

    # плохая чексумма
    bad = bytes([0x12, 0x04, 0x00, 0x00])
    r = ecu.handle(bad)
    check("bad cks: C0", len(r) == 1 and r[0][2] == 0xC0)

    # commit: первый ответ busy (A1), затем A0 00
    ecu2 = Ds2Ecu(erase_delay_ms=0, busy_first=1)
    r1 = ecu2.handle(build(0x12, bytes([0x0A])))[0]
    r2 = ecu2.handle(build(0x12, bytes([0x0A])))[0]
    check("commit: A1 -> A0 00", r1[2] == 0xA1 and r2[2] == 0xA0 and r2[3] == 0x00)

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


# ---------------------------------------------------------------- main

def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Симулятор ЭБУ BMW DS2 по TCP")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--addr", default="0x12")
    ap.add_argument("--id", default=DEFAULT_ID)
    ap.add_argument("--image", help="образ для чтений 0x06 (файл)")
    ap.add_argument("--erase-delay-ms", type=int, default=800, help="пауза-«мёртвое окно» перед ответом на старт сессии")
    ap.add_argument("--busy-first", type=int, default=1, help="сколько A1 отдать перед ответом на commit")
    ap.add_argument("--no-echo", action="store_true", help="адаптер без эха")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    image = open(args.image, "rb").read() if args.image else b""
    ecu = Ds2Ecu(addr=int(args.addr, 16), ident=args.id, image=image,
                 erase_delay_ms=args.erase_delay_ms, busy_first=args.busy_first)
    try:
        serve(args.host, args.port, ecu, echo=not args.no_echo, verbose=args.verbose)
    except KeyboardInterrupt:
        print("\n[sim] stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
