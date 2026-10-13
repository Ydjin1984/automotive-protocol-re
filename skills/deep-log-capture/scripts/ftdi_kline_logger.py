#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ftdi_kline_logger.py — глубокий логгер обмена с ЭБУ через FTDI (D2XX/VCP) или TCP.

Возможности:
  * транспорты: D2XX (ctypes → FTD2XX.DLL, без pip-зависимостей), VCP (pyserial), TCP (симулятор);
  * настройка линии: скорость/чётность/стоп-биты/латенси/таймауты (D2XX);
  * эхо-обработка K-line: auto|on|off (счётное эхо, авто-детект адаптера без эха);
  * DS2-помощник: сборка кадра [addr][len][payload][xor], probe, лестница скоростей;
  * режимы: --listen, --send, --ds2, --probe-ds2, --replay (золотая трасса);
  * лог по канону (text) + JSONL; шапка с конфигурацией.

Примеры:
  python ftdi_kline_logger.py --tcp 127.0.0.1:5555 --probe-ds2        # против симулятора
  python ftdi_kline_logger.py --serial A1B2C3D4 --baud 9600 --parity even --latency 1 --probe-ds2
  python ftdi_kline_logger.py --port COM6 --listen --out listen.log
  python ftdi_kline_logger.py --serial A1B2C3D4 --ladder 125000,19200,9600 --probe-ds2
  python ftdi_kline_logger.py --serial A1B2C3D4 --replay trace.txt --from 1 --to 40 --out replay.log
  python ftdi_kline_logger.py --selftest
"""
from __future__ import annotations

import argparse
import ctypes
import json
import re
import socket
import sys
import time
from typing import List, Optional, Tuple

# ================================================================ утилиты

def hexs(bs: bytes) -> str:
    return " ".join(f"{b:02X}" for b in bs)


def parse_hex(s: str) -> bytes:
    return bytes(int(x, 16) for x in re.findall(r"[0-9A-Fa-f]{2}", s))


def xor_cks(bs: bytes) -> int:
    x = 0
    for b in bs:
        x ^= b
    return x


def ds2_build(addr: int, payload: bytes) -> bytes:
    body = bytes([addr, 3 + len(payload)]) + payload
    return body + bytes([xor_cks(body)])


# ================================================================ транспорты

class Transport:
    name = "?"

    def open(self) -> None: ...
    def close(self) -> None: ...
    def write(self, data: bytes) -> int: ...
    def read(self, n: int, timeout_ms: int) -> bytes: ...
    def drain(self) -> bytes: ...


class FakeTransport(Transport):
    """Для --selftest: отдаёт заранее заготовленные чанки, пишет в лог."""
    name = "fake"

    def __init__(self, chunks: List[bytes]):
        self.chunks = list(chunks)
        self.written: List[bytes] = []

    def open(self) -> None: pass
    def close(self) -> None: pass

    def write(self, data: bytes) -> int:
        self.written.append(bytes(data))
        return len(data)

    def read(self, n: int, timeout_ms: int) -> bytes:
        if not self.chunks:
            return b""
        if self.chunks[0] is None:      # None = «пустое окно» (симуляция таймаута)
            self.chunks.pop(0)
            return b""
        if len(self.chunks[0]) <= n:
            return self.chunks.pop(0)
        out, self.chunks[0] = self.chunks[0][:n], self.chunks[0][n:]
        return out

    def drain(self) -> bytes:
        out = b"".join(self.chunks)
        self.chunks.clear()
        return out


class TcpTransport(Transport):
    def __init__(self, host: str, port: int):
        self.name = f"tcp://{host}:{port}"
        self.host, self.port = host, port
        self.sock: Optional[socket.socket] = None

    def open(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=5.0)

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def write(self, data: bytes) -> int:
        assert self.sock
        self.sock.sendall(data)
        return len(data)

    def read(self, n: int, timeout_ms: int) -> bytes:
        assert self.sock
        self.sock.settimeout(max(0.001, timeout_ms / 1000.0))
        try:
            return self.sock.recv(n)
        except socket.timeout:
            return b""

    def drain(self) -> bytes:
        self.sock.settimeout(0.05)
        out = bytearray()
        try:
            while True:
                c = self.sock.recv(4096)
                if not c:
                    break
                out.extend(c)
        except socket.timeout:
            pass
        return bytes(out)


class D2xxTransport(Transport):
    """Прямая работа с FTD2XX.DLL через ctypes (без pip-зависимостей)."""

    FT_OK = 0
    FT_OPEN_BY_SERIAL_NUMBER = 1
    FT_OPEN_BY_DESCRIPTION = 2
    FT_PURGE_RX = 1
    FT_PURGE_TX = 2
    PARITY = {"none": 0, "odd": 1, "even": 2, "mark": 3, "space": 4}

    def __init__(self, serial: Optional[str], index: int, baud: int, data_bits: int,
                 stop_bits: int, parity: str, latency_ms: int, timeout_ms: int):
        self.name = f"d2xx sn={serial or index} @{baud} 8{parity[0].upper()}{stop_bits}"
        self.serial, self.index = serial, index
        self.baud, self.data_bits, self.stop_bits = baud, data_bits, stop_bits
        self.parity, self.latency_ms, self.timeout_ms = parity, latency_ms, timeout_ms
        self._h: Optional[ctypes.c_void_p] = None
        self._dll = None
        self._dll_path = None

    def _load(self):
        if self._dll is not None:
            return self._dll
        last = None
        for path in ("ftd2xx.dll", "FTD2XX.dll"):
            try:
                self._dll = ctypes.WinDLL(path)
                self._dll_path = path
                return self._dll
            except OSError as e:      # не Windows или DLL не найдена
                last = e
        raise RuntimeError(f"FTD2XX.DLL не найдена ({last}). Установи драйвер D2XX или используй --port/--tcp.")

    def _check(self, rc: int, what: str) -> None:
        if rc != self.FT_OK:
            raise RuntimeError(f"{what} → FT_STATUS={rc}")

    def open(self) -> None:
        dll = self._load()
        h = ctypes.c_void_p()
        if self.serial:
            rc = dll.FT_OpenEx(ctypes.c_char_p(self.serial.encode()),
                               ctypes.c_uint32(self.FT_OPEN_BY_SERIAL_NUMBER), ctypes.byref(h))
        else:
            rc = dll.FT_Open(ctypes.c_int(self.index), ctypes.byref(h))
        self._check(rc, "FT_Open")
        self._h = h
        dll.FT_ResetDevice(h)
        dll.FT_SetTimeouts(h, ctypes.c_uint32(50), ctypes.c_uint32(self.timeout_ms))
        dll.FT_SetLatencyTimer(h, ctypes.c_ubyte(self.latency_ms))
        self._check(dll.FT_SetBaudRate(h, ctypes.c_uint32(self.baud)), f"FT_SetBaudRate({self.baud})")
        # stop bits: 0 = 1 stop, 2 = 2 stops
        sb = 0 if self.stop_bits == 1 else 2
        self._check(dll.FT_SetDataCharacteristics(h, ctypes.c_ubyte(self.data_bits),
                                                  ctypes.c_ubyte(sb),
                                                  ctypes.c_ubyte(self.PARITY[self.parity])),
                    "FT_SetDataCharacteristics")
        dll.FT_SetFlowControl(h, ctypes.c_ushort(0), ctypes.c_ubyte(0), ctypes.c_ubyte(0))
        dll.FT_Purge(h, ctypes.c_uint32(self.FT_PURGE_RX | self.FT_PURGE_TX))

    def close(self) -> None:
        if self._h and self._dll:
            self._dll.FT_Close(self._h)
            self._h = None

    def write(self, data: bytes) -> int:
        dll = self._load()
        assert self._h is not None
        buf = ctypes.create_string_buffer(data, len(data))
        written = ctypes.c_uint32(0)
        self._check(dll.FT_Write(self._h, buf, ctypes.c_uint32(len(data)), ctypes.byref(written)), "FT_Write")
        return int(written.value)

    def read(self, n: int, timeout_ms: int) -> bytes:
        dll = self._load()
        assert self._h is not None
        end = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < end:
            avail = ctypes.c_uint32(0)
            dll.FT_GetQueueStatus(self._h, ctypes.byref(avail))
            if avail.value:
                want = min(int(avail.value), n)
                buf = ctypes.create_string_buffer(want)
                got = ctypes.c_uint32(0)
                rc = dll.FT_Read(self._h, buf, ctypes.c_uint32(want), ctypes.byref(got))
                if rc == self.FT_OK and got.value:
                    return buf.raw[:got.value]
            time.sleep(0.001)
        return b""

    def drain(self) -> bytes:
        dll = self._load()
        assert self._h is not None
        out = bytearray()
        avail = ctypes.c_uint32(0)
        dll.FT_GetQueueStatus(self._h, ctypes.byref(avail))
        if avail.value:
            buf = ctypes.create_string_buffer(int(avail.value))
            got = ctypes.c_uint32(0)
            dll.FT_Read(self._h, buf, ctypes.c_uint32(avail.value), ctypes.byref(got))
            out.extend(buf.raw[:got.value])
        return bytes(out)

    @staticmethod
    def list_devices() -> List[str]:
        try:
            dll = ctypes.WinDLL("ftd2xx.dll")
        except OSError:
            return []
        num = ctypes.c_uint32(0)
        if dll.FT_CreateDeviceInfoList(ctypes.byref(num)) != 0:
            return []
        out = []
        for i in range(num.value):
            flags = ctypes.c_uint32(0); typ = ctypes.c_uint32(0); did = ctypes.c_uint32(0)
            locid = ctypes.c_uint32(0); handle = ctypes.c_void_p()
            sn = ctypes.create_string_buffer(16); desc = ctypes.create_string_buffer(64)
            rc = dll.FT_GetDeviceInfoDetail(ctypes.c_uint32(i), ctypes.byref(flags), ctypes.byref(typ),
                                            ctypes.byref(did), ctypes.byref(locid), sn, desc,
                                            ctypes.byref(handle))
            if rc == 0:
                out.append(f"[{i}] sn={sn.value.decode(errors='replace')} desc={desc.value.decode(errors='replace')} opened={bool(flags.value & 1)}")
        return out


class SerialTransport(Transport):
    """VCP через pyserial (быстрый зацеп; latency по умолчанию 16 мс)."""

    def __init__(self, port: str, baud: int, parity: str, data_bits: int, stop_bits: int):
        self.name = f"vcp {port} @{baud}"
        self.port, self.baud = port, baud
        self.parity, self.data_bits, self.stop_bits = parity, data_bits, stop_bits
        self.ser = None

    def open(self) -> None:
        import serial  # pip install pyserial
        pmap = {"none": serial.PARITY_NONE, "even": serial.PARITY_EVEN, "odd": serial.PARITY_ODD}
        self.ser = serial.Serial(self.port, self.baud, bytesize=self.data_bits,
                                 parity=pmap[self.parity],
                                 stopbits=1 if self.stop_bits == 1 else serial.STOPBITS_TWO,
                                 timeout=0.05)
        self.ser.reset_input_buffer()

    def close(self) -> None:
        if self.ser:
            self.ser.close()

    def write(self, data: bytes) -> int:
        self.ser.write(data)
        self.ser.flush()
        return len(data)

    def read(self, n: int, timeout_ms: int) -> bytes:
        self.ser.timeout = max(0.001, timeout_ms / 1000.0)
        return self.ser.read(n)

    def drain(self) -> bytes:
        self.ser.timeout = 0.05
        return self.ser.read(4096) or b""


# ================================================================ DS2-сессия

class Session:
    """Чтение/запись кадров с эхо-обработкой и каноническим логом."""

    def __init__(self, tr: Transport, opts, logf, jsonf):
        self.tr = tr
        self.opts = opts
        self.logf = logf
        self.jsonf = jsonf
        self.t0 = time.monotonic()
        self.tx_count = self.rx_count = self.echo_count = self.err_count = 0
        self._pending = bytearray()
        self.adapter_has_echo: Optional[bool] = None

    # ---- лог

    def _log(self, dir_: str, data: bytes, note: str = "") -> None:
        t = time.monotonic() - self.t0
        line = f"[+{t:.3f}s] {dir_:<4} {hexs(data)}"
        if note:
            line += f"   ; {note}"
        print(line)
        if self.logf:
            self.logf.write(line + "\n")
            self.logf.flush()
        if self.jsonf:
            self.jsonf.write(json.dumps({"kind": "data", "t": round(t, 3), "dir": dir_.lower(),
                                         "bytes": hexs(data), "note": note}, ensure_ascii=False) + "\n")
            self.jsonf.flush()

    def _logerr(self, text: str) -> None:
        self.err_count += 1
        t = time.monotonic() - self.t0
        line = f"[+{t:.3f}s] !! {text}"
        print(line)
        if self.logf:
            self.logf.write(line + "\n")

    # ---- низкий уровень

    def _read_raw(self, n: int, timeout_ms: int) -> bytes:
        if self._pending:
            out = bytes(self._pending[:n])
            del self._pending[:len(out)]
            if len(out) == n:
                return out
            n -= len(out)
            more = self.tr.read(n, timeout_ms)
            return out + more
        return self.tr.read(n, timeout_ms)

    def _read_exact(self, n: int, timeout_ms: int) -> bytes:
        buf = bytearray()
        end = time.monotonic() + timeout_ms / 1000.0
        while len(buf) < n:
            left_ms = int((end - time.monotonic()) * 1000)
            if left_ms <= 0:
                break
            chunk = self._read_raw(n - len(buf), left_ms)
            if chunk:
                buf.extend(chunk)
            else:
                time.sleep(0.001)
        return bytes(buf)

    # ---- эхо

    def _discard_echo(self, tx: bytes) -> None:
        """Счётное эхо-подавление: читаем до len(tx) байт и сравниваем с отправленным.

        - первый read пуст → адаптер без эха (запоминаем, дальше не ищем эхо);
        - полное совпадение → эхо отброшено; «хвост» сверх tx → уже ответ;
        - расхождение на байте m → эхо-префикс отброшен, всё с m — ответ;
        - совпал префикс, но короче tx → считаем частичным эхо (адаптер с медленным loopback).
        """
        if self.opts.echo == "off":
            return
        if self.adapter_has_echo is False:
            return
        chunk = self.tr.read(len(tx), self.opts.echo_timeout_ms)
        if not chunk:
            self.adapter_has_echo = False
            self._log("..", b"", "нет эха (адаптер без loopback; при потере ответов — --echo off)")
            return
        got = bytearray(chunk)
        while len(got) < len(tx):
            more = self.tr.read(len(tx) - len(got), 40)
            if not more:
                break
            got.extend(more)
        self.adapter_has_echo = True
        m = 0
        while m < min(len(got), len(tx)) and got[m] == tx[m]:
            m += 1
        if m == len(tx):
            self.echo_count += 1
            self._log("..", bytes(got[:m]), f"эхо отброшено ({m} Б)")
            if len(got) > m:
                self._pending.extend(got[m:])
        elif m == len(got):
            self._log("..", bytes(got), f"частичное эхо {m}/{len(tx)} Б")
        else:
            self._logerr(f"эхо/ответ: совпало {m} Б, расхождение — остаток в буфер ответа")
            self._pending.extend(got[m:])

    # ---- операции

    def send_frame(self, frame: bytes, wait_response: bool = True,
                   timeout_ms: Optional[int] = None) -> bytes:
        self._log("TX", frame)
        self.tr.write(frame)
        self.tx_count += 1
        self._discard_echo(frame)
        if not wait_response:
            return b""
        tmo = timeout_ms or self.opts.timeout_ms
        hdr = self._read_exact(2, tmo)
        if len(hdr) < 2:
            self._logerr(f"нет ответа за {tmo} мс")
            return b""
        if hdr[0] != self.opts.addr:
            self._logerr(f"ответ не от 0x{self.opts.addr:02X} (первый байт 0x{hdr[0]:02X})")
            return hdr
        ln = hdr[1]
        if not (4 <= ln <= 250):
            self._logerr(f"подозрительная длина кадра: {ln}")
            return hdr
        rest = self._read_exact(ln - 2, tmo)
        frame_rx = hdr + rest
        if len(frame_rx) < ln:
            self._logerr(f"недочитан кадр ({len(frame_rx)}/{ln})")
            return frame_rx
        self.rx_count += 1
        cks_ok = xor_cks(frame_rx[:-1]) == frame_rx[-1]
        note = "" if cks_ok else "CKS MISMATCH"
        self._log("RX", frame_rx, note)
        return frame_rx

    def send_payload(self, payload: bytes, **kw) -> bytes:
        return self.send_frame(ds2_build(self.opts.addr, payload), **kw)


# ================================================================ режимы

def probe_ds2(sess: Session, baud_note: str = "") -> Tuple[bytes, str]:
    resp = sess.send_payload(bytes([0x00]))
    verdict = "нет ответа"
    if len(resp) >= 3:
        if resp[2] == 0xA0:
            ident = resp[3:-1]
            verdict = f"A0 OK, ID={ident.decode('ascii', 'replace')}"
        else:
            verdict = f"статус 0x{resp[2]:02X}"
    print(f"# probe-ds2 {baud_note}: {verdict}")
    return resp, verdict


def run_ladder(sess: Session, ladder: List[int]) -> bool:
    for baud in ladder:
        tr = sess.tr
        sess.opts.baud = baud
        if hasattr(tr, "baud"):
            tr.baud = baud
        try:
            tr.close()
        except Exception:
            pass
        try:
            tr.open()
        except Exception as e:
            print(f"# {baud}: открыть не удалось: {e}")
            continue
        resp, verdict = probe_ds2(sess, f"@{baud}")
        if len(resp) >= 3 and resp[2] == 0xA0:
            print(f"# успех на {baud} бод")
            return True
    print("# ни одна скорость не дала A0 — проверь провод K-line, питание и эхо адаптера")
    return False


RE_TX_LINE = re.compile(r"TX[:\s]+\s*([0-9A-Fa-f]{2}(?:[ \t]+[0-9A-Fa-f]{2})+)")


def parse_trace_tx(path: str) -> List[bytes]:
    out: List[bytes] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "echo" in line.lower():
                continue
            m = RE_TX_LINE.search(line)
            if m:
                out.append(parse_hex(m.group(1)))
    return out


def run_replay(sess: Session, frames: List[bytes]) -> None:
    n = 0
    for i, fr in enumerate(frames, 1):
        if fr[0] != sess.opts.addr:
            continue
        n += 1
        print(f"# replay #{i} ({n}/{len(frames)})")
        sess.send_frame(fr)


# ================================================================ selftest

def selftest() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    # 1. сборка кадра DS2
    check("ds2_build: 12 04 00 16", ds2_build(0x12, bytes([0x00])) == bytes([0x12, 0x04, 0x00, 0x16]))
    check("ds2_build: 12 05 0B 03 1F",
          ds2_build(0x12, bytes([0x0B, 0x03])) == bytes([0x12, 0x05, 0x0B, 0x03, 0x1F]))

    class O:
        echo = "auto"; echo_timeout_ms = 60; timeout_ms = 300; addr = 0x12

    def mk_session(chunks, echo=None):
        o = O()
        if echo is not None:
            o.echo = echo
        return Session(FakeTransport(chunks), o, None, None)

    # 2. эхо полное, затем ответ
    s = mk_session([bytes([0x12, 0x04, 0x00, 0x16]), bytes([0x12, 0x04, 0xA0, 0xB6])])
    r = s.send_frame(bytes([0x12, 0x04, 0x00, 0x16]))
    check("echo full: ответ получен", r == bytes([0x12, 0x04, 0xA0, 0xB6]))
    check("echo full: эхо распознано", s.echo_count == 1 and s.adapter_has_echo is True)

    # 3. адаптер без эха: окно эха пустое (None), затем приходит ответ
    s = mk_session([None, bytes([0x12, 0x04, 0xA0, 0xB6])])
    r = s.send_frame(bytes([0x12, 0x04, 0x00, 0x16]))
    check("no echo: ответ не потерян", r == bytes([0x12, 0x04, 0xA0, 0xB6]))
    check("no echo: адаптер помечен", s.adapter_has_echo is False)

    # 3b. --echo off: ответ читается как есть (для адаптеров без loopback)
    s = mk_session([bytes([0x12, 0x04, 0xA0, 0xB6])], echo="off")
    r = s.send_frame(bytes([0x12, 0x04, 0x00, 0x16]))
    check("echo off: ответ не потерян", r == bytes([0x12, 0x04, 0xA0, 0xB6]))

    # 4. эхо + ответ склеены в один чанк (типичный аккумулированный кадр)
    s = mk_session([bytes([0x12, 0x04, 0x00, 0x16, 0x12, 0x04, 0xA0, 0xB6])])
    r = s.send_frame(bytes([0x12, 0x04, 0x00, 0x16]))
    check("echo+resp слитно: ответ извлечён", r == bytes([0x12, 0x04, 0xA0, 0xB6]))

    # 5. длинный ответ (45 Б) в нескольких чанках, echo off
    long_payload = bytes([0xA0]) + bytes(range(40))
    frame = ds2_build(0x12, long_payload)
    s = mk_session([frame[:3], frame[3:7], frame[7:]], echo="off")
    r = s.send_frame(bytes([0x12, 0x04, 0x00, 0x16]))
    check("чанки: длинный кадр собран целиком", r == frame)

    # 6. реплей-парсер трассы
    import tempfile, os
    sample = ("[07:56:01.909] TX 12 04 0D 1B\n"
              "[07:56:01.909] RX 12 04 0D 1B   <= echo of TX\n"
              "[07:56:02.048] RX 12 4C A0 31 39\n"
              "TX: 12 04 00 16\n")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(sample)
        p = f.name
    try:
        frames = parse_trace_tx(p)
        check("replay: 2 TX-кадра (эхо пропущено)", len(frames) == 2)
        check("replay: кадры верные",
              frames[0] == bytes([0x12, 0x04, 0x0D, 0x1B]) and frames[1] == bytes([0x12, 0x04, 0x00, 0x16]))
    finally:
        os.unlink(p)

    # 7. частичное эхо: первые 2 байта совпали, дальше — ответ
    s = mk_session([bytes([0x12, 0x04, 0xAA, 0xBB])])
    r = s.send_frame(bytes([0x12, 0x04, 0x00, 0x16]), wait_response=False)
    check("частичное эхо: остаток в буфере, ошибка залогирована", s.err_count >= 1)

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


# ================================================================ main

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Глубокий логгер обмена с ЭБУ (FTDI D2XX/VCP/TCP)")
    ap.add_argument("--serial", help="серийник FTDI (D2XX)")
    ap.add_argument("--dev", type=int, default=0, help="индекс FTDI (D2XX), если нет --serial")
    ap.add_argument("--port", help="COM-порт (VCP, pyserial)")
    ap.add_argument("--tcp", help="HOST:PORT (например, симулятор ЭБУ)")
    ap.add_argument("--list-devices", action="store_true", help="показать FTDI-устройства (D2XX)")
    ap.add_argument("--addr", default="0x12", help="адрес ЭБУ (hex)")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--data", type=int, default=8)
    ap.add_argument("--parity", default="even", choices=["none", "even", "odd"])
    ap.add_argument("--stop", type=int, default=1, choices=[1, 2])
    ap.add_argument("--latency", type=int, default=1, help="latency timer D2XX, мс (1 = для логов)")
    ap.add_argument("--timeout", type=int, default=1200, help="таймаут ответа, мс")
    ap.add_argument("--echo", default="auto", choices=["auto", "on", "off"])
    ap.add_argument("--echo-timeout", type=int, default=300, dest="echo_timeout_ms")
    ap.add_argument("--listen", action="store_true", help="пассивно слушать линию и логировать")
    ap.add_argument("--send", action="append", default=[], help="отправить кадр целиком (hex), можно повторять")
    ap.add_argument("--ds2", action="append", default=[], help="отправить DS2 payload (hex) с --addr")
    ap.add_argument("--probe-ds2", action="store_true", help="послать 12 04 00 16 (ident)")
    ap.add_argument("--ladder", help="лестница скоростей для probe, например 125000,19200,9600")
    ap.add_argument("--replay", help="файл с TX-строками (золотая трасса)")
    ap.add_argument("--from", dest="fr", type=int, default=1)
    ap.add_argument("--to", dest="to", type=int, default=0)
    ap.add_argument("--out", help="файл текстового лога")
    ap.add_argument("--jsonl", help="файл JSONL-лога")
    ap.add_argument("--seconds", type=float, default=0, help="для --listen: длительность, с (0 = до Ctrl+C)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.list_devices:
        devs = D2xxTransport.list_devices()
        print("\n".join(devs) if devs else "D2XX: устройств не найдено (или нет FTD2XX.DLL)")
        return 0

    if not (args.tcp or args.serial or args.port or args.selftest):
        args.selftest = True   # без железа и без режима — просто показать самопроверку

    opts = argparse.Namespace(addr=int(args.addr, 16), timeout_ms=args.timeout,
                              echo=args.echo, echo_timeout_ms=args.echo_timeout_ms, baud=args.baud)

    if args.selftest and not (args.tcp or args.serial or args.port):
        return selftest()

    # транспорт
    if args.tcp:
        host, _, port = args.tcp.partition(":")
        tr: Transport = TcpTransport(host or "127.0.0.1", int(port or 5555))
    elif args.serial or args.dev is not None and not args.port:
        tr = D2xxTransport(args.serial, args.dev, args.baud, args.data, args.stop,
                           args.parity, args.latency, args.timeout)
    else:
        tr = SerialTransport(args.port, args.baud, args.parity, args.data, args.stop)

    logf = open(args.out, "w", encoding="utf-8") if args.out else None
    jsonf = open(args.jsonl, "w", encoding="utf-8") if args.jsonl else None

    def header():
        from datetime import datetime
        h = ["# automotive-protocol-re log v1",
             f"# time={datetime.now().isoformat(timespec='seconds')}",
             f"# transport={tr.name}",
             f"# line={args.baud} {args.data}{args.parity[0].upper()}{args.stop} latency_ms={args.latency}",
             f"# ds2_addr=0x{opts.addr:02X} echo={args.echo}",
             f"# tool=ftdi_kline_logger.py"]
        for line in h:
            print(line)
            if logf:
                logf.write(line + "\n")
        if jsonf:
            jsonf.write(json.dumps({"kind": "meta", "transport": tr.name, "baud": args.baud,
                                    "parity": args.parity, "data_bits": args.data, "stop_bits": args.stop,
                                    "latency_ms": args.latency, "addr": opts.addr,
                                    "echo": args.echo}, ensure_ascii=False) + "\n")

    try:
        tr.open()
    except Exception as e:
        print(f"# ОШИБКА открытия транспорта: {e}", file=sys.stderr)
        return 2

    sess = Session(tr, opts, logf, jsonf)
    header()

    try:
        if args.listen:
            print("# listen…")
            end = time.monotonic() + args.seconds if args.seconds else None
            while end is None or time.monotonic() < end:
                chunk = tr.read(4096, 200)
                if chunk:
                    sess._log("RX", chunk)
            return 0

        if args.ladder:
            ok = run_ladder(sess, [int(x) for x in args.ladder.split(",")])
            return 0 if ok else 3

        if args.replay:
            frames = parse_trace_tx(args.replay)
            sel = frames[args.fr - 1: (args.to or len(frames))]
            print(f"# replay: {len(sel)} из {len(frames)} кадров")
            run_replay(sess, sel)
            return 0

        if args.probe_ds2:
            resp, _ = probe_ds2(sess)
            return 0 if (len(resp) >= 3 and resp[2] == 0xA0) else 3

        for fr in args.send:
            sess.send_frame(parse_hex(fr))

        for pl in args.ds2:
            sess.send_payload(parse_hex(pl))

        if not (args.send or args.ds2):
            print("# нет режима: укажи --listen / --probe-ds2 / --send / --ds2 / --replay")
        return 0
    finally:
        t = time.monotonic() - sess.t0
        summary = (f"# session end: tx={sess.tx_count} rx={sess.rx_count} echo={sess.echo_count} "
                   f"errors={sess.err_count} duration={t:.3f}s")
        print(summary)
        if logf:
            logf.write(summary + "\n")
            logf.close()
        if jsonf:
            jsonf.write(json.dumps({"kind": "meta_end", "tx": sess.tx_count, "rx": sess.rx_count,
                                    "echo": sess.echo_count, "errors": sess.err_count,
                                    "duration": round(t, 3)}) + "\n")
            jsonf.close()
        tr.close()


if __name__ == "__main__":
    sys.exit(main())
