#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""frida-launch.py — запуск frida-serial-hook.js (spawn или attach) с записью в файл.

Требуется пакет frida:  pip install frida frida-tools

Примеры:
  python frida-launch.py --spawn "C:\\path\\BMS46 Quickflash.exe" --out capture-live.log
  python frida-launch.py --attach 16812 --out capture-live.log
  python frida-launch.py --selftest
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime
from typing import Optional


def run(mode: str, target: str, script_path: str, out_path: str, resume: bool = True) -> int:
    try:
        import frida  # type: ignore
    except ImportError:
        print("нужен пакет frida:  pip install frida frida-tools", file=sys.stderr)
        return 2

    with open(script_path, encoding="utf-8") as f:
        source = f.read()

    device = frida.get_local_device()
    session = None
    pid = None
    try:
        if mode == "spawn":
            pid = device.spawn([target])
            session = device.attach(pid)
            script = session.create_script(source)
        else:
            pid = int(target)
            session = device.attach(pid)
            script = session.create_script(source)
    except Exception as e:
        print(f"не удалось подключиться: {e}", file=sys.stderr)
        return 3

    logf = open(out_path, "a", encoding="utf-8")
    logf.write("==== frida-serial-hook ====\n")
    logf.write(f"# capture start {datetime.now().isoformat(timespec='seconds')} pid={pid}\n")
    logf.flush()

    def on_message(message, data):
        if message.get("type") == "send":
            logf.write(str(message.get("payload")) + "\n")
            logf.flush()
        elif message.get("type") == "error":
            logf.write("[script-error] " + str(message.get("description")) + "\n")
            logf.flush()

    script.on("message", on_message)
    script.load()
    print(f"# hook активен (pid={pid}), лог: {out_path}")

    if mode == "spawn" and resume:
        device.resume(pid)
        print("# процесс запущен")

    try:
        while True:
            time.sleep(1.0)
            if session and not session.is_detached:
                continue
            print("# сессия завершена")
            break
    except KeyboardInterrupt:
        print("\n# stop по Ctrl+C")
    finally:
        logf.write(f"# capture end {datetime.now().isoformat(timespec='seconds')}\n")
        logf.close()
        if session:
            try:
                session.detach()
            except Exception:
                pass
    return 0


def selftest() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    here = os.path.dirname(os.path.abspath(__file__))
    js = os.path.join(here, "frida-serial-hook.js")
    check("скрипт frida-serial-hook.js рядом", os.path.exists(js))
    if os.path.exists(js):
        src = open(js, encoding="utf-8").read()
        check("есть хуки COM (CreateFileW/ReadFile/WriteFile)", all(k in src for k in ("CreateFileW", "ReadFile", "WriteFile")))
        check("есть хуки ftd2xx (FT_Write/FT_Read)", "FT_Write" in src and "FT_Read" in src)
        check("совместимость с Frida 17 (getGlobalExportByName)", "getGlobalExportByName" in src)
    try:
        import frida  # noqa: F401
        check("пакет frida установлен", True)
    except ImportError:
        print("SKIP  пакет frida не установлен (это ок для офлайн-проверки)")
    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main(argv: Optional[list] = None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="Запуск Frida-хука обмена с COM/ftd2xx")
    ap.add_argument("--spawn", help="EXE для запуска")
    ap.add_argument("--attach", help="PID уже запущенного процесса")
    ap.add_argument("--script", default=os.path.join(here, "frida-serial-hook.js"))
    ap.add_argument("--out", default="capture-live.log")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.spawn:
        return run("spawn", args.spawn, args.script, args.out, resume=not args.no_resume)
    if args.attach:
        return run("attach", args.attach, args.script, args.out)
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
