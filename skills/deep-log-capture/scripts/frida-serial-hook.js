/*
 * frida-serial-hook.js — перехват обмена чужой программы с адаптером.
 *
 * Два слоя:
 *   1) kernel32/kernelbase: CreateFileW / ReadFile / WriteFile / CloseHandle — по COM-хендлам (VCP);
 *   2) ftd2xx.dll (если загружен): FT_Read / FT_Write и настройки чипа.
 *
 * Формат строк (канон плагина, совместим с telegram_parse.py):
 *   [+94.086s] TX ftd2xx FT_Write rc=0 len=4 n=4 : 12 04 00 16
 *   [+70.537s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b
 *
 * Запуск:
 *   frida -f "C:\path\app.exe" -l frida-serial-hook.js -o capture-live.log
 *   python frida-launch.py --attach 12345 --out capture-live.log
 *
 * Замечания:
 *   - реализация CreateFile/ReadFile/WriteFile на Win10/11 живёт в kernelbase.dll,
 *     kernel32 — форвардер, поэтому хукаем оба, если сможем;
 *   - для overlapped I/O буфер чтения валиден только по завершении: логируем в onLeave
 *     и не падаем при недоступности буфера (try/catch, дамп ≤4096 байт);
 *   - Frida 17: Module.getExportByName(name) удалён — используем getExportSafe().
 */
'use strict';

var T0 = Date.now();
function ts() { return '+' + ((Date.now() - T0) / 1000).toFixed(3) + 's'; }
function send2(line) { send(line); }

function hexDump(ptr, len) {
  try {
    var n = Math.min(len, 4096);
    var bytes = new Uint8Array(ptr.readByteArray(n));
    var out = [];
    for (var i = 0; i < bytes.length; i++) out.push(('0' + bytes[i].toString(16)).slice(-2));
    return out.join(' ');
  } catch (e) {
    return '<read-error ' + e + '>';
  }
}

function getExportSafe(modName, fnName) {
  try {
    if (typeof Module.getGlobalExportByName === 'function')
      return Module.getGlobalExportByName(fnName);
  } catch (e) { /* not found */ }
  try {
    var m = Process.getModuleByName(modName);
    return m.getExportByName(fnName);
  } catch (e) { return null; }
}

// ============================================================ слой 1: COM (VCP)

var comHandles = {};

function hookComLayer(modName) {
  var cw = getExportSafe(modName, 'CreateFileW');
  var rf = getExportSafe(modName, 'ReadFile');
  var wf = getExportSafe(modName, 'WriteFile');
  var ch = getExportSafe(modName, 'CloseHandle');

  if (cw) Interceptor.attach(cw, {
    onEnter: function (args) { this.path = args[0].readUtf16String(); },
    onLeave: function (ret) {
      try {
        if (this.path && /com\d+/i.test(this.path) && ret.toInt32() !== -1) {
          comHandles[ret.toString()] = this.path;
          send2('[' + ts() + '] VCP OPEN ' + this.path + ' handle=' + ret);
        }
      } catch (e) {}
    }
  });

  if (rf) Interceptor.attach(rf, {
    onEnter: function (args) {
      this.ok = comHandles.hasOwnProperty(args[0].toString());
      if (!this.ok) return;
      this.buf = args[1];
      this.want = args[2].toInt32();
      this.got = args[3];
      this.port = comHandles[args[0].toString()];
    },
    onLeave: function (ret) {
      if (!this.ok) return;
      try {
        var n = this.got.readU32();
        if (n > 0) send2('[' + ts() + '] VCP RX ReadFile(' + this.port + ') n=' + n + ' : ' + hexDump(this.buf, n));
      } catch (e) {}
    }
  });

  if (wf) Interceptor.attach(wf, {
    onEnter: function (args) {
      this.ok = comHandles.hasOwnProperty(args[0].toString());
      if (!this.ok) return;
      this.n = args[2].toInt32();
      this.port = comHandles[args[0].toString()];
      if (this.n > 0)
        send2('[' + ts() + '] VCP TX WriteFile(' + this.port + ') n=' + this.n + ' : ' + hexDump(args[1], this.n));
    }
  });

  if (ch) Interceptor.attach(ch, {
    onEnter: function (args) {
      var k = args[0].toString();
      if (comHandles.hasOwnProperty(k)) {
        send2('[' + ts() + '] VCP CLOSE ' + comHandles[k]);
        delete comHandles[k];
      }
    }
  });
}

// ============================================================ слой 2: ftd2xx.dll

var WANTED = [
  'FT_Open', 'FT_OpenEx', 'FT_Close', 'FT_Read', 'FT_Write',
  'FT_SetBaudRate', 'FT_SetDataCharacteristics', 'FT_SetTimeouts', 'FT_SetLatencyTimer',
  'FT_SetFlowControl', 'FT_Purge', 'FT_ResetDevice', 'FT_SetBitMode', 'FT_GetQueueStatus',
  'FT_SetUSBParameters', 'FT_SetChars', 'FT_EE_UARead', 'FT_GetLibraryVersion'
];

var ftdiHooked = false;

function hookFtdi() {
  if (ftdiHooked) return;
  var count = 0;

  WANTED.forEach(function (name) {
    var addr = getExportSafe('ftd2xx.dll', name);
    if (!addr) return;
    count++;
    if (name === 'FT_Write') {
      Interceptor.attach(addr, {
        onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); this.pwritten = args[3]; },
        onLeave: function (ret) {
          var n = 0; try { n = this.pwritten.readU32(); } catch (e) {}
          send2('[' + ts() + '] TX ftd2xx FT_Write rc=' + ret.toInt32() + ' len=' + this.len + ' n=' + n + ' : ' + hexDump(this.buf, Math.min(this.len, 4096)));
        }
      });
    } else if (name === 'FT_Read') {
      Interceptor.attach(addr, {
        onEnter: function (args) { this.buf = args[1]; this.want = args[2].toInt32(); this.pgot = args[3]; },
        onLeave: function (ret) {
          var n = 0; try { n = this.pgot.readU32(); } catch (e) {}
          if (n > 0 && ret.toInt32() === 0)
            send2('[' + ts() + '] RX ftd2xx FT_Read rc=0 want=' + this.want + ' n=' + n + ' : ' + hexDump(this.buf, n));
        }
      });
    } else if (name === 'FT_Open' || name === 'FT_OpenEx') {
      Interceptor.attach(addr, {
        onEnter: function (args) { this.a = args[0]; this.b = args[1]; },
        onLeave: function (ret) {
          send2('[' + ts() + '] ftd2xx ' + name + ' rc=' + ret.toInt32());
        }
      });
    } else if (name === 'FT_SetBaudRate') {
      Interceptor.attach(addr, {
        onEnter: function (args) { this.v = args[1].toInt32(); },
        onLeave: function (ret) { send2('[' + ts() + '] ftd2xx FT_SetBaudRate baud=' + this.v + ' rc=' + ret.toInt32()); }
      });
    } else if (name === 'FT_SetDataCharacteristics' || name === 'FT_SetLatencyTimer' || name === 'FT_SetFlowControl') {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.line = name + ' a1=' + args[1].toInt32() + ' a2=' + args[2].toInt32() + ' a3=' + args[3].toInt32();
        },
        onLeave: function (ret) { send2('[' + ts() + '] ftd2xx ' + this.line + ' rc=' + ret.toInt32()); }
      });
    } else if (name === 'FT_EE_UARead') {
      Interceptor.attach(addr, {
        onEnter: function (args) { this.buf = args[1]; this.len = args[2].toInt32(); },
        onLeave: function (ret) {
          if (ret.toInt32() === 0)
            send2('[' + ts() + '] ftd2xx FT_EE_UARead len=' + this.len + ' : ' + hexDump(this.buf, Math.min(this.len, 128)));
        }
      });
    } else {
      Interceptor.attach(addr, { onLeave: function (ret) { send2('[' + ts() + '] ftd2xx ' + name + ' rc=' + ret.toInt32()); } });
    }
  });

  ftdiHooked = true;
  send2('[' + ts() + '] # ftd2xx.dll hooks installed (' + count + ')');
}

// ============================================================ установка

send2('[' + ts() + '] # frida-serial-hook active (pid=' + Process.id + ')');

hookComLayer('kernel32.dll');
hookComLayer('kernelbase.dll');

try {
  // модуль уже загружен?
  Process.getModuleByName('ftd2xx.dll');
  hookFtdi();
} catch (e) {
  if (Process.attachModuleObserver) {
    Process.attachModuleObserver({
      onAdded: function (mod) { if (/^ftd2xx\.dll$/i.test(mod.name)) hookFtdi(); }
    });
  }
  // плюс мягкий polling на случай старых сборок
  var timer = setInterval(function () {
    try { Process.getModuleByName('ftd2xx.dll'); hookFtdi(); clearInterval(timer); } catch (e) {}
  }, 400);
}
