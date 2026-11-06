"""Run wheel_sim.py as the hub's CDC engine over a localhost TCP socket.

wheel_sim opens its port with pyserial's serial_for_url, so the bridge passes
`socket://127.0.0.1:<port>` and accepts the connection here — no tty, works on
Windows. One engine process per USB attach: attaching the hub == plugging it
in (fresh session/handshake state), detaching kills it. Host->engine bytes that
arrive before the engine has connected are buffered.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

log = logging.getLogger('uhub.engine')

SIM_DIR = Path(__file__).resolve().parent.parent
HOST_BUFFER_CAP = 256 * 1024


class EngineLink:
    def __init__(self, model: str, on_data: Callable[[bytes], None],
                 log_path: Optional[Path] = None, extra_args: tuple = ()):
        self.model = model
        self._on_data = on_data
        self._log_path = log_path
        self._extra_args = tuple(extra_args)
        self._server: Optional[asyncio.base_events.Server] = None
        self._port = 0
        self._proc: Optional[subprocess.Popen] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._pending = bytearray()
        self._generation = 0
        self._log_fh = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accept, '127.0.0.1', 0)
        self._port = self._server.sockets[0].getsockname()[1]

    async def close(self) -> None:
        self.stop_engine()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    # ── engine process lifecycle ────────────────────────────────────────
    def start_engine(self) -> None:
        self.stop_engine()
        self._generation += 1
        cmd = [sys.executable, str(SIM_DIR / 'wheel_sim.py'), '--model', self.model,
               '--console', *self._extra_args, f'socket://127.0.0.1:{self._port}']
        if self._log_path is not None:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_fh = open(self._log_path, 'ab')
            out = self._log_fh
        else:
            out = None
        log.info('starting engine: %s', ' '.join(cmd[1:]))
        # wheel_sim writes non-ASCII (→, box drawing) to logs opened without an
        # explicit encoding. On Windows before Python 3.15 that defaults to
        # cp1252 and the first '→' raises UnicodeEncodeError in the read thread,
        # silencing the wheel. UTF-8 mode makes every default open() UTF-8.
        env = dict(os.environ, PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
        self._proc = subprocess.Popen(cmd, cwd=str(SIM_DIR.parent), stdout=out,
                                      stderr=subprocess.STDOUT if out else None,
                                      stdin=subprocess.DEVNULL, env=env)

    def stop_engine(self) -> None:
        self._generation += 1
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._log_fh is not None:
            self._log_fh.close()
            self._log_fh = None
        self._pending.clear()

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ── data path ───────────────────────────────────────────────────────
    def write(self, data: bytes) -> None:
        """Host -> engine (CDC bulk OUT)."""
        if self._writer is not None and not self._writer.is_closing():
            self._writer.write(data)
            return
        if self._proc is None:
            return                      # not attached / no engine: drop
        self._pending += data
        if len(self._pending) > HOST_BUFFER_CAP:
            del self._pending[:len(self._pending) - HOST_BUFFER_CAP]

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        gen = self._generation
        if self._proc is None or self._writer is not None:
            writer.close()
            return
        self._writer = writer
        log.info('engine connected')
        if self._pending:
            writer.write(bytes(self._pending))
            self._pending.clear()
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                if gen != self._generation:
                    break
                self._on_data(data)
        except (ConnectionError, OSError):
            pass
        finally:
            if self._writer is writer:
                self._writer = None
            writer.close()
            if gen == self._generation:
                code = self._proc.poll() if self._proc else None
                log.warning('engine disconnected (exit code %s) — see %s', code, self._log_path)
