"""Single-instance lock and local IPC helper using QLocalServer and Win32 named pipes."""

from __future__ import annotations

import contextlib
import time

import win32file
import win32pipe
from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

SERVER_NAME = "PPV_PerAppVPN_SingleInstance_v1"


class SingleInstanceController(QObject):
    """Ensures only one GUI instance runs and forwards 'SHOW' requests to the active one."""

    show_requested = Signal()

    def __init__(self, server_name: str = SERVER_NAME, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.server_name = server_name
        self._server: QLocalServer | None = None
        self._clients: list[QLocalSocket] = []

    def _pipe_path(self) -> str:
        return rf"\\.\pipe\{self.server_name}"

    def _send_command(self, cmd: bytes, timeout_ms: int = 800) -> bool:
        pipe_path = self._pipe_path()
        with contextlib.suppress(Exception):
            win32pipe.WaitNamedPipe(pipe_path, timeout_ms)
        try:
            handle = win32file.CreateFile(
                pipe_path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )
        except Exception:
            return False

        try:
            win32file.WriteFile(handle, cmd)
            win32file.ReadFile(handle, 64)
            return True
        except Exception:
            return False
        finally:
            with contextlib.suppress(Exception):
                win32file.CloseHandle(handle)

    def try_notify_existing(self, timeout_ms: int = 800) -> bool:
        """Return True if an existing instance accepted a SHOW message."""
        return self._send_command(b"SHOW\n", timeout_ms=timeout_ms)

    def start_listening(self, wait_for_release_sec: float = 0.0) -> bool:
        """Start listening as the primary instance. Returns False if another instance owns the lock."""
        deadline = time.monotonic() + max(0.0, wait_for_release_sec)
        while True:
            if self._try_listen_once():
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.15)

    def _try_listen_once(self) -> bool:
        if self._send_command(b"PING\n", timeout_ms=300):
            return False

        QLocalServer.removeServer(self.server_name)
        server = QLocalServer(self)
        server.setSocketOptions(QLocalServer.SocketOption.WorldAccessOption)
        if not server.listen(self.server_name):
            return False
        server.newConnection.connect(self._handle_new_connection)
        self._server = server
        return True

    def _handle_new_connection(self) -> None:
        if self._server is None:
            return
        while self._server.hasPendingConnections():
            conn = self._server.nextPendingConnection()
            if conn is None:
                continue
            self._clients.append(conn)
            conn.readyRead.connect(lambda c=conn: self._read_client(c))
            conn.disconnected.connect(lambda c=conn: self._on_disconnected(c))
            if conn.bytesAvailable() > 0:
                self._read_client(conn)

    def _on_disconnected(self, conn: QLocalSocket) -> None:
        with contextlib.suppress(RuntimeError):
            if conn.bytesAvailable() > 0:
                self._read_client(conn)
            conn.deleteLater()
        if conn in self._clients:
            self._clients.remove(conn)

    def _read_client(self, conn: QLocalSocket) -> None:
        data = bytes(conn.readAll()).decode("utf-8", errors="ignore").strip()
        if not data:
            return
        if "SHOW" in data:
            self.show_requested.emit()
        if conn.state() == QLocalSocket.LocalSocketState.ConnectedState:
            conn.write(b"OK\n")
            conn.flush()

    def close(self) -> None:
        clients = list(self._clients)
        self._clients.clear()
        for conn in clients:
            with contextlib.suppress(Exception):
                conn.disconnect()
                conn.close()
                conn.deleteLater()
        if self._server is not None:
            with contextlib.suppress(Exception):
                self._server.close()
                self._server.deleteLater()
            self._server = None
            with contextlib.suppress(Exception):
                QLocalServer.removeServer(self.server_name)
