"""Run a syntax validator in an OS sandbox (S8 §5).

See docs/spikes/s8-syntax-validation.md.

This is the only module in ``redteam.validate`` that starts processes.

Every validator process gets:

- a minimal environment (``env -i`` style): ``PATH=/usr/bin:/bin`` plus the
  validator's own directory, ``HOME``/``TMPDIR`` inside a fresh temp dir,
  ``PSModulePath`` pointing at an empty dir, telemetry opt-outs;
- an empty temp dir as cwd; the payload only ever goes through stdin, never
  argv;
- rlimits (CPU, open files, file size, no core dumps; ``RLIMIT_AS`` on Linux)
  and a memory watchdog that polls the process group's RSS;
- a wall-clock timeout, after which the whole process group is killed;
- an OS sandbox: ``sandbox-exec -f parse.sb`` on macOS (no network, writes
  only inside the temp dir, no reads of the user's home, no exec except the
  validator binary, fork only when asked for), ``bwrap --unshare-all`` on
  Linux, or a verified locked-down container (``redteam/validate.Dockerfile``).

If none of those is available the validator is not run at all: callers get a
``Failure('no-sandbox')`` and report ``validator_crash``. Nothing here ever
runs a validator unsandboxed.

Nothing in this module logs or formats process output: a parser's stderr may
quote the payload, so callers only extract positions and fixed IDs from it.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import resource
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

# docs/plan/phase-5.md §5.9.
VALIDATOR_TIMEOUT_MS = 2_000
VALIDATOR_RLIMIT_AS_MB = 512
# macOS ignores RLIMIT_AS, so a watchdog kills the group above this RSS.
VALIDATOR_RSS_LIMIT_MB = 512
# Startup of the long-running pwsh server (cold .NET start is ~0.2-1 s).
SERVER_STARTUP_TIMEOUT_MS = 15_000
# CPU seconds: one-shot validators vs. the long-running server.
VALIDATOR_CPU_SECONDS = 5
SERVER_CPU_SECONDS = 600
VALIDATOR_NOFILE = 256
# Largest file a validator may write inside its temp dir.
VALIDATOR_FSIZE_BYTES = 1 << 20
# stdout/stderr beyond this is a crash (a parser never needs that much).
VALIDATOR_OUTPUT_CAP = 64 * 1024
WATCHDOG_INTERVAL_MS = 20

PROFILE = Path(__file__).with_name('parse.sb')
SANDBOX_EXEC = '/usr/bin/sandbox-exec'
BWRAP_CANDIDATES = ('/usr/bin/bwrap', '/bin/bwrap')
# Set by redteam/validate.Dockerfile; only trusted after _container_ok().
CONTAINER_ENV = 'PASTEWARDEN_SANDBOX'


class Failure(str):
    """Why a validator run did not produce a usable result.

    One of ``no-sandbox``, ``spawn-failed``, ``timeout``, ``output-cap``,
    ``rss-limit``, ``signal``, ``closed``. Never contains process output.
    """


def failure_id(prefix: str, failure: str) -> str:
    """Issue id for a failure: ``no-sandbox`` is global, the rest are
    prefixed with the validator (``zsh.timeout``)."""
    return 'no-sandbox' if failure == 'no-sandbox' else f'{prefix}.{failure}'


@dataclass(frozen=True)
class ExecSpec:
    """A validator binary and its fixed arguments (never the payload)."""

    exe: str
    args: tuple[str, ...] = ()
    allow_fork: bool = False
    # .NET reserves far more address space than it uses, so pwsh opts out of
    # RLIMIT_AS and relies on the RSS watchdog and GCHeapHardLimit instead.
    rlimit_as: bool = True
    env: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RunResult:
    returncode: int | None
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    failure: Failure | None = None
    duration_ms: float = 0.0


# --------------------------------------------------------------------------
# Backend detection


def _container_ok() -> bool:
    """The container flags are verified, not just trusted from the env."""
    if os.environ.get(CONTAINER_ENV) != 'container':
        return False
    if not sys.platform.startswith('linux') or os.geteuid() == 0:
        return False
    try:
        ifaces = set(os.listdir('/sys/class/net'))
    except OSError:
        return False
    if ifaces - {'lo'}:
        return False
    try:
        return bool(os.statvfs('/').f_flag & os.ST_RDONLY)
    except OSError:
        return False


def _bwrap() -> str | None:
    for path in BWRAP_CANDIDATES:
        if os.access(path, os.X_OK):
            return path
    return None


def backend() -> str | None:
    """``sandbox-exec``, ``container``, ``bwrap`` or None (refuse to run)."""
    if sys.platform == 'darwin':
        if os.access(SANDBOX_EXEC, os.X_OK) and PROFILE.is_file():
            return 'sandbox-exec'
        return None
    if sys.platform.startswith('linux'):
        if _container_ok():
            return 'container'
        if _bwrap():
            return 'bwrap'
    return None


def find_executable(*candidates: str) -> str | None:
    """First existing executable among absolute candidates, as a realpath.

    The sandbox allows exec of exactly this path, so symlinks are resolved.
    """
    for cand in candidates:
        if not cand:
            continue
        path = os.path.expanduser(cand)
        if not os.path.isabs(path):
            found = shutil.which(path)
            if not found:
                continue
            path = found
        real = os.path.realpath(path)
        if os.path.isfile(real) and os.access(real, os.X_OK):
            return real
    return None


# --------------------------------------------------------------------------
# Workspace


class Workspace:
    """A fresh temp dir: ``home/``, ``tmp/``, ``empty/``, ``cwd/``."""

    def __init__(self) -> None:
        self.root = Path(
            os.path.realpath(tempfile.mkdtemp(prefix='pw-validate-'))
        )
        for sub in ('home', 'tmp', 'empty', 'cwd'):
            (self.root / sub).mkdir(mode=0o700)

    @property
    def home(self) -> Path:
        return self.root / 'home'

    @property
    def tmp(self) -> Path:
        return self.root / 'tmp'

    @property
    def empty(self) -> Path:
        return self.root / 'empty'

    @property
    def cwd(self) -> Path:
        return self.root / 'cwd'

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self) -> Workspace:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _env(spec: ExecSpec, ws: Workspace) -> dict[str, str]:
    exe_dir = os.path.dirname(spec.exe)
    path = '/usr/bin:/bin'
    if exe_dir not in ('/usr/bin', '/bin'):
        path = f'{exe_dir}:{path}'
    env = {
        'PATH': path,
        'HOME': str(ws.home),
        'TMPDIR': str(ws.tmp),
        'PSModulePath': str(ws.empty),
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'POWERSHELL_TELEMETRY_OPTOUT': '1',
        'POWERSHELL_UPDATECHECK': 'Off',
        'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
        'DOTNET_NOLOGO': '1',
    }
    env.update(dict(spec.env))
    return env


def _argv(spec: ExecSpec, ws: Workspace, kind: str) -> list[str]:
    cmd = [spec.exe, *spec.args]
    if kind == 'sandbox-exec':
        home = os.path.realpath(os.path.expanduser('~'))
        return [
            SANDBOX_EXEC,
            '-f',
            str(PROFILE),
            '-D',
            f'WORK={ws.root}',
            '-D',
            f'USER_HOME={home}',
            '-D',
            f'EXEC={spec.exe}',
            '-D',
            f'EXEC_DIR={os.path.dirname(spec.exe)}',
            '-D',
            f'ALLOW_FORK={1 if spec.allow_fork else 0}',
            *cmd,
        ]
    if kind == 'bwrap':
        bwrap = _bwrap() or BWRAP_CANDIDATES[0]
        exe_dir = os.path.dirname(spec.exe)
        return [
            bwrap,
            '--unshare-all',
            '--die-with-parent',
            '--new-session',
            '--cap-drop',
            'ALL',
            '--ro-bind',
            '/',
            '/',
            '--tmpfs',
            '/home',
            '--tmpfs',
            '/root',
            '--tmpfs',
            '/tmp',  # noqa: S108 - a private tmpfs inside bwrap
            '--proc',
            '/proc',
            '--dev',
            '/dev',
            '--ro-bind',
            exe_dir,
            exe_dir,
            '--bind',
            str(ws.root),
            str(ws.root),
            '--chdir',
            str(ws.cwd),
            *cmd,
        ]
    return cmd


def _limits(spec: ExecSpec, cpu_seconds: int):
    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(
            resource.RLIMIT_NOFILE, (VALIDATOR_NOFILE, VALIDATOR_NOFILE)
        )
        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (VALIDATOR_FSIZE_BYTES, VALIDATOR_FSIZE_BYTES),
        )
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if spec.rlimit_as and sys.platform.startswith('linux'):
            limit = VALIDATOR_RLIMIT_AS_MB << 20
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    return apply


# --------------------------------------------------------------------------
# Memory watchdog


class _RUsageInfoV0(ctypes.Structure):
    _fields_ = [
        ('uuid', ctypes.c_uint8 * 16),
        ('user_time', ctypes.c_uint64),
        ('system_time', ctypes.c_uint64),
        ('pkg_idle_wkups', ctypes.c_uint64),
        ('interrupt_wkups', ctypes.c_uint64),
        ('pageins', ctypes.c_uint64),
        ('wired_size', ctypes.c_uint64),
        ('resident_size', ctypes.c_uint64),
        ('phys_footprint', ctypes.c_uint64),
        ('proc_start_abstime', ctypes.c_uint64),
        ('proc_exit_abstime', ctypes.c_uint64),
    ]


_LIBPROC = None
if sys.platform == 'darwin':
    with contextlib.suppress(OSError):
        _LIBPROC = ctypes.CDLL('/usr/lib/libproc.dylib')


def group_rss_bytes(pgid: int) -> int:
    """Total resident memory of a process group (best effort, 0 if unknown)."""
    if _LIBPROC is not None:
        buf = (ctypes.c_int * 256)()
        n = _LIBPROC.proc_listpgrppids(pgid, buf, ctypes.sizeof(buf))
        total = 0
        for pid in buf[: max(0, min(n, 256))]:
            info = _RUsageInfoV0()
            if _LIBPROC.proc_pid_rusage(pid, 0, ctypes.byref(info)) == 0:
                total += max(info.resident_size, info.phys_footprint)
        return total
    try:
        with open(f'/proc/{pgid}/statm', encoding='ascii') as f:
            return int(f.read().split()[1]) * os.sysconf('SC_PAGE_SIZE')
    except (OSError, ValueError, IndexError):
        return 0


# --------------------------------------------------------------------------
# Process control


def _spawn(
    spec: ExecSpec, ws: Workspace, cpu_seconds: int
) -> subprocess.Popen[bytes] | Failure:
    kind = backend()
    if kind is None:
        return Failure('no-sandbox')
    try:
        return subprocess.Popen(
            _argv(spec, ws, kind),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ws.cwd,
            env=_env(spec, ws),
            close_fds=True,
            start_new_session=True,
            preexec_fn=_limits(spec, cpu_seconds),
        )
    except OSError:
        return Failure('spawn-failed')


def _kill(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(OSError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        proc.kill()
    with contextlib.suppress(Exception):
        proc.wait(timeout=5)
    for f in (proc.stdin, proc.stdout, proc.stderr):
        if f is not None:
            with contextlib.suppress(OSError):
                f.close()


def _rss_over(pgid: int) -> bool:
    return group_rss_bytes(pgid) > VALIDATOR_RSS_LIMIT_MB << 20


def run(
    spec: ExecSpec,
    stdin: bytes,
    *,
    timeout_ms: int = VALIDATOR_TIMEOUT_MS,
    workspace: Workspace | None = None,
) -> RunResult:
    """Run ``spec`` once in the sandbox, feeding ``stdin`` and collecting
    capped output. The process group is killed on timeout, output overflow
    or excessive RSS.
    """
    start = time.monotonic()
    own_ws = workspace is None
    ws = workspace or Workspace()
    try:
        proc = _spawn(spec, ws, VALIDATOR_CPU_SECONDS)
        if isinstance(proc, Failure):
            return RunResult(None, b'', b'', proc)
        result = _pump(proc, stdin, start + timeout_ms / 1000)
        return RunResult(
            result[0],
            result[1],
            result[2],
            result[3],
            (time.monotonic() - start) * 1000,
        )
    finally:
        if own_ws:
            ws.close()


def _pump(
    proc: subprocess.Popen[bytes], data: bytes, deadline: float
) -> tuple[int | None, bytes, bytes, Failure | None]:
    if not (proc.stdin and proc.stdout and proc.stderr):
        _kill(proc)
        return None, b'', b'', Failure('spawn-failed')
    in_fd = proc.stdin.fileno()
    out_fd = proc.stdout.fileno()
    err_fd = proc.stderr.fileno()
    out = {out_fd: bytearray(), err_fd: bytearray()}
    sel = selectors.DefaultSelector()
    view = memoryview(data)
    failure: Failure | None = None
    try:
        for fd in (out_fd, err_fd):
            os.set_blocking(fd, False)
            sel.register(fd, selectors.EVENT_READ)
        os.set_blocking(in_fd, False)
        if view:
            sel.register(in_fd, selectors.EVENT_WRITE)
        else:
            proc.stdin.close()
        last_watch = 0.0
        while sel.get_map():
            now = time.monotonic()
            if now >= deadline:
                failure = Failure('timeout')
                break
            if now - last_watch >= WATCHDOG_INTERVAL_MS / 1000:
                last_watch = now
                if _rss_over(proc.pid):
                    failure = Failure('rss-limit')
                    break
            wait = min(deadline - now, WATCHDOG_INTERVAL_MS / 1000)
            for key, _ in sel.select(wait):
                fd = key.fd
                if fd == in_fd:
                    try:
                        n = os.write(fd, view[:65536])
                    except BlockingIOError:
                        continue
                    except OSError:
                        n = len(view)  # reader went away; stop writing
                    view = view[n:]
                    if not view:
                        sel.unregister(fd)
                        with contextlib.suppress(OSError):
                            proc.stdin.close()
                    continue
                try:
                    chunk = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b''
                if not chunk:
                    sel.unregister(fd)
                    continue
                out[fd] += chunk
                if len(out[fd]) > VALIDATOR_OUTPUT_CAP:
                    failure = Failure('output-cap')
                    break
            if failure:
                break
        if failure is None:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                failure = Failure('timeout')
    finally:
        sel.close()
    # Kill the group either way: it also reaps leftover children.
    _kill(proc)
    if failure is not None:
        return None, b'', b'', failure
    rc = proc.returncode
    if rc is not None and rc < 0:
        return rc, b'', b'', Failure('signal')
    return rc, bytes(out[out_fd]), bytes(out[err_fd]), None


class Server:
    """A long-running sandboxed validator speaking one line per request.

    Used for the pwsh parse server. ``request`` writes one line and waits for
    one response line; any timeout, overflow, crash or RSS excess kills the
    process and returns a :class:`Failure` (callers then restart).
    """

    def __init__(self, spec: ExecSpec, workspace: Workspace) -> None:
        self._spec = spec
        self._ws = workspace
        self._proc: subprocess.Popen[bytes] | None = None
        self._buf = bytearray()

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def start(
        self, timeout_ms: int = SERVER_STARTUP_TIMEOUT_MS
    ) -> bytes | Failure:
        """Spawn the server and return its first (ready) line."""
        self.close()
        proc = _spawn(self._spec, self._ws, SERVER_CPU_SECONDS)
        if isinstance(proc, Failure):
            return proc
        if not (proc.stdout and proc.stderr and proc.stdin):
            _kill(proc)
            return Failure('spawn-failed')
        os.set_blocking(proc.stdout.fileno(), False)
        os.set_blocking(proc.stderr.fileno(), False)
        self._proc = proc
        self._buf = bytearray()
        return self._read_line(time.monotonic() + timeout_ms / 1000)

    def request(
        self, line: bytes, timeout_ms: int = VALIDATOR_TIMEOUT_MS
    ) -> bytes | Failure:
        """Send ``line`` (without newline); return the response or Failure."""
        if not self.alive:
            return Failure('closed')
        if self._proc is None or self._proc.stdin is None:
            return Failure('closed')
        deadline = time.monotonic() + timeout_ms / 1000
        try:
            self._proc.stdin.write(line + b'\n')
            self._proc.stdin.flush()
        except OSError:
            self.close()
            return Failure('closed')
        return self._read_line(deadline)

    def _read_line(self, deadline: float) -> bytes | Failure:
        proc = self._proc
        if proc is None or proc.stdout is None or proc.stderr is None:
            return Failure('closed')
        out_fd = proc.stdout.fileno()
        err_fd = proc.stderr.fileno()
        sel = selectors.DefaultSelector()
        sel.register(out_fd, selectors.EVENT_READ)
        sel.register(err_fd, selectors.EVENT_READ)
        failure: Failure | None = None
        last_watch = 0.0
        try:
            while True:
                nl = self._buf.find(b'\n')
                if nl >= 0:
                    line = bytes(self._buf[:nl])
                    del self._buf[: nl + 1]
                    return line
                if len(self._buf) > VALIDATOR_OUTPUT_CAP:
                    failure = Failure('output-cap')
                    break
                now = time.monotonic()
                if now >= deadline:
                    failure = Failure('timeout')
                    break
                if now - last_watch >= WATCHDOG_INTERVAL_MS / 1000:
                    last_watch = now
                    if _rss_over(proc.pid):
                        failure = Failure('rss-limit')
                        break
                wait = min(deadline - now, WATCHDOG_INTERVAL_MS / 1000)
                for key, _ in sel.select(wait):
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    except OSError:
                        chunk = b''
                    if key.fd == err_fd:
                        # stderr is drained and dropped: it may quote input.
                        if not chunk:
                            sel.unregister(err_fd)
                        continue
                    if not chunk:
                        failure = Failure('closed')
                        break
                    self._buf += chunk
                if failure:
                    break
        finally:
            sel.close()
        self.close()
        return failure

    def close(self) -> None:
        if self._proc is not None:
            _kill(self._proc)
            self._proc = None
        self._buf = bytearray()
