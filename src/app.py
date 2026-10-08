#  Copyright (C) 2026 ghostnull
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.

"""Samba Share Configuration Manager.

Requirements:
  * Python 3 with PyGObject and GTK >= 4.10 (Gtk.AlertDialog / Gtk.FileDialog / Gtk.DropDown)
  * configupdater  (pip install configupdater --break-system-packages)
  * Samba tools on PATH: testparm, smbpasswd, pdbedit, smbcontrol
  * polkit's pkexec (only when NOT running as root)
  * samba_manager.ui next to this file

Privilege model:
  The GUI runs as your normal user. Everything that needs root (writing smb.conf,
  Samba users, service control, creating share directories) is done by a small
  helper: this same file started as `pkexec python3 app.py --helper`. One helper
  process is started lazily and reused, so you authenticate once per session.
  Passwords travel over the helper's stdin pipe, never on a command line.
  Running the whole app as root (sudo -E python3 app.py) still works; the helper
  code is then called in-process.

Lists use Gtk.ColumnView on Gio.ListStore models; drop-downs use Gtk.DropDown.
The columns are created in Python; samba_manager.ui only declares the widgets.
"""

import os
import re
import sys
import glob
import json
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import pwd
import grp

import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, Gio, GLib, GObject, Pango

if (Gtk.get_major_version(), Gtk.get_minor_version()) < (4, 10):
    print("Error: GTK 4.10 or newer is required.")
    sys.exit(1)

try:
    from configupdater import ConfigUpdater
except ImportError:
    ConfigUpdater = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONF_PATH = '/etc/samba/smb.conf'
MAX_BACKUPS = 10

FILE_MASKS = ['0644', '0660', '0640', '0666', '0600']
FILE_MASK_LABELS = [
    "0644 - Standard (Owner rw, others r)",
    "0660 - Restricted Group (Owner & group rw, others none)",
    "0640 - Group Read Only (Owner rw, group r, others none)",
    "0666 - Public (Everyone rw)",
    "0600 - Private (Only owner rw)",
    "Custom / Do not change",
]
DIR_MASKS = ['0755', '0770', '0750', '0777', '0700']
DIR_MASK_LABELS = [
    "0755 - Standard (Owner rwx, others rx)",
    "0770 - Restricted Group (Owner & group rwx, others none)",
    "0750 - Group Read Only (Owner rwx, group rx, others none)",
    "0777 - Public / Wide Open (Everyone has rwx)",
    "0700 - Private (Only owner has rwx)",
    "Custom / Do not change",
]

# Samba ignores case and whitespace in parameter names, and several parameters
# have aliases. Keys here are the canonical names this app writes; values are
# the normalized (lowercase, no whitespace) spellings that mean the same thing.
KEY_ALIASES = {
    'workgroup': {'workgroup'},
    'server string': {'serverstring'},
    'security': {'security'},
    'map to guest': {'maptoguest'},
    'guest account': {'guestaccount'},
    'comment': {'comment'},
    'path': {'path', 'directory'},
    'browseable': {'browseable', 'browsable'},
    'read only': {'readonly'},
    'guest ok': {'guestok', 'public'},
    'valid users': {'validusers'},
    'force user': {'forceuser'},
    'create mask': {'createmask', 'createmode'},
    'force create mode': {'forcecreatemode'},
    'directory mask': {'directorymask', 'directorymode'},
    'force directory mode': {'forcedirectorymode'},
}
# Aliases whose meaning is the opposite of the canonical key.
INVERTED_ALIASES = {'read only': {'writable', 'writeable', 'writeok'}}

SHARE_KEYS = [
    'comment', 'path', 'browseable', 'read only', 'guest ok', 'valid users',
    'force user', 'create mask', 'force create mode', 'directory mask',
    'force directory mode',
]
GLOBAL_KEYS = ['workgroup', 'server string', 'security', 'map to guest', 'guest account']

SPECIAL_SHARES = {'homes', 'printers'}          # valid sections that have no path
RESERVED_NEW_NAMES = {'global', 'homes', 'printers'}
INVALID_SHARE_CHARS = re.compile(r'[\[\]"/\\:|<>+=;,*?]')
USERNAME_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.\-]*\$?$')
USER_TOKEN_RE = re.compile(r'[@+&]*(?:"[^"]*"|[^\s,"]+)')

# Samba's own default for "read only" is yes.
READ_ONLY_DEFAULT = True

DAEMON_UNITS = {'smbd': ('smbd', 'smb')}

# stderr lines from `testparm` that are informational, not warnings.
TESTPARM_NOISE = ('load smb config files', 'loaded services file ok', 'weak crypto',
                  'server role:', 'press enter', 'rlimit_max', 'registered MSG_REQ'.lower())


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def norm_key(key):
    """Normalize a Samba parameter name: lowercase, all whitespace removed."""
    return ''.join(str(key).lower().split())


def to_bool(value, default=False):
    if value is None:
        return default
    v = str(value).strip().lower()
    if v in ('yes', 'true', '1', 'on'):
        return True
    if v in ('no', 'false', '0', 'off'):
        return False
    return default


def mask_index(value, masks):
    """Index of `value` (octal string, any zero padding) in `masks`, or None."""
    if not value:
        return None
    try:
        v = int(str(value).strip(), 8)
    except ValueError:
        return None
    for i, m in enumerate(masks):
        if int(m, 8) == v:
            return i
    return None


def parse_user_list(text):
    """Split a Samba user list (commas/whitespace, double quotes allowed)."""
    return USER_TOKEN_RE.findall(text or '')


def unquote_user(token):
    return token.replace('"', '')


def quote_user(name):
    """Quote a user/group name if it contains whitespace (keeps @, +, & prefixes)."""
    if name and '"' not in name and any(c.isspace() for c in name):
        prefix = ''
        while name and name[0] in '@+&':
            prefix += name[0]
            name = name[1:]
        return f'{prefix}"{name}"'
    return name


def path_status(path):
    """'dir', 'file', 'missing' or 'unknown' (e.g. permission denied) for `path`."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return 'missing'
    except OSError:
        return 'unknown'
    return 'dir' if stat.S_ISDIR(st.st_mode) else 'file'


# ---------------------------------------------------------------------------
# GTK list / drop-down helpers
# ---------------------------------------------------------------------------

class RowItem(GObject.Object):
    """One row in a list model; `values` holds the cell strings."""
    __gtype_name__ = 'SambaManagerRowItem'

    def __init__(self, *values):
        super().__init__()
        self.values = tuple(values)


def new_store():
    return Gio.ListStore(item_type=RowItem)


def fill_store(store, rows):
    """Replace the whole content of `store` with `rows` (tuples of strings)."""
    store.splice(0, store.get_n_items(), [RowItem(*r) for r in rows])


def append_names(store, names):
    store.splice(store.get_n_items(), 0, [RowItem(n) for n in names])


def model_values(model, col=0):
    return [model.get_item(i).values[col] for i in range(model.get_n_items())]


def store_find(store, name, col=0):
    for i in range(store.get_n_items()):
        if store.get_item(i).values[col] == name:
            return i
    return -1


def add_text_column(view, title, index, expand=False):
    factory = Gtk.SignalListItemFactory()

    def on_setup(_factory, list_item):
        label = Gtk.Label(xalign=0)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        label.set_margin_start(6)
        label.set_margin_end(6)
        label.set_margin_top(4)
        label.set_margin_bottom(4)
        list_item.set_child(label)

    def on_bind(_factory, list_item):
        list_item.get_child().set_text(list_item.get_item().values[index])

    factory.connect('setup', on_setup)
    factory.connect('bind', on_bind)
    column = Gtk.ColumnViewColumn(title=title, factory=factory)
    column.set_resizable(True)
    column.set_expand(expand)
    view.append_column(column)


def make_selection(model):
    return Gtk.SingleSelection(model=model, autoselect=False, can_unselect=True)


def set_dropdown_items(dropdown, items, selected=0):
    dropdown.set_model(Gtk.StringList.new(list(items)))
    dropdown.set_selected(selected)


def dropdown_index(dropdown):
    """Selected index of a Gtk.DropDown, or -1 when nothing is selected."""
    idx = dropdown.get_selected()
    return -1 if idx == Gtk.INVALID_LIST_POSITION else idx


def dropdown_text(dropdown):
    item = dropdown.get_selected_item()
    return item.get_string() if item is not None else ''


# ---------------------------------------------------------------------------
# Fatal startup dialog
# ---------------------------------------------------------------------------

def show_fatal_dialog_and_exit(title, text):
    """Graphical error for problems detected before the main window exists."""
    app = Gtk.Application(application_id='com.samba.manager.startuperror')

    def on_activate(app):
        window = Gtk.ApplicationWindow(application=app)
        window.set_title(title)
        window.set_default_size(460, 190)
        window.set_resizable(False)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        for side in ('start', 'end', 'top', 'bottom'):
            getattr(box, f'set_margin_{side}')(20)
        label = Gtk.Label(label=text)
        label.set_wrap(True)
        label.set_selectable(True)
        box.append(label)
        button = Gtk.Button(label="OK, Exit")
        button.connect("clicked", lambda btn: app.quit())
        box.append(button)
        window.set_child(box)
        window.present()

    app.connect('activate', on_activate)
    app.run(None)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Service control
# ---------------------------------------------------------------------------

class SambaServiceManager:
    WAIT_TIMEOUT = 8.0  # seconds to wait for the daemon to reach the wanted state

    @staticmethod
    def _has_systemd():
        # Same test as sd_booted(): systemd is PID 1 only if this directory exists.
        return os.path.isdir('/run/systemd/system') and shutil.which('systemctl') is not None

    @staticmethod
    def _get_service_name():
        if SambaServiceManager._has_systemd():
            for name in ['smbd', 'smb']:
                res = subprocess.run(['systemctl', 'status', name], capture_output=True, text=True)
                # 0 = active, 3 = inactive/failed, 4 = no such unit
                if res.returncode in (0, 3):
                    return name
        return 'smbd'

    @staticmethod
    def is_running(daemon='smbd'):
        """Process-table check (works unprivileged and in containers)."""
        try:
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    try:
                        with open(f'/proc/{pid}/comm', 'r') as f:
                            if f.read().strip() == daemon:
                                return True
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        continue
        except Exception:
            pass

        try:
            if subprocess.run(['pgrep', '-x', daemon], capture_output=True).returncode == 0:
                return True
        except FileNotFoundError:
            pass
        return False

    @staticmethod
    def status(daemon='smbd'):
        """Status for the UI: ask systemd when present, otherwise scan processes."""
        if SambaServiceManager._has_systemd():
            for unit in DAEMON_UNITS.get(daemon, (daemon,)):
                try:
                    rc = subprocess.run(['systemctl', 'is-active', '--quiet', unit],
                                        timeout=5, stdin=subprocess.DEVNULL).returncode
                except (OSError, subprocess.TimeoutExpired):
                    break
                if rc == 0:
                    return True
        return SambaServiceManager.is_running(daemon)

    @staticmethod
    def _terminate_smbd():
        """Send SIGTERM to every smbd process without needing pkill (absent on minimal installs)."""
        count = 0
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    if f.read().strip() != 'smbd':
                        continue
                os.kill(int(pid), signal.SIGTERM)
                count += 1
            except OSError:
                continue
        return count

    @staticmethod
    def _wait_for_state(want_running, timeout=None):
        """Poll until the daemon is (or is not) running. Returns True on success."""
        deadline = time.monotonic() + (timeout or SambaServiceManager.WAIT_TIMEOUT)
        while time.monotonic() < deadline:
            if SambaServiceManager.is_running() == want_running:
                return True
            time.sleep(0.25)
        return SambaServiceManager.is_running() == want_running

    @staticmethod
    def execute(action):
        """Runs as root (inside the helper)."""
        if action == 'restart':
            stop_ok, stop_log = SambaServiceManager.execute('stop')
            if not stop_ok:
                return False, stop_log + "\nRestart aborted: the service could not be stopped.\n"
            time.sleep(1)
            start_ok, start_log = SambaServiceManager.execute('start')
            return start_ok, stop_log + "\n" + start_log

        if action not in ('start', 'stop'):
            return False, f"Unknown action: {action}\n"

        want_running = (action == 'start')
        if SambaServiceManager.is_running() == want_running:
            state = "running" if want_running else "stopped"
            return True, f"Samba is already {state}.\n"

        service = SambaServiceManager._get_service_name()
        has_sysd = SambaServiceManager._has_systemd()

        if want_running:
            for runtime_dir in ['/var/run/samba', '/var/cache/samba', '/var/lib/samba/locks', '/var/log/samba']:
                try:
                    os.makedirs(runtime_dir, mode=0o755, exist_ok=True)
                except Exception:
                    pass
            for pid_file in ['/var/run/samba/smbd.pid', '/var/run/smbd.pid']:
                try:
                    if os.path.exists(pid_file):
                        os.remove(pid_file)
                except Exception:
                    pass
            commands = []
            if has_sysd:
                commands.append(['systemctl', 'start', service])
            commands.extend([['service', service, 'start'], ['/etc/init.d/smbd', 'start'], ['smbd', '-D']])
        else:
            commands = []
            if has_sysd:
                commands.append(['systemctl', 'stop', service])
            commands.extend([['service', service, 'stop'], ['/etc/init.d/smbd', 'stop'], ['pkill', 'smbd']])

        log = f"Attempting to {action} Samba service ({service})...\n"
        for cmd in commands:
            log += f"Running: {' '.join(cmd)}\n"
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                                        stdin=subprocess.DEVNULL)
            except FileNotFoundError:
                log += f"-> Command not found: {cmd[0]}\n"
                continue
            except subprocess.TimeoutExpired:
                log += "-> Command timed out; not trying further methods.\n"
                break

            log += result.stdout + result.stderr
            if result.returncode != 0:
                log += f"-> Exit status {result.returncode}, trying next method.\n"
                continue

            # The command reported success. Give the daemon time to settle, and do
            # NOT fall through to other launchers, which could start a duplicate smbd.
            if SambaServiceManager._wait_for_state(want_running):
                return True, log + f"-> SUCCESS: {' '.join(cmd)}\n"
            return False, log + ("-> Command succeeded but the daemon did not reach the expected "
                                 "state in time. Not trying other methods, to avoid duplicate daemons.\n")

        if not want_running and SambaServiceManager.is_running():
            sent = SambaServiceManager._terminate_smbd()
            log += f"Fallback: sent SIGTERM directly to {sent} smbd process(es).\n"
            if SambaServiceManager._wait_for_state(False):
                return True, log + "-> SUCCESS: SIGTERM\n"

        if SambaServiceManager.is_running() == want_running:
            return True, log + "\nFinished service execution sequence.\n"
        return False, log + "\nAll methods failed.\n"


# ---------------------------------------------------------------------------
# Privileged operations (these functions run as root, in the helper process)
# ---------------------------------------------------------------------------

def _testparm_check(tmp_path):
    """Run `testparm -s` on a candidate file. Raises if rejected, returns warning text."""
    try:
        res = subprocess.run(['testparm', '-s', tmp_path], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL, timeout=30)
    except FileNotFoundError:
        return ''  # testparm not installed: cannot validate
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip()[:1500]
        raise RuntimeError("testparm rejected the new configuration; nothing was written.\n\n" + detail)
    warnings = [ln for ln in res.stderr.splitlines()
                if ln.strip() and not ln.strip().lower().startswith(TESTPARM_NOISE)]
    return '\n'.join(warnings)[:1500]


def _backup_file(target):
    backup = f"{target}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(target, backup)
    backups = sorted(glob.glob(glob.escape(target) + '.bak-*'))
    for old in backups[:-MAX_BACKUPS]:
        try:
            os.remove(old)
        except OSError:
            pass
    return backup


def op_ping():
    return 'pong'


def op_save_conf(path, content):
    """Atomically write smb.conf: temp file -> testparm -> backup -> replace."""
    target = os.path.realpath(path)
    if target != os.path.realpath(DEFAULT_CONF_PATH):
        raise ValueError(f"Refusing to write anywhere but {DEFAULT_CONF_PATH}.")
    directory = os.path.dirname(target)
    os.makedirs(directory, exist_ok=True)

    fd, tmp = tempfile.mkstemp(dir=directory, prefix='.smb.conf.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        if os.path.exists(target):
            st = os.stat(target)
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass  # e.g. proot / unprivileged environments: ownership is best-effort
        else:
            os.chmod(tmp, 0o644)

        warnings = _testparm_check(tmp)
        backup = _backup_file(target) if os.path.exists(target) else None
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    return {'backup': backup, 'warnings': warnings}


def op_reload_conf():
    if not SambaServiceManager.is_running():
        return {'status': 'not_running', 'detail': ''}
    try:
        res = subprocess.run(['smbcontrol', 'all', 'reload-config'], capture_output=True,
                             text=True, timeout=30, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return {'status': 'missing', 'detail': ''}
    except subprocess.TimeoutExpired:
        return {'status': 'timeout', 'detail': ''}
    if res.returncode != 0:
        return {'status': 'failed', 'detail': (res.stderr or res.stdout).strip()}
    return {'status': 'ok', 'detail': ''}


def op_list_users():
    try:
        res = subprocess.run(['pdbedit', '-L'], capture_output=True, text=True, check=True,
                             stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("'pdbedit' was not found. Is Samba installed?")
    except subprocess.CalledProcessError as e:
        raise RuntimeError((e.stderr or e.stdout or '').strip() or "pdbedit failed.")
    return [line.split(':')[0] for line in res.stdout.splitlines() if line.strip()]


def op_set_password(username, password):
    if not USERNAME_RE.match(username or ''):
        raise ValueError("Invalid username. Use letters, digits, '_', '.', '-' "
                         "and do not start with '-' or '.'.")
    if not password:
        raise ValueError("Password cannot be empty.")
    if '\n' in password or '\r' in password:
        raise ValueError("Password cannot contain line breaks.")
    try:
        res = subprocess.run(['smbpasswd', '-a', '-s', username],
                             input=f"{password}\n{password}\n", capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError("'smbpasswd' was not found. Is Samba installed?")
    if res.returncode != 0:
        raise RuntimeError((res.stderr or res.stdout).strip() or "Failed to set password.")


def op_delete_user(username):
    if not USERNAME_RE.match(username or ''):
        raise ValueError("Invalid username.")
    try:
        res = subprocess.run(['smbpasswd', '-x', username], capture_output=True, text=True,
                             stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("'smbpasswd' was not found. Is Samba installed?")
    if res.returncode != 0:
        raise RuntimeError((res.stderr or res.stdout).strip() or "Failed to delete user.")


def op_service(action):
    return list(SambaServiceManager.execute(action))


def op_apply_fs(ops):
    """Create / chmod share directories. New directories are chowned to the force user."""
    errors = []
    for op in ops:
        share, path, mode, owner = op['share'], op['path'], op.get('mode'), op.get('owner')
        try:
            if not os.path.isabs(path):
                raise ValueError("path must be absolute")
            if os.path.exists(path) and not os.path.isdir(path):
                raise NotADirectoryError("exists but is not a directory")

            if not os.path.isdir(path):
                ids = None
                if owner:
                    try:
                        pw = pwd.getpwnam(owner)
                        ids = (pw.pw_uid, pw.pw_gid)
                    except KeyError:
                        errors.append(f"[{share}] force user '{owner}' does not exist; "
                                      f"{path} will be owned by root.")
                missing, p = [], path
                while not os.path.exists(p) and p != os.path.dirname(p):
                    missing.append(p)
                    p = os.path.dirname(p)
                for d in reversed(missing):
                    os.mkdir(d)
                    # mkdir(mode=) is umask-filtered, so chmod explicitly.
                    os.chmod(d, (mode if mode is not None else 0o755) if d == path else 0o755)
                if ids:
                    os.chown(path, *ids)
            elif op.get('chmod_existing') and mode is not None:
                os.chmod(path, mode)
        except Exception as e:
            errors.append(f"[{share}] {path}: {e}")
    return errors


OPS = {
    'ping': op_ping, 'save_conf': op_save_conf, 'reload_conf': op_reload_conf,
    'list_users': op_list_users, 'set_password': op_set_password,
    'delete_user': op_delete_user, 'service': op_service, 'apply_fs': op_apply_fs,
}


def helper_main():
    """Entry point of `pkexec python3 app.py --helper`: line-delimited JSON on stdin/stdout."""
    if os.geteuid() != 0:
        sys.exit("The helper must run as root.")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if req.get('op') not in OPS:
                raise ValueError(f"Unknown operation: {req.get('op')}")
            result = OPS[req['op']](**req.get('args', {}))
            resp = {'ok': True, 'result': result}
        except Exception as e:
            resp = {'ok': False, 'error': str(e) or e.__class__.__name__}
        sys.stdout.write(json.dumps(resp) + '\n')
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Privilege broker (GUI side)
# ---------------------------------------------------------------------------

class PrivilegeError(RuntimeError):
    pass


class PrivilegedHelper:
    """Calls the OPS table as root: in-process when already root, else via one pkexec helper."""

    def __init__(self):
        self.direct = os.geteuid() == 0
        self.proc = None
        self.lock = threading.Lock()

    def call(self, op, **args):
        if self.direct:
            return OPS[op](**args)
        with self.lock:
            line = ''
            try:
                proc = self._ensure()
                proc.stdin.write(json.dumps({'op': op, 'args': args}) + '\n')
                proc.stdin.flush()
                line = proc.stdout.readline()
            except PrivilegeError:
                raise
            except (BrokenPipeError, OSError):
                pass
            if not line:
                self._reset()
                raise PrivilegeError("Administrator authorization was cancelled or the helper stopped.")
        resp = json.loads(line)
        if not resp['ok']:
            raise RuntimeError(resp['error'])
        return resp['result']

    def _ensure(self):
        if self.proc is None or self.proc.poll() is not None:
            if shutil.which('pkexec') is None:
                raise PrivilegeError("pkexec (polkit) is not installed. Install polkit, "
                                     "or run this program as root.")
            self.proc = subprocess.Popen(
                ['pkexec', sys.executable, os.path.abspath(__file__), '--helper'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
        return self.proc

    def _reset(self):
        proc, self.proc = self.proc, None
        if proc is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def close(self):
        with self.lock:
            self._reset()      # EOF on stdin makes the helper exit


HELPER = PrivilegedHelper()


# ---------------------------------------------------------------------------
# Samba users / system accounts
# ---------------------------------------------------------------------------

class SambaUserManager:
    @staticmethod
    def get_users():
        return HELPER.call('list_users')

    @staticmethod
    def set_password(username, password):
        HELPER.call('set_password', username=username, password=password)

    @staticmethod
    def delete_user(username):
        HELPER.call('delete_user', username=username)

    @staticmethod
    def get_system_users():
        users = ['root']
        try:
            for p in pwd.getpwall():
                if 1000 <= p.pw_uid < 65534 and 'nobody' not in p.pw_name:
                    users.append(p.pw_name)
        except Exception:
            pass
        return sorted(set(users))

    @staticmethod
    def get_system_groups():
        groups = []
        try:
            for g in grp.getgrall():
                if 1000 <= g.gr_gid < 65534 and 'nogroup' not in g.gr_name:
                    groups.append(g.gr_name)
        except Exception:
            pass
        return sorted(set(groups))


# ---------------------------------------------------------------------------
# smb.conf handling
# ---------------------------------------------------------------------------

class SambaConfigHandler:
    def __init__(self, filepath=DEFAULT_CONF_PATH):
        self.filepath = filepath
        self.load_error = None
        self.is_new_file = False
        self._added_sections = set()      # lowercase names of sections created by this app
        self.updater = ConfigUpdater(
            allow_no_value=True,
            delimiters=('=',),            # ':' is legal inside keys, e.g. "fruit:metadata"
            strict=False,                 # tolerate duplicate keys/sections
            empty_lines_in_values=False,
        )
        self.load_config()

    # -- loading / saving ---------------------------------------------------

    def load_config(self):
        self.load_error = None
        if os.path.exists(self.filepath):
            try:
                self.updater.read(self.filepath, encoding='utf-8')
            except Exception as e:
                self.load_error = f"Could not read or parse {self.filepath}:\n\n{e}"
        else:
            # Start from defaults; the real file is created only when the user saves.
            self.is_new_file = True
            self._add_section('global')
            sec = self.updater['global']
            for key, val in (('workgroup', 'WORKGROUP'), ('server string', 'Samba Server'),
                             ('security', 'user'), ('map to guest', 'Bad User'),
                             ('guest account', 'nobody')):
                self._set_option(sec, key, val)

    def _add_section(self, name):
        self.updater.add_section(name)
        self._added_sections.add(name.lower())

    def _render(self):
        """Render the file, keeping the user's formatting.

        Only sections created by this app get a separating blank line, so comments
        that sit directly above an existing [section] header are never pulled apart.
        """
        out = []
        for line in str(self.updater).splitlines():
            m = re.match(r'^\s*\[(.+?)\]\s*$', line)
            if (m and m.group(1).lower() in self._added_sections and out
                    and out[-1].strip() != '' and not out[-1].rstrip().endswith('\\')):
                out.append('')
            out.append(line)
        return '\n'.join(out).rstrip('\n') + '\n'

    def save_config(self):
        """Hand the rendered file to the privileged helper.

        Returns {'backup': path or None, 'warnings': testparm warning text}.
        """
        result = HELPER.call('save_conf', path=self.filepath, content=self._render())
        self.is_new_file = False
        return result

    # -- generic option access (alias / whitespace aware) -------------------

    def _match(self, section, canonical):
        """Raw keys in `section` that mean `canonical`, as (raw_key, inverted)."""
        names = KEY_ALIASES[canonical]
        inverted = INVERTED_ALIASES.get(canonical, set())
        found = []
        for raw in list(section.keys()):
            n = norm_key(raw)
            if n in names:
                found.append((raw, False))
            elif n in inverted:
                found.append((raw, True))
        return found

    def _get_option(self, section, canonical):
        found = self._match(section, canonical)
        if not found:
            return None
        raw, inverted = found[-1]  # Samba: last occurrence wins
        value = section[raw].value
        if value is None:
            return ''
        if inverted:
            b = to_bool(value, None)
            return value if b is None else ('no' if b else 'yes')
        return value

    def _set_option(self, section, canonical, value):
        """Set (str) or remove (None) an option; aliases of it are removed so no
        conflicting duplicates remain."""
        found = self._match(section, canonical)
        canon_norm = norm_key(canonical)
        keep = next((raw for raw, inv in found if not inv and norm_key(raw) == canon_norm), None)
        for raw, _ in found:
            if raw != keep:
                section.remove_option(raw)
        if value is None:
            if keep is not None:
                section.remove_option(keep)
            return
        section[keep or canonical] = value

    def _find_section(self, name):
        for s in self.updater.sections():
            if s.lower() == name.lower():
                return s
        return None

    # -- global -------------------------------------------------------------

    def get_global_settings(self):
        name = self._find_section('global')
        if name is None:
            return {}
        sec = self.updater[name]
        result = {}
        for key in GLOBAL_KEYS:
            val = self._get_option(sec, key)
            if val is not None:
                result[key] = val
        return result

    def update_global_settings(self, workgroup, server_string, security, map_to_guest, guest_account):
        """A value of None leaves that setting exactly as it is in the file."""
        name = self._find_section('global')
        if name is None:
            self._add_section('global')
            name = 'global'
        sec = self.updater[name]
        for key, val in (('workgroup', workgroup), ('server string', server_string),
                         ('security', security), ('map to guest', map_to_guest),
                         ('guest account', guest_account)):
            if val is not None:
                self._set_option(sec, key, val)

    # -- shares -------------------------------------------------------------

    def get_shares(self):
        return [s for s in self.updater.sections() if s.lower() != 'global']

    def get_share_details(self, share_name):
        if share_name not in self.updater:
            return {}
        sec = self.updater[share_name]
        details = {}
        for key in SHARE_KEYS:
            val = self._get_option(sec, key)
            if val is not None:
                details[key] = val
        return details

    def add_or_update_share(self, share_name, path, comment, read_only, browsable, guest_ok,
                            valid_users='', force_user='', dir_perms=None, file_perms=None,
                            force_modes=False, old_name=None):
        """Create or update a share in place.

        Unknown ("custom") options, comments and position are preserved.
        dir_perms / file_perms: None = leave existing masks (and force modes) untouched,
        str = set the mask. force_modes additionally writes `force create mode` /
        `force directory mode` with the same value; when False those are removed.
        old_name: set when renaming; all options are carried over to the new section.
        """
        if old_name and old_name != share_name and old_name in self.updater:
            if share_name not in self.updater:
                self._add_section(share_name)
                old_sec = self.updater[old_name]
                new_sec = self.updater[share_name]
                for key in list(old_sec.keys()):
                    val = old_sec[key].value
                    new_sec[key] = val if val is not None else ''
            self.updater.remove_section(old_name)
        elif share_name not in self.updater:
            self._add_section(share_name)

        sec = self.updater[share_name]
        self._set_option(sec, 'comment', comment or None)
        self._set_option(sec, 'path', path or None)
        self._set_option(sec, 'browseable', 'yes' if browsable else 'no')
        self._set_option(sec, 'read only', 'yes' if read_only else 'no')
        self._set_option(sec, 'valid users', valid_users or None)
        self._set_option(sec, 'guest ok', 'yes' if guest_ok else 'no')
        self._set_option(sec, 'force user', force_user or None)

        if file_perms is not None:
            self._set_option(sec, 'create mask', file_perms or None)
            self._set_option(sec, 'force create mode', (file_perms or None) if force_modes else None)
        if dir_perms is not None:
            self._set_option(sec, 'directory mask', dir_perms or None)
            self._set_option(sec, 'force directory mode', (dir_perms or None) if force_modes else None)

    def delete_share(self, share_name):
        if share_name in self.updater:
            self.updater.remove_section(share_name)


# ---------------------------------------------------------------------------
# GTK application
# ---------------------------------------------------------------------------

class SambaManagerApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id='com.samba.manager')
        self.unsaved_changes = False
        self.action_in_progress = False
        self._status_busy = False
        self.pending_fs = {}              # share name -> deferred directory create/chmod
        self.current_edit_share = ''
        self._initial_file_idx = 0
        self._initial_dir_idx = 0
        self._initial_force = False
        self.keep_security = False
        self.keep_map_guest = False
        self.window = None
        self.handler = SambaConfigHandler()
        self.builder = Gtk.Builder()

    # -- startup ------------------------------------------------------------

    def do_activate(self):
        if self.window is not None:      # second activation: just raise the window
            self.window.present()
            return

        ui_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samba_manager.ui")
        self.builder.add_from_file(ui_path)
        self.window = self.builder.get_object("main_window")
        self.window.set_application(self)

        if self.handler.load_error:
            self.window.set_sensitive(False)
            self.window.present()
            dialog = Gtk.AlertDialog(
                message="Cannot load configuration",
                detail=self.handler.load_error + "\n\nNothing was modified. The application will now close.")
            dialog.choose(self.window, None, lambda d, r: self.quit())
            return

        self.window.connect("close-request", self.on_window_close_request)

        self.setup_dropdowns()
        self.setup_lists()
        self.setup_dialog_bindings()
        self.setup_ui_bindings()

        self.refresh_shares_list()
        self.check_daemon_status()
        GLib.timeout_add_seconds(2, self.check_daemon_status)

        self.unsaved_changes = False
        self.update_statusbar()
        self.window.present()
        self.connect_helper_async()

        if self.handler.is_new_file:
            self.show_alert(
                "Configuration file not found",
                f"{self.handler.filepath} does not exist.\n\n"
                "Starting from default settings. The file will be created when you save.")

    def do_shutdown(self):
        HELPER.close()
        Gtk.Application.do_shutdown(self)

    def connect_helper_async(self):
        """Start the privileged helper in the background so the polkit prompt shows at launch."""
        def work():
            try:
                HELPER.call('ping')
                err = None
            except Exception as e:
                err = str(e)
            GLib.idle_add(self._helper_ready, err)
        threading.Thread(target=work, daemon=True).start()

    def _helper_ready(self, err):
        if err:
            self.show_alert("Administrator access unavailable",
                            f"{err}\n\nYou can keep editing, but saving, Samba users and service "
                            "control need administrator rights and will ask again when used.")
        else:
            self.refresh_users_list()
        return False

    def setup_ui_bindings(self):
        b = self.builder.get_object
        b("entry_workgroup").connect("changed", self.mark_unsaved)
        b("entry_server_string").connect("changed", self.mark_unsaved)
        b("entry_guest_account").connect("changed", self.mark_unsaved)
        b("combo_security").connect("notify::selected", self.mark_unsaved)
        b("combo_map_guest").connect("notify::selected", self.mark_unsaved)
        b("btn_save").connect("clicked", self.on_save_clicked)

        b("btn_add_share").connect("clicked", self.on_add_share_clicked)
        b("btn_edit_share").connect("clicked", self.on_edit_share_clicked)
        b("btn_delete_share").connect("clicked", self.on_delete_share_clicked)

        b("btn_add_user").connect("clicked", self.on_add_user_clicked)
        b("btn_change_password").connect("clicked", self.on_change_password_clicked)
        b("btn_delete_user").connect("clicked", self.on_delete_user_clicked)

        b("btn_start").connect("clicked", lambda w: self.on_service_action("start"))
        b("btn_stop").connect("clicked", lambda w: self.on_service_action("stop"))
        b("btn_restart").connect("clicked", lambda w: self.on_service_action("restart"))

        self.lbl_status_val = b("lbl_status_val")
        self.textview_log = b("textview_log")
        self.textbuffer_log = self.textview_log.get_buffer()
        self.lbl_statusbar = b("lbl_statusbar")

    def setup_dropdowns(self):
        b = self.builder.get_object
        glob_settings = self.handler.get_global_settings()

        # Security: only user-level is offered. If the file uses something else
        # (ads, domain, ...), offer "keep existing" so saving never clobbers it.
        security_items = ["User-Level Security (Standard standalone server)"]
        existing_sec = str(glob_settings.get('security', '')).strip()
        self.keep_security = bool(existing_sec) and existing_sec.lower() != 'user'
        if self.keep_security:
            security_items.append(f"Keep existing: security = {existing_sec}")
        set_dropdown_items(b("combo_security"), security_items, 1 if self.keep_security else 0)

        # Map to guest: same idea for values the UI does not offer (e.g. "Bad Uid").
        map_items = ["Never (No guest access)", "Bad User (Standard fallback)", "Bad Password"]
        cmap = str(glob_settings.get('map to guest', 'Never')).strip().lower()
        self.keep_map_guest = cmap not in ('', 'never', 'bad user', 'bad password')
        if self.keep_map_guest:
            map_items.append(f"Keep existing: map to guest = {glob_settings.get('map to guest')}")
        if self.keep_map_guest:
            map_sel = 3
        else:
            map_sel = {'bad user': 1, 'bad password': 2}.get(cmap, 0)
        set_dropdown_items(b("combo_map_guest"), map_items, map_sel)

        b("entry_workgroup").set_text(glob_settings.get('workgroup') or 'WORKGROUP')
        b("entry_server_string").set_text(glob_settings.get('server string') or 'Samba Server')
        b("entry_guest_account").set_text(glob_settings.get('guest account') or 'nobody')

        set_dropdown_items(b("share_combo_file_perms"), FILE_MASK_LABELS)
        set_dropdown_items(b("share_combo_dir_perms"), DIR_MASK_LABELS)

    def setup_lists(self):
        b = self.builder.get_object

        self.store_shares = new_store()
        cv_shares = b("columnview_shares")
        for i, (title, expand) in enumerate([('Share Name', False), ('Path', True), ('Read Only', False),
                                             ('Guest OK', False), ('Valid Users', True), ('Dir Perms', False)]):
            add_text_column(cv_shares, title, i, expand)
        self.sel_shares = make_selection(self.store_shares)
        cv_shares.set_model(self.sel_shares)
        cv_shares.connect('activate', self.on_shares_row_activated)

        self.store_users = new_store()
        cv_users = b("columnview_users")
        add_text_column(cv_users, 'Samba Username', 0, True)
        self.sel_users = make_selection(self.store_users)
        cv_users.set_model(self.sel_users)
        cv_users.connect('activate', self.on_users_row_activated)

    def on_shares_row_activated(self, view, position):
        self.sel_shares.set_selected(position)
        self.on_edit_share_clicked(None)

    def on_users_row_activated(self, view, position):
        self.sel_users.set_selected(position)
        self.on_change_password_clicked(None)

    def setup_dialog_bindings(self):
        b = self.builder.get_object

        self.share_window = b("share_window")
        self.share_window.set_transient_for(self.window)
        b("share_btn_cancel").connect("clicked", lambda w: self.share_window.close())
        b("share_btn_ok").connect("clicked", self.on_share_save_clicked)
        b("share_btn_browse").connect("clicked", self.on_share_browse_clicked)
        b("share_btn_open_fm").connect("clicked", self.on_share_open_folder_clicked)
        b("share_btn_pick_valid").connect("clicked", self.on_share_pick_valid_clicked)
        b("share_btn_pick_force").connect("clicked", self.on_share_pick_force_clicked)
        b("share_entry_path").connect("changed", self.update_path_warning)
        b("share_entry_name").connect("changed", self.update_path_warning)

        self.password_window = b("password_window")
        self.password_window.set_transient_for(self.window)
        b("pass_btn_cancel").connect("clicked", lambda w: self.password_window.close())
        b("pass_btn_ok").connect("clicked", self.on_password_save_clicked)

        self.valid_users_window = b("valid_users_window")
        self.valid_users_window.set_transient_for(self.share_window)
        b("vu_btn_cancel").connect("clicked", lambda w: self.valid_users_window.close())
        b("vu_btn_ok").connect("clicked", self.on_valid_users_apply_clicked)
        self.store_vu_avail = new_store()
        self.store_vu_sel = new_store()
        self.vu_filter = Gtk.CustomFilter.new(self.vu_filter_func)
        self.filter_vu_avail = Gtk.FilterListModel(model=self.store_vu_avail, filter=self.vu_filter)
        b("vu_search").connect("search-changed",
                               lambda w: self.vu_filter.changed(Gtk.FilterChange.DIFFERENT))
        cv_vu_avail = b("vu_cv_avail")
        cv_vu_sel = b("vu_cv_sel")
        add_text_column(cv_vu_avail, "Available", 0, True)
        add_text_column(cv_vu_sel, "Selected", 0, True)
        self.sel_vu_avail = make_selection(self.filter_vu_avail)
        self.sel_vu_sel = make_selection(self.store_vu_sel)
        cv_vu_avail.set_model(self.sel_vu_avail)
        cv_vu_sel.set_model(self.sel_vu_sel)
        b("vu_btn_add").connect("clicked", self.vu_add_selected)
        b("vu_btn_remove").connect("clicked", self.vu_remove_selected)
        b("vu_btn_add_all").connect("clicked", self.vu_add_all)
        b("vu_btn_remove_all").connect("clicked", self.vu_remove_all)
        b("vu_btn_custom").connect("clicked", self.vu_add_custom)
        b("vu_entry_custom").connect("activate", self.vu_add_custom)

        self.force_user_window = b("force_user_window")
        self.force_user_window.set_transient_for(self.share_window)
        b("fu_btn_cancel").connect("clicked", lambda w: self.force_user_window.close())
        b("fu_btn_ok").connect("clicked", self.on_force_user_apply_clicked)
        self.store_fu = new_store()
        self.fu_filter = Gtk.CustomFilter.new(self.fu_filter_func)
        self.filter_fu = Gtk.FilterListModel(model=self.store_fu, filter=self.fu_filter)
        b("fu_search").connect("search-changed",
                               lambda w: self.fu_filter.changed(Gtk.FilterChange.DIFFERENT))
        cv_fu = b("fu_columnview")
        add_text_column(cv_fu, "System Users", 0, True)
        self.sel_fu = make_selection(self.filter_fu)
        cv_fu.set_model(self.sel_fu)
        cv_fu.connect('activate', self.on_fu_row_activated)

    # -- generic UI helpers -------------------------------------------------

    @staticmethod
    def _choose_finish(dialog, result):
        """choose_finish() raises GLib.Error when the dialog is dismissed (Escape)."""
        try:
            return dialog.choose_finish(result)
        except GLib.Error:
            return -1

    def show_alert(self, title, message, alert_type="info"):
        dialog = Gtk.AlertDialog(message=title, detail=message)
        dialog.show(self.window)

    def mark_unsaved(self, *args):
        self.unsaved_changes = True
        self.update_statusbar()

    def update_statusbar(self):
        msg = f'Target file: {self.handler.filepath} | Shares: {len(self.handler.get_shares())}'
        if self.unsaved_changes:
            msg += '  [UNSAVED CHANGES]'
        self.lbl_statusbar.set_text(msg)

    def append_log(self, text):
        end_iter = self.textbuffer_log.get_end_iter()
        self.textbuffer_log.insert(end_iter, text + "\n")
        new_end_iter = self.textbuffer_log.get_end_iter()
        mark = self.textbuffer_log.create_mark(None, new_end_iter, False)
        self.textview_log.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
        self.textbuffer_log.delete_mark(mark)

    # -- window close -------------------------------------------------------

    def on_window_close_request(self, window):
        if not self.unsaved_changes:
            return False
        dialog = Gtk.AlertDialog(
            message="Unsaved Changes",
            detail="You have unsaved changes to smb.conf. Do you want to save them before exiting?",
            buttons=["Cancel", "Discard", "Save"]
        )
        dialog.set_cancel_button(0)
        dialog.set_default_button(2)
        dialog.choose(self.window, None, self.on_close_confirm)
        return True

    def on_close_confirm(self, dialog, result):
        res = self._choose_finish(dialog, result)
        if res == 1:
            self.unsaved_changes = False
            self.pending_fs.clear()
            self.window.close()
        elif res == 2:
            if self.on_save_clicked(None):   # stay open if saving failed
                self.window.close()

    # -- service control ----------------------------------------------------

    def check_daemon_status(self):
        """Timer callback: poll in a worker thread so the UI never blocks."""
        if not self._status_busy:
            self._status_busy = True
            threading.Thread(target=self._poll_status, daemon=True).start()
        return True

    def _poll_status(self):
        try:
            smbd = SambaServiceManager.status('smbd')
        except Exception:
            smbd = False
        GLib.idle_add(self._apply_status, smbd)

    def _apply_status(self, smbd):
        self._status_busy = False
        b = self.builder.get_object
        if smbd:
            self.lbl_status_val.set_markup("<span foreground='green' weight='bold'>Running</span>")
        else:
            self.lbl_status_val.set_markup("<span foreground='red' weight='bold'>Stopped</span>")

        # While an action runs the buttons stay disabled; the timer must not re-enable them.
        if not self.action_in_progress:
            b("btn_start").set_sensitive(not smbd)
            b("btn_stop").set_sensitive(smbd)
            b("btn_restart").set_sensitive(smbd)
        return False

    def on_service_action(self, action):
        if self.action_in_progress:
            return
        self.action_in_progress = True
        b = self.builder.get_object
        b("btn_start").set_sensitive(False)
        b("btn_stop").set_sensitive(False)
        b("btn_restart").set_sensitive(False)
        self.append_log(f"--- Executing: {action.upper()} ---")

        def run_action_thread():
            try:
                success, log_output = HELPER.call('service', action=action)
            except Exception as e:
                success, log_output = False, f"Error: {e}"

            def update_ui():
                self.append_log(log_output)
                self.action_in_progress = False
                self.check_daemon_status()
                return False

            GLib.idle_add(update_ui)

        threading.Thread(target=run_action_thread, daemon=True).start()

    # -- shares -------------------------------------------------------------

    def refresh_shares_list(self):
        rows = []
        for share in self.handler.get_shares():
            d = self.handler.get_share_details(share)
            path = d.get('path', '')
            dir_perms = d.get('directory mask')
            if not dir_perms and path and os.path.exists(path):
                try:
                    dir_perms = f"{os.stat(path).st_mode & 0o777:04o}"
                except Exception:
                    pass
            rows.append((
                share, str(path or 'N/A'),
                'Yes' if to_bool(d.get('read only'), READ_ONLY_DEFAULT) else 'No',
                'Yes' if to_bool(d.get('guest ok'), False) else 'No',
                d.get('valid users', '') or 'All', dir_perms or 'N/A'
            ))
        fill_store(self.store_shares, rows)
        self.update_statusbar()

    def get_selected_share_name(self):
        item = self.sel_shares.get_selected_item()
        return item.values[0] if item is not None else None

    def open_share_dialog(self, share_name='', data=None):
        self.current_edit_share = share_name
        editing = bool(share_name)
        data = data or {}
        b = self.builder.get_object

        b("share_window").set_title('Edit Share' if editing else 'Add New Share')
        b("share_entry_name").set_text(share_name)
        # [homes] / [printers] legitimately have no path: don't invent one when editing.
        b("share_entry_path").set_text(data.get('path', '' if editing else '/home'))
        b("share_entry_comment").set_text(data.get('comment', ''))
        b("share_switch_readonly").set_active(to_bool(data.get('read only'), READ_ONLY_DEFAULT))
        b("share_switch_browseable").set_active(to_bool(data.get('browseable'), True))
        b("share_switch_guest").set_active(to_bool(data.get('guest ok'), False))
        b("share_entry_valid_users").set_text(data.get('valid users', ''))
        b("share_entry_force_user").set_text(data.get('force user', ''))

        # Unset or unrecognised masks (e.g. 0775) map to "Custom / Do not change"
        # so saving never overwrites them. A brand-new share defaults to Standard.
        f_idx = mask_index(data.get('create mask'), FILE_MASKS)
        if f_idx is None:
            f_idx = len(FILE_MASKS) if editing else 0
        d_idx = mask_index(data.get('directory mask'), DIR_MASKS)
        if d_idx is None:
            d_idx = len(DIR_MASKS) if editing else 0
        force = bool(data.get('force create mode') or data.get('force directory mode'))

        b("share_combo_file_perms").set_selected(f_idx)
        b("share_combo_dir_perms").set_selected(d_idx)
        b("share_switch_force_modes").set_active(force)
        self._initial_file_idx, self._initial_dir_idx, self._initial_force = f_idx, d_idx, force

        self.update_path_warning()
        b("share_window").present()

    def update_path_warning(self, *args):
        b = self.builder.get_object
        label = b("share_lbl_path_warning")
        path = b("share_entry_path").get_text().strip()
        name = b("share_entry_name").get_text().strip().lower()
        text = ''
        if path and name not in SPECIAL_SHARES:
            if not path.startswith('/'):
                text = "Path must be absolute (start with '/')."
            else:
                state = path_status(path)
                if state == 'missing':
                    text = "This directory does not exist yet; it will be created when you save smb.conf."
                elif state == 'file':
                    text = "This path exists but is not a directory."
                elif state == 'unknown':
                    text = "Cannot check this path with your permissions."
        label.set_visible(bool(text))
        label.set_markup(f"<span foreground='#b36b00'>{GLib.markup_escape_text(text)}</span>" if text else '')

    def on_share_open_folder_clicked(self, widget):
        path = self.builder.get_object("share_entry_path").get_text().strip()
        if path_status(path) != 'dir':
            self.show_alert("Cannot open folder", "That directory does not exist yet. "
                                                  "It is created when you save smb.conf.")
            return
        Gtk.FileLauncher.new(Gio.File.new_for_path(path)).launch(self.share_window, None, self._on_launch_done)

    @staticmethod
    def _on_launch_done(launcher, result):
        try:
            launcher.launch_finish(result)
        except GLib.Error:
            pass

    def on_add_share_clicked(self, widget):
        self.open_share_dialog()

    def on_edit_share_clicked(self, widget):
        sel = self.get_selected_share_name()
        if sel:
            self.open_share_dialog(sel, self.handler.get_share_details(sel))

    def on_delete_share_clicked(self, widget):
        sel = self.get_selected_share_name()
        if not sel:
            return
        dialog = Gtk.AlertDialog(message="Confirm Deletion", detail=f"Delete share '{sel}'?",
                                 buttons=["Cancel", "Delete"])
        dialog.set_cancel_button(0)
        dialog.choose(self.window, None, self.on_delete_share_confirm, sel)

    def on_delete_share_confirm(self, dialog, result, sel):
        if self._choose_finish(dialog, result) == 1:
            self.handler.delete_share(sel)
            self.pending_fs.pop(sel, None)
            self.mark_unsaved()
            self.refresh_shares_list()

    def on_share_save_clicked(self, widget):
        b = self.builder.get_object
        name = b("share_entry_name").get_text().strip()
        editing = self.current_edit_share

        if not name:
            self.show_alert("Error", "Share name cannot be empty.")
            return
        if INVALID_SHARE_CHARS.search(name):
            self.show_alert("Error", "Share name contains invalid characters "
                                     "(any of  [ ] \" / \\ : | < > + = ; , * ? ).")
            return
        lname = name.lower()
        if lname == 'global':
            self.show_alert("Error", "'global' is reserved and cannot be used as a share name.")
            return
        if lname in RESERVED_NEW_NAMES and lname != editing.lower():
            self.show_alert("Error", f"'{name}' is a special Samba section and cannot be used "
                                     "as the name of a new share.")
            return
        others = [s.lower() for s in self.handler.get_shares() if s != editing]
        if lname in others:
            self.show_alert("Error", f"Share '{name}' already exists (share names are case-insensitive).")
            return

        special = lname in SPECIAL_SHARES
        path = b("share_entry_path").get_text().strip()
        if not path and not special:
            self.show_alert("Error", "Directory path cannot be empty.")
            return
        if path and not path.startswith('/'):
            self.show_alert("Error", "Directory path must be an absolute path (starting with '/').")
            return
        if path and not special and path_status(path) == 'file':
            self.show_alert("Error", f"'{path}' exists but is not a directory.")
            return

        file_idx = dropdown_index(b("share_combo_file_perms"))
        dir_idx = dropdown_index(b("share_combo_dir_perms"))
        if file_idx < 0:
            file_idx = len(FILE_MASKS)
        if dir_idx < 0:
            dir_idx = len(DIR_MASKS)
        force = b("share_switch_force_modes").get_active()
        file_perms = FILE_MASKS[file_idx] if file_idx < len(FILE_MASKS) else None   # None = custom
        dir_mode = DIR_MASKS[dir_idx] if dir_idx < len(DIR_MASKS) else None
        force_user = unquote_user(b("share_entry_force_user").get_text().strip())

        # Only rewrite mask / force options in smb.conf when the user actually changed them.
        conf_file_perms, conf_dir_perms = file_perms, dir_mode
        if editing and file_idx == self._initial_file_idx and force == self._initial_force:
            conf_file_perms = None
        if editing and dir_idx == self._initial_dir_idx and force == self._initial_force:
            conf_dir_perms = None

        # Filesystem changes are deferred until smb.conf is actually saved.
        self.pending_fs.pop(editing, None)
        self.pending_fs.pop(name, None)
        if path and not special:
            self.pending_fs[name] = {
                'share': name,
                'path': path,
                'mode': int(dir_mode, 8) if dir_mode else None,
                'owner': force_user or None,
                # Only touch an existing directory if the user changed the dropdown.
                'chmod_existing': dir_mode is not None and dir_idx != self._initial_dir_idx,
            }

        self.handler.add_or_update_share(
            name, path, b("share_entry_comment").get_text().strip(),
            b("share_switch_readonly").get_active(), b("share_switch_browseable").get_active(),
            b("share_switch_guest").get_active(), b("share_entry_valid_users").get_text().strip(),
            b("share_entry_force_user").get_text().strip(), conf_dir_perms, conf_file_perms,
            force_modes=force, old_name=editing or None
        )
        self.mark_unsaved()
        self.refresh_shares_list()
        b("share_window").close()

    def apply_pending_fs(self):
        """Create / chmod share directories via the helper. Returns a list of error strings."""
        if not self.pending_fs:
            return []
        ops = list(self.pending_fs.values())
        self.pending_fs.clear()
        try:
            return HELPER.call('apply_fs', ops=ops)
        except Exception as e:
            return [f"Could not create share directories: {e}"]

    def on_share_browse_clicked(self, widget):
        dialog = Gtk.FileDialog()
        dialog.select_folder(self.share_window, None, self.on_folder_selected)

    def on_folder_selected(self, dialog, result):
        try:
            folder = dialog.select_folder_finish(result)
            if folder:
                self.builder.get_object("share_entry_path").set_text(folder.get_path())
        except GLib.Error:
            pass

    # -- valid users picker -------------------------------------------------

    def on_share_pick_valid_clicked(self, widget):
        current = []
        for token in parse_user_list(self.builder.get_object("share_entry_valid_users").get_text()):
            name = unquote_user(token)
            if name not in current:
                current.append(name)

        candidates = sorted(set(model_values(self.store_users)))
        candidates += [f"@{g}" for g in SambaUserManager.get_system_groups()]
        avail = [(u,) for u in candidates if u not in current]
        selected = [(u,) for u in candidates if u in current]
        selected += [(u,) for u in current if u not in candidates]   # unknown users / other prefixes
        fill_store(self.store_vu_avail, avail)
        fill_store(self.store_vu_sel, selected)
        self.builder.get_object("vu_entry_custom").set_text("")

        self.builder.get_object("valid_users_window").present()

    def vu_filter_func(self, item, *args):
        query = self.builder.get_object("vu_search").get_text().lower()
        return not query or query in item.values[0].lower()

    def vu_add_selected(self, widget):
        item = self.sel_vu_avail.get_selected_item()
        if item is None:
            return
        name = item.values[0]
        append_names(self.store_vu_sel, [name])
        pos = store_find(self.store_vu_avail, name)
        if pos >= 0:
            self.store_vu_avail.remove(pos)

    def vu_remove_selected(self, widget):
        item = self.sel_vu_sel.get_selected_item()
        if item is None:
            return
        name = item.values[0]
        append_names(self.store_vu_avail, [name])
        pos = store_find(self.store_vu_sel, name)
        if pos >= 0:
            self.store_vu_sel.remove(pos)

    def vu_add_all(self, widget):
        # Only rows visible through the search filter move; hidden ones stay available.
        moving = model_values(self.filter_vu_avail)
        moving_set = set(moving)
        remaining = [(n,) for n in model_values(self.store_vu_avail) if n not in moving_set]
        append_names(self.store_vu_sel, moving)
        fill_store(self.store_vu_avail, remaining)

    def vu_remove_all(self, widget):
        append_names(self.store_vu_avail, model_values(self.store_vu_sel))
        self.store_vu_sel.remove_all()

    def vu_add_custom(self, widget):
        """Add a name typed by hand, e.g. `alice`, `@staff`, `+unixgroup` or `&nisgroup`."""
        entry = self.builder.get_object("vu_entry_custom")
        name = unquote_user(entry.get_text().strip())
        if not name:
            return
        if ',' in name:
            self.show_alert("Error", "Add one name at a time (no commas).")
            return
        if name not in model_values(self.store_vu_sel):
            append_names(self.store_vu_sel, [name])
        pos = store_find(self.store_vu_avail, name)
        if pos >= 0:
            self.store_vu_avail.remove(pos)
        entry.set_text("")

    def on_valid_users_apply_clicked(self, widget):
        users = ", ".join(quote_user(n) for n in model_values(self.store_vu_sel))
        self.builder.get_object("share_entry_valid_users").set_text(users)
        self.builder.get_object("valid_users_window").close()

    # -- force user picker --------------------------------------------------

    def on_share_pick_force_clicked(self, widget):
        rows = [("(None / Do not force)",)] + [(u,) for u in SambaUserManager.get_system_users()]
        fill_store(self.store_fu, rows)
        self.builder.get_object("force_user_window").present()

    def fu_filter_func(self, item, *args):
        q = self.builder.get_object("fu_search").get_text().lower()
        v = item.values[0].lower()
        return not q or "(none" in v or q in v

    def on_fu_row_activated(self, view, position):
        self.sel_fu.set_selected(position)
        self.on_force_user_apply_clicked(None)

    def on_force_user_apply_clicked(self, widget):
        item = self.sel_fu.get_selected_item()
        user = ''
        if item is not None and not item.values[0].startswith("("):
            user = item.values[0]
        self.builder.get_object("share_entry_force_user").set_text(user)
        self.builder.get_object("force_user_window").close()

    # -- users --------------------------------------------------------------

    def refresh_users_list(self):
        try:
            users = SambaUserManager.get_users()
        except Exception as e:
            self.append_log(f"Could not list Samba users: {e}")
            users = []
        fill_store(self.store_users, [(u,) for u in users])

    def get_selected_user_name(self):
        item = self.sel_users.get_selected_item()
        return item.values[0] if item is not None else None

    def on_add_user_clicked(self, widget):
        self.open_password_dialog("")

    def on_change_password_clicked(self, widget):
        sel = self.get_selected_user_name()
        if sel:
            self.open_password_dialog(sel)

    def open_password_dialog(self, username):
        b = self.builder.get_object
        if not username:
            # smbpasswd -a only works for existing Unix accounts: offer exactly those.
            existing = set(model_values(self.store_users))
            candidates = [u for u in SambaUserManager.get_system_users()
                          if u != 'root' and u not in existing]
            if not candidates:
                self.show_alert("No eligible system users",
                                "Every regular system account already has a Samba user.\n\n"
                                "Create the Unix account first (e.g. 'sudo adduser NAME'), "
                                "then add it here.")
                return
            set_dropdown_items(b("pass_dropdown_user"), candidates)
        b("password_window").set_title('Set User Password' if username else 'Add Samba User')
        b("pass_entry_user").set_text(username)
        b("pass_entry_user").set_visible(bool(username))
        b("pass_dropdown_user").set_visible(not username)
        b("pass_entry_pass").set_text("")
        b("pass_entry_confirm").set_text("")
        b("password_window").present()

    def on_password_save_clicked(self, widget):
        b = self.builder.get_object
        if b("pass_entry_user").get_visible():
            user = b("pass_entry_user").get_text().strip()
        else:
            user = dropdown_text(b("pass_dropdown_user"))
        pw1 = b("pass_entry_pass").get_text()
        pw2 = b("pass_entry_confirm").get_text()
        if not user:
            self.show_alert("Error", "Username cannot be empty.")
            return
        if not pw1:
            self.show_alert("Error", "Password cannot be empty.")
            return
        if pw1 != pw2:
            self.show_alert("Error", "Passwords do not match.")
            return
        try:
            SambaUserManager.set_password(user, pw1)
        except Exception as e:
            self.show_alert("Error", str(e))
            return
        self.refresh_users_list()
        self.show_alert("Success", f"Password set for {user}.")
        b("password_window").close()

    def on_delete_user_clicked(self, widget):
        sel = self.get_selected_user_name()
        if not sel:
            return
        dialog = Gtk.AlertDialog(message="Confirm Deletion", detail=f"Delete user '{sel}'?",
                                 buttons=["Cancel", "Delete"])
        dialog.set_cancel_button(0)
        dialog.choose(self.window, None, self.on_delete_user_confirm, sel)

    def on_delete_user_confirm(self, dialog, result, sel):
        if self._choose_finish(dialog, result) == 1:
            try:
                SambaUserManager.delete_user(sel)
                self.refresh_users_list()
            except Exception as e:
                self.show_alert("Error", str(e))

    # -- saving -------------------------------------------------------------

    def on_save_clicked(self, widget):
        b = self.builder.get_object

        # Security: user-level unless the file used something else and the user kept it.
        sec_val = None if (self.keep_security and dropdown_index(b("combo_security")) == 1) else "user"

        map_idx = dropdown_index(b("combo_map_guest"))
        map_val = {0: "Never", 1: "Bad User", 2: "Bad Password"}.get(map_idx)   # 3 = keep existing

        guest_acc = b("entry_guest_account").get_text().strip() or 'nobody'
        try:
            pwd.getpwnam(guest_acc)
        except KeyError:
            self.show_alert("Error", f"Guest account user '{guest_acc}' does not exist on this system.")
            return False

        self.handler.update_global_settings(
            b("entry_workgroup").get_text().strip() or 'WORKGROUP',
            b("entry_server_string").get_text().strip() or 'Samba Server',
            sec_val, map_val, guest_acc
        )

        try:
            result = self.handler.save_config()
        except Exception as e:
            self.show_alert("Error", f"Could not save configuration:\n\n{e}")
            return False

        self.unsaved_changes = False
        fs_errors = self.apply_pending_fs()
        self.refresh_shares_list()

        try:
            reload_res = HELPER.call('reload_conf')
        except Exception as e:
            reload_res = {'status': 'failed', 'detail': str(e)}
        status, detail = reload_res['status'], reload_res['detail']
        if status == 'not_running':
            reload_msg = "\n\nNote: Samba daemon is not running. Start the service manually from the Control tab."
        elif status == 'ok':
            reload_msg = "\n\nSamba configuration reloaded successfully."
        elif status == 'missing':
            reload_msg = "\n\nNote: 'smbcontrol' not found. Cannot auto-reload."
        elif status == 'timeout':
            reload_msg = "\n\nWarning: 'smbcontrol' timed out. Restart manually."
        else:
            reload_msg = "\n\nWarning: reloading the configuration failed. Restart manually." + \
                         (f"\n{detail}" if detail else "")

        message = f"File written successfully to: {self.handler.filepath}"
        if result.get('backup'):
            message += f"\nBackup: {result['backup']}"
        message += reload_msg
        if result.get('warnings'):
            message += "\n\ntestparm warnings:\n" + result['warnings']
        if fs_errors:
            message += "\n\nDirectory problems:\n" + "\n".join(fs_errors)

        # Silent on success when called from the close dialog, but never hide errors.
        if widget is not None or fs_errors:
            self.show_alert("Saved" if not fs_errors else "Saved with warnings", message)
        return True


def main():
    if '--helper' in sys.argv[1:]:
        helper_main()
        return
    if ConfigUpdater is None:
        print("Error: The 'configupdater' module is missing.")
        print("Please install it via: pip install configupdater --break-system-packages")
        sys.exit(1)
    if os.geteuid() != 0 and shutil.which('pkexec') is None:
        show_fatal_dialog_and_exit(
            "Administrator access unavailable",
            "pkexec (polkit) was not found, so this program cannot get the rights it needs.\n\n"
            "Install polkit, or launch the program as root:\n"
            f"sudo -E python3 {os.path.abspath(__file__)}")
    app = SambaManagerApp()
    sys.exit(app.run(None))


if __name__ == '__main__':
    main()