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
  * Python 3 with PyGObject and GTK >= 4.10 (Gtk.AlertDialog / Gtk.FileDialog)
  * configupdater  (pip install configupdater --break-system-packages)
  * Samba tools on PATH: testparm, smbpasswd, pdbedit, smbcontrol
  * samba_manager.ui next to this file
  * Must run as root, e.g.:  sudo -E python3 /opt/samba_manager/app.py
    (-E keeps DISPLAY / WAYLAND_DISPLAY / XDG_RUNTIME_DIR so GTK can open a window)

Lists use Gtk.ColumnView on Gio.ListStore models. The columns are created in
Python; samba_manager.ui only declares the GtkColumnView widgets.
"""

import os
import re
import sys
import glob
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import pwd

import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, Gio, GLib, GObject, Pango, Gdk

if (Gtk.get_major_version(), Gtk.get_minor_version()) < (4, 10):
    print("Error: GTK 4.10 or newer is required (Gtk.AlertDialog / Gtk.FileDialog).")
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


# ---------------------------------------------------------------------------
# List helpers (Gtk.ColumnView + Gio.ListStore)
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


# ---------------------------------------------------------------------------
# Root warning
# ---------------------------------------------------------------------------

def show_root_warning_and_exit():
    """Displays a graphical error dialog when launched without root, then exits."""
    app = Gtk.Application(application_id='com.samba.manager.rootwarning')

    def on_activate(app):
        window = Gtk.ApplicationWindow(application=app)
        window.set_title("Root Privileges Required")
        window.set_default_size(460, 190)
        window.set_resizable(False)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(20)
        box.set_margin_end(20)
        box.set_margin_top(20)
        box.set_margin_bottom(20)

        script = os.path.abspath(__file__)
        label = Gtk.Label(
            label="Hey, you need to run this as root!\n\n"
                  "Samba Share Configuration Manager requires administrator rights "
                  "to manage shares and services.\n\n"
                  "Please launch it using:\n"
                  f"sudo -E python3 {script}\n\n"
                  "(-E keeps your display environment so the window can open.)"
        )
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
    def is_running():
        try:
            for pid in os.listdir('/proc'):
                if pid.isdigit():
                    try:
                        with open(f'/proc/{pid}/comm', 'r') as f:
                            if f.read().strip() == 'smbd':
                                return True
                    except (FileNotFoundError, PermissionError, ProcessLookupError):
                        continue
        except Exception:
            pass

        try:
            if subprocess.run(['pgrep', '-x', 'smbd'], capture_output=True).returncode == 0:
                return True
        except FileNotFoundError:
            pass
        return False

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
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
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
# Samba users
# ---------------------------------------------------------------------------

class SambaUserManager:
    @staticmethod
    def get_users():
        try:
            res = subprocess.run(['pdbedit', '-L'], capture_output=True, text=True, check=True)
            return [line.split(':')[0] for line in res.stdout.splitlines() if line.strip()]
        except Exception:
            return []

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
    def set_password(username, password):
        if not USERNAME_RE.match(username or ''):
            raise ValueError("Invalid username. Use letters, digits, '_', '.', '-' "
                             "and do not start with '-' or '.'.")
        if not password:
            raise ValueError("Password cannot be empty.")
        if '\n' in password or '\r' in password:
            raise ValueError("Password cannot contain line breaks.")
        try:
            res = subprocess.run(['smbpasswd', '-a', '-s', username],
                                 input=f"{password}\n{password}\n",
                                 capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError("'smbpasswd' was not found. Is Samba installed?")
        if res.returncode != 0:
            raise RuntimeError((res.stderr or res.stdout).strip() or "Failed to set password.")

    @staticmethod
    def delete_user(username):
        try:
            res = subprocess.run(['smbpasswd', '-x', username], capture_output=True, text=True)
        except FileNotFoundError:
            raise RuntimeError("'smbpasswd' was not found. Is Samba installed?")
        if res.returncode != 0:
            raise RuntimeError((res.stderr or res.stdout).strip() or "Failed to delete user.")


# ---------------------------------------------------------------------------
# smb.conf handling
# ---------------------------------------------------------------------------

class SambaConfigHandler:
    def __init__(self, filepath=DEFAULT_CONF_PATH):
        self.filepath = filepath
        self.load_error = None
        self.is_new_file = False
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
            # Do not silently fall back to ./smb.conf. Start from defaults and
            # create the real file only when the user saves.
            self.is_new_file = True
            self.updater.add_section('global')
            sec = self.updater['global']
            for key, val in (('workgroup', 'WORKGROUP'), ('server string', 'Samba Server'),
                             ('security', 'user'), ('map to guest', 'Bad User'),
                             ('guest account', 'nobody')):
                self._set_option(sec, key, val)

    def _render(self):
        lines = str(self.updater).splitlines()
        out = []
        for line in lines:
            # Keep the user's formatting, comments and continuation lines intact;
            # only make sure newly added sections are separated by a blank line.
            if (line.lstrip().startswith('[') and out and out[-1].strip() != ''
                    and not out[-1].rstrip().endswith('\\')):
                out.append('')
            out.append(line)
        return '\n'.join(out).rstrip('\n') + '\n'

    @staticmethod
    def _validate(tmp_path):
        """Run `testparm -s` on the candidate file. Raises if Samba rejects it."""
        try:
            res = subprocess.run(['testparm', '-s', tmp_path], capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=30)
        except FileNotFoundError:
            return  # testparm not installed: cannot validate
        if res.returncode != 0:
            detail = (res.stderr or res.stdout).strip()[:1500]
            raise RuntimeError("testparm rejected the new configuration; nothing was written.\n\n" + detail)

    @staticmethod
    def _backup(target):
        backup = f"{target}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
        shutil.copy2(target, backup)
        backups = sorted(glob.glob(glob.escape(target) + '.bak-*'))
        for old in backups[:-MAX_BACKUPS]:
            try:
                os.remove(old)
            except OSError:
                pass
        return backup

    def save_config(self):
        """Atomically write smb.conf: temp file -> testparm -> backup -> replace.

        Returns the backup path, or None if there was no previous file.
        """
        content = self._render()
        target = os.path.realpath(self.filepath)
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

            self._validate(tmp)

            backup = self._backup(target) if os.path.exists(target) else None
            os.replace(tmp, target)
        except Exception:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        self.is_new_file = False
        return backup

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
        """Set (str), remove (None) or leave alone (don't call) an option.

        Aliases of the same parameter are removed so no conflicting duplicates remain.
        """
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
            self.updater.add_section('global')
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
                            old_name=None):
        """Create or update a share in place.

        Unknown ("custom") options, comments and position are preserved.
        dir_perms / file_perms: None = leave existing masks untouched, '' = remove, str = set.
        old_name: set when renaming; all options are carried over to the new section.
        """
        if old_name and old_name != share_name and old_name in self.updater:
            if share_name not in self.updater:
                self.updater.add_section(share_name)
                old_sec = self.updater[old_name]
                new_sec = self.updater[share_name]
                for key in list(old_sec.keys()):
                    val = old_sec[key].value
                    new_sec[key] = val if val is not None else ''
            self.updater.remove_section(old_name)
        elif share_name not in self.updater:
            self.updater.add_section(share_name)

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
            self._set_option(sec, 'force create mode', file_perms or None)
        if dir_perms is not None:
            self._set_option(sec, 'directory mask', dir_perms or None)
            self._set_option(sec, 'force directory mode', dir_perms or None)

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
        self.pending_fs = {}              # share name -> deferred directory create/chmod
        self.current_edit_share = ''
        self._initial_dir_idx = 0
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

        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(b"""
            popover, popover contents, popover listview {
                min-height: 0px;
                padding: 2px;
            }
            popover contents list {
                background-color: @theme_bg_color;
            }
        """)
        display = Gdk.Display.get_default()
        if display:
            Gtk.StyleContext.add_provider_for_display(
                display,
                css_provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

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
        self.refresh_users_list()
        self.check_daemon_status()
        GLib.timeout_add_seconds(2, self.check_daemon_status)

        self.unsaved_changes = False
        self.update_statusbar()
        self.window.present()

        if self.handler.is_new_file:
            self.show_alert(
                "Configuration file not found",
                f"{self.handler.filepath} does not exist.\n\n"
                "Starting from default settings. The file will be created when you save.")

    def setup_ui_bindings(self):
        b = self.builder.get_object
        b("entry_workgroup").connect("changed", self.mark_unsaved)
        b("entry_server_string").connect("changed", self.mark_unsaved)
        b("entry_guest_account").connect("changed", self.mark_unsaved)
        b("combo_security").connect("changed", self.mark_unsaved)
        b("combo_map_guest").connect("changed", self.mark_unsaved)
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

        combo_sec = b("combo_security")
        combo_sec.remove_all()
        for item in security_items:
            combo_sec.append_text(item)
        combo_sec.set_active(1 if self.keep_security else 0)

        # Map to guest: same idea for values the UI does not offer (e.g. "Bad Uid").
        map_items = ["Never (No guest access)", "Bad User (Standard fallback)", "Bad Password"]
        cmap = str(glob_settings.get('map to guest', 'Never')).strip().lower()
        self.keep_map_guest = cmap not in ('', 'never', 'bad user', 'bad password')
        if self.keep_map_guest:
            map_items.append(f"Keep existing: map to guest = {glob_settings.get('map to guest')}")

        combo_map = b("combo_map_guest")
        combo_map.remove_all()
        for item in map_items:
            combo_map.append_text(item)

        b("entry_workgroup").set_text(glob_settings.get('workgroup') or 'WORKGROUP')
        b("entry_server_string").set_text(glob_settings.get('server string') or 'Samba Server')
        b("entry_guest_account").set_text(glob_settings.get('guest account') or 'nobody')

        if self.keep_map_guest:
            combo_map.set_active(3)
        elif cmap == 'bad user':
            combo_map.set_active(1)
        elif cmap == 'bad password':
            combo_map.set_active(2)
        else:
            combo_map.set_active(0)

        combo_file = b("share_combo_file_perms")
        combo_file.remove_all()
        for label in FILE_MASK_LABELS:
            combo_file.append_text(label)

        combo_dir = b("share_combo_dir_perms")
        combo_dir.remove_all()
        for label in DIR_MASK_LABELS:
            combo_dir.append_text(label)

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
        b("share_btn_pick_valid").connect("clicked", self.on_share_pick_valid_clicked)
        b("share_btn_pick_force").connect("clicked", self.on_share_pick_force_clicked)

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
        b = self.builder.get_object
        running = SambaServiceManager.is_running()
        if running:
            self.lbl_status_val.set_markup("<span foreground='green' weight='bold'>Running</span>")
        else:
            self.lbl_status_val.set_markup("<span foreground='red' weight='bold'>Stopped</span>")

        # While an action runs the buttons stay disabled; the timer must not re-enable them.
        if not self.action_in_progress:
            b("btn_start").set_sensitive(not running)
            b("btn_stop").set_sensitive(running)
            b("btn_restart").set_sensitive(running)
        return True

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
                success, log_output = SambaServiceManager.execute(action)
            except Exception as e:
                success, log_output = False, f"Unexpected error: {e}"

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
            dir_perms = d.get('directory mask') or d.get('create mask')
            if not dir_perms and path and os.path.exists(path):
                try:
                    dir_perms = f"{os.stat(path).st_mode & 0o777:04o}"
                except Exception:
                    pass
            mode_str = dir_perms or 'N/A'
            rows.append((
                share, str(path or 'N/A'),
                'Yes' if to_bool(d.get('read only'), False) else 'No',
                'Yes' if to_bool(d.get('guest ok'), False) else 'No',
                d.get('valid users', '') or 'All', mode_str
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
        b("share_switch_readonly").set_active(to_bool(data.get('read only'), False))
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

        b("share_combo_file_perms").set_active(f_idx)
        b("share_combo_dir_perms").set_active(d_idx)
        self._initial_dir_idx = d_idx

        b("share_window").present()

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

        file_idx = b("share_combo_file_perms").get_active()
        dir_idx = b("share_combo_dir_perms").get_active()
        if file_idx < 0:
            file_idx = len(FILE_MASKS)
        if dir_idx < 0:
            dir_idx = len(DIR_MASKS)
        file_perms = FILE_MASKS[file_idx] if file_idx < len(FILE_MASKS) else None   # None = custom
        dir_perms = DIR_MASKS[dir_idx] if dir_idx < len(DIR_MASKS) else None

        # Filesystem changes are deferred until smb.conf is actually saved.
        self.pending_fs.pop(editing, None)
        self.pending_fs.pop(name, None)
        if path and not special:
            self.pending_fs[name] = {
                'path': path,
                'mode': int(dir_perms, 8) if dir_perms else None,
                # Only touch an existing directory if the user changed the dropdown.
                'chmod_existing': dir_perms is not None and dir_idx != self._initial_dir_idx,
            }

        self.handler.add_or_update_share(
            name, path, b("share_entry_comment").get_text().strip(),
            b("share_switch_readonly").get_active(), b("share_switch_browseable").get_active(),
            b("share_switch_guest").get_active(), b("share_entry_valid_users").get_text().strip(),
            b("share_entry_force_user").get_text().strip(), dir_perms, file_perms,
            old_name=editing or None
        )
        self.mark_unsaved()
        self.refresh_shares_list()
        b("share_window").close()

    def apply_pending_fs(self):
        """Create / chmod share directories. Returns a list of error strings."""
        errors = []
        for share, op in list(self.pending_fs.items()):
            path, mode = op['path'], op['mode']
            try:
                if os.path.exists(path) and not os.path.isdir(path):
                    raise NotADirectoryError("exists but is not a directory")
                if not os.path.isdir(path):
                    os.makedirs(path, exist_ok=True)
                    os.chmod(path, mode if mode is not None else 0o755)   # makedirs(mode=) is umask-filtered
                elif op['chmod_existing'] and mode is not None:
                    os.chmod(path, mode)
            except Exception as e:
                errors.append(f"[{share}] {path}: {e}")
        self.pending_fs.clear()
        return errors

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

        all_users = sorted(set(SambaUserManager.get_users()))
        avail = [(u,) for u in all_users if u not in current]
        selected = [(u,) for u in all_users if u in current]
        selected += [(u,) for u in current if u not in all_users]   # @groups and unknown users
        fill_store(self.store_vu_avail, avail)
        fill_store(self.store_vu_sel, selected)

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
        fill_store(self.store_users, [(u,) for u in SambaUserManager.get_users()])

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
        b("password_window").set_title('Set User Password' if username else 'Add Samba User')
        b("pass_entry_user").set_text(username)
        b("pass_entry_user").set_sensitive(not bool(username))
        b("pass_entry_pass").set_text("")
        b("pass_entry_confirm").set_text("")
        b("password_window").present()

    def on_password_save_clicked(self, widget):
        b = self.builder.get_object
        user = b("pass_entry_user").get_text().strip()
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
        sec_val = None if (self.keep_security and b("combo_security").get_active() == 1) else "user"

        map_idx = b("combo_map_guest").get_active()
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
            backup = self.handler.save_config()
        except Exception as e:
            self.show_alert("Error", f"Could not save configuration:\n\n{e}")
            return False

        self.unsaved_changes = False
        fs_errors = self.apply_pending_fs()
        self.refresh_shares_list()

        if not SambaServiceManager.is_running():
            reload_msg = "\n\nNote: Samba daemon is not running. Start the service manually from the Control tab."
        else:
            try:
                result = subprocess.run(['smbcontrol', 'all', 'reload-config'],
                                        capture_output=True, text=True, timeout=30)
                if result.returncode != 0 or any(err in (result.stdout + result.stderr).lower()
                                                 for err in ["not found", "failed"]):
                    reload_msg = "\n\nWarning: 'smbcontrol' failed to reload config. Restart manually."
                else:
                    reload_msg = "\n\nSamba configuration reloaded successfully."
            except FileNotFoundError:
                reload_msg = "\n\nNote: 'smbcontrol' not found. Cannot auto-reload."
            except subprocess.TimeoutExpired:
                reload_msg = "\n\nWarning: 'smbcontrol' timed out. Restart manually."

        message = f"File written successfully to: {self.handler.filepath}"
        if backup:
            message += f"\nBackup: {backup}"
        message += reload_msg
        if fs_errors:
            message += "\n\nDirectory problems:\n" + "\n".join(fs_errors)

        # Silent on success when called from the close dialog, but never hide errors.
        if widget is not None or fs_errors:
            self.show_alert("Saved" if not fs_errors else "Saved with warnings", message)
        return True


def main():
    if os.geteuid() != 0:
        show_root_warning_and_exit()      # exits
    if ConfigUpdater is None:
        print("Error: The 'configupdater' module is missing.")
        print("Please install it via: pip install configupdater --break-system-packages")
        sys.exit(1)
    app = SambaManagerApp()
    sys.exit(app.run(None))


if __name__ == '__main__':
    main()