# Samba Manager

Modern GTK 4 graphical interface for managing Samba shares and users, tailored specifically for containerized Linux environments.

## Purpose & Environment
Samba Manager is designed to run inside **Termux PRoot-Distro (Debian)** on Android. It provides a native GTK 4 interface to manage file sharing directly on your device, bypassing the need for host device rooting or full Linux desktop init stacks. It also runs on a regular Linux desktop.

**Requirements:** GTK **4.10 or newer** (the app uses `Gtk.AlertDialog`, `Gtk.FileDialog`, `Gtk.FileLauncher` and `Gtk.DropDown`). On startup it checks the GTK version and exits with a clear message if it is too old.

## Visual Interface Overview

Here is a look at Samba Manager's interface across its primary tabs:

* **Shares Management Tab:** View, add, edit, or delete shares, file paths, read-only status, guest access permissions, valid users, and directory masks.
  ![Shares Tab](images/Screenshot_2026-10-06_09-01-53.png)
* **Edit Share Dialog:** Fine-tune individual share parameters including share name, target directory path (with an inline warning if it is missing or not a directory), comments, access toggles, file/directory masks, an optional **Force Permissions** switch, valid users (users and groups), and force user mappings. **Open Folder** opens the path in your file manager.
  ![Edit Share](images/Screenshot_2026-10-06_09-02-53.png)
* **Global Settings Tab:** Configure server-wide options like workgroups, server strings, security modes, map-to-guest behaviors, and guest accounts.
  ![Global Settings](images/Screenshot_2026-10-06_09-03-20.png)
* **Samba Users Tab:** Add local Samba accounts (type-ahead field, see below), modify user passwords, or delete users directly from the graphical list.
  ![Samba Users](images/Screenshot_2026-10-06_09-03-35.png)
* **Service Control Tab:** Monitor live daemon status (`Running`), start, stop, or restart the service, and review step-by-step execution logs.
  ![Service Control](images/Screenshot_2026-10-06_09-04-01.png)

## Architecture & Security Model
To keep configuration predictable, lightweight, and container-friendly, Samba Manager enforces key security defaults in `/etc/samba/smb.conf`:

- **User Security (`security = user`):** Security is set to `user` mode. Other Samba auth modes (`ADS`, `DOMAIN`, `SERVER`) are not offered. If an existing `smb.conf` already uses a different mode, the app shows a "Keep existing" choice so saving never silently overwrites it. When user-level is the only option, the Security dropdown is greyed out because there is nothing to choose. All share access relies exclusively on local Samba user accounts managed via `smbpasswd` and `pdbedit`.
- **Configurable Guest Account:** Guest and anonymous access can be configured directly from the Global Settings tab (defaulting to `nobody` with system user validation).
- **Direct Daemon Management:** Does not rely on `systemctl` in PRoot. Starting tries `service`, the init script, then `smbd -D` directly, clearing stale PID files in `/var/run/samba` first and reading `/proc` to check process status. The app waits up to 8 seconds for the daemon to reach the expected state, stops after the first method that succeeds (so a second `smbd` is never launched), and falls back to signalling `smbd` directly if `pkill` is unavailable. On systems where systemd is actually running (a normal desktop), the status display asks `systemctl is-active` instead. Status is polled in a background thread, so the window never stalls.
- **Automated Config Reloads:** Reloads running configuration changes on save via `smbcontrol all reload-config`. Whether the reload worked is decided by the command's exit status, and the result (or a "daemon not running" note) is shown in the save dialog.

### Privileges
Everything that needs root (writing `smb.conf`, `smbpasswd` / `pdbedit`, service control, creating share directories, reloading) lives in one small privileged helper: `app.py --helper`.

- **Running as root (recommended in PRoot):** launch with `sudo -E python3 /opt/samba_manager/app.py`. The helper code then runs inside the same process and no extra prompt appears.
- **Running as a normal user (regular Linux desktop):** the window opens as you, and the helper is started through `pkexec` (polkit). You authenticate once at launch and the helper is reused for the rest of the session. Passwords are sent to it over a pipe, never on a command line. If `pkexec` is not installed the app says so and exits. `pkexec` is normally not available inside PRoot, so use the root launch there.
- **Limits of the helper:** it only ever writes `/etc/samba/smb.conf`, and only accepts the fixed set of operations the app uses.
- **Install permissions:** because `pkexec` runs `app.py` as root, keep `/opt/samba_manager` owned by root and not writable by other users. `sudo make install` does this.

### Safe saving
- `smb.conf` is written to a temporary file, validated with `testparm -s`, then swapped in atomically. If validation fails, nothing is written and the error is shown. Warnings that `testparm` prints even when the file is accepted are shown in the save dialog.
- Before each overwrite, a timestamped backup (`smb.conf.bak-YYYYmmdd-HHMMSS`) is kept next to the original; the 10 most recent are retained.
- Existing comments, formatting, unknown options and Samba parameter aliases (`writable`, `browsable`, `public`, ...) are preserved or normalised rather than duplicated. Sections the app creates are separated by a blank line; existing sections, and the comments sitting above them, are left exactly as they were.
- If `smb.conf` cannot be parsed, the app refuses to start editing it instead of risking an overwrite. If the file is missing, the app starts from defaults and creates it on save.

### Share directories
Creating a share directory or changing its permissions is deferred until you click **Save smb.conf**. An existing directory's mode is only changed if you explicitly pick a different directory mask. Masks the app does not recognise (for example `0775`) appear as "Custom / Do not change" and are left untouched.

When a new directory is created, it is owned by the share's **Force User** (and that user's primary group), so a share with `force user` is writable straight away. Missing parent directories are created too, with mode `0755`. If the force user does not exist, the directory is still created, owned by root, and you get a warning.

### Share defaults
- **Read Only:** a share with no `read only` setting is shown as read-only, matching Samba's own default. Editing and saving such a share keeps it read-only unless you switch it off.

### Permission masks
The dialog writes `create mask` and `directory mask` by default. The **Force Permissions** switch additionally writes `force create mode` and `force directory mode` with the same values, so new files and folders always have at least those bits (handy for group-shared folders). With it off, those two options are removed. Mask and force options already in the file are only rewritten if you change the masks or the switch in the dialog.

### Valid users and groups
The **Manage Users** picker builds the share's `valid users` line.

- The Available list shows your Samba users and the system's regular groups (GID 1000 and up, shown as `@groupname`).
- Type any name into the box at the bottom to add it by hand, for example `alice`, `@staff`, `+staff` or `&netgroup`.
- Meaning of the prefixes (from `smb.conf`): `@name` is looked up as a NIS netgroup first, then as a Unix group; `+name` means Unix group only; `&name` means NIS netgroup only.
- A group decides who is **allowed**. Each member still needs their own Samba user (with a password) to log in, and changes to group membership only affect connections made afterwards.
- Groups served by LDAP/AD with enumeration turned off will not appear in the list. Type `@groupname` by hand.

### Adding Samba users
**Add User** uses a text field with type-ahead: as you type it suggests up to 8 matching system accounts. Suggestions are only a convenience, so this works with very large directories (500+ accounts). When you save, the name is checked against the system: it must be an existing account (create it first, for example with `sudo adduser NAME`), it cannot be `root`, and it cannot already be a Samba user (use **Change Password** for those).

## Required PRoot Configuration: `force user = root`
PRoot emulates Linux namespaces via user-space translation over Android's file system storage. Because of UID/GID mapping boundaries between Android and the PRoot Debian container, network clients will often encounter **"Permission Denied"** errors when reading or writing to shared directories.

### How to configure shares in Samba Manager:
1. Open or edit your share in **Samba Manager**.
2. In the **Force User** field (or using the **Select User** button), set the user to **`root`**.
3. Save the share configuration.

Setting `force user = root` causes the background `smbd` process to evaluate file reads and writes with container-root permissions, bypassing UID/GID translation discrepancies across Android host storage.

## Dependencies
```bash
sudo apt update && sudo apt install -y samba smbclient python3-gi python3-gi-cairo gir1.2-gtk-4.0 python3-pip git make
pip install configupdater --break-system-packages
```
On a regular desktop where you do not launch the app as root, also install `pkexec` (polkit); it is not needed when running as root.

## Installation & Building

### 1. Clone the Repository
```bash
git clone https://github.com/ghostnull1/samba-manager.git
cd samba-manager
```

### 2. Build and Install
Samba Manager uses a Makefile to copy application files (`app.py` and `samba_manager.ui`) to `/opt/samba_manager`, create system command links, and register the desktop entry. Run the following command with root privileges:

```bash
sudo make install
```

### Running
Launch it from the desktop entry, or directly. As root (the `-E` keeps your `DISPLAY` so the window can open, for example under Termux:X11):

```bash
sudo -E python3 /opt/samba_manager/app.py
```

On a regular desktop with polkit you can also start it as your normal user and approve the administrator prompt:

```bash
python3 /opt/samba_manager/app.py
```

### Uninstallation
If you ever need to remove Samba Manager from your container environment, run:

```bash
sudo make uninstall
```