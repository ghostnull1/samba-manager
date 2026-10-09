# Changelog

## 2026-10-08

### Changed
- The GUI can now run as a normal user. Root-only work (saving `smb.conf`, `smbpasswd`/`pdbedit`, service control, share directory creation, config reload) goes through a `pkexec` helper (`app.py --helper`) that is started once per session. Running the whole app as root still works.
- `create mask` / `directory mask` are written by default. The new **Force Permissions** switch controls `force create mode` / `force directory mode`. Existing masks are only rewritten when changed in the dialog.
- Add User uses a type-ahead field instead of a list of every account, and validates the typed name on save.
- `Gtk.ComboBoxText` replaced by `Gtk.DropDown`. The Security dropdown is greyed out when it has a single option.
- Service status is polled in a background thread (uses `systemctl is-active` when systemd is running).
- Reload success is decided by exit status; `testparm` warnings are shown in the save dialog.
- The Dir Perms column shows `directory mask` (or the directory's real mode) instead of `create mask`.

### Added
- Valid Users picker lists system groups as `@group` and accepts typed names (`@group`, `+group`, `&netgroup`).
- Inline warning when a share path is missing, not a directory, or not absolute.
- Open Folder button now opens the share path in the file manager.

### Fixed
- `read only` now defaults to yes when unset, as in Samba. Editing a share no longer silently makes it writable.
- Blank lines are only added before sections the app creates, so comments above existing sections stay attached.
- New share directories (and missing parents) are created with the right mode and the leaf is chowned to the force user.
