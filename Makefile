PREFIX ?= /usr/local
DATADIR ?= /usr/share

install:
	mkdir -p /opt/samba_manager
	cp src/app.py src/samba_manager.ui /opt/samba_manager/
	chmod +x /opt/samba_manager/app.py
	ln -sf /opt/samba_manager/app.py $(PREFIX)/bin/samba-manager
	cp desktop/samba-manager.desktop $(DATADIR)/applications/
	update-desktop-database -q
	@echo "Installation complete!"

uninstall:
	rm -rf /opt/samba_manager
	rm -f $(PREFIX)/bin/samba-manager
	rm -f $(DATADIR)/applications/samba-manager.desktop
	update-desktop-database -q
	@echo "Uninstallation complete!"
