
Debian
====================
This directory contains files used to package merakid/meraki-qt
for Debian-based Linux systems. If you compile merakid/meraki-qt yourself, there are some useful files here.

## meraki: URI support ##


meraki-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install meraki-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your meraki-qt binary to `/usr/bin`
and the `../../share/pixmaps/dash128.png` to `/usr/share/pixmaps`

meraki-qt.protocol (KDE)

