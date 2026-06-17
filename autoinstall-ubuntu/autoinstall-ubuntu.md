# Ubuntu Autoinstall Files
This directory contains autoinstall files for use with
the Ubuntu installation process.

There should be two autoinstall files for now in this
directory:

* `autoinstall-capt-ready.yml` which sets up a Xubuntu
   24.04 system capable of ruunning the original Canon
   CAPT driver, and,

* `autoinstall-dev.yml`, which sets up a system running
   the latest Ubuntu Budgie LTS release (currently 26.04),
   preinstalled with the development tools required to
   compile `captdriver`.

Both systems will have the tools to analyse and debug
CAPT printer drivers (official or alternative), such as
Wireshark, and a C compiler suite.

## Using This File
When prompted by the Ubuntu installer to choose between an
Interactive or an Automated installation, select Automated
Installation, and either:

1. Use the direct URL: https://github.com/mounaiban/studycapt/autoinstall-ubuntu/...

2. Run the command `python -m http.server --bind $IP_ADDRESS 9001`
   in the same directory as the autoinstall files.
   `$IP_ADDRESS` is the IP address of the host system, which is:
   
   * `127.0.0.1` or `::1` when setting up a physical system
     (bare metal),
   
   * The LAN IP address of the host system, when setting up on
     a virtual machine that is sharing a local network with the
     host.
    
   * If the IP address is `::1`, then the autoinstall URL is
     http://[::1]:9001/autoinstall-dev.yml or 
     http://[::1]:9001/autoinstall-capt-ready.yml


## Canon CAPT-Ready System: `autoinstall-capt-ready`
This autoinstall file prepares a Xubuntu 24.04 system which
has the necessary dependencies installed to run the official
Canon CAPT drivers. The drivers, as well as the web browser
must be installed manually after the Xubuntu installation
completes.

### Installing the Web Browser
The CAPT-ready system will not have a pre-installed
web browser. Please run any of the following commands
to install your preferred web browser:

```sh
snap install firefox
```

```sh
snap install chromium
```

### Downloading and Installing Canon Drivers
The official Canon drivers are not automatically downloaded
and installed, out of respect for the license terms and
conditions the Canon drivers.

Canon CAPT drivers are available in multiple forms from
multiple websites run by Canon's network of regional
subsidiaries and subcontractors. The most complete known
distribution is the [V2.71 CAPT Printer Driver package](https://in.canon/en/support/0100459601?model=4896B005),
which includes drivers for all known CAPT printer devices.

To install the drivers, extract the contents of the tarball
and navigate to the Debian directory to find the two Deb
packages.

#### Linux CAPT Driver 2.71 Details

* Filename: linux-capt-drv-v271-uken.tar.gz

* SHA256: 8565a2fdc4f452bb8cf97ceadadd6614d12eac73e253ac6d59e61b8abae941be

* BLAKE3/256: 1d0edfe68c1ab664773811b0c6e9d608b90a4523f4cdac4425c671923a09e2c8

### Printing via USB
After installing the official CAPT driver, run the following
commands to correctly add your printer to CUPS:

#### Adding the USB Printer to CUPS
With your printer device attached to the system and powered
on, run the following commands:

```sh
sudo lpadmin -v ccp://localhost:59687 -p $PRINTER_NAME -P /usr/share/cups/model/$PPD_FILE -E
sudo ccpdadmin -p $PRINTER_NAME -o $DEVICE_PATH
```
> **Captdriver users:** please note the different device URI

The correct PPD for your printer device contains the model
name in the filename. Where there are multiple PPD files for
a particular model, any should work as well as the other.

> If you can't decide, choose the "K" PPD file.

The device path is usually `/dev/usb/lp0` if there is only one
printer attached to the host system.

> PROTIP: avoid using any other `lp*` that is not under
  `/dev/usb`, or `ccpd` can't communicate with the printer!

#### Starting ccpd
The `ccpd` program is a port monitor daemon which communicates
with CAPT printers to check the device's status and to send
print jobs. Start `ccpd` by running:

```sh
sudo systemctl start ccpd
```

For now, the daemon has to be restarted on every reboot.
A means of autostarting `ccpd` using systemd unit files is
being investigated.

If `ccpd` fails to start, rebooting the system may help.

### Example: Setting Up a USB-Attached LBP7200
The process of setting up an LBP7200 may look like this:

```sh
# linux-capt-drv-v271-uken.tar.gz was downloaded into
# ~/Downloads earlier...
cd ~/Downloads
tar -xf linux-capt-drv-v271-uken.tar.gz
sudo dpkg -i linux-capt-drv-v271-uken/64-bit_Driver/Debian/*rpm
# (CAPT driver installs..)
sudo lpadmin -v ccp://localhost:59687 -p LBP7200 \
  -P /usr/share/cups/model/CNCUPSLBP7200CCAPTK.ppd -E
sudo ccpdadmin -p LBP7200 -o /dev/usb/lp0
# (after rebooting the system...)
sudo service ccpd start
# (to check on the printer...)
captstatusui -P LBP7200
# (you can now print from your apps...)
```

## Enabling USB Traffic Capture in Wireshark
Wireshark is installed by both autoinstall files. However,
the user must be added to the `wireshark` group to enable
capturing without the potentially dangerous practice of
running Wireshark as root:

```sh
sudo usermod -aG wireshark $(whoami)
```

Log out and back in for the group membership to take effect.

To enable USB traffic capture, run this command once
every reboot:

```sh
sudo modprobe usbmon && sudo setfacl -m u:${USER}:r /dev/usbmon*
```

Further configuration will be required to automatically
enable USB capture across reboots. For details on how to
do this ,please consult the [Wireshark documentation on](http://wiki.wireshark.org/CaptureSetup/USB).


## References
Le, Bao-Hiep. _Canon LBP printers drivers installer for Ubuntu._ [https://github.com/hieplpvip/ubuntu_canon_printer/blob/master/canon_lbp_setup.sh]
