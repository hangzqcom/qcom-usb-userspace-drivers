# Qualcomm USB Userspace Drivers
Qualcomm userspace drivers provides logical representations of Qualcomm chipset-enabled mobile devices over USB connection. The drivers support Windows & Linux environments.


## Key Features
  - Supports Windows and Linux platforms.
  - Supports X64/X86/ARM64 architectures.
  - Compatible with Qualcomm tools like QUTS, QXDM, QDL, and more.

## Repository Structure

```
/
├─ src/                        # Qualcomm USB userspace driver source root directory
│   ├── linux/                 # Linux userspace driver source
│   └── windows/               # Windows userspace driver source
│         ├── installer/       # Self-extracting installer (build scripts, C source)
│         └── ...              # Signed driver setup information (INF) and catalog files
├─ README.md                   # This file
└─ ...                         # Other files and directories
```

## Install / Uninstall

#### Windows — Self-Extracting Installer

The recommended way to install/manage drivers on Windows is the self-extracting
installer EXE produced by `src\windows\installer\package.bat`.

| Command | Description |
|---|---|
| `QcomUsbDriverInstaller.exe` | Install drivers (auto-upgrades if an older version is found) |
| `QcomUsbDriverInstaller.exe /query` | Query installed driver package name, version, and date |
| `QcomUsbDriverInstaller.exe /force` | Force install (bypass version check — reinstall or downgrade) |
| `QcomUsbDriverInstaller.exe /version` | Print installer version and exit |
| `QcomUsbDriverInstaller.exe /help` | Print usage help |

> **Note:** The installer requires Administrator privileges and will prompt for
> elevation automatically.

The installer records the installed version, INF list, and install date in the
registry at `HKLM\SOFTWARE\Qualcomm\QcomUsbDrivers`. On upgrade or `/force`
reinstall, it automatically uninstalls previously installed driver packages
before installing the new ones.

**Building the installer:**
```bat
cd src\windows\installer
package.bat
```
This produces `QcomUsbDriverInstaller_<version>.exe` in the current directory.

#### Windows — Manual Installation

- **Install:** Right-click the `.inf` file and select **Install**.

- **Uninstall (Device Manager):**
  1. Open **Device Manager**.
  2. Right-click the target device and select **Uninstall device**.
  3. Check **Attempt to remove the driver for this device**.
  4. Click **Uninstall**.

- **Uninstall (Command Line):**
  1. Locate the **Published Name** of the installed driver package:
     ```bat
     pnputil /enum-drivers
     ```
  2. Delete the driver from the system:
     ```bat
     pnputil /delete-driver oemxx.inf /uninstall /force
     ```
#### Linux command:
  Navigate to folder `src/linux`

- Installation
```bash
./qcom_userspace.sh install
```
- Uninstallation
```bash
./qcom_userspace.sh uninstall
```

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Make your changes and ensure they compile on all supported platforms.
4. Submit a pull request with a clear description of the changes.

Please follow the existing coding style and run the appropriate static analysis tools before submitting.

## Bug & Vulnerability reporting

Please review the [security](./SECURITY.md) before reporting vulnerabilities with the project

## Contributor's License Agreement

Please review the Qualcomm product [license](./LICENSE.txt), [code of conduct](./CODE-OF-CONDUCT.md) & terms
and conditions before contributing.

## Contact

For questions, bug reports, or feature requests, please open an issue on GitHub or contact the maintainers
