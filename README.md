# Wemo Switch Repair Tool

CLI utility to recover and re-provision Wemo switches using `pywemo` on Windows.

## Features

- Scan nearby Wi-Fi networks
- Select Wemo setup SSID
- Select destination Wi-Fi SSID
- Enter destination Wi-Fi password with double-entry confirmation
- Set Wemo device name before provisioning
- Review screen with optional password reveal (`P`)
- Global quit support (`Q`) with confirmation
- Best-effort pre-launch network state restore on exit
- `-simulate` modes for safe dry runs
- Timestamped run logs

## Requirements

- Windows 10/11
- Python 3.11+ (tested with 3.13)
- A Wi-Fi adapter supported by Windows WLAN APIs
- Wemo device in setup mode

## Install

Create a folder for the tool:

```powershell
New-Item -ItemType Directory -Path C:\Users\{userid}\BelkinSucks -Force
Set-Location C:\Users\{userid}\BelkinSucks
```

Copy `FixBrokenWemo.py`, `requirements.txt`, and this README into that folder, then run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Important: run from the project environment. A fresh PowerShell window in another directory will fail with `ModuleNotFoundError` unless you use the project `.venv` interpreter.

Option A (recommended): change to project directory and activate `.venv` first.

```powershell
Set-Location C:\Users\{userid}\BelkinSucks
.\.venv\Scripts\Activate.ps1
```

Option B: run directly with the `.venv` Python path from any directory.

```powershell
C:\Users\{userid}\BelkinSucks\.venv\Scripts\python.exe C:\Users\{userid}\BelkinSucks\FixBrokenWemo.py
```

Normal run:

```powershell
python .\FixBrokenWemo.py
```

Debug run (verbose console output):

```powershell
python .\FixBrokenWemo.py -debug
```

Simulation modes:

```powershell
python .\FixBrokenWemo.py -simulate success
python .\FixBrokenWemo.py -simulate fail-once -debug
```

Custom log file path:

```powershell
python .\FixBrokenWemo.py -log C:\temp\wemo_repair.log
```

Console-only mode (no log file):

```powershell
python .\FixBrokenWemo.py -log NOLOG
```

From any directory without activating `.venv`:

```powershell
C:\Users\{userid}\BelkinSucks\.venv\Scripts\python.exe C:\Users\{userid}\BelkinSucks\FixBrokenWemo.py -log NOLOG
```

## Prompt flow

1. Select Wemo Wi-Fi
	- If no SSID appears to contain `Wemo`/`Belkin`, a warning is shown above the list.
    - `Wemo`/`Belkin` SSID's are tagged (possible wemo)
2. Select Destination Wi-Fi
3. Enter Destination password twice (masked)
4. Enter Wemo device name
5. Review settings and confirm (`Y/N/P`, where `P` reveals password)

## Notes

- Wemo setup can return uncertain status (`status=3`) even when configuration succeeds. The tool treats this as likely success and reports accordingly.
- Destination Wi-Fi password is not validated prior to programming the Wemo.
- By default, output is logged to timestamped files: `wemo_repair_YYYYMMDD_HHMMSS.log`.
- `-log <full path>` writes logs to a custom file location.
- `-log NOLOG` disables file logging and prints to console only.
- In `-log NOLOG` mode, startup shows a warning that verbose `pywemo` failure messages may appear on console. These do not necessarily reflect an actual failure and are part of the normal processing, and are normally supressed and/or sent to the log file only for debugging. They appear in NOLOG because you would never be able to see any actual issues if they remained supressed.
- Each run writes clear start/end markers (with elapsed time) to make appended log files easier to read.

## Troubleshooting

- If setup fails, rerun with `-debug` and inspect the latest log file.
- If wrong Wi-Fi credentials were provisioned, factory reset the Wemo and run the tool again.
- If you get `ModuleNotFoundError: No module named 'pywemo'`, you are not using the project `.venv` Python interpreter.

## Project files

- `FixBrokenWemo.py` — main CLI script
- `requirements.txt` — Python dependencies
- `.gitignore` — git ignores for virtualenv, logs, cache files

## Acknowledgments

This tool is a wrapper workflow built on top of the excellent `pywemo` project.

- `pywemo` (core Wemo discovery/control/setup library): https://github.com/pywemo/pywemo
- Huge thanks to the `pywemo` maintainers and contributors for making this repair workflow possible.

## Disclaimer

Use at your own risk. Validate behavior in your network environment before production use.

## Private Message to Belkin

I don't mind that you shut it all down. Business is business, I get it, but PLEASE open source the firmware so those of us with 30+ Wemo devices and BELIEVED in you, can at least maintain them. Thank you. If you do this I'll officially remove "BelkinSucks" from the sample path.
