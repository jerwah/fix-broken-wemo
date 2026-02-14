from __future__ import annotations

import argparse
import getpass
import logging
import os
import subprocess
import sys
import time
import ctypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

import pywemo
from pywemo.exceptions import SetupException
from pywifi import PyWiFi, const
from pywifi.iface import Interface


@dataclass(frozen=True)
class WifiChoice:
	ssid: str
	is_open: bool


@dataclass
class PreLaunchState:
	connected_ssid: str | None


class UserQuit(Exception):
	pass


class WorkflowError(Exception):
	pass


SIMULATE_MODE_OFF = "off"
SIMULATE_MODE_SUCCESS = "success"
SIMULATE_MODE_FAIL_ONCE = "fail-once"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
_USE_COLOR: bool | None = None
_RUN_START_DT: datetime | None = None
_RUN_START_PERF: float | None = None


def _log_run_header(logger: logging.Logger) -> None:
	global _RUN_START_DT, _RUN_START_PERF
	_RUN_START_DT = datetime.now()
	_RUN_START_PERF = time.perf_counter()

	separator = "=" * 72
	logger.info(separator)
	logger.info("Start of FixBrokenWemo.py | %s", _RUN_START_DT.strftime("%Y-%m-%d %H:%M:%S"))
	logger.info(separator)


def _log_run_trailer(logger: logging.Logger) -> None:
	end_dt = datetime.now()
	elapsed = 0.0
	if _RUN_START_PERF is not None:
		elapsed = max(0.0, time.perf_counter() - _RUN_START_PERF)

	separator = "=" * 72
	logger.info(separator)
	logger.info(
		"End of FixBrokenWemo.py | %s | elapsed=%.2f seconds",
		end_dt.strftime("%Y-%m-%d %H:%M:%S"),
		elapsed,
	)
	logger.info(separator)


def supports_color() -> bool:
	global _USE_COLOR
	if _USE_COLOR is not None:
		return _USE_COLOR

	if os.getenv("NO_COLOR"):
		_USE_COLOR = False
		return _USE_COLOR

	if not sys.stdout.isatty():
		_USE_COLOR = False
		return _USE_COLOR

	if os.name != "nt":
		_USE_COLOR = True
		return _USE_COLOR

	try:
		kernel32 = ctypes.windll.kernel32
		handle = kernel32.GetStdHandle(-11)
		mode = ctypes.c_uint32()
		if handle == 0 or handle == -1:
			_USE_COLOR = False
			return _USE_COLOR
		if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
			_USE_COLOR = False
			return _USE_COLOR
		ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
		new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
		if kernel32.SetConsoleMode(handle, new_mode) == 0:
			_USE_COLOR = False
			return _USE_COLOR
		_USE_COLOR = True
		return _USE_COLOR
	except Exception:
		_USE_COLOR = False
		return _USE_COLOR


def resolve_log_path(log_option: str | None) -> Path | None:
	if not log_option:
		return Path.cwd() / f"wemo_repair_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

	if log_option.strip().upper() == "NOLOG":
		return None

	return Path(log_option).expanduser()


def validate_log_writable(log_path: Path) -> None:
	parent = log_path.parent
	if not parent.exists():
		raise WorkflowError(f"Log directory does not exist: {parent}")

	if not parent.is_dir():
		raise WorkflowError(f"Log parent path is not a directory: {parent}")

	try:
		with log_path.open("a", encoding="utf-8"):
			pass
	except Exception as exc:  # noqa: BLE001
		raise WorkflowError(f"Unable to write log file: {log_path} ({exc})") from exc


def setup_logging(debug: bool, log_option: str | None) -> logging.Logger:
	logger = logging.getLogger("wemo_repair")
	logger.setLevel(logging.DEBUG)
	logger.propagate = False
	logger.handlers.clear()

	log_path = resolve_log_path(log_option)
	file_handler: logging.Handler | None = None
	if log_path is not None:
		validate_log_writable(log_path)
		file_handler = logging.FileHandler(log_path, encoding="utf-8")
		file_handler.setLevel(logging.DEBUG)
		file_handler.setFormatter(
			logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s")
		)
		logger.addHandler(file_handler)

	console_handler = logging.StreamHandler(sys.stdout)
	console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
	console_handler.setFormatter(logging.Formatter("%(levelname)-7s | %(message)s") if debug else logging.Formatter("%(message)s"))
	logger.addHandler(console_handler)

	pywemo_logger = logging.getLogger("pywemo")
	pywemo_discovery_logger = logging.getLogger("pywemo.discovery")
	for external_logger in (pywemo_logger, pywemo_discovery_logger):
		external_logger.handlers.clear()
		external_logger.propagate = False
		external_logger.setLevel(logging.DEBUG)
		if file_handler is not None:
			external_logger.addHandler(file_handler)
		if debug:
			external_logger.addHandler(console_handler)

	_log_run_header(logger)

	if log_path is not None:
		logger.info("Log file: %s", log_path)
	else:
		logger.info("Logging mode: console only (NOLOG)")
		warning_lines = [
			"*** NO LOG MODE DETECTED - ALL MESSAGES WILL LOG TO CONSOLE (VERBOSE!) ***",
			" ** WHEN IN NOLOG MODE YOU MAY SEE FAILURES MESSAGES FROM PYWEMO **",
			"   * THIS IS NORMAL AND EXPECTED *",
		]
		for line in warning_lines:
			if supports_color():
				logger.warning(f"{RED}{line}{RESET}")
			else:
				logger.warning(line)
	return logger


def _run_netsh(args: list[str]) -> subprocess.CompletedProcess[str]:
	return subprocess.run(
		["netsh", *args],
		capture_output=True,
		text=True,
		check=False,
	)


def run_netsh(args: list[str]) -> str:
	completed = _run_netsh(args)
	return (completed.stdout or "") + (completed.stderr or "")


def _parse_netsh_interfaces(output: str) -> list[dict[str, str]]:
	interfaces: list[dict[str, str]] = []
	current: dict[str, str] = {}

	for raw_line in output.splitlines():
		line = raw_line.strip()
		if not line or ":" not in line:
			continue

		key, value = line.split(":", 1)
		normalized_key = key.strip().lower()
		normalized_value = value.strip()

		if normalized_key == "name" and current:
			interfaces.append(current)
			current = {}

		current[normalized_key] = normalized_value

	if current:
		interfaces.append(current)

	return interfaces


def _tail_lines(text: str, max_lines: int = 25) -> str:
	lines = text.splitlines()
	if len(lines) <= max_lines:
		return text.strip()
	return "\n".join(lines[-max_lines:]).strip()


def log_wifi_diagnostics(logger: logging.Logger, context: str, iface: Interface | None = None) -> None:
	logger.debug("===== WIFI DIAGNOSTICS START: %s =====", context)
	if iface is not None:
		try:
			logger.debug("pywifi iface status code: %s", iface.status())
		except Exception as exc:  # noqa: BLE001
			logger.debug("Unable to read pywifi interface status: %s", exc)

		try:
			profiles = [profile.ssid for profile in iface.network_profiles() if getattr(profile, "ssid", None)]
			logger.debug("pywifi saved profiles count=%s ssids=%s", len(profiles), profiles)
		except Exception as exc:  # noqa: BLE001
			logger.debug("Unable to enumerate pywifi profiles: %s", exc)

	for args in [
		["wlan", "show", "interfaces"],
		["wlan", "show", "profiles"],
		["wlan", "show", "networks", "mode=bssid"],
	]:
		completed = _run_netsh(args)
		logger.debug("netsh %s | rc=%s", " ".join(args), completed.returncode)
		logger.debug("netsh output (tail):\n%s", _tail_lines((completed.stdout or "") + (completed.stderr or "")))
	logger.debug("===== WIFI DIAGNOSTICS END: %s =====", context)


def get_connected_ssid() -> str | None:
	output = run_netsh(["wlan", "show", "interfaces"])
	interfaces = _parse_netsh_interfaces(output)

	for iface in interfaces:
		if iface.get("state", "").lower() == "connected" and iface.get("name", "").lower() == "wi-fi":
			ssid = iface.get("ssid", "").strip()
			if ssid:
				return ssid

	for iface in interfaces:
		if iface.get("state", "").lower() == "connected":
			ssid = iface.get("ssid", "").strip()
			if ssid:
				return ssid

	return None


def scan_networks(iface: Interface, logger: logging.Logger) -> list[WifiChoice]:
	logger.info("Scanning for WiFi networks...")
	logger.debug("Starting pywifi scan on interface.")
	iface.scan()
	time.sleep(4.0)
	results = iface.scan_results()
	logger.debug("pywifi scan returned %s raw results.", len(results))

	deduped: dict[str, WifiChoice] = {}
	for result in results:
		ssid = (result.ssid or "").strip()
		if not ssid:
			continue
		is_open = not result.akm or const.AKM_TYPE_NONE in result.akm
		current = deduped.get(ssid)
		if current is None:
			deduped[ssid] = WifiChoice(ssid=ssid, is_open=is_open)
		elif current.is_open and not is_open:
			deduped[ssid] = WifiChoice(ssid=ssid, is_open=False)

	networks = sorted(deduped.values(), key=lambda n: n.ssid.lower())
	logger.debug("Unique SSIDs after dedupe: %s", [n.ssid for n in networks])
	if not networks:
		log_wifi_diagnostics(logger, "scan_networks-empty", iface)
		raise WorkflowError("No WiFi networks found.")
	return networks


def scan_networks_netsh(logger: logging.Logger) -> list[WifiChoice]:
	logger.info("Scanning for WiFi networks (simulation mode)...")
	output = run_netsh(["wlan", "show", "networks", "mode=bssid"])
	logger.debug("netsh scan raw output (tail):\n%s", _tail_lines(output))

	deduped: dict[str, WifiChoice] = {}
	current_ssid: str | None = None
	for raw_line in output.splitlines():
		line = raw_line.strip()
		if line.lower().startswith("ssid ") and ":" in line:
			value = line.split(":", 1)[1].strip()
			current_ssid = value if value else None
			continue

		if line.lower().startswith("authentication") and ":" in line and current_ssid:
			auth_value = line.split(":", 1)[1].strip().lower()
			is_open = "open" in auth_value
			if current_ssid not in deduped:
				deduped[current_ssid] = WifiChoice(ssid=current_ssid, is_open=is_open)
			elif deduped[current_ssid].is_open and not is_open:
				deduped[current_ssid] = WifiChoice(ssid=current_ssid, is_open=False)

	networks = sorted(deduped.values(), key=lambda n: n.ssid.lower())
	logger.debug("netsh parsed SSIDs: %s", [n.ssid for n in networks])
	if not networks:
		log_wifi_diagnostics(logger, "scan_networks_netsh-empty", None)
		raise WorkflowError("No WiFi networks found.")
	return networks


def prompt_with_quit(prompt: str) -> str:
	while True:
		value = input(prompt).strip()
		if value.upper() != "Q":
			return value

		confirm = input("Are you sure Y/N: ").strip().upper()
		if confirm == "Y":
			raise UserQuit()
		if confirm == "N":
			continue


def prompt_secret_with_quit(prompt: str) -> str:
	while True:
		value = getpass.getpass(prompt).strip()
		if value.upper() != "Q":
			return value

		confirm = input("Are you sure Y/N: ").strip().upper()
		if confirm == "Y":
			raise UserQuit()
		if confirm == "N":
			continue


def prompt_menu_choice(
	title: str,
	options: Iterable[WifiChoice],
	mark_possible_wemo: bool = False,
) -> WifiChoice:
	option_list = list(options)
	while True:
		print()
		print(title)
		for idx, option in enumerate(option_list, start=1):
			security = "Open" if option.is_open else "Secured"
			possible_wemo = ""
			if mark_possible_wemo:
				ssid_lower = option.ssid.lower()
				if "wemo" in ssid_lower or "belkin" in ssid_lower:
					if supports_color():
						possible_wemo = f" {GREEN}(possible wemo){RESET}"
					else:
						possible_wemo = " (possible wemo)"
			print(f"  {idx}. {option.ssid} ({security}){possible_wemo}")

		value = prompt_with_quit("Select number (or Q to quit): ")
		if not value.isdigit():
			print("Invalid selection.")
			continue
		index = int(value)
		if 1 <= index <= len(option_list):
			return option_list[index - 1]
		print("Selection out of range.")


def connect_wifi(
	iface: Interface,
	ssid: str,
	password: str | None,
	is_open: bool,
	logger: logging.Logger,
	timeout_seconds: float = 20.0,
) -> bool:
	logger.debug("Connecting workstation to SSID '%s' (open=%s)", ssid, is_open)
	try:
		iface.disconnect()
		time.sleep(1.0)
	except Exception as exc:  # noqa: BLE001
		logger.debug("Exception during iface.disconnect(): %s", exc)
		log_wifi_diagnostics(logger, f"disconnect-exception-{ssid}", iface)

	try:
		logger.debug("Connected SSID before connect attempt: %s", get_connected_ssid())
	except Exception as exc:  # noqa: BLE001
		logger.debug("Exception reading pre-connect SSID: %s", exc)

	try:
		profiles = iface.network_profiles()
		logger.debug("Removing %s existing pywifi profiles before connect.", len(profiles))
		for profile in profiles:
			iface.remove_network_profile(profile)
	except Exception as exc:  # noqa: BLE001
		logger.debug("Exception removing existing profiles: %s", exc)
		log_wifi_diagnostics(logger, f"profile-remove-exception-{ssid}", iface)

	profile = iface.add_network_profile(_build_profile(ssid, password, is_open, const.AKM_TYPE_WPA2PSK))
	logger.debug("Attempting WPA2 connect to '%s'.", ssid)
	iface.connect(profile)
	if _wait_for_connection(ssid, timeout_seconds):
		logger.debug("WPA2 connect confirmed for '%s'.", ssid)
		return True

	if not is_open:
		logger.debug("WPA2 connect failed for '%s'; retrying with WPA", ssid)
		iface.disconnect()
		time.sleep(1.0)
		for existing in iface.network_profiles():
			iface.remove_network_profile(existing)
		profile = iface.add_network_profile(_build_profile(ssid, password, is_open, const.AKM_TYPE_WPAPSK))
		logger.debug("Attempting WPA connect to '%s'.", ssid)
		iface.connect(profile)
		wpa_connected = _wait_for_connection(ssid, timeout_seconds)
		if not wpa_connected:
			log_wifi_diagnostics(logger, f"connect-failed-wpa-{ssid}", iface)
		return wpa_connected

	log_wifi_diagnostics(logger, f"connect-failed-open-{ssid}", iface)

	return False


def _build_profile(ssid: str, password: str | None, is_open: bool, akm: int):
	from pywifi import Profile

	profile = Profile()
	profile.ssid = ssid
	profile.auth = const.AUTH_ALG_OPEN
	profile.akm.clear()

	if is_open:
		profile.akm.append(const.AKM_TYPE_NONE)
		profile.cipher = const.CIPHER_TYPE_NONE
		profile.key = ""
	else:
		profile.akm.append(akm)
		profile.cipher = const.CIPHER_TYPE_CCMP
		profile.key = password or ""

	return profile


def _wait_for_connection(ssid: str, timeout_seconds: float) -> bool:
	end_time = time.time() + timeout_seconds
	poll_count = 0
	while time.time() < end_time:
		current = get_connected_ssid()
		poll_count += 1
		if current == ssid:
			return True
		if poll_count <= 3 or poll_count % 5 == 0:
			logging.getLogger("wemo_repair").debug(
				"Waiting for SSID '%s': poll=%s observed='%s' remaining=%.1fs",
				ssid,
				poll_count,
				current,
				max(0.0, end_time - time.time()),
			)
		time.sleep(0.75)
	logging.getLogger("wemo_repair").debug("Timeout waiting for SSID '%s'. Final observed='%s'", ssid, get_connected_ssid())
	return False


def restore_prelaunch_state(
	iface: Interface,
	state: PreLaunchState,
	logger: logging.Logger,
) -> None:
	logger.info("Restoring pre-launch network state...")
	logger.debug("Pre-launch target SSID for restore: %s", state.connected_ssid or "<disconnected>")
	if state.connected_ssid:
		restored = connect_wifi(
			iface=iface,
			ssid=state.connected_ssid,
			password=None,
			is_open=False,
			logger=logger,
			timeout_seconds=20,
		)
		if not restored:
			output = run_netsh(["wlan", "connect", f"name={state.connected_ssid}"])
			logger.debug("netsh reconnect output: %s", output.strip())
			final = get_connected_ssid()
			if final == state.connected_ssid:
				logger.info("Restored WiFi connection: %s", state.connected_ssid)
			else:
				logger.warning("Failed to restore original WiFi SSID: %s", state.connected_ssid)
		else:
			logger.info("Restored WiFi connection: %s", state.connected_ssid)
	else:
		iface.disconnect()
		time.sleep(1.0)
		if get_connected_ssid() is None:
			logger.info("Restored disconnected WiFi state.")
		else:
			logger.warning("Expected disconnected WiFi state but connection remains.")
			log_wifi_diagnostics(logger, "restore-expected-disconnected-but-connected", iface)


def restore_prelaunch_state_simulated(state: PreLaunchState, logger: logging.Logger) -> None:
	logger.info("Simulation mode: no network changes were made; no restore needed.")
	logger.info("Pre-launch SSID was: %s", state.connected_ssid or "<disconnected>")


def capture_target_wifi_password(target: WifiChoice, logger: logging.Logger) -> str:
	if target.is_open:
		logger.info("Target WiFi is open; skipping password prompt.")
		return ""

	while True:
		password_1 = prompt_secret_with_quit(f"Enter password for '{target.ssid}' (or Q to quit): ")
		password_2 = prompt_secret_with_quit("Enter the password again (or Q to quit): ")
		if password_1 == password_2:
			return password_1
		print("Passwords do not match. Reenter.")


def validate_target_wifi_simulated(target: WifiChoice, logger: logging.Logger) -> str:
	return capture_target_wifi_password(target, logger)


def find_wemo_in_setup_mode(logger: logging.Logger, debug: bool) -> pywemo.WeMoDevice:
	urls_to_try = ["http://10.22.22.1/setup.xml", "http://192.168.1.1/setup.xml"]

	for url in urls_to_try:
		logger.debug("Trying Wemo setup URL: %s", url)
		try:
			device = pywemo.device_from_description(url, debug=debug)
		except Exception as exc:  # noqa: BLE001
			logger.debug("Wemo setup URL probe failed at %s with error: %s", url, exc)
			device = None
		if device is not None:
			logger.info("Found Wemo device at %s", url)
			return device

	try:
		devices = pywemo.discover_devices(debug=debug)
	except Exception as exc:  # noqa: BLE001
		logger.debug("pywemo.discover_devices failed: %s", exc)
		raise
	if not devices:
		raise WorkflowError("Could not discover Wemo device while connected to Wemo AP.")

	logger.info("Discovered Wemo device: %s", devices[0])
	return devices[0]


def try_set_wemo_name(device: pywemo.WeMoDevice, name: str, logger: logging.Logger) -> bool:
	basicevent = getattr(device, "basicevent", None)
	if basicevent is None:
		logger.warning("Wemo basicevent service not available; skipping rename.")
		return False

	def get_friendly_name() -> str | None:
		getter = getattr(basicevent, "GetFriendlyName", None)
		if getter is None:
			return None
		try:
			result = getter() or {}
		except Exception as exc:  # noqa: BLE001
			logger.debug("GetFriendlyName call failed during rename verification: %s", exc)
			return None

		for key, value in result.items():
			if "friendlyname" in key.lower() or key.lower() == "name":
				return str(value).strip()
		return None

	actions = list(basicevent.actions.items())
	logger.debug("Available basicevent actions for rename consideration: %s", [action_name for action_name, _ in actions])

	def rank_action(action_name: str) -> tuple[int, str]:
		lowered = action_name.lower()
		if lowered.startswith("set") and "name" in lowered:
			return (0, lowered)
		if lowered.startswith("change") and "name" in lowered:
			return (1, lowered)
		if "name" in lowered and not lowered.startswith("get"):
			return (2, lowered)
		return (99, lowered)

	candidate_actions = [
		(action_name, action)
		for action_name, action in actions
		if "name" in action_name.lower() and not action_name.lower().startswith("get")
	]
	candidate_actions.sort(key=lambda pair: rank_action(pair[0]))

	if not candidate_actions:
		logger.warning("No setter-like name action found on basicevent; skipping rename.")
		return False

	for action_name, action in candidate_actions:
		kwargs = {}
		for arg_name in action.args:
			lowered = arg_name.lower()
			if "name" in lowered:
				kwargs[arg_name] = name

		if not kwargs:
			continue

		try:
			logger.debug("Trying rename action '%s' with args=%s", action_name, list(kwargs.keys()))
			response = action(**kwargs)
			logger.debug("Rename action '%s' response: %s", action_name, response)

			observed_name = get_friendly_name()
			if observed_name is None:
				logger.debug("Wemo name action '%s' sent; verification getter unavailable.", action_name)
				return True
			if observed_name == name:
				logger.debug("Wemo name set using action '%s'.", action_name)
				return True

			logger.debug(
				"Rename action '%s' did not update name (observed '%s', expected '%s').",
				action_name,
				observed_name,
				name,
			)
		except Exception as exc:  # noqa: BLE001
			logger.debug("Rename action '%s' failed: %s", action_name, exc)

	logger.warning("No successful name-setting action found; continuing without rename.")
	return False


def run_workflow(debug: bool, simulate_mode: str, log_option: str | None) -> int:
	logger = setup_logging(debug, log_option)
	simulate = simulate_mode != SIMULATE_MODE_OFF
	iface = None
	if not simulate:
		wifi = PyWiFi()
		interfaces = wifi.interfaces()
		logger.debug("Detected %s pywifi interface(s).", len(interfaces))
		if not interfaces:
			log_wifi_diagnostics(logger, "no-pywifi-interface", None)
			raise WorkflowError("No WiFi interface found on this workstation.")
		iface = interfaces[0]
		logger.debug("Using first pywifi interface for workflow.")
	else:
		logger.info(
			"Simulation mode enabled (%s). WiFi connect/disconnect and Wemo provisioning will not run.",
			simulate_mode,
		)

	prelaunch = PreLaunchState(connected_ssid=get_connected_ssid())
	logger.info("Initial connected SSID: %s", prelaunch.connected_ssid or "<disconnected>")

	try:
		if simulate:
			networks = scan_networks_netsh(logger)
		else:
			networks = scan_networks(iface, logger)

		possible_wemo_found = any(
			("wemo" in network.ssid.lower() or "belkin" in network.ssid.lower())
			for network in networks
		)
		if not possible_wemo_found:
			warning_text = "* WARNING: NO OBVIOUS WEMO WIFI SSID DETECTED *"
			print()
			if supports_color():
				print(f"{YELLOW}{warning_text}{RESET}")
			else:
				print(warning_text)

		wemo_wifi = prompt_menu_choice("Select Wemo WiFi:", networks, mark_possible_wemo=True)
		target_options = [network for network in networks if network.ssid != wemo_wifi.ssid]
		if not target_options:
			raise WorkflowError("No destination WiFi choices remain after selecting the Wemo WiFi.")
		target_wifi = prompt_menu_choice("Select destination WiFi (Connect To):", target_options)

		if simulate:
			target_password = validate_target_wifi_simulated(target_wifi, logger)
		else:
			target_password = capture_target_wifi_password(target_wifi, logger)
		desired_name = prompt_with_quit("Enter Wemo device name (or Q to quit): ")

		print()
		print("Review")
		print(f"  Wemo WiFi:        {wemo_wifi.ssid}")
		print(f"  Connect To WiFi:  {target_wifi.ssid}")
		if target_wifi.is_open:
			password_for_review = "<open network>"
		else:
			password_for_review = "*" * len(target_password)
		print(f"  With Password:    {password_for_review}")
		print(f"  Device Name:      {desired_name}")
		print()
		warning_text = (
			"** WARNING ** Wifi password is not validated. If you configure wemo with wrong "
			"password, you'll need to factory reset it and try again"
		)
		if supports_color():
			print(f"{YELLOW}{warning_text}{RESET}")
		else:
			print(warning_text)
		print()

		confirm = prompt_with_quit(
			f"Do you wish to program the Wemo at {wemo_wifi.ssid} now? Y/N/P (or Q to quit): "
		).upper()

		while confirm not in {"Y", "N", "P"}:
			print("Please enter Y, N, or P.")
			confirm = prompt_with_quit(
				f"Do you wish to program the Wemo at {wemo_wifi.ssid} now? Y/N/P (or Q to quit): "
			).upper()

		while confirm == "P":
			if target_wifi.is_open:
				print("WiFi password: <open network>")
			else:
				print(f"WiFi password: {target_password}")
			input("Press Enter to hide password and continue...")
			for _ in range(4):
				print()
			confirm = prompt_with_quit(
				f"Do you wish to program the Wemo at {wemo_wifi.ssid} now? Y/N/P (or Q to quit): "
			).upper()
			while confirm not in {"Y", "N", "P"}:
				print("Please enter Y, N, or P.")
				confirm = prompt_with_quit(
					f"Do you wish to program the Wemo at {wemo_wifi.ssid} now? Y/N/P (or Q to quit): "
				).upper()

		if confirm == "N":
			logger.info("No selected. Exiting without programming changes.")
			return 0

		if simulate:
			logger.info("Simulation mode: would connect to Wemo AP '%s'.", wemo_wifi.ssid)
			logger.info("Simulation mode: would set Wemo device name to '%s'.", desired_name)
			if simulate_mode == SIMULATE_MODE_FAIL_ONCE:
				logger.warning("Simulation mode: simulated provisioning failure on first attempt.")
				if not prompt_retry_programming(wemo_wifi.ssid):
					logger.info("User declined retry after simulated failure.")
					return 1
				logger.info("Simulation mode: retry accepted.")
			logger.info("Simulation mode: would program Wemo to connect to '%s'.", target_wifi.ssid)
			logger.info("Simulation mode: provisioning completed successfully.")
			return 0

		logger.info("Connecting workstation to Wemo AP '%s'...", wemo_wifi.ssid)
		connected = connect_wifi(
			iface=iface,
			ssid=wemo_wifi.ssid,
			password="" if wemo_wifi.is_open else None,
			is_open=wemo_wifi.is_open,
			logger=logger,
			timeout_seconds=25,
		)
		if not connected:
			log_wifi_diagnostics(logger, f"wemo-connect-failed-{wemo_wifi.ssid}", iface)
			raise WorkflowError(f"Unable to connect to Wemo AP '{wemo_wifi.ssid}'.")

		logger.info("Discovering Wemo in setup mode. Please wait, this may take a few moments...")
		device = find_wemo_in_setup_mode(logger, debug)
		try_set_wemo_name(device, desired_name, logger)

		logger.info("Programming Wemo to connect to '%s'...", target_wifi.ssid)
		logger.info("Please wait, this may take a few moments...")
		try:
			status, close_status = device.setup(
				ssid=target_wifi.ssid,
				password=target_password if not target_wifi.is_open else "",
				timeout=30.0,
				connection_attempts=1,
				status_delay=1.0,
			)
		except SetupException as exc:
			message = str(exc)
			logger.debug("device.setup SetupException for target SSID '%s': %s", target_wifi.ssid, message)
			if "status=3" in message.replace(" ", ""):
				logger.warning(
					"pywemo returned uncertain status=3 for '%s'. Treating as likely success per observed device behavior.",
					target_wifi.ssid,
				)
				logger.info("Wemo programming completed with uncertain status (status=3).")
				return 0
			log_wifi_diagnostics(logger, f"device-setup-exception-{target_wifi.ssid}", iface)
			raise
		except Exception as exc:  # noqa: BLE001
			logger.debug("device.setup exception for target SSID '%s': %s", target_wifi.ssid, exc)
			log_wifi_diagnostics(logger, f"device-setup-exception-{target_wifi.ssid}", iface)
			raise
		logger.info("Wemo setup response: status=%s close_status=%s", status, close_status)
		logger.info("Wemo programming completed successfully.")
		return 0

	except UserQuit:
		logger.info("User requested quit.")
		return 0
	finally:
		if simulate:
			restore_prelaunch_state_simulated(prelaunch, logger)
		else:
			restore_prelaunch_state(iface, prelaunch, logger)


def prompt_retry_programming(wemo_ssid: str) -> bool:
	while True:
		answer = prompt_with_quit(
			f"Programming failed for Wemo at {wemo_ssid}. Retry now? Y/N (or Q to quit): "
		).upper()
		if answer in {"Y", "N"}:
			return answer == "Y"
		print("Please enter Y or N.")


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Wemo Switch Repair Tool")
	parser.add_argument(
		"-debug",
		"--debug",
		action="store_true",
		help="Enable debug console output",
	)
	parser.add_argument(
		"-simulate",
		choices=[SIMULATE_MODE_SUCCESS, SIMULATE_MODE_FAIL_ONCE],
		help="Run prompt flow without changing WiFi/hardware. Modes: success, fail-once",
	)
	parser.add_argument(
		"-log",
		help="Optional log file path. Use NOLOG for console-only output.",
	)
	return parser.parse_args()


def main() -> int:
	args = parse_args()
	try:
		simulate_mode = args.simulate if args.simulate else SIMULATE_MODE_OFF
		return run_workflow(debug=args.debug, simulate_mode=simulate_mode, log_option=args.log)
	except WorkflowError as exc:
		logger = logging.getLogger("wemo_repair")
		if logger.handlers:
			logger.error("Error: %s", exc)
		else:
			print(f"Error: {exc}")
		return 1
	except Exception as exc:  # noqa: BLE001
		logger = logging.getLogger("wemo_repair")
		if logger.handlers:
			logger.exception("Unexpected error: %s", exc)
		else:
			print(f"Unexpected error: {exc}")
		return 1
	finally:
		logger = logging.getLogger("wemo_repair")
		if logger.handlers:
			_log_run_trailer(logger)


if __name__ == "__main__":
	raise SystemExit(main())
