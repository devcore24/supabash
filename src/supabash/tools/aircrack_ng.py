import csv
import re
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from supabash.runner import CommandRunner, CommandResult
from supabash.logger import setup_logger
from supabash.tool_settings import resolve_timeout_seconds

logger = setup_logger(__name__)


class AircrackNgScanner:
    """
    Wrapper for Aircrack-ng suite (airodump-ng capture).
    """

    def __init__(self, runner: CommandRunner = None):
        self.runner = runner if runner else CommandRunner()

    def scan(
        self,
        interface: str,
        channel: Optional[str] = None,
        output_dir: Optional[str] = None,
        arguments: Optional[str] = None,
        airmon: bool = False,
        cancel_event=None,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Capture nearby WiFi networks using airodump-ng and parse CSV output.

        Args:
            interface (str): Wireless interface (e.g., wlan0 or wlan0mon).
            channel (str, optional): Channel to lock (e.g., "6").
            output_dir (str, optional): Output directory for CSV files.
            arguments (str, optional): Extra airodump-ng CLI args.
            airmon (bool): Auto start/stop monitor mode via airmon-ng.
        """
        iface = (interface or "").strip()
        if not iface:
            return {"success": False, "error": "Interface is required", "command": ""}

        if output_dir:
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
        else:
            out_dir = Path(tempfile.mkdtemp(prefix="aircrack-ng-"))

        prefix = out_dir / "aircrack"
        monitor_iface = iface
        started_airmon = False
        start_cmd = ""

        try:
            if airmon:
                start_result = self.runner.run(
                    ["airmon-ng", "start", iface],
                    timeout=resolve_timeout_seconds(30, default=30),
                    cancel_event=cancel_event,
                )
                start_cmd = start_result.command
                if not start_result.success:
                    err = start_result.stderr or start_result.error_message or "airmon-ng failed"
                    return {
                        "success": False,
                        "error": err,
                        "canceled": bool(getattr(start_result, "canceled", False)),
                        "command": start_result.command,
                    }
                monitor_iface = self._extract_monitor_interface(
                    start_result.stdout, start_result.stderr, iface
                )
                started_airmon = True

            command = ["airodump-ng", "--output-format", "csv", "--write", str(prefix)]
            if channel:
                command.extend(["-c", str(channel)])
            if arguments:
                command.extend(arguments.split())
            command.append(monitor_iface)

            timeout = resolve_timeout_seconds(timeout_seconds, default=120)
            kwargs = {"timeout": timeout}
            if cancel_event is not None:
                kwargs["cancel_event"] = cancel_event

            result: CommandResult = self.runner.run(command, **kwargs)
            parsed, csv_path = self._load_csv(out_dir, prefix)
            has_data = bool(parsed and (parsed.get("access_points") or parsed.get("clients")))

            if not result.success and not has_data:
                err = result.stderr or result.error_message
                if not err:
                    err = f"Command failed (RC={result.return_code}): {result.command}"
                return {
                    "success": False,
                    "error": err,
                    "canceled": bool(getattr(result, "canceled", False)),
                    "raw_output": result.stdout,
                    "command": result.command,
                }

            scan_data = parsed or {"access_points": [], "clients": [], "total_access_points": 0, "total_clients": 0}
            scan_data.update(
                {
                    "interface": iface,
                    "monitor_interface": monitor_iface,
                    "channel": str(channel) if channel is not None else None,
                    "output_dir": str(out_dir),
                    "csv_path": str(csv_path) if csv_path else None,
                    "airmon": bool(airmon),
                }
            )
            return {
                "success": True,
                "scan_data": scan_data,
                "command": result.command,
                "airmon_start_command": start_cmd or None,
            }
        finally:
            if airmon and started_airmon:
                stop_result = self.runner.run(
                    ["airmon-ng", "stop", monitor_iface],
                    timeout=resolve_timeout_seconds(30, default=30),
                )
                if stop_result.command:
                    logger.info(f"Stopped monitor mode via: {stop_result.command}")

    def _extract_monitor_interface(self, stdout: str, stderr: str, fallback: str) -> str:
        text = "\n".join([stdout or "", stderr or ""])
        for line in text.splitlines():
            if "monitor" not in line.lower():
                continue
            match = re.search(r"\bon\s+([A-Za-z0-9._:-]+)\b", line)
            if match:
                return match.group(1)
        # Fallback: common convention is <iface>mon
        if fallback.endswith("mon"):
            return fallback
        return f"{fallback}mon"

    def _load_csv(self, output_dir: Path, prefix: Path) -> Tuple[Optional[Dict[str, Any]], Optional[Path]]:
        candidates = [
            Path(f"{prefix}-01.csv"),
            Path(f"{prefix}.csv"),
        ]
        for path in candidates:
            data = self._parse_csv(path)
            if data is not None:
                return data, path

        csv_files = sorted(output_dir.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in csv_files:
            data = self._parse_csv(path)
            if data is not None:
                return data, path
        return None, None

    def _parse_csv(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.exists():
            return None

        access_points: List[Dict[str, Any]] = []
        clients: List[Dict[str, Any]] = []
        section = None

        try:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                reader = csv.reader(handle)
                for row in reader:
                    if not row or all(not cell.strip() for cell in row):
                        section = None
                        continue
                    header = row[0].strip()
                    if header == "BSSID":
                        section = "ap"
                        continue
                    if header == "Station MAC":
                        section = "client"
                        continue
                    if section == "ap":
                        ap = self._parse_ap_row(row)
                        if ap:
                            access_points.append(ap)
                    elif section == "client":
                        client = self._parse_client_row(row)
                        if client:
                            clients.append(client)
        except Exception:
            return None

        return {
            "access_points": access_points,
            "clients": clients,
            "total_access_points": len(access_points),
            "total_clients": len(clients),
        }

    def _parse_ap_row(self, row: List[str]) -> Optional[Dict[str, Any]]:
        bssid = self._get(row, 0)
        if not bssid:
            return None
        channel = self._to_int(self._get(row, 3))
        privacy = self._get(row, 5)
        cipher = self._get(row, 6)
        auth = self._get(row, 7)
        power = self._to_int(self._get(row, 8))
        essid = self._get(row, 13)
        security = self._classify_security(privacy)
        return {
            "bssid": bssid,
            "channel": channel,
            "privacy": privacy,
            "cipher": cipher,
            "authentication": auth,
            "power": power,
            "essid": essid,
            "security": security,
        }

    def _parse_client_row(self, row: List[str]) -> Optional[Dict[str, Any]]:
        station = self._get(row, 0)
        if not station:
            return None
        power = self._to_int(self._get(row, 3))
        packets = self._to_int(self._get(row, 4))
        bssid = self._get(row, 5)
        probed = self._get(row, 6)
        return {
            "station": station,
            "power": power,
            "packets": packets,
            "bssid": bssid,
            "probed_essids": probed,
        }

    def _get(self, row: List[str], idx: int) -> str:
        if idx >= len(row):
            return ""
        return row[idx].strip()

    def _to_int(self, value: str) -> Optional[int]:
        try:
            return int(str(value).strip())
        except Exception:
            return None

    def _classify_security(self, privacy: str) -> str:
        priv = (privacy or "").upper()
        if "WEP" in priv:
            return "WEP"
        if "WPA" in priv:
            return "WPA"
        if "OPN" in priv or "OPEN" in priv or not priv:
            return "OPEN"
        return priv.replace(" ", "")
