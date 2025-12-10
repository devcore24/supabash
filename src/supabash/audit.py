import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from supabash.logger import setup_logger
from supabash.tools import (
    NmapScanner,
    WhatWebScanner,
    NucleiScanner,
    GobusterScanner,
    SqlmapScanner,
    TrivyScanner,
)

logger = setup_logger(__name__)


class AuditOrchestrator:
    """
    Simple orchestrator to run available scanners and aggregate results.
    """

    def __init__(
        self,
        scanners: Optional[Dict[str, Any]] = None,
    ):
        # Allow dependency injection for testing
        self.scanners = scanners or {
            "nmap": NmapScanner(),
            "whatweb": WhatWebScanner(),
            "nuclei": NucleiScanner(),
            "gobuster": GobusterScanner(),
            "sqlmap": SqlmapScanner(),
            "trivy": TrivyScanner(),
        }

    def _run_tool(self, name: str, func) -> Dict[str, Any]:
        try:
            result = func()
            success = result.get("success", False)
            return {"tool": name, "success": success, "data": result}
        except Exception as e:
            logger.error(f"{name} execution failed: {e}")
            return {"tool": name, "success": False, "error": str(e)}

    def run(self, target: str, output: Path, container_image: Optional[str] = None) -> Dict[str, Any]:
        agg: Dict[str, Any] = {
            "target": target,
            "results": [],
        }
        if container_image:
            agg["container_image"] = container_image

        # Recon & web scans
        agg["results"].append(
            self._run_tool("nmap", lambda: self.scanners["nmap"].scan(target))
        )
        agg["results"].append(
            self._run_tool("whatweb", lambda: self.scanners["whatweb"].scan(target))
        )
        agg["results"].append(
            self._run_tool("nuclei", lambda: self.scanners["nuclei"].scan(target))
        )
        agg["results"].append(
            self._run_tool("gobuster", lambda: self.scanners["gobuster"].scan(target))
        )
        agg["results"].append(
            self._run_tool("sqlmap", lambda: self.scanners["sqlmap"].scan(target))
        )

        if container_image:
            agg["results"].append(
                self._run_tool("trivy", lambda: self.scanners["trivy"].scan(container_image))
            )

        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                json.dump(agg, f, indent=2)
            agg["saved_to"] = str(output)
        except Exception as e:
            logger.error(f"Failed to write audit report: {e}")
            agg["saved_to"] = None
            agg["write_error"] = str(e)

        return agg
