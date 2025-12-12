import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


@dataclass
class JobStatus:
    job_id: str
    kind: str
    target: str
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    state: str = "running"  # running|done|failed|canceled
    current_step: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
    events: list[str] = field(default_factory=list)

    def elapsed_seconds(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)


class BackgroundJob:
    def __init__(self, job_id: str, kind: str, target: str, fn: Callable[[], Any]):
        self.job_id = job_id
        self.kind = kind
        self.target = target
        self._fn = fn
        self.cancel_event = threading.Event()
        self.status = JobStatus(job_id=job_id, kind=kind, target=target)
        self.result: Any = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def cancel(self) -> None:
        self.cancel_event.set()
        self.status.message = "Cancellation requested"
        self._add_event("cancel", "Cancellation requested")

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def _run(self) -> None:
        try:
            self.result = self._fn()
            if self.status.state == "running":
                if self.cancel_event.is_set():
                    self.status.state = "canceled"
                elif isinstance(self.result, dict) and self.result.get("canceled"):
                    self.status.state = "canceled"
                else:
                    self.status.state = "done"
            self.status.finished_at = time.time()
            self._add_event("done", "Finished")
        except Exception as e:
            self.status.state = "failed"
            self.status.error = str(e)
            self.status.finished_at = time.time()
            self._add_event("failed", str(e))

    def _add_event(self, kind: str, msg: str) -> None:
        try:
            line = f"{time.strftime('%H:%M:%S')} {kind}: {msg}"
            self.status.events.append(line)
            if len(self.status.events) > 25:
                del self.status.events[: len(self.status.events) - 25]
        except Exception:
            return


class JobManager:
    """
    Simple single-active-job manager for chat.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.active: Optional[BackgroundJob] = None
        self._counter = 0

    def start_job(self, kind: str, target: str, fn: Callable[[], Any]) -> BackgroundJob:
        with self._lock:
            if self.active and self.active.is_alive():
                raise RuntimeError("A job is already running. Use /stop or wait.")
            self._counter += 1
            job = BackgroundJob(job_id=str(self._counter), kind=kind, target=target, fn=fn)
            self.active = job
            job.start()
            return job

    def get_status(self) -> Optional[JobStatus]:
        with self._lock:
            return self.active.status if self.active else None

    def cancel_active(self) -> bool:
        with self._lock:
            if not self.active or not self.active.is_alive():
                return False
            self.active.cancel()
            return True

    def take_result_if_done(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self.active:
                return None
            if self.active.is_alive():
                return None
            result = self.active.result
            status = self.active.status
            self.active = None
            return {"status": status, "result": result}
