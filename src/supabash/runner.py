import subprocess
import shlex
import os
import signal
import time
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from supabash.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class CommandResult:
    """
    Standardized result object for all command executions.
    """
    command: str
    return_code: int
    stdout: str
    stderr: str
    success: bool
    error_message: Optional[str] = None
    canceled: bool = False

class CommandRunner:
    """
    Handles secure execution of system commands (subprocess wrapper).
    """

    def run(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        cancel_event: Optional[Any] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        """
        Executes a command and returns the result.
        
        Args:
            command (List[str]): The command and its arguments (e.g., ['ls', '-la']).
            timeout (int, optional): Maximum time in seconds to wait.
            env (Dict[str, str], optional): Environment variables to override.
            cancel_event: Optional threading.Event-like object; if set, terminates the process.
            cwd (str, optional): Working directory for the command.
            
        Returns:
            CommandResult: Object containing output, error code, and status.
        """
        cmd_str = shlex.join(command)
        logger.debug(f"Executing command: {cmd_str}")

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                env=env,
                cwd=cwd,
                start_new_session=True,
            )

            start = time.time()
            stdout_chunks: List[str] = []
            stderr_chunks: List[str] = []

            def terminate(reason: str, *, rc: int, canceled: bool) -> CommandResult:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except Exception:
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                    try:
                        proc.wait(timeout=1.0)
                    except Exception:
                        pass
                # Drain pipes (best-effort) to avoid ResourceWarnings
                try:
                    out2, err2 = proc.communicate(timeout=0.2)
                    if out2:
                        stdout_chunks.append(out2)
                    if err2:
                        stderr_chunks.append(err2)
                except Exception:
                    pass
                out = "".join(stdout_chunks).strip()
                err = "".join(stderr_chunks).strip()
                msg = f"{reason}: {cmd_str}"
                return CommandResult(
                    command=cmd_str,
                    return_code=rc,
                    stdout=out,
                    stderr=err,
                    success=False,
                    error_message=msg,
                    canceled=canceled,
                )

            while True:
                if cancel_event is not None:
                    try:
                        if cancel_event.is_set():
                            logger.warning(f"Command canceled: {cmd_str}")
                            return terminate("Command canceled", rc=-2, canceled=True)
                    except Exception:
                        pass

                if timeout is not None and (time.time() - start) > timeout:
                    logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                    return terminate(f"Command timed out after {timeout} seconds", rc=-1, canceled=False)

                try:
                    out, err = proc.communicate(timeout=0.1)
                    if out:
                        stdout_chunks.append(out)
                    if err:
                        stderr_chunks.append(err)
                    break
                except subprocess.TimeoutExpired as e:
                    if e.output:
                        stdout_chunks.append(e.output)
                    if e.stderr:
                        stderr_chunks.append(e.stderr)
                    continue

            out = "".join(stdout_chunks).strip()
            err = "".join(stderr_chunks).strip()
            rc = proc.returncode if proc.returncode is not None else -1
            is_success = rc == 0

            if not is_success:
                logger.warning(f"Command failed (RC={rc}): {cmd_str}")
                if err:
                    logger.debug(f"Stderr: {err}")

            return CommandResult(
                command=cmd_str,
                return_code=rc,
                stdout=out,
                stderr=err,
                success=is_success,
            )

        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out after {timeout} seconds: {cmd_str}"
            logger.error(error_msg)
            return CommandResult(
                command=cmd_str,
                return_code=-1,
                stdout="",
                stderr="",
                success=False,
                error_message=error_msg
            )
            
        except FileNotFoundError:
            # This happens if the binary (e.g., 'nmap') is not found
            error_msg = f"Executable not found: {command[0]}"
            logger.error(error_msg)
            return CommandResult(
                command=cmd_str,
                return_code=127, # Standard shell exit code for 'command not found'
                stdout="",
                stderr=error_msg,
                success=False,
                error_message=error_msg
            )

        except Exception as e:
            error_msg = f"Unexpected error executing {cmd_str}: {str(e)}"
            logger.exception(error_msg)
            return CommandResult(
                command=cmd_str,
                return_code=-1,
                stdout="",
                stderr=str(e),
                success=False,
                error_message=error_msg
            )
