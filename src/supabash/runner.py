import subprocess
import shlex
from typing import List, Optional, Dict
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

class CommandRunner:
    """
    Handles secure execution of system commands (subprocess wrapper).
    """

    def run(self, command: List[str], timeout: Optional[int] = None, env: Optional[Dict[str, str]] = None) -> CommandResult:
        """
        Executes a command and returns the result.
        
        Args:
            command (List[str]): The command and its arguments (e.g., ['ls', '-la']).
            timeout (int, optional): Maximum time in seconds to wait.
            env (Dict[str, str], optional): Environment variables to override.
            
        Returns:
            CommandResult: Object containing output, error code, and status.
        """
        cmd_str = shlex.join(command)
        logger.debug(f"Executing command: {cmd_str}")

        try:
            # Capture output (stdout/stderr) and run the process
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,  # Decodes output to string automatically
                errors='replace', # Replace invalid characters instead of crashing
                timeout=timeout,
                env=env,
                check=False # We handle return codes manually
            )
            
            is_success = result.returncode == 0
            
            # Log failure details if it failed
            if not is_success:
                logger.warning(f"Command failed (RC={result.returncode}): {cmd_str}")
                logger.debug(f"Stderr: {result.stderr.strip()}")

            return CommandResult(
                command=cmd_str,
                return_code=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                success=is_success
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
