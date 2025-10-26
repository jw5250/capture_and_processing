import sys
import subprocess
def run(cmd):
    '''
        Runs a command using subprocess and handles errors.
        Arguments:
        - cmd (List[str]): Command and arguments to run.
        Returns:
            subprocess.CompletedProcess: Result of the command execution.
    '''
    try:
        return subprocess.run(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=True)
    except FileNotFoundError:
        print("Error: tshark not found on PATH. Install Wireshark/tshark or "
              "add it to PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {' '.join(cmd)}", file=sys.stderr)
        if e.stderr:
            print(e.stderr.decode(errors="ignore"), file=sys.stderr)
        sys.exit(1)