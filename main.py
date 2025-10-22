import re
import subprocess
import sys
from pathlib import Path

"""
authors: Anishya Thinesh (amt2622@rit.edu), <add names + emails here>
         Evan Lonczak    (egl1669@rit.edu)
"""

# regex to grab hex lines from tshark to get offset and the 16 bytes on that
# line
# this is from GenAI, I hate regex
HEX_LINE_RE = re.compile(
    r"^\s*([0-9A-Fa-f]{4})\s+((?:[0-9A-Fa-f]{2}\s+){1,16})(?:.*)?$")


def collect_input():
    """
    Prompt the user to specify:

    1. The number of files to create (must be between 1 and 3).
    2. The number of bytes to save for each packet (must be between 0 and 64).

    Returns:
        tuple:
            num_files (int): Number of files to create.
            num_bytes (int): Number of bytes to save for each packet.
    """
    # get the number of files to create
    while True:
        try:
            num_files = int(
                input("Enter the number of files to create (1-3): ")
            )
            if 1 <= num_files <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # get the number of bytes to save for each packet
    while True:
        try:
            num_bytes = int(
                input(
                    "Enter the number of bytes to save for each packet "
                    "(0-64): "
                )
            )
            if 0 <= num_bytes <= 64:
                break
            else:
                print("Please enter a number between 0 and 64.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    return num_files, num_bytes


def run(cmd):
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


def capture_to_pcap(interface, count, pcap_path):
    '''
    Capture packets on the specified interface and save to pcap file.
    Arguments:
    - interface (str): Network interface to capture on.
    - count (int): Number of packets to capture.
    - pcap_path (Path): Path to save the pcap file.

    Returns:
        None
    '''
    cmd = [
        "tshark",
        "-i", interface,
        "-c", str(count),
        "-w", str(pcap_path),
        "-q",
        "-n",
    ]
    print(f"[+] Capturing {count} packets on {interface} -> {pcap_path.name}")
    run(cmd)


def parse_packets_from_pcap(pcap_path):
    '''
    Parse packets from a pcap file into a list of packets, each represented as
      a list of byte strings.
    Arguments:
    - pcap_path (Path): Path to the pcap file.
    Returns:
        List[List[str]]: List of packets, each packet is a list of byte
        strings.
    '''
    cmd = ["tshark", "-r", str(pcap_path), "-x", "-q", "-n"]
    proc = run(cmd)
    text = proc.stdout.decode(errors="ignore").splitlines()

    packets = []
    current = []

    for line in text:
        m = HEX_LINE_RE.match(line)
        if m:
            offset = m.group(1)
            bytes_str = m.group(2)
            # split on whitespace to get 1–16 tokens like 'ff', 'ab', ...
            tokens = [tok.lower() for tok in bytes_str.split()]
            # detect new packet when offset resets to 0000 and we already have
            # data
            if offset.lower() == "0000" and current:
                packets.append(current)
                current = []
            current.extend(tokens)
        else:
            # non-hex line, we can skip
            pass

    if current:
        packets.append(current)

    return packets


def write_text_dump(packets, out_path: Path):
    """
    Writes packets to text so that each packet looks like:
    0000  aa bb cc ... (16 bytes)
    0010  ...
    sep
    Arguments:
    - packets (List[List[str]]): List of packets, each packet is a list of
    byte strings.
    - out_path (Path): Path to output text file.
    Returns:
        None
    ...
    """
    with out_path.open("w", encoding="utf-8") as f:
        for idx, pkt in enumerate(packets):
            # 16 bytes per line with increasing 4-hex-digit offsets
            for i in range(0, len(pkt), 16):
                line_bytes = pkt[i:i + 16]
                offset = f"{i:04x}"
                f.write(f"{offset}  {' '.join(line_bytes)}\n")
            f.write("sep\n")
    print(f"[+] Wrote text dump: {out_path.name}")


if __name__ == "__main__":
    # collect user input
    num_files, num_bytes = collect_input()
    print(f"Capturing {num_files} files with {num_bytes} bytes per packet...")
    base_dir = Path(".").resolve()
    for i in range(num_files):
        pcap = base_dir / f"capture{i}.pcapng"
        text_dump = base_dir / f"capture{i}.txt"
        capture_to_pcap("en0", num_bytes, pcap)
        packets = parse_packets_from_pcap(pcap)
        if not packets:
            print(f"[!] No packets parsed from {pcap.name}")
            continue

        write_text_dump(packets, text_dump)
