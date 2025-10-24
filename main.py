import re
import subprocess
import sys
from pathlib import Path
import os


import cleanNParse

"""
authors: Anishya Thinesh (amt2622@rit.edu), Justin Wu (jw5250@rit.edu),
         Evan Lonczak    (egl1669@rit.edu)
"""


# Create a "tee" class to duplicate prints
class Tee:
    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)

    def flush(self):
        for f in self.files:
            f.flush()


# regex to grab hex lines from tshark to get offset and the 16 bytes on that
# line
# this is from GenAI, I hate regex
HEX_LINE_RE = re.compile(
    r"^\s*([0-9A-Fa-f]{4})\s+((?:[0-9A-Fa-f]{2}\s+){1,16})(?:.*)?$")

#Initializes the parameters defined.
def collect_input():
    """
    Prompt the user to specify:

    - Whether to capture new packets or process an existing file.
    - If processing an existing file, get the filename and validate it.
    - If capturing new packets, get the number of files to create (1-3)
      and the number of bytes to save per packet (0-64).

    Returns:
        tuple: (capture (bool), user_input (dict))
    """
    # initialize user input dictionary
    user_input = {
        "capture": (),
        "existing_file": (),
    }
    # ask if user wants to start capture or process existing file
    while True:
        # TODO: ask for EITHER pcapng or k12text file to process
        choice = input(
            "Do you want to (c)apture new packets "
            "or (p)rocess existing (k12text/pcapng) file? "
        ).strip().lower()
        if choice in ('c', 'p'):
            break
        else:
            print("Invalid choice. Please enter 'c' to capture or 'p' to"
                  " process.")

    if choice == 'p':  # process existing file
        capture = False

        # check if filename is valid
        while True:
            # TODO: ask for EITHER pcapng or k12text filename
            filename = input(
                "Enter the path to the existing (k12text/pcapng) file: "
                "").strip()
            if not os.path.isfile(filename):
                print("Error: File does not exist.")
            elif not os.access(filename, os.R_OK):
                print("Error: File is not readable (permission denied).")
            # TODO: pick either pcapng or k12text
            elif not (filename.endswith(".pcapng") or
                      filename.endswith(".k12text")):
                print("Error: File must be a .pcapng or .k12text file.")
            else:
                # File is valid and readable
                break

        user_input["existing_file"] = (filename)
        return capture, user_input
    else:  # capture new packets
        capture = True
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
        user_input["capture"] = (num_files, num_bytes)

        return capture, user_input

#This should run a subprocess with a command.
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

<<<<<<< HEAD
#Runs the actual capture command
def capture_to_pcap(interface, count, pcap_path):
=======

def capture_to_pcap(interface, bytes, pcap_path):
    '''
    Capture 100 packets on the specified interface and save to pcap file.
    Arguments:
    - interface (str): Network interface to capture on.
    - count (int): Number of bytes to capture per packet.
    - pcap_path (Path): Path to save the pcap file.

    Returns:
        None
    '''
>>>>>>> df713e39d5ae030073b5928b928f5d618d01c141
    cmd = [
        "tshark",
        "-i", interface,
        "-c", str(100),
        "-s", str(bytes),
        "-w", str(pcap_path),
        "-q",
        "-n",
    ]
    print(f"""[+] Capturing 100 packets with {bytes} bytes each on
          {interface} -> {pcap_path.name}""")
    run(cmd)


#Runs "tshark -r <pcap_path> -x -q -n"
    #Converts output to something that could be easily written to a .txt.
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


def analyze_packet_types(packets):
    """
    Analyzes packet types in the captured packets.
    Arguments:
    - packets (List[List[str]]): List of packets, each packet is a list of
    byte strings.
    Returns:
        dict: Dictionary with counts of different packet types.
    """
    type_counts = {
        "ipv4": 0,
        "ipv6": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
    }

    for pkt in packets:
        if len(pkt) < 14:
            continue  # Not enough data for Ethernet header
        eth_type = ''.join(pkt[12:14])
        if eth_type == '0800':  # IPv4
            type_counts["ipv4"] += 1
            if len(pkt) < 23:
                continue  # Not enough data for IP header
            protocol = pkt[23]
            if protocol == '06':
                type_counts["tcp"] += 1
            elif protocol == '11':
                type_counts["udp"] += 1
            elif protocol == '01':
                type_counts["icmp"] += 1
        elif eth_type == '86dd':  # IPv6
            type_counts["ipv6"] += 1
            if len(pkt) < 20:
                continue  # Not enough data for IPv6 header
            next_header = pkt[20]
            if next_header == '06':
                type_counts["tcp"] += 1
            elif next_header == '11':
                type_counts["udp"] += 1
            elif next_header == '3a':
                type_counts["icmp"] += 1

    return type_counts


def parse_info(packets):
    """
    Parses the following from captured packets:
    - Total number of packets captured.
    - Total # of 802.3 and DIX Ethernet frames.
    - Avg size of the Ethernet data field.
    - Number of IPv4 and IPv6 packets.
    - Total number of TCP, UDP, and ICMP packets.
    Returns:
        tuple: (total packets (int),
                TODO if this is your part fill out this documentation (int),
                TODO if this is your part fill out this documentation (float),
                ipv4 packet count (int),
                ipv6 packet count (int),
                tcp packet count (int),
                udp packet count (int),
                icmp packet count (int))
    """
    # - Total number of packets captured.
    total_packets = len(packets)
    # - Total # of 802.3 and DIX Ethernet frames.
    # TODO
    # - Avg size of the Ethernet data field.
    # TODO
    # Number of IPv4 and IPv6 packets.
    # Total number of TCP, UDP, and ICMP packets.
    type_counts = analyze_packet_types(packets)

    # placeholders are 0 or 0.0
    return (total_packets, 0, 0.0, type_counts["ipv4"], type_counts["ipv6"],
            type_counts["tcp"], type_counts["udp"], type_counts["icmp"])


def print_summary(total_packets, eth_frame_count, avg_eth_data_size,
                  ipv4_count, ipv6_count, tcp_count, udp_count, icmp_count):
    """
    Prints a summary of the packet analysis.
    Arguments:
    - total_packets (int): Total number of packets captured.
    TODO fill out the rest of the arguments
    - ipv4_count (int): Number of IPv4 packets.
    - ipv6_count (int): Number of IPv6 packets.
    - tcp_count (int): Number of TCP packets.
    - udp_count (int): Number of UDP packets.
    - icmp_count (int): Number of ICMP packets.
    Returns:
        None
    """
    print("\n--- Packet Analysis Summary ---")
    print(f"Total packets captured: {total_packets}")
    # TODO print other requirements
    print(f"IPv4 packets: {ipv4_count}")
    print(f"IPv6 packets: {ipv6_count}")
    print(f"TCP packets: {tcp_count}")
    print(f"UDP packets: {udp_count}")
    print(f"ICMP packets: {icmp_count}")
    print("--------------------------------\n")

    # print summary statistics
    # TODO fill out other requirements's statistics
    print("--- Packet Summary Statistics ---")
    print("Most Common Packet Type: ")
    most_common = {
        "IPv4": ipv4_count,
        "IPv6": ipv6_count,
        "TCP": tcp_count,
        "UDP": udp_count,
        "ICMP": icmp_count,
    }
    most_common_type = max(most_common, key=most_common.get)
    print(f"  {most_common_type} ({most_common[most_common_type]} packets)")

    print("Least Common Packet Type: ")
    least_common_type = min(most_common, key=most_common.get)
    print(f"  {least_common_type} ({most_common[least_common_type]} packets)")

    print("Packet Type Distribution: ")
    for pkt_type, count in most_common.items():
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        print(f"  {pkt_type}: {count} packets ({percentage:.2f}%)")

    print("--------------------------------\n")


if __name__ == "__main__":
<<<<<<< HEAD
    # collect user input
    num_files, num_bytes = collect_input()
    base_dir = Path(".").resolve()
    for i in range(num_files):
        pcap = base_dir / f"capture{i}.pcapng"
        text_dump = base_dir / f"capture{i}.txt"
        capture_to_pcap("en0", num_bytes, pcap) # Writes all data to the file stored in pcap.
        packets = parse_packets_from_pcap(pcap) # Given pcap, parses the initial result into a new thing.
        if not packets:
            print(f"[!] No packets parsed from {pcap.name}")
            continue

        write_text_dump(packets, text_dump) #Converts intermediate format from packets to a list of strings.
        packetBytes = cleanNParse.getByteStream(text_dump, "sep") #Convert into an array of strings (finally!)
    print(f"Capturing {num_files} files with {num_bytes} bytes per packet...")
=======
    with open("output.txt", "w",) as f:
        sys.stdout = Tee(sys.stdout, f)

        # collect user input
        capture, user_input = collect_input()

        # array with all captured packets across files
        packets = []
        if not capture:  # process existing file
            filename = user_input["existing_file"]
            print(f"[+] Processing existing file: {filename}...\n")
            # TODO: process packets from file
            # and add to global packets array
            # and add system updates for progress!!!
            print("[+] Processing of existing file complete.\n")
        else:  # capture new packets
            num_files, num_bytes = user_input["capture"]
            print(
                f"[+] Starting packet capture of {num_files} files "
                f"with {num_bytes} bytes per packet...\n"
            )
            base_dir = Path(".").resolve()

            # capture and process each file
            for i in range(num_files):
                # name paths
                pcap = base_dir / f"capture{i}.pcapng"
                text_dump = base_dir / f"capture{i}.txt"

                # capture packets to pcap
                capture_to_pcap("en0", num_bytes, pcap)

                # clean packets and add to global list
                print(f"[+] Cleaning packets from {pcap.name}...")
                packets_from_file = parse_packets_from_pcap(pcap)

                # check if any packets were parsed
                if not packets_from_file:
                    print(f"[!] No packets parsed from {pcap.name}")
                    continue
                else:
                    packets.extend(packets_from_file)
                print()

                # We don't need to write text dump files for this assignment
                # TODO: remove
                # write_text_dump(packets, text_dump)

            print("[+] Packet capture and cleaning complete.\n")

        # parse info from all packets
        print("[+] Analyzing packets...")
        (total_packets, eth_frame_count, avg_eth_data_size,
            ipv4_count, ipv6_count, tcp_count, udp_count,
            icmp_count) = parse_info(packets)

        # print summary of analysis
        print("[+] Packet analysis complete.")

        # print summary
        print_summary(total_packets, eth_frame_count,
                      avg_eth_data_size, ipv4_count, ipv6_count,
                      tcp_count, udp_count, icmp_count)
    sys.stdout = sys.__stdout__
    print("[+] Output written to output.txt")
>>>>>>> df713e39d5ae030073b5928b928f5d618d01c141
