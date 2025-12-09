import subprocess
import sys
from pathlib import Path
import os
import re
import cleanNParse
import summaryStatistics
from typing import Any
import time

"""
authors: Anishya Thinesh (amt2622@rit.edu), Justin Wu (jw5250@rit.edu),
         Evan Lonczak    (egl1669@rit.edu)
"""

import subprocess

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
    user_input: dict[str, Any] = {
        "capture": None,
        "existing_file": None,
    }
    # ask if user wants to start capture or process existing file
    while True:
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
                      filename.endswith(".txt")):
                print("Error: File must be a .pcapng or .k12text file.")
            else:
                # File is valid and readable
                break

        user_input["existing_file"] = (filename)
        return capture, user_input
    else:  # capture new packets
        capture = True
        # get interface to capture on
        # list available interfaces using tshark
        result = subprocess.run(["tshark", "-D"],
                                capture_output=True, text=True)
        interfaces = result.stdout.strip().split("\n")

        # Display interfaces to user
        print("Available network interfaces:")
        for line in interfaces:
            print(line)

        # Ask user to pick one
        while True:
            choice = input(
                "Enter the number of the interface to capture on: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                interface = interfaces[int(choice) - 1].split()[1].strip('()')
                break
            else:
                print("Invalid input. "
                      "Please enter a valid number from the list.")

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

        # get the number of packets to capture
        while True:
            try:
                num_packets = int(
                    input(
                        "Enter the number of packets to capture "
                        "(1-100): "
                    )
                )
                if 1 <= num_packets <= 100:
                    break
                else:
                    print("Please enter a number between 0 and 100.")
            except ValueError:
                print("Invalid input. Please enter an integer.")

        user_input["capture"] = (num_files, num_bytes, num_packets, interface)

        return capture, user_input


def capture_to_pcap(interface, bytes, num_packets, pcap_path):
    '''
    Capture 100 packets on the specified interface and save to pcap file.
    Arguments:
    - interface (str): Network interface to capture on.
    - count (int): Number of bytes to capture per packet.
    - pcap_path (Path): Path to save the pcap file.

    Returns:
        None
    '''
    cmd = [
        "tshark",
        "-i", interface,
        "-c", str(num_packets),
        "-w", str(pcap_path),
        "-q",
        "-n",
    ]
    print(f"""[+] Capturing {num_packets} packets with {bytes} bytes each on
          {interface} -> {pcap_path.name}""")
    cleanNParse.run(cmd)


def parse_packets_from_pcap(pcap_path):
    '''
    Parse packets from a pcap file into a list of packets, each represented as
      a list of byte strings.
    Arguments:
    - pcap_path (Path): Path to the pcap file.
    Returns:
        List[str]: List of packets, each packet is a byte
        string.
    '''
    cmd = ["tshark", "-r", str(pcap_path), "-x",
           "--hexdump", "noascii", "-q", "-n"]
    proc = cleanNParse.run(cmd)
    text = proc.stdout.decode(errors="ignore").splitlines()
    return cleanNParse.parse_bytestream(text)


def write_substrings_to_file(filename, packets, numBytes):

    numNibbles = numBytes * 2
    with open(filename, "w") as f:
        for p in packets:
            packetsSaved = p[0:numNibbles]
            # Write the nth part of the packet that is numBytes long.
            f.write(packetsSaved + "\n")


def analyze_packet_types(packets):
    """
    Analyzes packet types in the captured packets.
    Arguments:
    - packets (List[str]): List of packets, each packet is a list of
    byte strings.
    Returns:
        dict: Dictionary with counts of different packet types.
    """
    type_counts = {
        "internet_layer": {
            "ipv4": 0,
            "ipv6": 0,
            "other": 0, 
        },
        "ip_protocol": {
            "icmp": 0,
            "tcp": 0,
            "udp": 0,
            "other": 0,
        }
    }

    for pkt in packets:
        if len(pkt) < 28:
            type_counts["internet_layer"]["other"] += 1
            continue  # Not enough data for Ethernet header
        # Each byte is two nibbles/characters.
        eth_type = pkt[24:28]
        if eth_type == '0800':  # IPv4

            type_counts["internet_layer"]["ipv4"] += 1
            if len(pkt) < 46:
                type_counts["ip_protocol"]["other"] += 1
                continue  # Not enough data for IP header
            protocol = pkt[46:48]  # Get the 23rd byte.
            if protocol == '06':
                type_counts["ip_protocol"]["tcp"] += 1
            elif protocol == '11':
                type_counts["ip_protocol"]["udp"] += 1
            elif protocol == '01':
                type_counts["ip_protocol"]["icmp"] += 1
            else:
                type_counts["ip_protocol"]["other"] += 1

        elif eth_type == '86dd':  # IPv6

            type_counts["internet_layer"]["ipv6"] += 1
            if len(pkt) < 40:
                type_counts["ip_protocol"]["other"] += 1
                continue  # Not enough data for IPv6 header
            next_header = pkt[40:42]
            if next_header == '06':
                type_counts["ip_protocol"]["tcp"] += 1
            elif next_header == '11':
                type_counts["ip_protocol"]["udp"] += 1
            elif next_header == '3a':
                type_counts["ip_protocol"]["icmp"] += 1
            else:
                type_counts["ip_protocol"]["other"] += 1
        else:
            type_counts["internet_layer"]["other"] += 1
    return type_counts


def parse_info(packets):
    """
    Parses the following from captured packets:
    - Total number of packets captured.
    - Total # of 802.3 and DIX Ethernet frames.
    - Avg size of the Ethernet data field.
    - Number of IPv4 and IPv6 packets.
    - Total number of TCP, UDP, ICMP, IPv4, IPv6, packets and anything that isn't.
    Returns:
        tuple: (total packets (int),
                total number of each type of ethernet frame (tuple(int, int)),
                average ethernet frame data field length (float),
                ipv4 packet count (int),
                ipv6 packet count (int),
                tcp packet count (int),
                udp packet count (int),
                icmp packet count (int),
                other internet packet count (int),
                other ip protocol packet count (int))
    """

    # - Total number of packets captured.
    total_packets = len(packets)
    # - Total # of 802.3 and DIX Ethernet frames.

    num_ethernet_frame_types = summaryStatistics.get_ethernet_data_types(
        packets)

    # - Avg size of the Ethernet data field.
    eth_data_size = summaryStatistics.get_packet_data_widths(packets)
    avg_eth_data_size = sum(eth_data_size) / len(eth_data_size)

    # Number of IPv4 and IPv6 packets.
    # Total number of TCP, UDP, and ICMP packets.
    type_counts = analyze_packet_types(packets)

    # placeholders are 0 or 0.0
    return (total_packets, num_ethernet_frame_types, avg_eth_data_size,
            type_counts["internet_layer"]["ipv4"], type_counts["internet_layer"]["ipv6"],
            type_counts["ip_protocol"]["tcp"], type_counts["ip_protocol"]["udp"], type_counts["ip_protocol"]["icmp"], 
            type_counts["internet_layer"]["other"], type_counts["ip_protocol"]["other"])


def print_summary(total_packets, eth_frame_count, avg_eth_data_size,
                  ipv4_count, ipv6_count, tcp_count, udp_count, icmp_count, other_internet_count, other_ip_protocol_count):
    """
    Prints a summary of the packet analysis.
    Arguments:
    - total_packets (int): Total number of packets captured.
    - eth_frame_count (tuple(int, int)):  total number of each type of ethernet frame
    - avg_eth_data_size (float): average ethernet frame data field length
    - ipv4_count (int): Number of IPv4 packets.
    - ipv6_count (int): Number of IPv6 packets.
    - tcp_count (int): Number of TCP packets.
    - udp_count (int): Number of UDP packets.
    - icmp_count (int): Number of ICMP packets.
    - other_internet_count (int): Number of packets that are on the internet layer not ipv4 or ipv6
    - other_ip_protocol_count (int): Number of packets that have an ip protocol that isn't icmp, udp, or tcp.
    Returns:
        None
    """
    print("\n--- Packet Analysis Summary ---")
    print(f"Total packets captured: {total_packets}")
    print(f"Total number of DIX ethernet frames: {eth_frame_count['DIX']}")
    print(f"Total number of 802.3 ethernet frames: {eth_frame_count['802.3']}")
    print(f"Average size of an ethernet frame: {avg_eth_data_size}")
    print(f"IPv4 packets: {ipv4_count}")
    print(f"IPv6 packets: {ipv6_count}")
    print(f"Other internet packets: {other_internet_count}")

    print(f"TCP packets: {tcp_count}")
    print(f"UDP packets: {udp_count}")
    print(f"ICMP packets: {icmp_count}")
    print(f"Packets with another ip protocol: {other_ip_protocol_count}")
    print("--------------------------------\n")

    # print summary statistics
    print("--- Packet Summary Statistics ---")
    print("Most Common Packet Type: ")
    most_common = {
        "IPv4": ipv4_count,
        "IPv6": ipv6_count,
        "Other internet": other_internet_count,
        "TCP": tcp_count,
        "UDP": udp_count,
        "ICMP": icmp_count,
        "Other ip protocol": other_ip_protocol_count,
    }
    most_common_type = max(most_common, key=lambda x: most_common[x])
    print(f"  {most_common_type} ({most_common[most_common_type]} packets)")

    print("Least Common Packet Type: ")
    least_common_type = min(most_common, key=lambda x: most_common[x])
    print(f"  {least_common_type} ({most_common[least_common_type]} packets)")

    print("Packet Type Distribution: ")
    for pkt_type, count in most_common.items():
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        print(f"  {pkt_type}: {count} packets ({percentage:.2f}%)")

    print("Ethernet Frame Distribution: ")
    for frame_type, count in eth_frame_count.items():
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        print(f"  {frame_type}: {count} frames ({percentage:.2f}%)")

    print("--------------------------------\n")


def print_ipv4_checksum_summary(checksum_stats):
    """
    Prints summary information about IPv4 header checksum validation.
    Arguments:
    - checksum_stats (dict): Summary data produced by ipv4_checksum_stats.
    """
    print("--- IPv4 Header Checksums ---")
    if checksum_stats["total_ipv4"] == 0:
        print("No IPv4 packets found; checksum validation skipped.")
        print("--------------------------------\n")
        return

    print(f"IPv4 packets checked: {checksum_stats['total_ipv4']}")
    print(f"Valid checksums: {checksum_stats['valid']}")
    print(f"Invalid checksums: {checksum_stats['invalid']}")
    if checksum_stats["skipped"] > 0:
        print(
            f"Skipped (truncated/unsupported headers): "
            f"{checksum_stats['skipped']}"
        )
    print("--------------------------------\n")


def group_packet_times(packet_times, packets):
    """
    Groups the amount of time a packet took to arrive (relative to the previous one) based on packet type.
    Assumes len(packet_times) == len(packets)
    Arguments:
    - packet_times(List[int]): List containing the amount of time a packet took to arrive, relative to the previous packet.
    Returns:
        Dict[str, List[int]]: Set of lists of packet times, grouped by packet type.
    """
    i = 1  # Exclude the first packet, as it's the literal baseline.

    packet_groups = dict()
    packet_groups["tcp"] = []
    packet_groups["udp"] = []
    packet_groups["icmp"] = []
    packet_groups["other"] = []

    while (i < len(packets)):
        # Each byte is two nibbles/characters.
        if len(packets[i]) < 24:
            packet_groups["other"].append(packet_times[i-1])
            i += 1
            continue
        eth_type = packets[i][24:28]
        if eth_type == '0800':  # IPv4
            if len(packets[i]) < 46:
                packet_groups["other"].append(packet_times[i-1])
                i += 1
                continue  # Not enough data for IP header
            protocol = packets[i][46:48]  # Get the 23rd byte.
            if protocol == '06':
                packet_groups["tcp"].append(packet_times[i-1])
            elif protocol == '11':
                packet_groups["udp"].append(packet_times[i-1])
            elif protocol == '01':
                packet_groups["icmp"].append(packet_times[i-1])
            else:
                packet_groups["other"].append(packet_times[i-1])
        elif eth_type == '86dd':  # IPv6
            if len(packets[i]) < 40:
                packet_groups["other"].append(packet_times[i-1])
                i += 1
                continue  # Not enough data for IPv6 header
            next_header = packets[i][40:42]
            if next_header == '06':
                packet_groups["tcp"].append(packet_times[i-1])
            elif next_header == '11':
                packet_groups["udp"].append(packet_times[i-1])
            elif next_header == '3a':
                packet_groups["icmp"].append(packet_times[i-1])
            else:
                packet_groups["other"].append(packet_times[i-1])
        else:
            packet_groups["other"].append(packet_times[i-1])

        i += 1
    return packet_groups


# Gets the average packet times for each packet.
    # Should do the following:
    # Print the average packet time for a given packet.
    # The average packet time given all types of packet.
    # Print the standard deviation for a given packet.
def print_summary_packet_times(packet_groups):
    """
    Prints summary statistics of the packet times.
    Arguments:
    - packet_groups(Dict[str, List[int]]):Set of lists containing the amount of time a packet took to arrive,
                                          relative to the previous packet. Grouped by packet type.
    Returns:
        None
    """
    packet_times = []
    for packet_type, time_gaps in packet_groups.items():
        packet_times.extend(time_gaps)
    if len(packet_times) == 0:
        print("\nNot enough packets to analyze packet times.")
        return
    print("\n--- Packet Time Analysis Summary ---")
    avg_pkt_time = sum(packet_times)/(len(packet_times))
    print(f"Average packet time (in microseconds):{avg_pkt_time}")
    stdev_pkt_time = summaryStatistics.standard_deviation(packet_times)
    print(
        f"Standard deviation of packet times(in microseconds):{stdev_pkt_time}")
    print("--------------------------------\n")

    for packet_type, times in packet_groups.items():
        print(f"For packet type: \"{packet_type}\"\n")
        if len(times) > 0:
            avg_pkt_time = sum(times)/(len(times))
            print(f"Average packet time (in microseconds):{avg_pkt_time}")
            stdev_pkt_time = summaryStatistics.standard_deviation(times)
            print(
                f"Standard deviation of packet time (in microseconds):{stdev_pkt_time}")
            variance_pkt_time = summaryStatistics.variance(times)
            print(
                f"Variance of packet time (in microseconds):{variance_pkt_time}")
        else:
            print("No packets of this type found")
        print("--------------------------------")


def print_metadata(num_packets: int, capture_duration: float, avg_pkt_size: float, payload_bytes: int):
    """
    Prints metadata about the packet capture.
    Arguments:
    - num_packets (int): Total number of packets captured.
    - capture_duration (float): Duration of the capture in seconds.
    - avg_pkt_size (float): Average size of packets in bytes.
    - payload_bytes (int): Total number of payload bytes captured.
    Returns:
        None
    """
    print("\n--- Packet Capture Metadata ---")
    print(f"Total packets captured: {num_packets}")
    print(f"Capture duration (seconds): {capture_duration:.2f}")
    print(f"Average packet size (bytes): {avg_pkt_size:.2f}")
    print(f"Total payload bytes captured: {payload_bytes}")
    print("--------------------------------\n")


def get_payload_bytes(packets: list[str]) -> int:
    total_ip_payload = 0
    num_ipv4_packets = 0

    for pkt in packets:
        if len(pkt) < 28:
            continue  # not enough for Ethernet + minimal IP header

        eth_type = pkt[24:28]
        if eth_type != '0800':  # skip non-IPv4
            continue

        num_ipv4_packets += 1

        # IP header starts at byte 14 (28 hex chars)
        ip_header_first_byte = int(pkt[28:30], 16)
        ihl = ip_header_first_byte & 0x0F  # lower 4 bits
        ip_header_length = ihl * 4  # in bytes

        # Total length field in IP header (bytes 2-3 of IP header)
        total_length = int(pkt[28+4:28+8], 16)  # hex string of 2 bytes
        ip_payload_bytes = total_length - ip_header_length

        if ip_payload_bytes > 0:
            total_ip_payload += ip_payload_bytes
    return total_ip_payload


if __name__ == "__main__":
    with open("output.txt", "w", ) as f:
        sys.stdout = Tee(sys.stdout, f)

        # collect user input
        capture, user_input = collect_input()

        # array with all captured packets across files
        packets = []

        packet_time_groups = []

        packet_timelines = []
        files_choosen = []

        # initialize total capture time
        capture_time = 0.0
        if not capture:  # process existing file
            filename = user_input["existing_file"]
            files_choosen.append(filename)
            print(f"[+] Processing existing file: {filename}...\n")

            if filename.endswith("txt"):
                packets = cleanNParse.get_byte_stream_k12(filename)
                packet_times = cleanNParse.parse_time_stamps_k12(filename)
                packet_timelines.append(packet_times)
                packet_time_groups.append(
                    group_packet_times(packet_times, packets))
            else:  # pcapng file
                packets = parse_packets_from_pcap(Path(filename))
                packet_times = cleanNParse.parse_time_stamps_pcapng(
                    Path(filename))
                packet_timelines.append(packet_times)
                packet_time_groups.append(
                    group_packet_times(packet_times, packets))
            print("[+] Processing of existing file complete.\n")
        else:  # capture new packets
            num_files, num_bytes, num_packets, interface = user_input["capture"]
            print(
                f"[+] Starting packet capture of {num_files} files "
                f"with {num_bytes} bytes per packet...\n"
            )
            base_dir = Path(".").resolve()

            # init start/end time variables
            start_time, end_time = None, None

            # capture and process each file
            for i in range(num_files):
                # name paths
                pcap = base_dir / f"capture{i}.pcapng"

                # start time tracking
                start_time = time.time()

                # capture packets to pcap
                capture_to_pcap(interface, num_bytes, num_packets, pcap)

                # end time tracking
                end_time = time.time()

                # calculate capture duration
                capture_time += end_time - start_time

                # record the file associated with the given ordered lists of packets
                files_choosen.append(pcap.name)

                # clean packets and add to global list
                print(f"[+] Cleaning packets from {pcap.name}...")
                packets_from_file = parse_packets_from_pcap(pcap)
                write_substrings_to_file(
                    "packetParts" + str(i) + ".txt", packets_from_file, num_bytes)
                # check if any packets were parsed
                if not packets_from_file:
                    print(f"[!] No packets parsed from {pcap.name}")
                    continue
                else:
                    packets.extend(packets_from_file)
                    packet_timestamps_from_file = cleanNParse.parse_time_stamps_pcapng(
                        pcap)
                    packet_timelines.append(packet_timestamps_from_file)
                    packet_time_groups.append(group_packet_times(
                        packet_timestamps_from_file, packets_from_file))
                print()

            print("[+] Packet capture and cleaning complete.\n")

        # parse info from all packets
        print("[+] Analyzing packets...")
        (total_packets, eth_frame_count, avg_eth_data_size,
         ipv4_count, ipv6_count, tcp_count, udp_count,
         icmp_count, other_internet_count, other_transport_count) = parse_info(packets)
        checksum_stats = summaryStatistics.ipv4_checksum_stats(packets)

        # print summary of analysis
        print("[+] Packet analysis complete.")

        # print summary
        print_summary(total_packets, eth_frame_count,
                      avg_eth_data_size, ipv4_count, ipv6_count,
                      tcp_count, udp_count, icmp_count, other_internet_count, other_transport_count)
        print_ipv4_checksum_summary(checksum_stats)
        # Visualizations
        protocol_counts = analyze_packet_types(packets)

        summaryStatistics.plot_protocol_distribution(protocol_counts["internet_layer"], "internet")
        summaryStatistics.plot_protocol_distribution(protocol_counts["ip_protocol"], "ip protocol type")

        if len(packet_time_groups) > 0:
            # Combine the packet arrival times of every file into a single dictionary.
            i = 0
            for packet_timeline in packet_timelines:
                if(len(packet_timeline) > 0):
                    summaryStatistics.generate_timestamp_graph_by_microseconds(
                        packet_timeline, files_choosen[i])
                i += 1
            total_packet_time_group = packet_time_groups[0]
            for key in packet_time_groups[0].keys():
                i = 1
                while i < len(packet_time_groups):
                    for time_gap in packet_time_groups[i][key]:
                        total_packet_time_group[key].append(time_gap)
                    i += 1
            print_summary_packet_times(total_packet_time_group)
        else:
            print("Not enough packets to visualize the timeline.")
        # Metadata about the capture

        # Calculations for metadata
        num_pkts = total_packets
        # Calculate total capture duration
        if capture:
            capture_duration = capture_time
        else:
            # For existing files, we can estimate duration from timestamps
            all_timestamps = []

            for timeline in packet_timelines:
                all_timestamps.extend(timeline)
            if len(all_timestamps) != 0:
                capture_duration = sum(all_timestamps) / \
                    1_000_000  # convert to seconds
            else:
                capture_duration = 0.0
        # Average packet size in bytes
        avg_pkt_size = (sum(len(pkt) for pkt in packets) /
                        num_pkts) / 2 if num_pkts > 0 else 0.0
        # Total payload bytes captured
        payload_bytes = get_payload_bytes(packets)

        # Print metadata
        print_metadata(num_pkts, capture_duration, avg_pkt_size, payload_bytes)

        # display the histogram for payload distribution
        summaryStatistics.make_histogram(packets)
    sys.stdout = sys.__stdout__
    print("[+] Output written to output.txt")
