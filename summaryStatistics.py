# All network packets are stored as big endian, so the most significant byte is the leftmost and the least
# significant is the leftmost. as of currently, need to run "source capture_and_processing_venv/bin/activate" on my (Justin's)
# computer because python3 can't use python modules directly installed onto my system (must use virtual environment now)
import subprocess
import sys
import math
from matplotlib import pyplot as plt
import numpy as np
import cleanNParse

# Notes:
# Packets don't have a crc at this point, so this should work.


# Extracts the data field width from all ethernet packets.
# Returns a numpy array.
def get_packet_data_widths(packets):
    """
    Get the width of the data field for each ethernet packet.
    Arguments:
    - packets (List[str]): List of packets, each packet is a byte string.
    Returns:
        np array: Np array representing the length of each ethernet packet. 
    """
    # Code to convert
    finalResult = []
    # print(type(packets))
    for packet in packets:  # first bound is inclusive, second is exclusive.
        # print(packet[24:28])
        #if len(packet) < 28:
        #    continue
        if int(packet[24:28], 16) > 1500:  # if the packet is ethernet II
            # Each character represents one nibble, so divide by 2.
            finalResult.append(len(packet[28:]) // 2)
        else:  # Assume its IEEE 802.3
            finalResult.append(int(packet[24:28], 16))
    return np.array(finalResult)


def get_ethernet_data_types(packets):
    """
    Counts the total amount of each ethernet packet type in the captured packets. Assumes there are only
    DIX and 802.3 packets.
    Arguments:
    - packets (List[str]): List of packets, each packet is a byte string.
    Returns:
        dict: Dictionary with counts of different packet types.
    """
    types = dict()
    types["802.3"] = 0
    types["DIX"] = 0

    for packet in packets:  # first bound is inclusive, second is exclusive.
        if int(packet[24:28], 16) > 1500:  # if the packet is ethernet II
            # Each character represents one nibble, so divide by 2.
            types["DIX"] += 1
        else:  # Assume its IEEE 802.3
            types["802.3"] += 1

    return types

def generate_time_gap_between_packets(timestamps):
    """
    Arguments:
    - timestamps (List[tuple(int, int, int, int)]): List of times when a packet arrived.
                                                    First is hours, second is minutes,
                                                    third is seconds, fourth is microseconds.
    Returns:
        List[int]: List of the time the network capturing software waited between packet n and n+1.
    """
    i = 0
    times = []
    while ( i < (len(timestamps)-1) ):
        start = cleanNParse.time_to_microseconds(timestamps[i])
        end = cleanNParse.time_to_microseconds(timestamps[i+1])
        times.append(cleanNParse.time_between_packet_arrivals(start, end))
        i += 1
    return times

def generate_timestamp_graph_by_microseconds(timegaps, filename):
    """
    Visualize the length of time it took for each packet to arrive, relative to the previous one.
    Arguments:
    - timegaps (List[int]): List of the time the network capturing software waited between packet n and n+1.
    """
    #Given matplotlib, initialize the actual graph.
    fig, ax = plt.subplots()
    x = np.arange(len(timegaps))
    ax.bar(x, np.array(timegaps))
    ax.set_xticks(np.arange(len(timegaps)), minor=True)
    ax.set_ylabel("Time (microseconds)")
    ax.set_xlabel("The gap between the n and n+1 packets' instance of arrival")
    plt.title(f"Time it took for some packet to arrive, given the previous packet for file: {filename}")
    plt.show()

def variance(arr):
    """
    Get the variance of a list of integers. Uses L2 distance for calculating distance between mean and a point.
    Arguments:
    - arr (List[int]) : List of integers.
    Returns:
        Float:The variance
    """
    if len(arr) <= 1:
        return 0 #No deviation from something that doesn't exist or is just a single element... right?

    mean = sum(arr)/len(arr)
    var = 0.0
    for val in arr:
        var += (val-mean)**2

    return var/(len(arr)-1)

def standard_deviation(arr):
    """
    Get the standard deviation of a list of integers. Uses L2 distance for calculating distance between mean and a point.
    Arguments:
    - arr (List[int]) : List of integers.
    Returns:
        Float:The standard deviation
    """
    return math.sqrt(variance(arr))


def make_histogram(packets):
    """
    Makes a histogram based on packet data field length.
    Arguments:
    - packets (List[str]): List of packets, each packet is a byte string.
    """
    data = get_packet_data_widths(packets)
    fig, ax = plt.subplots()
    style = {'facecolor': 'none', 'edgecolor': 'C0', 'linewidth': 3}
    bins = np.array([0, 301, 601, 901, 1201, 1501])
    ax.hist(data, bins=bins, **style)
    ax.set_xticks(np.arange(0, 1500.1, 1500/5))
    ax.set_ylabel("Number of packets")
    ax.set_xlabel("Ranges of data size")

    plt.title("Distribution of packets by payload size")
    plt.show()


def plot_protocol_distribution(type_counts, subject):
    """
    Plot a pie chart of protocol distribution using existing counts.
    Arguments:
    - type_counts (dict): Counts keyed by protocol name.
    """
    total = sum(type_counts.values())
    if total == 0:
        print("[!] No packets available to plot protocol distribution.")
        return

    labels = []
    values = []
    for proto, count in type_counts.items():
        if count <= 0:
            continue
        labels.append(proto.upper())
        values.append(count)

    if not values:
        print("[!] No non-zero protocol counts to plot.")
        return

    fig, ax = plt.subplots()
    ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    ax.axis("equal")  # Keep the pie circular.
    plt.title(f"Protocol Distribution by: {subject}")
    plt.show()


def calculate_ipv4_header_checksum(packet):
    """
    Calculate the IPv4 header checksum for a packet represented as a hex string.
    Arguments:
    - packet (str): The full Ethernet frame as a hex string with no separators.
    Returns:
        tuple[int | None, int | None]: (calculated_checksum, stored_checksum).
                                       Returns (None, None) if the packet is
                                       not IPv4 or does not contain a full
                                       header.
    """
    ethernet_header_len = 14 * 2
    min_ip_header_len = 20  # bytes

    if len(packet) < ethernet_header_len + min_ip_header_len * 2:
        return None, None

    # EtherType is bytes 12-13 -> hex chars 24-27.
    if packet[24:28].lower() != "0800":
        return None, None

    ip_header_start = ethernet_header_len
    ihl = int(packet[ip_header_start:ip_header_start + 2], 16) & 0x0F
    if ihl < 5:  # invalid header length
        return None, None

    ip_header_len_bytes = ihl * 4
    ip_header_len_chars = ip_header_len_bytes * 2
    if len(packet) < ip_header_start + ip_header_len_chars:
        return None, None

    ip_header = packet[ip_header_start:ip_header_start + ip_header_len_chars]
    stored_checksum = int(ip_header[20:24], 16)

    header_for_checksum = ip_header[:20] + "0000" + ip_header[24:]

    checksum = 0
    for i in range(0, len(header_for_checksum), 4):
        word = int(header_for_checksum[i:i+4], 16)
        checksum += word
        # fold any carry back into the lower 16 bits
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = (~checksum) & 0xFFFF
    return checksum, stored_checksum


def ipv4_checksum_stats(packets):
    """
    Validate IPv4 header checksums across packets.
    Arguments:
    - packets (List[str]): List of packets, each packet is a byte string.
    Returns:
        dict: Summary counts for checksum validation.
    """
    stats = {
        "total_ipv4": 0,
        "valid": 0,
        "invalid": 0,
        "skipped": 0,  # IPv4 packets missing enough header bytes
    }

    for packet in packets:
        if len(packet) < 28 or packet[24:28].lower() != "0800":
            continue

        stats["total_ipv4"] += 1
        calculated, stored = calculate_ipv4_header_checksum(packet)
        if calculated is None or stored is None:
            stats["skipped"] += 1
            continue

        if calculated == stored:
            stats["valid"] += 1
        else:
            stats["invalid"] += 1

    return stats


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
    cmd = ["tshark", "-r", str(pcap_path), "-x", "--hexdump", "noascii", "-q", "-n"]
    proc = run(cmd)
    text = proc.stdout.decode(errors="ignore").splitlines()

    return cleanNParse.parse_bytestream(text)

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

if __name__ == "__main__":
    """packet_strings = parse_packets_from_pcap("capture0.pcapng")
    packetWidths = get_packet_data_widths(packet_strings)
    print(packetWidths)
    dictPackets = get_ethernet_data_types(packet_strings)
    print(dictPackets)
    make_histogram(packet_strings)"""

    packet_timestamps = cleanNParse.parse_time_stamps_pcapng("capture1.pcapng")
    generate_timestamp_graph_by_microseconds(packet_timestamps)
