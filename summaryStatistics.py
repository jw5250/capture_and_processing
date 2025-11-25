# All network packets are stored as big endian, so the most significant byte is the leftmost and the least
# significant is the leftmost. as of currently, need to run "source capture_and_processing_venv/bin/activate" on my (Justin's)
# computer because python3 can't use python modules directly installed onto my system (must use virtual environment now)
import subprocess
import sys
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

def generate_timestamp_graph_by_microseconds(timegaps):
    """
    Visualize the length of time it took for each packet to arrive, relative to the previous one.
    Arguments:
    - timegaps (List[int]): List of the time the network capturing software waited between packet n and n+1.
    """
    #Initialize the timestamp array.
    times = generate_time_gap_between_packets(timegaps)
    print(times)
    #Given matplotlib, initialize the actual graph.
    fig, ax = plt.subplots()
    x = np.arange(len(times))
    ax.bar(x, np.array(times))
    ax.set_xticks(np.arange(len(times)))
    ax.set_ylabel("Time (microseconds)")
    ax.set_xlabel("The nth gap between two packets' instance of arrival")
    plt.show()

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
    plt.show()

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
