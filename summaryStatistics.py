#All network packets are stored as big endian, so the most significant byte is the leftmost and the least significant is the leftmost.
#as of currently, need to run "source capture_and_processing_venv/bin/activate" on my computer because python3 can't use python modules directly installed onto my system (must use virtual environment now)
from matplotlib import pyplot as plt
import numpy as np
import cleanNParse

#Notes:
    #Packets don't have a crc at this point, so this should work.
    #I should first test this

#Extracts the data field width from all ethernet packets.
    #Returns a numpy array.
def get_packet_data_widths(packets):
    """
    Get the width of the data field for each ethernet packet.
    Arguments:
    - packets (List[str]): List of packets, each packet is a byte string.
    Returns:
        np array: Np array representing the length of each ethernet packet. 
    """
    #Code to convert 
    finalResult = []
    #print(type(packets))
    for packet in packets:#first bound is inclusive, second is exclusive.
        #print(packet[24:28])
        if int(packet[24:28], 16) > 1500:#if the packet is ethernet II
            #Each character represents one nibble, so divide by 2.
            finalResult.append(len(packet[28:])//2)
        else: #Assume its IEEE 802.3
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
    for packet in packets:#first bound is inclusive, second is exclusive.
        #print(packet[24:28])
        if int(packet[24:28], 16) > 1500:#if the packet is ethernet II
            #Each character represents one nibble, so divide by 2.
            types["DIX"] += 1            
        else: #Assume its IEEE 802.3
            types["802.3"] += 1
    return types


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
    ax.set_ylabel("Number of packets")
    ax.set_xlabel("Ranges of data size")
    plt.show()

if __name__ == "__main__":
    packet_strings = cleanNParse.getByteStream("testPackets.txt", "sep")
    packetWidths = get_packet_data_widths(packet_strings)
    packetWidths2 = get_packet_data_widths(packet_strings)
    dictPackets = get_ethernet_data_types(packet_strings)
    print(dictPackets)
    make_histogram(packet_strings)