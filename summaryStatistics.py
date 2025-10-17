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
def getPacketDataWidths(packets, type):
    if len(type) != len(packets):
        print("Packet and type arrays don't match.")
        return np.array([])
    #Code to convert 
    finalResult = []
    i = 0
    for packet in packets:#first bound is inclusive, second is exclusive.

        if type[i] == "DIX":
            #Each character represents one nibble, so divide by 2.
            finalResult.append(len(packet[28:])//2)#Assumes that the packet is at least 46 bytes.
        else: #Assume its IEEE 802.3
            finalResult.append(int(packet[24:28], 16)) #Should get all 4 nibbles needed
        i += 1
    return np.array(finalResult)



# data: assumed to be a 1d numpy array.
    #Automatically makes a histogram. currently needs:
        #Axes
def makeHistogram(data):
    fig, ax = plt.subplots()
    style = {'facecolor': 'none', 'edgecolor': 'C0', 'linewidth': 3}
    bins = np.array([0, 301, 601, 901, 1201, 1501])
    ax.hist(data, bins=bins, **style)
    ax.set_ylabel("Number of packets")
    ax.set_xlabel("Ranges of data size")
    plt.show()

if __name__ == "__main__":
    #print(int("8000", 16))
    packet_strings = cleanNParse.getByteStream("testPackets.txt", "sep")
    testTypes = []
    for packet in packet_strings:
        testTypes.append("DIX")
    packetWidths = getPacketDataWidths(packet_strings, testTypes)
    print(packetWidths)
    makeHistogram(packetWidths)
    #2 + 