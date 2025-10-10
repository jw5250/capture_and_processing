#as of currently, need to run "source capture_and_processing_venv/bin/activate" on my computer because python3 can't use python modules directly installed onto my system (must use virtual environment now)
from matplotlib import pyplot as plt
import numpy as np
import cleanNParse

#Notes:
    #Packets don't have a crc at this point, so this should work.

#Extracts the data field width from all ethernet packets.
    #Returns a numpy array.
def getPacketDataWidths(packets, type):
    #Code to convert 
    finalResult = []
    i = 0
    for packet in packets:
        #first bound is inclusive, second is exclusive.
        if type[i] == "DIX":
            finalResult.append(len(packet[28:])//2)
        else:
            finalResult.append(int(packet[24:28], 16)) #Should get all 4 nibbles needed
        i += 1
    return np.array(finalResult)



# data: assumed to be a 1d numpy array.
    #Automatically makes a histogram. currently needs:
        #Axes
def makeHistogram(data):
    fig, ax = plt.subplots()
    style = {'facecolor': 'none', 'edgecolor': 'C0', 'linewidth': 3}
    bins = np.array([0, 301, 601, 901, 1201, 1501, 1801])
    ax.hist(data, bins=bins, **style)
    ax.set_ylabel("Number of packets")
    ax.set_xlabel("Ranges of data size")
    plt.show()

if __name__ == "__main__":
    #packet_strings = cleanNParse.getByteStream("capture0.txt", "sep")
    #print(getPacketDataWidths(packet_strings))
    #testArr = np.array([1, 301, 1800])
    #makeHistogram(testArr)
    #2 + 