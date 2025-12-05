import runCommand
import sys

MICROSECONDS_IN_A_SECOND = 1000000

SECONDS_IN_A_MINUTE = 60

MINUTES_IN_A_HOUR = 60

HOURS_IN_A_DAY = 24


def parse_bytestream(text):
    '''
    Parse a list of text lines into a list of byte strings representing packets.
    Arguments:
    - text (List[str]): Text output, separated by function .splitlines().
    Returns:
        List[str]: List of packets, each packet is a byte
        string.
    '''
    bytesOfPackets = []
    fileBytes = ""
    for line in text:
        line = line.strip()
        if line != "":
            bytesAsChars = line.split()
            del bytesAsChars[0]  # Remove the line number from the file.
            for byte in bytesAsChars:
                fileBytes += byte
        else:
            bytesOfPackets.append(fileBytes)
            fileBytes = ""
    #Should ignore any trailing newlines.
    if fileBytes != "":
        bytesOfPackets.append(fileBytes)
    return bytesOfPackets


#Notes on the k12 format:
#hr:min:sec,<milliseconds>
#Milliseconds format:
#xxx,xxx
#If less than 100,000, digits to the left of the most significant digit are 0.
def get_byte_stream_k12(name):
    '''
    Parse a k12 file from Wireshark into a list of byte strings representing packets.
    Assumes the file is a valid k12 file.
    Arguments:
    - name (str): File name.
    Returns:
        List[str]: List of packets, each packet is a byte
        string.
    '''
    bytesOfPackets = []
    with open(name, "r") as f:  # Read the file as a set of bytes
        while (line := f.readline()):
            if (len(line) > 0) and (line[0] == "|"):
                # Parse packet.
                line = line.replace("|", "")  # Remove this.
                subStrings = line.split()
                bytesOfPackets.append(subStrings[1])
    return bytesOfPackets


#Assumes the format is hh:mm:ss,<microseconds>
#Domain of hour: [0, 23], integer
#Domain of minute: [0, 59], integer
#Domain of second: [0, 59], integer
#Domain of microsecond: [0, 999999], integer
#Returns in tuple of ((<hour>, <minute>, <second>, <microsecond>))
def string_to_time(timeStr):
    '''
    Convert from a string representing a time of day into a tuple of an hour, minute, second, and microsecond.
    Arguments:
    - timeStr: The string that represents a time of day when a packet arrived.
    Returns:
        List[tuple(int, int, int, int)]: List of times when a packet arrived.
                                         First is hours, second is minutes,
                                         third is seconds, fourth is microseconds.
    '''
    hoursMinutesSeconds = timeStr[0:8].split(":")  #Extract the first part, convert into an array of strings.
    return ((int(hoursMinutesSeconds[0]), \
             int(hoursMinutesSeconds[1]), \
             int(hoursMinutesSeconds[2]), \
             int(timeStr[9:].replace(",", ""))))  #Extract the microseconds, ignore the first comma.


#Converts from a time tuple to an amount of milliseconds since 00:00:00.
def time_to_microseconds(time):
    '''
    Convert from a set of an hour, minute, second, and microsecond into the amount of milliseconds since the start
    of a day.
    Arguments:
    - timestamps (List[tuple(int, int, int, int)]): List of times when a packet arrived.
                                                    First is hours, second is minutes,
                                                    third is seconds, fourth is microseconds.
    Returns:
        int: Amount of time since the start of the day in microseconds.
    '''
    #Minutes in an hour: 60
    #Seconds in a minute: 60
    #Microseconds in a second: 1,000,000
    return time[0] * MICROSECONDS_IN_A_SECOND * SECONDS_IN_A_MINUTE * MINUTES_IN_A_HOUR + \
        time[1] * MICROSECONDS_IN_A_SECOND * SECONDS_IN_A_MINUTE + \
        time[2] * MICROSECONDS_IN_A_SECOND + \
        time[3]


#Assumes both timestamps are in microseconds.
#Makes assumption that there is less than one day worth of difference between both packets.
#This is because if packet 1=a and packet 2=b, the result is the same even if a and b were at different dates.
#packet1, packet 2 are times since 00:00:00 in microseconds.
def time_between_packet_arrivals(packet1, packet2):
    '''
    Gets the amount of time it took between two packets being sent, based on the days they were sent.
    Arguments:
    - packet1 (int): The start time, in microseconds. Must be convertable into an actual time.
    - packet2 (int): The end time, in microseconds. Must be convertable into an actual time.
    Returns:
        int: Amount of time that passed between both packets sent, in microseconds.
    '''
    if (packet2 >= packet1):
        return packet2 - packet1
    else:
        return packet2 + \
            (MICROSECONDS_IN_A_SECOND * SECONDS_IN_A_MINUTE * MINUTES_IN_A_HOUR * HOURS_IN_A_DAY - packet1)


#Limitations:
#Can accurately get time stamps of packets within a time gap of a day, as k12 provides no information as to the date the packet was captured on.
def parse_time_stamps_k12(name):
    '''
    Parse a k12 file from Wireshark into a list of tuples containing the time of day when each packet was received.
    Assumes the file is a valid k12 file.
    Arguments:
    - name (str): File name.
    Returns:
        List[tuple(int, int, int, int)]: List of times when a packet arrived. First is hours, second is minutes,
                                         third is seconds, fourth is microseconds.
    '''
    packetTimestamps = []

    with open(name, "r") as f:  # Read the file as a set of bytes
        #Modify to now handle 
        while (line := f.readline()):
            if (len(line) > 0) and (line[0].isdigit()):  #if the first value of the line is a number...
                # Parse packet.
                subStrings = line.split()  #Grabs any line that is "14:07:25,124,767   ETHER" and split it.
                packetTimestamps.append(string_to_time(subStrings[0]))

    packet_timestamps_in_microseconds = []
    for t_stamp in packetTimestamps:
        packet_timestamps_in_microseconds.append(time_to_microseconds(t_stamp))
    i = 1
    packet_timegaps = []
    while (i < len(packetTimestamps)):
        packet_timegaps.append(time_between_packet_arrivals(packet_timestamps_in_microseconds[i - 1],
                                                            packet_timestamps_in_microseconds[i]))
        i += 1

    return packet_timegaps


#Function for getting datetime and shit from pcapng
#Runs "tshark -r <pcapng file> -u hms -t ad"
#Strip whitespace from both ends of each line
#2nd element represents date, 3rd represents time
def parse_time_stamps_pcapng(filename):
    '''
    Parse a pcapng file from Wireshark into a list of tuples containing the time of day when each packet was received.
    Assumes the file is a valid pcapng file.
    Arguments:
    - name (str): File name.
    Returns:
        List[tuple(int, int, int, int)]: List of times when a packet arrived. First is hours, second is minutes,
                                         third is seconds, fourth is microseconds.
    '''
    cmd = ["tshark", "-r", filename, "-u", "hms", "-t", "ad"]
    proc = runCommand.run(cmd)
    packetTimestamps = []
    text = proc.stdout.decode(errors="ignore").splitlines()
    for line in text:
        args = line.strip().split()
        #print(args)
        packetTimestamps.append(string_to_time(args[2]))

    packet_timestamps_in_microseconds = []
    for t_stamp in packetTimestamps:
        packet_timestamps_in_microseconds.append(time_to_microseconds(t_stamp))
    i = 1
    packet_timegaps = []
    while (i < len(packetTimestamps)):
        packet_timegaps.append(time_between_packet_arrivals(packet_timestamps_in_microseconds[i - 1],
                                                            packet_timestamps_in_microseconds[i]))
        i += 1

    return packet_timegaps


def main():
    """
    cmd = ["tshark", "-r", "capture0.pcapng", "-x", "--hexdump", "noascii", "-q", "-n"]
    proc = runCommand.run(cmd)

    text = proc.stdout.decode(errors="ignore").splitlines()
    for line in text:
        print(line)
    packets = parse_bytestream(text)

    for p in packets:
        print(p)
        print()
    print(len(packets))

    """
    timeAndDateData1 = parse_time_stamps_pcapng("capture0.pcapng")
    for tup1 in timeAndDateData1:
        print(tup1)
        print()
    timeAndDateData2 = parse_time_stamps_k12("testFile.txt")
    for tup2 in timeAndDateData2:
        print(tup2)
        print()


if __name__ == "__main__":
    main()

#Test the following command:
#tshark -r capture0.pcapng -x --hexdump noascii -n -u hms -t ad
#To get the timestamps for pcapng, must run the following:
#tshark -r <pcapng file> -u hms -t ad
