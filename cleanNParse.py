import runCommand

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



def main():

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

if __name__ == "__main__":
    main()
