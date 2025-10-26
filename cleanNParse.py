#Each new packet starts with "0000"

# Given a specific text file, parse it into a set of byte streams.
# Returns an array of packets represented as a set of bytes.
# Parameters:
# name:file name
# lineSeparator:Separator used when making command to tshark.
def getByteStream(name):
    bytesOfPackets = []
    with open(name, "r") as f:  # Read the file as a set of bytes
        # How can I read a set of bytes at once?
        # Don't need to do that, I just need to
        # While reading the file...
        fileBytes = ""
        while ((line := f.readline()) != ""):
            line = line.strip() #Remove everything.

            if line != "":

                bytesAsChars = line.split()
                #print(bytesAsChars)
                del bytesAsChars[0]  # Remove the line number from the file.
                for byte in bytesAsChars:
                    fileBytes += byte
            else:

                bytesOfPackets.append(fileBytes)
                fileBytes = ""
        #there is no line after the final line in the custom text file, so just flush the rest of the bytes.
            #Should ignore any trailing newlines.
        if fileBytes != "":
            bytesOfPackets.append(fileBytes)
    return bytesOfPackets


def parse_bytestream(text):
    bytesOfPackets = []

    # How can I read a set of bytes at once?
    # Don't need to do that, I just need to
    # While reading the file...
    fileBytes = ""
    for line in text:
        line = line.strip() #Remove everything.
        if line != "":
            bytesAsChars = line.split()
            #print(bytesAsChars)
            del bytesAsChars[0]  # Remove the line number from the file.
            for byte in bytesAsChars:
                fileBytes += byte
        else:
            bytesOfPackets.append(fileBytes)
            fileBytes = ""
    #there is no line after the final line in the custom text file, so just flush the rest of the bytes.
        #Should ignore any trailing newlines.
    if fileBytes != "":
        bytesOfPackets.append(fileBytes)
    return bytesOfPackets

# Assumes the file is a valid k12 file.
def getByteStreamK12(name):
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
    #packets = getByteStream("testPackets.txt")


    cmd = ["tshark", "-r", "capture0.pcapng", "-x", "--hexdump", "noascii", "-q", "-n"]
    proc = run(cmd)

    text = proc.stdout.decode(errors="ignore").splitlines()
    for line in text:
        print(line)

    packets = parse_bytestream(text)

    #for p in packets:
    #    print(p)
    #    print()
    print(len(packets))

if __name__ == "__main__":
    main()
