# Given a specific text file, parse it into a set of byte streams.
# Returns an array of packets represented as a set of bytes.
# Parameters:
# name:file name
# lineSeparator:Separator used when making command to tshark.
def getByteStream(name, lineSeparator):
    bytesOfPackets = []
    with open(name, "r") as f:  # Read the file as a set of bytes
        # How can I read a set of bytes at once?
        # Don't need to do that, I just need to
        # While reading the file...
        while ((line := f.readline().strip("\n")) != ""):
            fileBytes = ""

            while (line != lineSeparator):
                # print(line)
                bytesAsChars = line.split()
                del bytesAsChars[0]  # Remove the line number from the file.
                for byte in bytesAsChars:
                    fileBytes += byte
                line = f.readline().strip("\n")
                if (line == ""):
                    break
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
    packets = getByteStreamK12("testFile.k12text")
    for p in packets:
        print(p)
    print(len(packets))


if __name__ == "__main__":
    main()
