#Given a specific text file, parse it into a set of byte streams.
    #Returns an array of packets represented as a set of bytes.
    #Parameters:
        #name:file name
        #lineSeparator:Separator used when making command to tshark.
def getByteStream(name, lineSeparator):
    bytesOfPackets = []
    with open(name, "r") as f:#Read the file as a set of bytes
        #How can I read a set of bytes at once?
            #Don't need to do that, I just need to
        #While reading the file...
        while((line := f.readline().strip("\n")) != ""):
            fileBytes = ""

            while(line != lineSeparator):
                #print(line)
                bytesAsChars = line.split()
                del bytesAsChars[0] # Remove the line number from the file.
                for byte in bytesAsChars:
                    fileBytes += byte
                line = f.readline().strip("\n")
                if(line == ""):
                    break
            bytesOfPackets.append(fileBytes)
    return bytesOfPackets

def main():
    getByteStream("testPackets.txt", "sep")

if __name__ == "__main__":
    main()