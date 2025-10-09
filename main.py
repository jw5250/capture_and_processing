"""
authors: Anishya Thinesh (amt2622@rit.edu), <add names + emails here>
"""


"""
Prompt the user to specify:

1. The number of files to create (must be between 1 and 3).
2. The number of bytes to save for each packet (must be between 0 and 64).

Returns:
    tuple:
        num_files (int): Number of files to create.
        num_bytes (int): Number of bytes to save for each packet.
"""


def collect_input():
    # get the number of files to create
    while True:
        try:
            num_files = int(
                input("Enter the number of files to create (1-3): ")
            )
            if 1 <= num_files <= 3:
                break
            else:
                print("Please enter a number between 1 and 3.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    # get the number of bytes to save for each packet
    while True:
        try:
            num_bytes = int(
                input(
                    "Enter the number of bytes to save for each packet "
                    "(0-64): "
                )
            )
            if 0 <= num_bytes <= 64:
                break
            else:
                print("Please enter a number between 0 and 64.")
        except ValueError:
            print("Invalid input. Please enter an integer.")

    return num_files, num_bytes


if __name__ == "__main__":
    # collect user input
    num_files, num_bytes = collect_input()
    print(f"Capturing {num_files} files with {num_bytes} bytes per packet...")
