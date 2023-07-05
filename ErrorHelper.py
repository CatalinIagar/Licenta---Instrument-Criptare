class Errors:
    def error_message(self, message):
        with open("ErrorMessages.txt", "r") as f:
            while(True):
                line = f.readline()
                if not line:
                    break

                line = line.strip()

                if line == message:
                    while True:
                        line = f.readline().rstrip()
                        if line == "END":
                            break
                        if line:
                            if line.startswith("Parameters:") or line.startswith(
                                    "Additional Options:") or line.startswith(
                                "Options:"):
                                print()  # Add an extra newline after the specified sections
                            print(line)
                    break

class Helper:

    def help_message(self, message):
        with open("HelpMessages.txt", "r") as f:
            while(True):
                line = f.readline()
                if not line:
                    break

                line = line.strip()

                if line == message:
                    while True:
                        line = f.readline().rstrip()
                        if line == "END":
                            break
                        if line:
                            if line.startswith("Parameters:") or line.startswith(
                                    "Additional Options:") or line.startswith(
                                    "Options:"):
                                print()  # Add an extra newline after the specified sections
                            print(line)
                    break
