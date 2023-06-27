class Errors:
    def error_message(self, message):
        with open("ErrorMessages.txt", "r") as f:
            while(True):
                line = f.readline()
                if not line:
                    break

                line = line.strip()

                if line == message:
                    while line != "END":
                        line = f.readline()
                        line = line.strip()
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
                    while line != "END":
                        line = f.readline()
                        line = line.strip()
                        print(line)
                    break