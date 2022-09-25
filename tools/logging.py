#!/usr/bin/env python3

from utils import *

class Logging:

    def logArrayToFile(self, array, filename):
        fileContent = ""
        for item in array:
            fileContent = f"{fileContent}\n{item}"
        self.loggingToFile(fileContent.strip(), filename)


    def loggingToFile(self, text, filename):
        with open(filename, mode="a") as f:
            f.write(f"{text}\n")