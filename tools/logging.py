#!/usr/bin/env python3

from utils import *
import utils

class Logging:

    def __init__(self):
        self.initLoggingFolders()

    def initLoggingFolders(self):
        utils.createFoler(f"{settings.Config.outputDir}", True)

    def logArrayToFile(self, array, filename):
        fileContent = ""
        for item in array:
            fileContent = f"{fileContent}\n{item}"
        self.loggingToFile(fileContent.strip(), filename)

    def loggingToFile(self, text, filename):
        filename = f"{settings.Config.outputFolder}/{settings.Config.outputDir}/{filename}"
        with open(filename, mode="a") as f:
            f.write(f"{text}\n")