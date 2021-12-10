# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import datetime

from ecc import FieldElement, S256Field,S256Point,PrivateKey, Signature,Point
from helper import hash256

import time

def print_hi():
    print(hash256('123'.encode('utf-8')))
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
