# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
mySecret = 19980828
#tx = 872e6f0effae19c0a83ac77ae1eae2f7028cc0820bea4f7cd3ca99103b4dd49f
import datetime
from ecc import FieldElement, S256Field,S256Point,PrivateKey, Signature,Point
from helper import hash256,hash160,encode_base58

import time

def print_hi():
   a = PrivateKey(mySecret)
   print(a.point.address(True,True))
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print_hi()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
