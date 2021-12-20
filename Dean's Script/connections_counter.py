import hyperloglog
import pyshark
import time
import sys
import datetime
import math

# marginError - The margin error of the hyper link link hash table
# sizeOfWindow - The size of each window 
# intervalOfWindows - The interval between windows, sizeOfWindow should be a divisible of this
# filename - The file name that the logs will be written into
marginError = 0.01
sizeOfWindow = 10
intervalOfWindows = 1
filename = "logs.txt"

# Defining the class of a window
# Parameters:
# timestamp - The time which the window started
# sizeOfWindow - The size of the window
# counter - The number of Quic connections in the window
# hll - The window's hyper link link
class Window:
  def __init__(self, timestamp, sizeOfWindow, counter, hll):
    self.timestamp = timestamp
    self.sizeOfWindow = sizeOfWindow
    self.counter = counter
    self.hll = hll

# Defining the function that makes the windows and counts the quic connections
# for each window
# Input parameters as specified above
# Outputs each window's timestamp, number of Quic connections and the window's size to the 
# screen and to filename
# In this function we create a list that represents all the windows (it is of constant size),
# update the list for every packet of Quic and printing the results to the screen and file
def slidingHLL(intervalOfWindows, filename, sizeOfWindow):
    original_stdout = sys.stdout #saving the original stdout to a variable
    with open(filename, 'w') as f: #creating the file in the same folder as the script
        sys.stdout = f 
        print("This file contains the logs for Quic connections:\n")
        sys.stdout = original_stdout
    timeAfterFirstWindow = time.time() + sizeOfWindow # The time of the end of the first window
    filter_cap = pyshark.LiveCapture(display_filter="quic") # Defining the pyshark live capture
    listOfWindows = []
    startTime = datetime.datetime.now() # The time of the first window that will be displayed
    for i in range(math.floor(sizeOfWindow / intervalOfWindows)): # Inserting the windows in the list
        listOfWindows.append(Window(startTime,sizeOfWindow,0,hyperloglog.HyperLogLog(marginError)))
        startTime = startTime + datetime.timedelta(0,intervalOfWindows)
    firstWindowPassed = False # A flag to represent that the time of the first window is not over
    startIndex = math.floor(sizeOfWindow / intervalOfWindows) # The start index of the list we need to print and initialize
    finishIndex = math.floor(sizeOfWindow / intervalOfWindows) # The index that represents the last index we need to print and initialize
    startTime = time.time() # The time we started the program, count from the computer's epoch
    for packet in filter_cap:
        timePassed = time.time() - startTime # The time passed since the script started
        if (time.time() >= timeAfterFirstWindow) and firstWindowPassed == False: # Checks if the first window is over
            firstWindowPassed = True
        if packet.layers[-1].get_field_value("quic.dcid") != None and firstWindowPassed == False: # First window is not over
            for i in range((math.floor(timePassed / intervalOfWindows) % math.floor(sizeOfWindow / intervalOfWindows)) + 1): # Updates the list of windows according to the time the packet arrived
                listOfWindows[i].hll.add(packet.layers[-1].get_field_value("quic.dcid").get_default_value())
                listOfWindows[i].counter = len(listOfWindows[i].hll)
        elif firstWindowPassed: # The first window is already over
            finishIndex = math.floor(timePassed / intervalOfWindows) 
            for i in range(startIndex, finishIndex + 1): # Prints(to the screen and file) and initializes the right windows and updates every window
                j = i % math.floor(sizeOfWindow / intervalOfWindows)
                msg = "Number of connections: " + str(listOfWindows[j].counter) + "\nWindow started at: " + str(listOfWindows[j].timestamp) + "\nSize of window: " + str(listOfWindows[j].sizeOfWindow) + "\n"
                print(msg)
                with open(filename, 'a+') as f:
                    sys.stdout = f 
                    print(msg)
                    sys.stdout = original_stdout
                updatedTime = listOfWindows[j].timestamp + datetime.timedelta(0,sizeOfWindow)
                listOfWindows[j] = Window(updatedTime,sizeOfWindow,0,hyperloglog.HyperLogLog(marginError))
                if (i == finishIndex):
                    startIndex = finishIndex + 1 
            if packet.layers[-1].get_field_value("quic.dcid") != None:
                for item in listOfWindows:
                    item.hll.add(packet.layers[-1].get_field_value("quic.dcid").get_default_value())
                    item.counter = len(item.hll)

slidingHLL(intervalOfWindows,filename,sizeOfWindow) # Calling the function