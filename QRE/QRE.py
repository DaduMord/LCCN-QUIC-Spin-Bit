import pyshark
import time

class conn_info:
    """
    A class to hold all relevant information for each QUIC connection we detect
    Field:
        - sb: holds current spin bit of the connection
        - rtt: holds current RTT estimation
        - edge_ts: timestamp of the last "edge" we detected.
                    we call each packet that switches the spin bit an "edge".
    """

    def __init__(self, sb, edge_ts, rtt=None): # initialize a new conn_info class. default for rtt field is None
        self.sb = sb
        self.rtt = rtt
        self.edge_ts = edge_ts

    def update(self, curr_sb, curr_ts): # update the rtt estimation and connection fields if necessary
        if (self.sb != curr_sb): # if spin bit has changed
            self.rtt = self.calc_rtt(curr_ts - self.edge_ts) # update rtt
            self.sb = curr_sb # update spin bit
            self.edge_ts = curr_ts # update edge timestamp

    def calc_rtt(self, new_rtt): # calculate a new rtt with the moving average algorithm
        if self.rtt is None: # if we don't have an estimation yet, use the last measurement as the estimation
            return new_rtt
        alpha = 7 / 8
        return alpha * self.rtt + (1 - alpha) * new_rtt 
    
    def __str__(self): # override the default cast to string
        last_edge_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.edge_ts))
        if self.rtt is None:
            res = "RTT: Not Yet Measured\n"
        else:
            res = "RTT: " + ("%.3f ms\n" % (self.rtt * 1000))
        res += "Last Edge Timestamp: " + last_edge_ts + "\n"
        return res

def print_conns(dict, log=None): # print the dictionary nicely to the default output and log file
    """
    Expects a dictionray of type Connection ID : conn_info
    """

    for key, value in dict.items():
        print("Connection ID:", key)
        print(value, end="\n")

        if log is not None:
            log.write("Connection ID: " + str(key) + "\n" + str(value) + "\n")

def print_finish(log=None): # print final message to default output and log file
    print("Stopping Estimator")

    if log is not None:
        log.write("Stopping Estimator\n")


def process_header(packet, quic_header, connections_dict):
    # Extract values from quic header   
    curr_dcid = quic_header.get_field_value("dcid")
    curr_sb =  quic_header.get_field_value("spin_bit")
    curr_ts = float(packet.sniff_timestamp)
    header_form = quic_header.get_field_value("header_form")
    long_packet_type = quic_header.get_field_value("long_packet_type")

    if header_form == "1" and long_packet_type == "0": # initial packet. values may be irrelevant
        return

    if curr_dcid is not None:
        curr_info = connections_dict.setdefault(curr_dcid, conn_info(curr_sb, curr_ts)) # add connection if new 
        curr_info.update(curr_sb, curr_ts) # update the connection's info

if __name__ == "__main__":
    """
    dictionary's keys: connection ID
    dictionary's values: [current spinbit's value, estimated RTT, last edge timestamp]
    """
    connections_dict = {}

    filename = ".\QRE\log.txt" # change this to output to a different file
    log = open(filename, "a") # open log file in mode=append
    log.write("\nStarting capture on time: " + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())) + "\n")

    live_cap = pyshark.LiveCapture(display_filter="quic") # TODO: choose specific interface

    try:
        for packet in live_cap: # iterate over captured packets. the loop will enter every time a quic packet is captured.
            process_header(packet, packet['quic'], connections_dict)

    except KeyboardInterrupt: # when stopped with Ctrl+C
        print_conns(connections_dict, log=log) # print the info of the connection and record it in log.txt
        print_finish(log) # print final message
        log.close()