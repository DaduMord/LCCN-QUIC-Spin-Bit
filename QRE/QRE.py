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
        - rtt_measurements: a list that holds all the rtt measurements that were
                    made for this connection and their timestamps (in tuple form).
    """
    # initialize a new conn_info class. default for rtt field is None
    def __init__(self, sb, edge_ts, rtt=None):
        self.sb = sb
        self.rtt = rtt
        self.edge_ts = edge_ts
        self.rtt_measurements = []

    # update the rtt estimation and connection fields if necessary
    def update(self, curr_sb, curr_ts):
        if (self.sb != curr_sb): # if spin bit has changed
            latest_rtt = curr_ts - self.edge_ts # calculate the time difference from last edge
            self.rtt = self.calc_rtt(latest_rtt) # update rtt
            self.rtt_measurements.append((latest_rtt, curr_ts)) # insert measurement to measurements array
            self.sb = curr_sb # update spin bit
            self.edge_ts = curr_ts # update edge timestamp

    # calculate a new rtt with the moving average algorithm
    def calc_rtt(self, new_rtt):
        if self.rtt is None: # if we don't have an estimation yet, use the last measurement as the estimation
            return new_rtt
        alpha = 7 / 8
        return alpha * self.rtt + (1 - alpha) * new_rtt 
    
    # override the default cast to string
    def __str__(self):
        # last_edgs_ts = time.time()
        last_edge_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.edge_ts))
        if self.rtt is None:
            res = "RTT: Not Yet Measured\n"
        else:
            res = "RTT: " + ("%.3f ms\n" % (self.rtt * 1000))
        res += "Last Edge Timestamp: " + last_edge_ts + "\n"
        return res

    # convert measurements array to string for printing purposes
    def measurements_tostr(self, measurements):
        if len(measurements) == 0:
            return "No Measurements"
        res = ""
        for i, measurement in enumerate(measurements):
            timestamp = measurement[1]
            timestamp_ms = timestamp % 1
            timestamp_ms = str(timestamp_ms)[2:8]
            rtt = "%.3f ms" % (measurement[0] * 1000)
            res += "%3s: %8s :: %s.%s\n" % (str(i), rtt, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp)), timestamp_ms)
        return res


# print the dictionary nicely to the default output and log file
def print_conns(dict, log=None, print_separate_files=False, timestamp=None):
    """
    Expects a dictionary of type Connection ID : conn_info
    """

    for key, value in dict.items():
        print("Connection ID:", key)
        print(value, end="\n")

        if log is not None:
            log.write("Connection ID: " + str(key) + "\n" + str(value) + "\n")
        if print_separate_files:
            conn_log = ".\\QRE\\logs\\" + timestamp.replace(":", ".") + " ID " + str(key).replace(":", "") + ".txt"
            with open(conn_log, "w+") as file:
                file.write("Connection ID: " + str(key) + "\n" + str(value) + "\n" + "RTT Measurements:\n")

                measurements_str = value.measurements_tostr(value.rtt_measurements)
                file.write(measurements_str)

                file.close()

# print final message to default output and log file
def print_finish(log=None):
    print("Stopping Estimator")

    if log is not None:
        log.write("Stopping Estimator\n")


def process_header(packet, quic_header, connections_dict):
    # Extract values from quic header   
    curr_dcid = quic_header.get_field_value("dcid") # dcid = Destination Connection ID
    curr_sb =  quic_header.get_field_value("spin_bit")
    curr_ts = float(packet.sniff_timestamp)

    # need to check if the packet is initial (dcid will be unusable)
    header_form = quic_header.get_field_value("header_form")
    long_packet_type = quic_header.get_field_value("long_packet_type")

    if header_form == "0": # short header
        if curr_dcid is not None:
            curr_info = connections_dict.setdefault(curr_dcid, conn_info(curr_sb, curr_ts)) # add connection if new
            curr_info.update(curr_sb, curr_ts) # update the connection's info

if __name__ == "__main__":
    """
    dictionary's keys: connection ID
    dictionary's values: [current spinbit's value, estimated RTT, last edge timestamp, rtt measurements]
    """
    connections_dict = {}
    start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

    filename = ".\\QRE\\logs\\log.txt" # change this to output to a different file
    log = open(filename, "a") # open log file in mode=append
    log.write("\nStarting capture on time: " + start_time + "\n")

    live_cap = pyshark.LiveCapture(display_filter="quic") # TODO: choose specific interface

    try: # TODO: live_cap.sniff_continuously()?
        for packet in live_cap: # iterate over captured packets. the loop will enter every time a quic packet is captured.
            process_header(packet, packet.layers[-1], connections_dict) # packet.layers[-1] gets the last header of the packet

    except KeyboardInterrupt: # when stopped with Ctrl+C
        print_conns(connections_dict, log=log, print_separate_files=True, timestamp=start_time) # print the info of the connection and record it in log.txt
        print_finish(log) # print final message
        log.close()