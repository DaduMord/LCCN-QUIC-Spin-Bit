import datetime
import pyshark
import time
import sys

class conn_info:
    def __init__(self, sb, edge_ts, rtt=None):
        self.sb = sb
        self.rtt = rtt
        self.edge_ts = edge_ts

    def update(self, curr_sb, curr_ts):
        if (self.sb != curr_sb): # if spin bit has changed
            self.rtt = self.calc_rtt(curr_ts - self.edge_ts)
            self.sb = curr_sb
            self.edge_ts = curr_ts

    def calc_rtt(self, new_rtt):
        if (self.rtt == None):
            return new_rtt
        alpha = 7 / 8
        return alpha * self.rtt + (1 - alpha) * new_rtt 
    
    def to_string(self):
        last_edge_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.edge_ts))
        if self.rtt is None:
            res = "RTT: Not Yet Measured\n"
        else:
            res = "RTT: " + ("%.3f ms\n" % (self.rtt*1000))
        res += "Current Spin Bit: " + str(self.sb) + "\n"\
                "Last Edge Timestamp: " + last_edge_ts
        return res


def print_conns(dict):
    """
    Expectes a dictionray of Connection ID : conn_info
    """
    # TODO: add print to log file
    for key, value in dict.items():
        print("Connection ID:", key)
        print(value.to_string(), end="\n\n")

if __name__ == "__main__": #TODO: add log file
    connections_dict = {}
    """
    dictionary's keys: connection ID
    dictionary's values: [current spinbit's value, estimated RTT, last edge timestamp]
    """
    live_cap = pyshark.LiveCapture(display_filter="quic") # TODO: choose specifice interface

    try:
        for i, packet in enumerate(live_cap):
        # for packet in live_cap:
            # print(packet.layers) #TODO: remove this
            quic_header = packet['quic'] #TODO: there can be multiple QUIC headers in a single packet
            
            #debug stuff
            # print(quic_header.field_names)  #TODO: remove
            # print("header_form:", quic_header.get_field_value("header_form"))
            # print("long_packet_type:", quic_header.get_field_value("long_packet_type"))
            # print("frame_type:", quic_header.get_field_value("frame_type"))
            # ['', 'connection_number', 'packet_length', 'short', 'header_form', 'fixed_bit', 'spin_bit', 'dcid', 'remaining_payload']
            
            
            curr_dcid = quic_header.get_field_value("dcid")
            curr_sb =  quic_header.get_field_value("spin_bit")
            # print("spin bit's value: ", curr_sb) #TODO: remove
            # print("spinbit's type:", type(curr_sb)) #TODO: remove
            curr_ts = float(packet.sniff_timestamp)
            header_form = quic_header.get_field_value("header_form")
            long_packet_type = quic_header.get_field_value("long_packet_type")

            # print(type(curr_dcid)) #TODO: remove
            # <class 'pyshark.packet.fields.LayerFieldsContainer'>


            if header_form == "1" and long_packet_type == "0": # Initial packet
                curr_scid = quic_header.get_field_value("scid")
                connections_dict[curr_scid] = conn_info(None, curr_ts) # Insert by scid. scid will be dcid for future packets
                continue

            curr_info = connections_dict.setdefault(curr_dcid, conn_info(curr_sb, curr_ts)) # Add connection if new 
            curr_info.update(curr_sb, curr_ts)

            
            # print(quic_header.get_field_value("connection_number"))
            # if quic_header.header_form == pyshark.packet.fields.LayerFieldsContainer(0):
            #     print(quic_header.spin_bit, packet_timestamp)

    except KeyboardInterrupt:
        live_cap.close()
        print_conns(connections_dict)
        print("Stopping Estimator")
        sys.exit(0)