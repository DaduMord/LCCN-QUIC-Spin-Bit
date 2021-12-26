import datetime
import pyshark

class conn_info:
    def __init__(self, sb, edge_ts, rtt=None):
        self.sb = sb
        self.rtt = rtt
        self.edge_ts = edge_ts

    def update_rtt(self, curr_sb):
        if (self.sb != curr_sb): # if spin bit has changed
            pass
        

    def moving_avg():
        pass


if __name__ == "__main__":
    connections_dict = {}
    """
    dictionary's keys: connection ID
    dictionary's values: [current spinbit's value, estimated RTT, last edge timestamp]
    """

    live_cap = pyshark.LiveCapture(display_filter="quic") # TODO: choose specifice interface
    for i, packet in enumerate(live_cap):
        quic_header = packet['quic']
        
        #debug stuff
        print(quic_header.field_names)  #TODO: remove
        # ['', 'connection_number', 'packet_length', 'short', 'header_form', 'fixed_bit', 'spin_bit', 'dcid', 'remaining_payload']
        
        
        curr_dcid = quic_header.get_field_value("dcid")
        curr_sb =  quic_header.get_field_value("spin_bit")
        print("spin bit's value: ", curr_sb) #TODO: remove
        print("spinbit's type:", type(curr_sb)) #TODO: remove
        curr_ts = packet.sniff_timestamp


        print(type(curr_dcid)) #TODO: remove
        #<class 'pyshark.packet.fields.LayerFieldsContainer'>

        connections_dict.setdefault(curr_dcid, conn_info(curr_sb, curr_ts)) # add connection if new 
        connections_dict[curr_dcid].update_rtt(curr_sb, curr_ts)


        # print(quic_header.get_field_value("connection_number"))
        # if quic_header.header_form == pyshark.packet.fields.LayerFieldsContainer(0):
        #     print(quic_header.spin_bit, packet_timestamp)