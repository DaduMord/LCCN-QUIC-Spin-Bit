import datetime
import pyshark

if __name__ == "__main__":
    live_cap = pyshark.LiveCapture(display_filter="quic")
    for i, packet in enumerate(live_cap):
        packet_timestamp = datetime.datetime.now()
        quic_header = packet['quic']
        print(quic_header.field_names)
        # if quic_header.header_form == pyshark.packet.fields.LayerFieldsContainer(0):
        #     print(quic_header.spin_bit, packet_timestamp)