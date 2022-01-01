

import argparse
import sys

def define_args(parser):
    parser.add_argument(
        "url", type=str, nargs="+", help="the URL to query (must be HTTPS)"
    )
    parser.add_argument(
        "-r",
        "--requests-file",
        type=str,
        help="The file with requests to send to the server",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        help="write downloaded files to this directory",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    #  TODO: add -rtt flag


def correct_format(line: str):
    return False
    pass


def handle_request_file(filename: str):
    url = ""
    url_base = "https://10.10.44.10:4433/"
    with open(filename, "r") as file:
        for line in file:
            if correct_format(line):
                args = line.split()

                if args[0] is "GET":
                    url += url_base + args[1]
                    
                elif args[0] is "POST":
                    #  TODO: figure out how to send multiple echoes, if possible
                    pass

    if url is "":
        url = url_base  # url base is also the default empty get requests needed
    return url


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QUIC modified client")
    define_args(parser)
    args = parser.parse_args()
    url = handle_request_file(args.requests_file)
    command_line = "./http3_client.cpython-39.pyc --ca-certs tests/pycacert.pem "
    command_line += "--output-dir " + args.output_dir
    command_line += "--quic-log " + args.quic_log
    command_line += url


        
    
    

        