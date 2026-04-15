import argparse
import packetlens.sniffer as sniffer
from packetlens.core import intializatin


def run():
    print("Starting engine")
    intializatin()


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--protocol",
        help="Filter based on protocol",
        choices=["TCP", "UDP", "ARP", "ICMP", "DNS"]
    )

    args = parser.parse_args()

    # 🔥 Set FILTER correctly
    if args.protocol:
        sniffer.FILTER = args.protocol

    run()