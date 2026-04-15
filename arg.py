import argparse
arg=argparse.ArgumentParser()
arg.add_argument("filter",help="Filter based on protocol",type=str)
val=arg.parse_args()
if val.filter=='tcp':
    print("ALl tcp packets")
