#!/usr/bin/python3

import sys
import os
import re
import datetime
from util import make_datetime, make_datetime_str_file, make_datetime_str_query, err

HERALD = "Slice-Data 1.4"


def print_help():
    print("Usage:  " + sys.argv[0] + " <start time> <end time> <output file> <time slice directory path>")


def main():
    if len(sys.argv) == 5:
        print(HERALD)
    else:
        print_help()
        sys.exit(1)

    start_time_s = sys.argv[1]
    end_time_s = sys.argv[2]
    output_file_path = sys.argv[3]
    slice_path = sys.argv[4] + "/"

    # get times
    start_time = make_datetime(start_time_s)
    if start_time:
        print(make_datetime_str_query(start_time))
    else:
        err("bad my_datetime string -- " + start_time_s, True)

    end_time = make_datetime(end_time_s)
    if end_time:
        print(make_datetime_str_query(end_time))
    else:
        err("bad my_datetime string -- " + end_time_s, True)

    out = open(output_file_path, 'w')
    out.write("set storage Quickstep\n")
    out.write("env unset exportLimit\n")

    # dump to files loop
    now_time = start_time
    second_delta = datetime.timedelta(seconds = 1)
    count = 0
    while True:
        count += 1
        do_query(now_time, out, slice_path)
        now_time = now_time + second_delta
        if now_time > end_time:
            break

    out.write("exit\n")
    out.close()

    print("total file count:  " + str(count))


def do_query(now_time, out, slice_path):
    out.write("%edge_time = \"my_datetime\" == '" + make_datetime_str_query(now_time) + "'" + "\n")
    out.write("$edges = $base.getEdge(%edge_time)\n")
    out.write("$verts = $edges.getEdgeEndpoints()\n")
    out.write("$grph = $edges + $verts\n")
    out.write("export > " + slice_path + make_datetime_str_file(now_time) + ".dot\n")
    out.write("dump all $grph\n")

if __name__ == "__main__":
    main()


