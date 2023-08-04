#!/usr/bin/python3

import sys
import os
import re
import datetime
from util import make_datetime, make_datetime_str_file, make_datetime_str_query

HERALD = "Find-Datetimes 1.1"


def print_help():
    print("Usage:  " + sys.argv[0] + " <input dot file path>")


def err(s, fatal = False):
    print("Error:  " + s)
    if fatal:
        sys.exit(1)


def main():
    if len(sys.argv) == 2:
        print(HERALD)
    else:
        print_help()
        sys.exit(1)

    input_file_path = sys.argv[1]
    input_file = open(input_file_path, 'r')

    # set initial times
    start_time = None
    end_time = None

    # loop reading lines
    while True:
        # get next line from file
        line = input_file.readline()
        if line:
            this_time = make_datetime(line)
            if this_time:
                if start_time:
                    if this_time < start_time:
                        start_time = this_time
                else:
                    start_time = this_time

                if end_time:
                    if end_time < this_time:
                        end_time = this_time
                else:
                    end_time = this_time

        else:
            break # if line is None, end of file is reached

    input_file.close()
    print("start time and end time:  ")
    print("\""  + make_datetime_str_query(start_time) + "\" \"" + make_datetime_str_query(end_time) + "\"")

if __name__ == "__main__":
    main()


