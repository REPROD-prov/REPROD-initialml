#!/usr/bin/python3

# analyze application of regular expressions to ML/procmon data

import sys
import os
from multiprocessing import Process, SimpleQueue
from datasets import ransomware_name_list
from slice_processes import DOT_EDGE_REGEX, REGULAR_ROOT_DIR, BENIGN_DIR, RAN_DIR
import index_table
import filename_store
import opcode_store
import csv
from make_ml_data import TABLE_FILE_EXT
from ransomware_regex import analyze_string_all_re, DIRECTORY_LIST, COL_COUNT, ROW_COUNT, DELIM, make_header, make_header2
from make_ml_data import BENIGN_CODE, BENIGN_INDEX, RAN_CODE, RAN_INDEX
from util import err


HERALD = "Analyze_Regex 2.13"

# format for an event is:  DD-DDDDDD-D, where DD is op index, DDDDDD is file index, and D is root (0) or extensioned (1) file type
EVENT_FORMAT = "DD-DDDDDD-D,"
EVENT_FORMAT_LEN = len(EVENT_FORMAT)


def print_help():
    print("Usage:  " + sys.argv[0] + " <opcode file path> <input directory path>")


def main():
    if len(sys.argv) == 3:
        print(HERALD)
        opcode_file_path = sys.argv[1]
        input_dir_path = sys.argv[2]
    else:
        print_help()
        sys.exit(1)

    my_opcode_store = opcode_store.OpcodeStore(opcode_file_path)

    if os.path.exists(input_dir_path):
        file_list = os.listdir(input_dir_path)
        if len(file_list) == 0:
            print("Warning:  input directory is empty -- " + input_dir_path)
            return
    else:
        print("Warning:  input directory doesn't exist -- " + input_dir_path)
        return

    do_output(make_header())
    do_output(make_header2())

    my_q = SimpleQueue()
    master_list = [None] * ROW_COUNT # initialize so threads only do assignment but don't grow list
    process_list = []
    for master_list_index in range(len(master_list)): # iterate over ransomware directories (rows)
        ranware = DIRECTORY_LIST[master_list_index]
        p = Process(target=run, args=(input_dir_path, ranware, my_opcode_store, master_list, master_list_index, my_q))
        process_list.append(p)
        p.start()

    for p in process_list: # wait for all threads to finish
        p.join()

    # while not my_q.empty():
    #     my_element = my_q.get()
    #     master_list[my_element[0]] = my_element[1]
    # for row_str in master_list:
    #     if row_str:
    #         do_output(row_str)


def run(input_dir_path, ranware, my_opcode_store, master_list, master_list_index, my_q):
    dir_path = os.path.join(input_dir_path, str(ranware.my_index))

    benign_list = [0] * COL_COUNT
    ran_list = [0] * COL_COUNT
    type_list = [benign_list, ran_list]

    dir_list = os.listdir(dir_path)
    for base_name in dir_list:  # iterate through files in each ransomware dir
        if ignore_file(base_name):
            continue

        my_filename_store = filename_store.FileNameStore(filename_store.NAME_TYPE)
        file_path = os.path.join(dir_path, base_name)

        type_string, regex_string = make_regex(file_path, my_filename_store, my_opcode_store)
        type_list_index = get_type_index(type_string)

        type_row_list = analyze_string_all_re(regex_string)
        # print(base_name + " " + str(type_row_list))

        sum_up_row(type_list[type_list_index], type_row_list)

    row_str = make_row(ranware, type_list)
    # my_q.put((master_list_index, row_str))
    print(str(master_list_index) + "\t" + row_str)


def make_row(ranware, row_list):
    row_str = ranware.my_name + DELIM
    for i in range(COL_COUNT):
        for type_index in range(2):
            my_list = row_list[type_index]
            row_str += str(my_list[i]) + DELIM

    return row_str


def do_output(row_str):
    print(row_str)


def sum_up_row(total_list, add_list):
    if len(total_list) != len(add_list):
        err("total_list and add_list have diff lengths", fatal=True)

    for i in range(len(total_list)):
        total_list[i] += add_list[i]


def get_type_index(ran_string):
    if ran_string == RAN_CODE: # ransomware
        type_index = RAN_INDEX
    else:
        type_index = BENIGN_INDEX

    return type_index


def make_regex(file_path, my_filename_store, my_opcode_store):
    my_string = ""
    my_type_string = None
    with open(file_path) as input_file:
        input_reader = csv.reader(input_file, delimiter='\t')
        for row_list in input_reader:
            if my_type_string is None:
                my_type_string = row_list[0] # Benign or Ransom
            opcode_string = my_opcode_store.get_index_str(row_list[3] + "\t" + row_list[4])
            file_string = my_filename_store.get_index_str(row_list[5])
            event_str = opcode_string + "-" + file_string
            my_string += event_str + ","

    return my_type_string, my_string


def ignore_file(file_name):
    if file_name.startswith("."):
        return True
    if file_name.endswith(TABLE_FILE_EXT):
        return True
    return False


if __name__ == "__main__":
    main()