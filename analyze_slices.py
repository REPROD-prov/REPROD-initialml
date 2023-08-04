#!/usr/bin/python3
# analyze time slice dot files for aggregate statistics on edge types

import sys
import os
import re
import pickle
from util import make_datetime, make_datetime_str_file, make_datetime_str_query, err
from datasets import ransomware_name_list
from slice_processes import DOT_EDGE_REGEX, REGULAR_ROOT_DIR, BENIGN_DIR, RAN_DIR
import instance_count

HERALD = "Analyze-Slices 1.07"

DOT_TYPE_REGEX = re.compile("type:(.+?)(\\\\n|\")", re.MULTILINE)
DOT_CATEGORY_REGEX = re.compile("category:(.+?)(\\\\n|\")", re.MULTILINE)

CATEGORIES = ['Used -- Read', 'Used -- Read Metadata', 'Used', 'WasGeneratedBy -- Write', 'WasGeneratedBy -- Write Metadata', 'WasGeneratedBy', 'WasTriggeredBy', 'WasControlledBy']
HEADER = ['Read', 'Read Metadata', 'Used', 'Write', 'Write Metadata', 'WasGeneratedBy', 'WasTriggeredBy', 'WasControlledBy']
EXTENSION = ".obj"


def print_help():
    print("Usage:  " + sys.argv[0] + " <percentage file path no extension> [<dataset name>]")


def main():
    if len(sys.argv) == 2:
        print(HERALD)
        out_path = sys.argv[1]

        dataset_name = None
    elif len(sys.argv) == 3:
        print(HERALD)
        out_path = sys.argv[1]
        dataset_name = sys.argv[2]
    else:
        print_help()
        sys.exit(1)

    benign_percent_list = [HEADER]
    ran_percent_list = [HEADER]
    if dataset_name:
        analyze(REGULAR_ROOT_DIR, dataset_name, benign_percent_list, ran_percent_list)
    else:
        for name in ransomware_name_list:
            analyze(REGULAR_ROOT_DIR, name, benign_percent_list, ran_percent_list)

    # write output files
    write_file(benign_percent_list, out_path + "-" + BENIGN_DIR + EXTENSION)
    write_file(ran_percent_list, out_path + "-" + RAN_DIR + EXTENSION)


def write_file(my_list, my_out_path):
    with open(my_out_path, 'wb') as output_file:
        pickle.dump(my_list, output_file)

    # output_file = open(my_out_path, 'w')
    #
    # first = True
    # for header_name in HEADER:
    #     if first:
    #         output_file.write(header_name)
    #         first = False
    #     else:
    #         output_file.write('\t' + header_name)
    # output_file.write(('\n'))
    #
    # for line_list in my_list:
    #     first = True
    #     for val in line_list:
    #         if first:
    #             output_file.write(str(val))
    #             first = False
    #         else:
    #             output_file.write('\t' + str(val))
    #     output_file.write(('\n'))
    #
    # output_file.close()


def analyze(directory_path, dataset_name, benign_percent_list, ran_percent_list):
    print("Analyzing dataset:  " + dataset_name)
    path = os.path.join(directory_path, dataset_name)

    analyze_type(path, dataset_name, BENIGN_DIR, benign_percent_list)
    analyze_type(path, dataset_name, RAN_DIR, ran_percent_list)


def analyze_type(path, dataset_name, type_name, global_list):
    my_path = os.path.join(path, type_name)
    if os.path.exists(my_path):
        file_list = os.listdir(my_path)
        if len(file_list) == 0:
            print("Warning:  type directory is empty -- " + my_path)
            return
    else:
        print("Warning:  type directory doesn't exist -- " + my_path)
        return

    my_count = instance_count.InstanceCount()
    for file_name in file_list:
        analyze_process(os.path.join(my_path, file_name), my_count)

    print(dataset_name + " -- " + type_name + ":")
    my_count.do_print_percent()

    my_list = []
    global_list.append(my_list)
    my_count.convert_to_percent()
    for category in CATEGORIES:
        val = my_count.get_dict().get(category)
        if val:
            my_list.append(val)
        else: # no edges of this type
            my_list.append(0.0)



def analyze_process(path, count):
    file_list = os.listdir(path)
    file_list.sort()

    for file_name in file_list:
        file_path = os.path.join(path, file_name)
        analyze_dot(file_path, count)


def analyze_dot(file_path, count):
    input_file = open(file_path, 'r')

    # loop reading lines
    while True:
        # get next line from file
        line = input_file.readline()
        if line:
            match = re.search(DOT_EDGE_REGEX, line)
            if match:
                match = re.search(DOT_TYPE_REGEX, line)
                if match:
                    my_s = match.group(1)
                    match = re.search(DOT_CATEGORY_REGEX, line)
                    if match:
                        my_s = my_s + " -- " + match.group(1)
                    if my_s in CATEGORIES:
                        count.add(my_s)
                    else:
                        err("can't find category -- " + my_s, fatal=True)
                else:
                    err("can't find type -- " + line, fatal = True)

        else:
            break  # if line is None, end of file is reached

    input_file.close()


if __name__ == "__main__":
    main()