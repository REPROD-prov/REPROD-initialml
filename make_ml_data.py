#!/usr/bin/python3

# make the data for machine learning
# uses dot files as input
# puts all data for a process into a single file
# a datum is:  [string:  date-time stamp, integer:  tenths of microseconds, integer:  operation index,
# integer:  file name index, integer:  0 for benign, 1 for ransomware]

import sys
import os
import re
import json
import shutil
from util import make_datetime, make_datetime_str_file, make_datetime_str_query, err, MICROSEC_PAT
from datasets import ransomware_name_list
from slice_processes import DOT_EDGE_REGEX, REGULAR_ROOT_DIR, BENIGN_DIR, RAN_DIR
import index_table

HERALD = "Make_ML_Data 1.14"

PRE_DI_RE = re.compile("^digraph.+")
PRE_GRAPH_RE = re.compile("^graph.+")
PRE_NODE_RE = re.compile("^node.+")
PRE_EDGE_RE = re.compile("^edge.+")
PRE_RE_LIST = [PRE_DI_RE, PRE_GRAPH_RE, PRE_NODE_RE, PRE_EDGE_RE]

POST_BRACKET_RE = re.compile("\}$")

ID_REGEX = "\"([0-9a-f]+)\""
LABEL_REGEX = " \[label=\"(.+)\"\];"
NODE_REGEX = re.compile(ID_REGEX + LABEL_REGEX, re.MULTILINE)
PATH_REGEX = re.compile("class:File System\\\\npath:(.+?)\\\\n", re.MULTILINE)

EDGE_REGEX = re.compile(ID_REGEX + " -> " + ID_REGEX + LABEL_REGEX, re.MULTILINE)

TYPE_REGEX = re.compile("type:(.+?)(\\\\n|\")", re.MULTILINE)
CATEGORY_REGEX = re.compile("category:(.+?)(\\\\n|\")", re.MULTILINE)
OP_REGEX = re.compile("operation:(.+?)(\\\\n|\")", re.MULTILINE)
TIME_REGEX = re.compile("time:" + MICROSEC_PAT + "(\\\\n|\")", re.MULTILINE)

ML_DIR = "ml"
HUMAN_DIR = "human"

DIR_PERMISSION_MODE = 0o777
FILE_PERMISSION_MODE = 0o666

TABLE_FILE_EXT = ".txt"

BENIGN_INDEX = 0
BENIGN_CODE = "B"
RAN_INDEX = 1
RAN_CODE = "R"


def print_help():
    print("Usage:  " + sys.argv[0] + " <input directory path> <output directory path>")


def main():
    if len(sys.argv) == 3:
        print(HERALD)
        input_dir_path = sys.argv[1]
        output_dir_path = sys.argv[2]
    else:
        print_help()
        sys.exit(1)

    (ml_dir_path, human_dir_path) = setup_ran_directory(output_dir_path)
    if os.path.exists(input_dir_path):
        file_list = os.listdir(input_dir_path)
        if len(file_list) == 0:
            print("Warning:  variant input directory is empty -- " + input_dir_path)
            return
    else:
        print("Warning:  variant directory doesn't exist -- " + input_dir_path)
        return

    op_table = index_table.IndexTable()
    op_table.get_index("\t") # ensure empty op has index of 0

    ran_table = index_table.IndexTable() # table of ransomware directory names

    for file_name in file_list:
        if ignore_file(file_name):
            continue
        ran_index = ran_table.get_index(file_name)
        ml_ran_path = os.path.join(ml_dir_path, str(ran_index))
        human_ran_path = os.path.join(human_dir_path, str(ran_index))
        analyze_variant(ran_index, os.path.join(input_dir_path, file_name), ml_ran_path, human_ran_path, op_table)

    op_table.do_dump(os.path.join(human_dir_path, "OpcodeTable" + TABLE_FILE_EXT))
    ran_table.do_dump(os.path.join(human_dir_path, "RansomwareTable" + TABLE_FILE_EXT))

    print("Finished")


def analyze_variant(ran_index, input_dir_path, ml_ran_path, human_ran_path, op_table):
    setup_directory( ml_ran_path)
    setup_directory( human_ran_path)

    file_id_table = index_table.IndexTable() # table of file ids
    file_id_table.get_index("") # ensure empty id has index of 0
    file_path_dict = {} # dictionary of (id, file path}
    process_table = index_table.IndexTable()

    benign_input_path = os.path.join(input_dir_path, BENIGN_DIR)
    analyze_type(benign_input_path, op_table, BENIGN_INDEX, file_id_table, file_path_dict, ml_ran_path, human_ran_path, process_table)

    ran_input_path = os.path.join(input_dir_path, RAN_DIR)
    analyze_type(ran_input_path, op_table, RAN_INDEX, file_id_table, file_path_dict, ml_ran_path, human_ran_path, process_table)

    dump_dict(file_path_dict, os.path.join(human_ran_path, "FileNames" + TABLE_FILE_EXT))


def dump_dict(my_dict, output_file_path):
    no_op = None


def dump_json(my_list, output_file_path):
    with open(output_file_path, 'w') as out_file:
        json.dump(my_list, out_file, indent=4)
    os.chmod(output_file_path, FILE_PERMISSION_MODE)


def dump_text(my_list, output_file_path):
    with open(output_file_path, 'w') as out_file:
        for my_tuple in my_list:
            for my_item in my_tuple:
                out_file.write(my_item + '\t')
            out_file.write('\n')
    os.chmod(output_file_path, FILE_PERMISSION_MODE)


def analyze_type(input_path, op_table, type_index, file_id_table, file_path_dict, ml_ran_path, human_ran_path, process_table):
    if os.path.exists(input_path):
        file_list = os.listdir(input_path)
        if len(file_list) == 0:
            print("Warning:  input type directory is empty -- " + input_path)
            return
    else:
        print("Warning:  input type directory doesn't exist -- " + input_path)
        return

    for file_name in file_list:
        if ignore_file(file_name):
            continue
        process_index = process_table.get_index(file_name)
        file_path = os.path.join(input_path, file_name)
        ml_file_path = os.path.join(ml_ran_path, str(process_index))
        human_file_path = os.path.join(human_ran_path, str(process_index))
        analyze_process(file_path, op_table, type_index, file_id_table, file_path_dict, ml_file_path, human_file_path)


def ignore_file(file_name):
    if file_name.startswith("."):
        return True
    if file_name.endswith(TABLE_FILE_EXT):
        return True
    return False


def analyze_process(input_path, op_table, type_index, file_id_table, file_path_dict, ml_file_path, human_file_path):
    ml_event_list = []
    human_event_list = []

    if os.path.exists(input_path):
        file_list = os.listdir(input_path)
        if len(file_list) == 0:
            print("Warning:  input process directory is empty -- " + input_path)
            return
    else:
        print("Warning:  input process directory doesn't exist -- " + input_path)
        return

    file_list.sort() # put timestamps in order
    for file_name in file_list:
        if ignore_file(file_name):
            continue

        (timestamp, extension) = os.path.splitext(file_name)
        file_path = os.path.join(input_path, file_name)
        (ml_file_event_list, human_file_event_list) = analyze_dot_file(file_path, timestamp, op_table, type_index, file_id_table, file_path_dict)

        ml_file_event_list.sort(key = lambda x: x[1])
        ml_event_list.extend(ml_file_event_list)
        human_file_event_list.sort(key = lambda x: x[2])
        human_event_list.extend(human_file_event_list)

    dump_json(ml_event_list, ml_file_path)
    dump_text(human_event_list, human_file_path)


def analyze_dot_file(file_path, timestamp, op_table, type_index, file_id_table, file_path_dict):
    ml_file_event_list = []
    human_file_event_list = []
    with open(file_path, 'r') as input_file:
        parse_preamble(input_file)

        parsing_nodes = True
        while True: # loop reading lines
            line = input_file.readline() # get next line from file
            if line:
                if parsing_nodes:
                    parsing_nodes = do_parse_node(line, file_id_table, file_path_dict)
                    if parsing_nodes:
                        continue  # still parsing nodes

                # now parsing edges
                if do_parse_edge(line, file_id_table, file_path_dict, timestamp, op_table, type_index, ml_file_event_list, human_file_event_list):
                    continue  # still parsing edges
                else:  # should be at file end
                    match = re.match(POST_BRACKET_RE, line)
                    if match:
                        break # successful completion
                    else:
                        err("bad line in file -- " + line, fatal=True)
            else:
                err("file ended before post bracket", fatal=True)

    return ml_file_event_list, human_file_event_list


def do_parse_node(line, file_id_table, file_path_dict):
    match = re.match(NODE_REGEX, line)
    if match:
        id = match.group(1)
        label = match.group(2)
        match = re.search(PATH_REGEX, label)
        if match:
            path = match.group(1)
            file_id_table.get_index(id)
            file_path_dict[id] = path
        return True
    else:
        return False


def do_parse_edge(line, file_id_table, file_path_dict, timestamp, op_table, type_index, ml_file_event_list, human_file_event_list):
    match = re.match(EDGE_REGEX, line)
    if match:
        id1 = match.group(1)
        id2 = match.group(2)
        label = match.group(3)

        match = re.search(MICROSEC_PAT, line)
        if match:
            msec = match.group(1)
        else:
            msec = "0"

        t = make_ml_edge_tuple(msec, id1, id2, label, file_id_table, timestamp, op_table, type_index)
        ml_file_event_list.append(t)
        t = make_human_edge_tuple(msec, id1, id2, label, file_path_dict, timestamp, type_index)
        human_file_event_list.append(t)
        return True
    else:
        return False


def make_ml_edge_tuple(msec, id1, id2, label, file_id_table, timestamp, op_table, type_index):
    file_index = get_file_index(id1, id2, file_id_table)
    if file_index is None:
        file_index = 0

    # get all label info
    match = re.search(OP_REGEX, label)
    if match:
        my_op = match.group(1)
    else:
        my_op = ""
    match = re.search(CATEGORY_REGEX, label)
    if match:
        my_cat = match.group(1)
    else:
        my_cat = ""
    # match = re.search(TYPE_REGEX, label)
    # if match:
    #     my_type = match.group(1)
    # else:
    #     my_type = ""

    s = my_cat + '\t' + my_op
    # s = my_type + '\t' + my_cat + '\t' + my_op
    op_index = op_table.get_index(s)

    my_tuple = (timestamp, int(msec), op_index, file_index, type_index)
    return my_tuple


def make_human_edge_tuple(msec, id1, id2, label, file_path_dict, timestamp, type_index):
    file_path = get_file_path(id1, id2, file_path_dict)
    if file_path is None:
        file_path = ""

    # get all label info
    match = re.search(OP_REGEX, label)
    if match:
        my_op = match.group(1)
    else:
        my_op = ""
    match = re.search(CATEGORY_REGEX, label)
    if match:
        my_cat = match.group(1)
    else:
        my_cat = ""
    # match = re.search(TYPE_REGEX, label)
    # if match:
    #     my_type = match.group(1)
    # else:
    #     my_type = ""

    op_s = my_cat + '\t' + my_op

    if type_index == RAN_INDEX: # ransomware
        type_s = RAN_CODE
    else:
        type_s = BENIGN_CODE

    my_tuple = (type_s, timestamp, msec, op_s, file_path)
    return my_tuple


def get_file_index(id1, id2, file_id_table):
    my_index = file_id_table.get_index_no_add(id1)
    if my_index is not None:
        return my_index

    return file_id_table.get_index_no_add(id2)


def get_file_path(id1, id2, file_path_dict):
    my_path = file_path_dict.get(id1)
    if my_path is not None:
        return my_path

    return file_path_dict.get(id2)


def parse_preamble(input_file):
    for pat in PRE_RE_LIST:
        line = input_file.readline() # get next line from file
        match = re.match(pat, line)
        if not match:
            err("bad preamble line -- " + line, fatal=True)


def setup_directory(name_path):
    if not os.path.exists(name_path):
        os.mkdir(name_path)
        os.chmod(name_path, DIR_PERMISSION_MODE)


def clear_dir(dir_path):
    shutil.rmtree(dir_path)


def setup_ran_directory(name_path):
    if  os.path.exists(name_path):
        clear_dir(name_path)

    setup_directory(name_path)

    ml_path = os.path.join(name_path, ML_DIR)
    setup_directory(ml_path)

    human_path = os.path.join(name_path, HUMAN_DIR)
    setup_directory(human_path)

    return ml_path, human_path


if __name__ == "__main__":
    main()

