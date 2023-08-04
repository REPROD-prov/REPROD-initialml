#!/usr/bin/python3
# analyze a time slice dot file for events ordered in time

import sys
import os
import re
import pickle
from util import make_datetime, make_datetime_str_file, make_datetime_str_query, err, MICROSEC_PAT
from datasets import ransomware_name_list
from slice_processes import DOT_EDGE_REGEX, REGULAR_ROOT_DIR, BENIGN_DIR, RAN_DIR
import instance_count

HERALD = "Analyze-Events 1.1"

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



def print_help():
    print("Usage:  " + sys.argv[0] + " <dataset name> <dot file path> ...")


def main():
    if len(sys.argv) >= 3:
        print(HERALD)
        dataset_name = sys.argv[1]

        dot_path_list = []
        for i in range(2, len(sys.argv)):
            dot_path_list.append(sys.argv[i])
        dot_path_list.sort()
    else:
        print_help()
        sys.exit(1)

    for dot_path in dot_path_list:
        event_list = [] # list of tuples:  (time string, event string)
        analyze(dot_path, event_list)
        produce_output(event_list, dataset_name, dot_path)


def produce_output(event_list, dataset_name, dot_path):
    event_list.sort()

    print()
    print()
    print("*** Analyzing " + dataset_name + " -- " + dot_path + ':')
    for t in event_list:
        print(t[0]+ '\t' + t[1])


def analyze(dot_path, event_list):
    with open(dot_path, 'r') as input_file:
        parse_preamble(input_file)

        parsing_nodes = True
        file_dict = {}
        while True: # loop reading lines
            line = input_file.readline() # get next line from file
            if line:
                if parsing_nodes:
                    parsing_nodes = do_parse_node(line, file_dict)
                    if parsing_nodes:
                        continue  # still parsing nodes

                # now parsing edges
                if do_parse_edge(line, file_dict, event_list):
                    continue  # still parsing edges
                else:  # should be at file end
                    match = re.match(POST_BRACKET_RE, line)
                    if match:
                        break # successful completion
                    else:
                        err("bad line in file -- " + line, fatal=True)
            else:
                err("file ended before post bracket", fatal=True)


def do_parse_node(line, file_dict):
    match = re.match(NODE_REGEX, line)
    if match:
        id = match.group(1)
        label = match.group(2)
        match = re.search(PATH_REGEX, label)
        if match:
            path = match.group(1)
            entry = file_dict.get(id)
            if not entry:
                file_dict[id] = path
            else:
                err("duplicate file dictionary entry -- " + id, fatal=True)
        return True
    else:
        return False


def do_parse_edge(line, file_dict, event_list):
    match = re.match(EDGE_REGEX, line)
    if match:
        id1 = match.group(1)
        id2 = match.group(2)
        label = match.group(3)

        match = re.search(MICROSEC_PAT, line)
        if match:
            msec = match.group(1)
        else:
            err("can't find time in line -- " + line, fatal=True)

        t = make_edge_tuple(msec, id1, id2, label, file_dict)
        if t:
            event_list.append(t)
        return True
    else:
        return False


def make_edge_tuple(msec, id1, id2, label, file_dict):
    path = get_path(id1, id2, file_dict)
    if path is None:
        return None

    # get most specific type
    match = re.search(OP_REGEX, label)
    if match:
        my_type = match.group(1)
    else:
        match = re.search(CATEGORY_REGEX, label)
        if match:
            my_type = match.group(1)
        else:
            match = re.search(TYPE_REGEX, label)
            if match:
                my_type = match.group(1)
            else:
                err("can't find type in label -- " + label, fatal=True)

    s = my_type + '\t' + path
    t = (msec, s)
    return t


def get_path(id1, id2, file_dict):
    path = file_dict.get(id1)
    if path:
        return path
    path = file_dict.get(id2)
    if path:
        return path
    else:
        return None
        # err("can't find file path for ids -- " + id1 + ", " + id2, fatal=True)


def parse_preamble(input_file):
    for pat in PRE_RE_LIST:
        line = input_file.readline() # get next line from file
        match = re.match(pat, line)
        if not match:
            err("bad preamble line -- " + line, fatal=True)


if __name__ == "__main__":
    main()