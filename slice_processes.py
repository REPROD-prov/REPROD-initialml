#!/usr/bin/python3

import sys
import os
import re
from util import make_datetime, make_datetime_str_file, make_datetime_str_query, err
from datasets import check_proc_name

HERALD = "Slice-Processes 1.20"

REGULAR_ROOT_DIR = "/homes/poggio/radix/data2/"
#REGULAR_ROOT_DIR = "/Users/andy/Documents/SRI/RADIX/data2/"
DOCKER_ROOT_DIR = "/spade-data2/"
BENIGN_DIR = "benign"
RAN_DIR = "ransomware"

ID_REGEX = re.compile("^\"([0-9a-f]+)\"")
DOT_NAME_REGEX = re.compile("\\\\nname:([0-9a-f]+).(exe|EXE)\\\\n")
DOT_EDGE_REGEX = re.compile("^\"([0-9a-f]+)\" -> \"([0-9a-f]+)\"")
DOT_DATETIME_REGEX = re.compile("datetime:(.+?(AM|PM))\\\\n")

DIR_PERMISSION_MODE = 0o777
FILE_PERMISSION_MODE = 0o666

timeslice_count = 0


def print_help():
    print("Usage:  " + sys.argv[0] + " <ransomware name>")


def main():
    global timeslice_count

    if len(sys.argv) == 2:
        print(HERALD)
    else:
        print_help()
        sys.exit(1)

    name_s = sys.argv[1]
    setup_directories(name_s)
    script_path = REGULAR_ROOT_DIR + name_s + ".sh"
    processes_path = REGULAR_ROOT_DIR + name_s + "-processes.dot"
    edges_path = REGULAR_ROOT_DIR + name_s + "-edges.dot"

    (benign_hm, ran_hm) = gather_processes(processes_path, name_s)
    process_count = len(benign_hm) + len(ran_hm)
    print(str(process_count) + " processes found")
    print("   " + str(len(ran_hm)) + " ransomware process(es) found")

    write_shell_script(name_s, edges_path, benign_hm, ran_hm, script_path, DOCKER_ROOT_DIR + name_s)
    print(str(timeslice_count) + " timeslices found")


def write_hm_script(name_s, type_s, my_hm, data_path, out):
    global timeslice_count

    my_data_path = data_path  + "/" + type_s
    for (my_id, my_set) in my_hm.items():
        process_dir_path = REGULAR_ROOT_DIR + name_s + "/" + type_s + "/" + my_id
        os.mkdir(process_dir_path)
        os.chmod(process_dir_path, DIR_PERMISSION_MODE)
        out.write("$my_process = vertices('" + my_id + "')\n")
        out.write("$my_lineage = $base.getLineage($my_process, 1, 'b')\n")
        for my_item in my_set:
            datetime_s = make_datetime_str_query(my_item)
            out.write("$my_edges = $my_lineage.getEdge(datetime = '" + datetime_s + "')\n")
            out.write("$my_vertices = $my_edges.getEdgeEndpoints()\n")
            out.write("$my_graph = $my_edges + $my_vertices\n")
            file_path = my_data_path + "/" + my_id + "/" + make_datetime_str_file(my_item) + ".dot"
            out.write("export > " + file_path + "\n")
            out.write("dump all $my_graph\n")
            timeslice_count += 1


def write_shell_script(name_s, edges_path, benign_hm, ran_hm, script_path, data_path):
    get_timestamps(edges_path, benign_hm, ran_hm)

    out = open(script_path, 'w')
    out.write("set storage Quickstep\n")
    out.write("env unset exportLimit\n")

    write_hm_script(name_s, BENIGN_DIR, benign_hm, data_path, out)
    write_hm_script(name_s, RAN_DIR, ran_hm, data_path, out)

    out.write("exit\n")
    out.close()
    os.chmod(script_path, FILE_PERMISSION_MODE)


def get_timestamps(edges_path, benign_hm, ran_hm):
    input_file = open(edges_path, 'r')

    # loop reading lines
    while True:
        # get next line from file
        line = input_file.readline()
        if line:
            match = re.search(DOT_EDGE_REGEX, line)
            if match:
                id1 = match.group(1)
                id2 = match.group(2)
                match = re.search(DOT_DATETIME_REGEX, line)
                if match:
                    my_datetime_s = match.group(1)
                    my_datetime = make_datetime(my_datetime_s)
                    add_datetime(id1, my_datetime, benign_hm, ran_hm)
                    add_datetime(id2, my_datetime, benign_hm, ran_hm)
                else:
                    err("can't find datetime -- " + line, fatal = True)

        else:
            break  # if line is None, end of file is reached

    input_file.close()


def add_datetime(my_id, my_datetime, benign_hm, ran_hm):
    my_set = benign_hm.get(my_id)
    if my_set is not None:
        my_set.add(my_datetime)
        return

    my_set = ran_hm.get(my_id)
    if my_set is not None:
        my_set.add(my_datetime)
        return


def gather_processes(processes_path, name_s):
    input_file = open(processes_path, 'r')

    # set initial times
    benign_hm = {}
    ran_hm = {}

    # loop reading lines
    while True:
        # get next line from file
        line = input_file.readline()
        if line:
            match = re.search(ID_REGEX, line)
            if match:
                my_id = match.group(1)
            else:
                continue #  not a process line

            match = re.search(DOT_NAME_REGEX, line)
            if match:
                proc_name = match.group(1)
                benign = check_proc_name(name_s, proc_name)
                if benign:
                    benign_hm[my_id] = set()
                else:  # must be ransomware process
                    ran_hm[my_id] = set()
            else: # must be benign
                benign_hm[my_id] = set()
        else:
            break  # if line is None, end of file is reached

    input_file.close()

    if len(benign_hm) == 0:
        err("no benign processes", fatal=True)

    return benign_hm, ran_hm


def setup_directories(name_s):
    name_path = REGULAR_ROOT_DIR + name_s + "/"
    if not os.path.exists(name_path):
        os.mkdir(name_path)
        os.chmod(name_path, DIR_PERMISSION_MODE)
    else:
        err(name_s + " directory already exists", fatal=True)

    benign_path = name_path + BENIGN_DIR
    if not os.path.exists(benign_path):
        os.mkdir(benign_path)
        os.chmod(benign_path, DIR_PERMISSION_MODE)

    ran_path = name_path + RAN_DIR
    if not os.path.exists(ran_path):
        os.mkdir(ran_path)
        os.chmod(ran_path, DIR_PERMISSION_MODE)


if __name__ == "__main__":
    main()
