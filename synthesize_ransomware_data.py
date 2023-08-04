#!/usr/bin/python3

# Synthesize ransomware data from existing ransomware data to improve benign/ransomware data balance
# Bootstrap the new data from the existing data
# Create both human and ML versions
# randomize:
#   number of malicious subsequences (50% to 150% of original count of malicious subsequences)
#      these are bootstrapped, i.e. sampled with replacement
#   placement of " " (by varying length of intervening norm sequences)
#   file names
#   content of norm subsequences (by selecting randomly for sampled norm event sequences and concatenation
#      these are bootstrapped, i.e. sampled with replacement
#   length of norm subsequences (50% of smallest to 150% of largest, same mean length as original)

import sys
import os
import re
from multiprocessing import Process
import traceback
import time
import filename_store
import opcode_store
from make_ml_data import setup_ran_directory, setup_directory, ML_DIR, HUMAN_DIR, FILE_PERMISSION_MODE, TABLE_FILE_EXT, dump_json, RAN_INDEX
from util import err, warn
from analyze_regex import EVENT_FORMAT_LEN, make_regex
from ransomware_regex import analyze_string, DIRECTORY_LIST, COL_COUNT, ROW_COUNT, DELIM, get_ran_seq_span_list, RE18
import random

HERALD = "Synthesize_Ransomware_Data 1.32"

# keep mean size the same
MIN_FRAC = 0.5 # 50%
MAX_FRAC = 1.5 # 150%

SYNTH_DATA_START_FILENAME = 1000
SYNTH_DATA_COPIES = 100 # number of synthetic data files to create for each ransomware

EVENT_RE = re.compile(r"(\d\d)-(\d\d\d\d\d\d)-(\d),") # event regex
EVENT_OPCODE_GROUP = 1
EVENT_FILENAME_GROUP = 2
EVENT_DERIV_GROUP = 3

OUT_DATETIME = "2001-01-01-00-00-01"
OUTPUT_PREAMBLE = "R\t" + OUT_DATETIME + "\t"


def print_help():
    print("Usage:  " + sys.argv[0] + " <input directory path> <output directory path>")


def main():
    if len(sys.argv) == 3:
        print(HERALD)
        print("")
        input_dir_path = sys.argv[1]
        output_dir_path = sys.argv[2]
    else:
        print_help()
        sys.exit(1)

    if os.path.exists(input_dir_path):
        file_list = os.listdir(input_dir_path)
        if len(file_list) == 0:
            err("Warning:  input directory is empty -- " + input_dir_path, fatal=True)
    else:
        err("Warning:  input directory doesn't exist -- " + input_dir_path, fatal=True)

    setup_ran_directory(output_dir_path)

    opcode_file_path = os.path.join(input_dir_path, "OpcodeTable.txt")
    my_opcode_store = opcode_store.OpcodeStore(opcode_file_path)

    process_list = []
    for ranware in DIRECTORY_LIST:
        p = Process(target=run, args=(input_dir_path, ranware, my_opcode_store, output_dir_path))
        p.start()
        process_list.append(p)
        time.sleep(.2)

    for p in process_list: # wait for all threads to finish
        p.join()

    print((""))
    print(HERALD + " finished")


def run(input_dir_path, ranware, my_opcode_store, output_dir_path):
    try:
        random.seed(7)  # make random numbers repeatable

        # make output directories
        out_human_path = os.path.join(output_dir_path, HUMAN_DIR, str(ranware.my_index))
        setup_directory(out_human_path)
        out_ml_path = os.path.join(output_dir_path, ML_DIR, str(ranware.my_index))
        setup_directory(out_ml_path)

        in_path = os.path.join(input_dir_path, str(ranware.my_index), ranware.my_ran_filename)
        if not os.path.exists(in_path):
            return # benign procmon traces only; no ransomware

        my_filename_store = filename_store.FileNameStore(filename_store.NAME_TYPE)
        type_string, regex_string = make_regex(in_path, my_filename_store, my_opcode_store)
        ran_seq_span_list = get_ran_seq_span_list(regex_string, ranware.my_re)
        norm_list, ran_list = make_event_lists(regex_string, ran_seq_span_list)

        # norm_list = ["10-000010-0,10-000010-1,"]
        # ran_list = ["07-000007-0,07-000007-1,"]

        for my_index in range(SYNTH_DATA_COPIES):
            synth_ran_count, synth_str = make_synth_str(norm_list, ran_list)

            base_name = str(SYNTH_DATA_START_FILENAME + my_index)
            write_human_file(out_human_path, synth_str, base_name, my_opcode_store)
            check_human_file(out_human_path, base_name, my_opcode_store, synth_ran_count, synth_str, ranware.my_re)

            write_ml_file(out_ml_path, synth_str, base_name)
    except Exception as e:
        err(traceback.format_exc())
        # Logs the error appropriately.
    print(".", end='')


def check_human_file(out_human_path, my_filename, my_opcode_store, synth_ran_count, synth_str, my_re):
    my_filename_store =  filename_store.FileNameStore(filename_store.NAME_TYPE)
    my_path = os.path.join(out_human_path, my_filename)
    type_string, regex_string = make_regex(my_path, my_filename_store, my_opcode_store)
    # check_strings(synth_str, regex_string)
    found_ran_count = analyze_string(regex_string, my_re)
    if synth_ran_count > found_ran_count:
        err(my_path + " ran counts in file don't match -- " + str(synth_ran_count) + " and " + str(found_ran_count), fatal=True)
    if synth_ran_count < found_ran_count:
        print("")
        warn(my_path + " ran counts in file don't match -- " + str(synth_ran_count) + " and " + str(found_ran_count))
        check_opcode(my_path, synth_str, regex_string)


# def check_strings(s1, s2):
#     if len(s1) != len(s2):
#         print("lengths differ -- " + str(len(s1)) + " and " + str(len(s2)))
#
#     for i in range(0,len(s1)):
#         c1 = s1[i]
#         c2 = s2[i]
#         if c1 != c2:
#             print("diff found")
#             print(s1[i-10:i+30])
#             print(s2[i-10:i+30])
#             xyz = 1


def check_opcode(my_path, synth_str, file_string):
    if len(synth_str) != len(file_string):
        err(my_path + " string lens in file don't match -- " + str(len(synth_str)) + " and " + str(len(file_string)), fatal=True)

    for synth_match, file_match in zip(re.finditer(EVENT_RE, synth_str), re.finditer(EVENT_RE, file_string)):
        synth_op = synth_match.group(EVENT_OPCODE_GROUP)
        file_op = file_match.group(EVENT_OPCODE_GROUP)
        if synth_op != file_op:
            err(my_path + " opcodes in file don't match -- " + synth_op + " and " + file_op, fatal=True)


def write_ml_file(out_ml_path, synth_str, my_filename):
    tenth_microsecond = 1000000
    my_path = os.path.join(out_ml_path, my_filename)
    my_list = []

    for match in re.finditer(EVENT_RE, synth_str):
        opcode = match.group(EVENT_OPCODE_GROUP)
        filename = match.group(EVENT_FILENAME_GROUP)
        deriv = match.group(EVENT_DERIV_GROUP)

        tenth_microsecond += 1
        file_index = (2 *int(filename)) + int(deriv) # encode deriv info into last bit of indes
        my_item = [OUT_DATETIME, tenth_microsecond, int(opcode), int(file_index), RAN_INDEX]
        my_list.append(my_item)

    dump_json(my_list, my_path)


def write_human_file(out_human_path, synth_str, my_filename, my_opcode_store):
    tenth_microsecond = 1000000
    my_path = os.path.join(out_human_path, my_filename)

    with open(my_path, 'w') as out_file:
        for match in re.finditer(EVENT_RE, synth_str):
            opcode = match.group(EVENT_OPCODE_GROUP)
            filename = match.group(EVENT_FILENAME_GROUP)
            deriv = match.group(EVENT_DERIV_GROUP)

            tenth_microsecond += 1
            opcode_str = my_opcode_store.get_name(opcode)
            filename_str = make_filename(filename, deriv)
            my_item = OUTPUT_PREAMBLE + str(tenth_microsecond) + "\t" + opcode_str + "\t" + filename_str
            out_file.write(my_item + "\n")

    os.chmod(my_path, FILE_PERMISSION_MODE)


def make_synth_str(norm_list, ran_list):
    ran_count = len(ran_list)
    norm_count = len(norm_list)
    norm_min_len, norm_max_len = get_str_lens(norm_list)
    my_filename_store = filename_store.FileNameStore(filename_store.INDEX_TYPE) # use just one filename_store for entire string (file)
        # filename store dict will be cleared as needed

    synth_ran_count = make_synth_ran_count(ran_count)
    my_str = ""
    my_str += make_synth_norm_str(norm_list, norm_count, my_filename_store)
    for this_count in range(0, synth_ran_count):
        my_str += make_synth_ran_str(ran_count, ran_list, my_filename_store)
        my_str += make_synth_norm_str(norm_list, norm_count, my_filename_store)

    return synth_ran_count, my_str


def make_synth_ran_str(ran_count, ran_list, my_filename_store): # just pick random one from list
    my_filename_store.reset_dict()
    rand_index = random.randint(0, ran_count - 1)
    existing_str =  ran_list[rand_index]
    new_str = fix_filenames(existing_str, my_filename_store)
    return new_str


def make_synth_norm_str(norm_list, norm_count, my_filename_store):
    # pick random norm seq from list
    rand_index = random.randint(0, norm_count - 1)
    norm_seq = norm_list[rand_index]
    norm_synth_len = make_synth_ran_count(len(norm_seq) / EVENT_FORMAT_LEN)
    # we vary len around randomly chosen norm seq to maintain distribution of norm seq lengths

    # loop concatenating random norm strings until reach desired length
    my_str = ""
    while True:
        my_filename_store.reset_dict()

        if ((len(my_str) + len(norm_seq)) / EVENT_FORMAT_LEN) < norm_synth_len:  # use the whole norm seq
            new_seq = fix_filenames(norm_seq, my_filename_store)
            my_str += new_seq

            # pick random norm seq from list
            rand_index = random.randint(0, norm_count - 1)
            norm_seq = norm_list[rand_index]
        else: # just fill up my_str to norm_synth_len
            fill_len = norm_synth_len - int(len(my_str) / EVENT_FORMAT_LEN)
            new_seq = fix_filenames(norm_seq[0:(fill_len * EVENT_FORMAT_LEN)], my_filename_store)
            my_str += new_seq
            break # done

    return my_str


def make_synth_ran_count(ran_count):
    count =  random.randint(int(ran_count * MIN_FRAC), int(ran_count * MAX_FRAC)) # includes both ends of range
    if count < 1:
        count = 1
    return count


def get_str_lens(my_list):
    min = sys.maxsize
    max = 0

    for my_str in my_list:
        if len(my_str) < min:
            min = len(my_str)
        if len(my_str) > max:
            max = len(my_str)

    return int(min / EVENT_FORMAT_LEN), int(max / EVENT_FORMAT_LEN)


def make_event_lists(my_str, ran_seq_span_list):
    norm_list = [] # normal event sequence list
    ran_list = [] # ransomware event sequence list

    # check for initial norm events
    my_span = ran_seq_span_list[0]
    ran_start = my_span[0]
    if ran_start > 0: # initial norm events
        norm_list.append(my_str[0:ran_start])

    for my_index in range(0, len(ran_seq_span_list)):
        my_span = ran_seq_span_list[my_index]
        ran_list.append(my_str[my_span[0]:my_span[1]])
        if (my_index + 1) < len(ran_seq_span_list): # more ran sequences
            # add norm sequence
            my_next_span = ran_seq_span_list[my_index + 1]
            norm_list.append(my_str[my_span[1]:my_next_span[0]])
        else: # last span; check for final norm events
            if my_span[1] < len(my_str): # more norm events
                norm_list.append(my_str[my_span[1]:len(my_str)])

    return norm_list, ran_list


# def check_re_match_list(my_list):
#     for my_item in my_list:
#         check_re_match(my_item)
#
#
# def check_re_match(my_item):
#     match = re.match(RE18, my_item)
#     if match:
#         print("found match")


def fix_filenames(in_str, my_filename_store): # insure file names (indices) are unique when concating event sequences
    out_str = ""
    for match in re.finditer(EVENT_RE, in_str):
        opcode = match.group(EVENT_OPCODE_GROUP)
        filename = match.group(EVENT_FILENAME_GROUP)
        deriv = match.group(EVENT_DERIV_GROUP)

        if deriv == filename_store.DERIVATIVE_STR: # file was derivative
            filename += TABLE_FILE_EXT

        new_filename = my_filename_store.get_index_str(filename)
        new_event = opcode + "-" + new_filename + ","
        out_str += new_event

    return out_str


def make_filename(index_str, type_str):
    if index_str == "000000":
        return ""
    else:
        my_index = int(index_str)
        filename = "C:\\\\Users\\\\U\\\\F" + str(my_index)
        if type_str == "1": # file has extension
            filename += TABLE_FILE_EXT
        return filename


if __name__ == "__main__":
    main()
