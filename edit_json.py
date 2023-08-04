#!/usr/bin/python3

# Edit an existing json-formatted file

import sys
import os
import re
import json
from make_ml_data import dump_json
from util import err


def read_json(file_path):
    with open(file_path, 'r') as in_file:
        read_obj = json.load(in_file)

    return read_obj


def edit(json_obj): # change this for specific edits
    for my_item in json_obj:
        if my_item[4] == 1:
            my_item[4] = 0
        else:
            err("Bad item found:  " + str(my_item[4]), fatal=True)


my_file_path = "/Users/andy/Documents/SRI/RADIX/development/data3/ml/12/146"
my_json_obj = read_json(my_file_path)
edit(my_json_obj)
dump_json(my_json_obj, my_file_path)
