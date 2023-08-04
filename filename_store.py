# store file names and index/derivative value
# indices only go up to MAX_INDEX
# empty file name is always index 0
# entry is (filename, (index, "index-derivValue string", "index"))

import os
from util import get_file_name_root, err


MAX_INDEX = 999999
ROOT = 0
ROOT_STR = str(ROOT)
DERIVATIVE = 1
DERIVATIVE_STR = str(DERIVATIVE)

NAME_TYPE = "name"
INDEX_TYPE = "index"


class FileNameStore:
    def __init__(self, my_type):
        if my_type == NAME_TYPE:
            self.is_name_type = True
        elif my_type == INDEX_TYPE:
            self.is_name_type = False
        else:
            err("bad type in filename_store -- " + my_type, fatal=True)
        self.dict = None # initialized here to declare variable; value not used
        self.reset_dict()
        self.current_index = 0 # initialized here to declare variable; value not used
        self.reset_index()

    def reset_dict(self):
        my_tuple = self.make_tuple(0, ROOT) # (filename, (index, "index-derivValue string", "index"))
        if self.is_name_type:
            self.dict = {"": my_tuple}
        else: # index type
            self.dict = {"000000": my_tuple}

    def reset_index(self):
        self.current_index = 0 # don't reuse index 0; current_index will be incremented before used

    def get_index_str(self, file_name):
        index_tuple = self.get_tuple(file_name)
        return index_tuple[1]

    def get_tuple(self, file_name):
        index_tuple = self.dict.get(file_name)
        if index_tuple is None:
            index_tuple = self.add_file_name(file_name)

        return index_tuple

    def get_root_tuple(self, path): # try to find a root by successively removing extensions
        new_file_name = path
        while True:
            old_file_name = new_file_name
            new_file_name = get_file_name_root(old_file_name)
            if new_file_name == old_file_name:
                break # no more extensions
            my_tuple = self.dict.get(new_file_name)
            if my_tuple:
                return my_tuple

        return None

    def add_file_name(self, file_name):  # filename is not in dict; add it
        # my_deriv_tuple = None # default
        # if self.is_name_type: # name may be derivative of existing
        #     my_deriv_tuple = self.get_root_tuple(file_name)

        my_deriv_tuple = self.get_root_tuple(file_name)

        if my_deriv_tuple:  # file name is derived (just has added extension) from existing file
            my_index = my_deriv_tuple[0]
            # no need to delete as we just reuse the index
            deriv_value = DERIVATIVE
        else:  # new root name -- needs new index
            if self.current_index >= MAX_INDEX:  # wrap index
                err("filename_store overflow -- over " + str(MAX_INDEX))
                self.reset_index()
            self.current_index += 1

            self.delete_index(self.current_index) # delete old index entries

            my_index = self.current_index
            deriv_value = ROOT

        new_tuple = self.make_tuple(my_index, deriv_value)
        self.dict[file_name] = new_tuple
        return new_tuple

    def delete_index(self, my_index):
        delete_list = []
        for k, v in self.dict.items():
            found_index = v[0]
            if my_index == found_index:
                delete_list.append(k)

        for k in delete_list:
            del self.dict[k]

    def make_tuple(self, index, deriv_value):
        my_filename_str = '{:06d}'.format(index)
        my_tuple_str = my_filename_str + '-' + str(deriv_value)
        my_tuple = (index, my_tuple_str, my_filename_str)
        return my_tuple
