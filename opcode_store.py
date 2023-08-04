import csv


class OpcodeStore:
    def __init__(self, input_file_path):
        self.dict = {}  # (opcode, index)
        self.dict_rev = {}  # (index, opcode)
        with open(input_file_path) as input_file:
            input_reader = csv.reader(input_file, delimiter='\t')
            for row_list in input_reader:
                opcode_str = row_list[1] + "\t" + row_list[2]
                index_str = '{:02d}'.format(int(row_list[0]))
                self.dict[opcode_str] = index_str
                self.dict_rev[index_str] = opcode_str

    def get_index_str(self, my_name):
        return self.dict[my_name]

    def get_name(self, my_index):
        return self.dict_rev[my_index]
