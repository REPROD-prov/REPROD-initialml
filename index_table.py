class IndexTable:
    def __init__(self):
        self.dict = {}

    def get_index(self, thing):
        my_value = self.dict.get(thing)
        if my_value is not None:
            my_index = my_value
        else:
            my_index = len(self.dict)
            self.dict[thing] = my_index
            # print(str(my_index) + '\t' + thing)
        return my_index

    def get_index_no_add(self, thing):
        return self.dict.get(thing)

    def get_dict(self):
        return self.dict

    def do_dump(self, path):
        with open(path, 'w') as output_file:
            for item in self.dict.items():
                output_file.write(str(item[1]) + "\t" + item[0] + '\n')
