class InstanceCount:
    def __init__(self):
        self.dict = {}

    def add(self, thing):
        my_value = self.dict.get(thing)
        if my_value:
            self.dict[thing] = my_value + 1
        else:
            self.dict[thing] = 1

    def get_dict(self):
        return self.dict

    def do_print(self):
        for items in self.dict.items():
            print(str(items[1]) + "\t" + items[0])

    def convert_to_percent(self):
        total = 0
        for count in self.dict.values():
            total += count

        for item in self.dict.items():
            self.dict[item[0]] = 100.0* item[1] / total

    def do_print_percent(self):
        total = 0
        for count in self.dict.values():
            total += count
        for item in self.dict.items():
            print(("%6.2f%% " + item[0]) % (100.0* item[1] / total))
