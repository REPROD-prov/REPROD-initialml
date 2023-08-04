import sys
import os
import re
import datetime
import ntpath


DATETIME_PAT = re.compile("(\d+)/(\d+)/(\d\d\d\d) (\d+):(\d\d):(\d\d) (AM|PM)")
MICROSEC_PAT = "\d+:\d\d:\d\d.(\d\d\d\d\d\d\d) (AM|PM)"


def err(s, fatal=False):
    print("Error:  " + s)
    if fatal:
        sys.exit(1)


def warn(s):
    print("Warning:  " + s)


def make_datetime(s):
    match = DATETIME_PAT.search(s)
    if match:
        y = int(match.group(3))
        m = int(match.group(1))
        d = int(match.group(2))
        h = int(match.group(4))
        min = int(match.group(5))
        s = int(match.group(6))
        meridian = match.group(7)
        if meridian == "PM":
            h += 12 # 24-hour time

        my_datetime = datetime.datetime(y, m, d, h, min, s)
        return my_datetime
    else:
        return None


def make_datetime_str_query(my_datetime):
    y = my_datetime.strftime("%Y")
    m = my_datetime.strftime("%-m")
    d = my_datetime.strftime("%-d")
    h = my_datetime.strftime("%-I")
    min = my_datetime.strftime("%M")
    s = my_datetime.strftime("%S")
    meridian = my_datetime.strftime("%p")

    return m + "/" + d + "/" + y + " " + h + ":" + min + ":" + s + " " + meridian


def make_datetime_str_file(my_datetime):
    y = my_datetime.strftime("%Y")
    m = my_datetime.strftime("%m")
    d = my_datetime.strftime("%d")
    h = my_datetime.strftime("%H")
    min = my_datetime.strftime("%M")
    s = my_datetime.strftime("%S")

    return y + "-" + m + "-" + d + "-" + h + "-" + min + "-" + s


def get_file_name(my_path): # get file name from Windows path
    head, tail = ntpath.split(my_path)
    # if path ends with a separator, tail will be empty; in that case, get basename of head (entire path)
    return tail or ntpath.basename(head)


def get_file_name_root(my_path): # return file name without extension
    #path = get_file_name(my_path)
    #split_tup = os.path.splitext(path)
    split_tup = ntpath.splitext(my_path)
    file_name_root = split_tup[0]
    return file_name_root


# s = get_file_name_root("C:\\a\\b\\c\\f.ext")
# s = get_file_name_root("C:\\a\\b.e\\c\\f")
# s = get_file_name_root("C:\\a\\b.e\\c\\f.e1.e2")
# s = get_file_name_root(s)
# s = ""