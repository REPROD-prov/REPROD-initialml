import re

GE = r"(\d\d-\d\d\d\d\d\d-\d,)" # generic event regex
QUEST = r"?"
STAR = r"*"
STARQ = STAR + QUEST
PLUS = r"+"
PLUSQ = PLUS + QUEST

RMF = r"(01|03|06|07|09|12|19|49)" # read metadata with file name
RMFGEN = r"(" + RMF + r"-\d\d\d\d\d\d-\d,)" # read metadata with generic file name
RMFNEW = r"(" + RMF + r"-(?P<ind>\d\d\d\d\d\d)-0,)" # read metadata with new file name
RMFNAMED = r"(" + RMF + r"-(?P=ind)-0,)" # read metadata with named file name
RMFNAMEDEXT = r"(" + RMF + r"-(?P=ind)-1,)" # read metadata with extensioned file name

RWR = r"((02|04|05|08)-\d\d\d\d\d\d-\d,)" # read/write reg

RFNEW = r"(11-(?P<ind>\d\d\d\d\d\d)-0,)" # read file with new file name
RFNAMED = r"(11-(?P=ind)-0,)" # read file with named file name
RFNAMEDEXT = r"(11-(?P=ind)-1,)" # read file with extensioned file name
RFGEN = r"(11-\d\d\d\d\d\d-\d,)" # read file with generic name

CFGEN = r"(29-\d\d\d\d\d\d-\d,)" # create file with generic name
CFNAMED = r"(29-(?P=ind)-0,)" # create file with named file name
CFNEW2 = r"(29-(?P<ind2>\d\d\d\d\d\d)-0,)" # create file2 with named file2 name
CFNAMEDEXT = r"(29-(?P=ind)-1,)" # create file with extensioned name

WMF = r"(24|25|30|41)" # write metadata with file name
WMFGEN = r"(" + WMF + r"-\d\d\d\d\d\d-\d,)" # write metadata with generic name
WMFNAMED = r"(" + WMF + r"-(?P=ind)-0,)" # write metadata with name
WMFNAMED2 = r"(" + WMF + r"-(?P=ind2)-0,)" # write metadata with name2
WMFNAMEDEXT = r"(" + WMF + r"-(?P=ind)-1,)" # write metadata with extensioned name

WFGEN = r"(23-\d\d\d\d\d\d-\d,)" # write file with generic name
WFNEW2 = r"(23-(?P<ind2>\d\d\d\d\d\d)-0,)" # write file2 with  name2
WFNAMED = r"(23-(?P=ind)-0,)" # write file with  name
WFNAMED2 = r"(23-(?P=ind2)-0,)" # write file2 with  name2
WFNAMEDEXT = r"(23-(?P=ind)-1,)" # write file with extensioned name

FRGEN = r"(38-\d\d\d\d\d\d-\d,)" # file rename
FRNAMED = r"(38-(?P=ind)-0,)" # file rename
FRNAMEDEXT = r"(38-(?P=ind)-1,)" # file extensioned rename
FDNAMED = r"(39-(?P=ind)-0,)" # file delete

class RanWare:
    def __init__(self, my_index, my_name, my_ran_filename, my_re):
        self.my_index = my_index # directory number
        self.my_name = my_name # ransomware name
        self.my_ran_filename = my_ran_filename # name of file containing ransomware process procmon
        self.my_re = my_re # regular expression for matching

R0 = RanWare(0, "Jigsaw", "157", re.compile( # Jigsaw
                RMFNEW
                + RWR + PLUS
                + RFGEN + STAR
                + CFGEN
                + WFGEN + PLUS
                + RWR + STAR
                + RFGEN + STARQ
                + CFNAMEDEXT
                + r"("
                    + RFGEN + STAR
                    + RFNAMED + PLUS
                    + RFGEN + STAR
                    + WFNAMEDEXT
                + r")" + PLUSQ
                + WFNAMEDEXT
                + RMFNAMED
                + FDNAMED
                , re.VERBOSE)
      )

R1 = RanWare(1, "benign1", "-1", None)

RE2 = re.compile( # wannacry (2), wannacry2 (3)
                RMFNEW
                + RMFNAMED
                + RFNAMED + PLUSQ
                + CFNAMEDEXT
                + WFNAMEDEXT + PLUSQ
                + r"("
                    + RFNAMED + PLUSQ
                    + WFNAMEDEXT
                + r")" + PLUSQ
                + WMFNAMEDEXT
                + RMFNAMEDEXT + PLUSQ
                + FRNAMEDEXT
                + WMFNAMEDEXT
                + r"("
                    + RMFNAMED + PLUSQ
                    + WFNAMED + PLUS
                    + WFGEN + PLUSQ
                    + WFNAMED + PLUS
                + r")?"
        , re.VERBOSE)
R2 = RanWare(2, "wannacry", "257", RE2)
R3 = RanWare(3, "wannacry2", "204", RE2)

RE4 = re.compile( # Cryptolocker (4), crypto2 (8)
                 RMFNEW
                 + RFNAMED + PLUSQ
                 + RWR + PLUSQ
                 + CFNAMED
                 + WFNAMED + PLUSQ
                 + RMFNAMED + PLUSQ
                 + FRNAMED
            , re.VERBOSE)
R4 = RanWare(4, "Cryptolocker", "159", RE4)
R8 = RanWare(8, "crypto2", "174", RE4)

R5 = RanWare(5, "Troldesh", "182", re.compile( # Troldesh
                 RMFNEW
                 + RMFNAMED + PLUSQ
                 + RFNAMED + PLUSQ
                 + WFNAMED + PLUSQ
                 + RMFNAMED
                 + WFNAMED + PLUSQ
                 + RMFNAMED + PLUSQ
            , re.VERBOSE)
        )

R6 = RanWare(6, "bengin2", "-1", None)

R7 = RanWare(7, "benign3", "-1", None)

RE9 = re.compile( # Dharma (9), dharma2 (10)
                 RMFNEW
                 + RMFNAMED + PLUSQ
                 + CFNAMEDEXT
                 + r"("
                    + RFNAMED + PLUSQ
                    + WFNAMEDEXT + PLUSQ
                 + r")+?"
                 + WMFNAMEDEXT + PLUSQ
                 + WMFNAMED + PLUSQ
                 + RMFNAMED + PLUSQ
                 + WMFNAMEDEXT
                 + RMFNAMED
                 + FDNAMED
         , re.VERBOSE)
R9 = RanWare(9, "Dharma", "204", RE9)
R10 = RanWare(10, "dharma2", "229", RE9)

RE11 = re.compile( # globeimposter2, GlobelImposter
                 RMFNEW
                 + RMFNAMED
                 + RWR + PLUS
                 + WFNAMED
                 + WFNEW2
                 + WFNAMED2 + STARQ
                 + r"("
                    + r"(" + RFNAMED + r"|" + RMFNAMED + r")" + PLUSQ
                    + WFNAMED + PLUSQ
                    + WFNAMED2 + PLUSQ
                    + WFNAMED + STARQ
                 + r")*?"
                 + RMFNAMED
                 + RMFNAMED
                 + FRNAMED
    , re.VERBOSE)

R11 = RanWare(11, "globeimposter2", "171", RE11)
R12 = RanWare(12, "GlobelImposter", "71", RE11)

R13 = RanWare(13, "Lockdown", "220", re.compile( # Lockdown
                 RMFNEW
                 + RFNAMED + PLUS
                 + CFNAMED
                 + WFNAMED + PLUS
                 + RMFNAMED + PLUS
                 + FRNAMED
                 , re.VERBOSE)
       )

RE18 = re.compile( # nefilim2 (14) and Nefilim (18)
                 RMFNEW
                 + r"("
                     + RMFGEN
                     + GE
                     + RMFGEN
                     + RWR + PLUSQ
                     + RMFGEN
                     + GE + GE
                     + RMFGEN + PLUSQ
                     + RWR + PLUSQ
                     + RMFGEN
                     + RWR + PLUSQ
                 + r")?"
                 + RFNAMED + PLUSQ
                 + WFNAMED + PLUSQ
                 + RMFNAMED + PLUSQ
                 + FRNAMED
                 , re.VERBOSE)
R18 = RanWare(18, "Netfilim", "144", RE18)
R14 = RanWare(14, "nefilim2", "174", RE18)

RE15 = re.compile( # Rapid (15), rapid2 (21)
                 RMFNEW
                 + RFNAMED + PLUSQ
                 + RWR + PLUSQ
                 + WFNAMED + PLUSQ
                 + RMFNAMED + PLUSQ
                 + FRNAMED
                 # + RMFNAMED + PLUSQ
                 # + r"("
                 #    + RFNAMEDEXT + PLUSQ
                 #    + WFNAMEDEXT + PLUSQ
                 # + r")" + PLUSQ
                 , re.VERBOSE)
R15 = RanWare(15, "Rapid", "183", RE15)
R21 = RanWare(21, "rapid2", "229", RE15)

RE16 = re.compile( # hive (16), hive2 (17)
                 RMFNEW + RMFNAMED + STARQ
                 + FRNAMED
                 + RMFNAMEDEXT
                 + r"("
                    + RFNAMEDEXT + PLUSQ
                    + WFNAMEDEXT + PLUSQ
                 + r")" + PLUSQ
                 , re.VERBOSE)
R16 = RanWare(16, "hive", "320", RE16)
R17 = RanWare(17, "hive2", "330", RE16)

R19 = RanWare(19, "Phobos", "190", re.compile( # Phobos
                 RMFNEW + RMFNAMED + STARQ
                 + CFNAMEDEXT
                 + r"("
                     + RFNAMED + PLUSQ
                     + WFNAMEDEXT + PLUSQ
                 + r")" + PLUSQ
                 + RMFNAMED
                 + WFNAMED + PLUSQ
                 # + GE + STARQ
                 # + FDNAMED
                 , re.VERBOSE)
       )

RE20 = re.compile( # REvil, revil2
                 RMFNEW
                 + RFNAMED
                 + GE + r"{0,100}?"
                 + RFGEN + RFNAMED + RFGEN
                 + GE + r"{0,100}?"
                 + WFGEN + WFNAMED + WFGEN
                 + GE + r"{0,500}?"
                 + FRGEN
                 + RMFNAMED + RMFNAMED
                 + FRNAMED
                 , re.VERBOSE)
R20 = RanWare(20, "REvil", "229", RE20)
R23 = RanWare(23, "revil2", "233", RE20)

RE22 = re.compile( # sugar, sugar2
                 RMFNEW
                 + RMFNAMED
                 + GE + r"{0,100}?"
                 + CFGEN # sugar lower cases the extensioned file name, so can't match
                 + RMFNAMED
                 + r"("
                     + RFNAMED + PLUSQ
                     + WFGEN + PLUSQ
                 + r")" + PLUSQ
                 + WFNAMED
                 + RMFNAMED
                 + FDNAMED
                 , re.VERBOSE)
R22 = RanWare(22, "sugar", "231", RE22)
R26 = RanWare(26, "sugar2", "232", RE22)

RE24 = re.compile( # thanos, thanos2
                 RMFNEW
                 + RMFNAMED + STARQ
                 + FRNAMED
                 + RMFNAMEDEXT + PLUSQ
                 + RFNAMEDEXT + PLUSQ
                 + CFNAMEDEXT
                 + WFNAMEDEXT + PLUSQ
                 + RMFNAMEDEXT
                 + WFNAMEDEXT
                 , re.VERBOSE)
R24 = RanWare(24, "thanos", "322", RE24)
R25 = RanWare(25, "thanos2", "320", RE24)

RE_LIST = [R0, R2, R4, R5, R9, R11, R13, R18, R15, R16, R19, R20, R22, R24] # columns
#RE_LIST = [R11]
COL_COUNT = len(RE_LIST)

# DIRECTORY_LIST = [R0, R1, R2, R3, R4, R8, R5, R6, R7, R9, R10, R11, R12, R13, R18, R14, R15, R21, R16, R17, R19, R20, R23, R22, R26, R24, R25] # rows
DIRECTORY_LIST = [R1, R18]
ROW_COUNT = len(DIRECTORY_LIST)

DELIM = "\t"


def get_ransomware(dir_name):
    dir_index = int(dir_name)
    for my_ransomware in DIRECTORY_LIST:
        if dir_index == my_ransomware.my_index:
            return my_ransomware

    return None


def get_ran_seq_span_list(my_string, my_re):
    my_iter = re.finditer(my_re, my_string)
    ran_seq_list = [m.span() for m in my_iter]
    return ran_seq_list


def make_header():
    h = DELIM
    for my_ranware in RE_LIST:
        h += my_ranware.my_name + DELIM + " " + DELIM

    return h


def make_header2():
    h = DELIM
    for my_ranware in RE_LIST:
        h += "benign" + DELIM + "ran" + DELIM

    return h


def analyze_string_all_re(my_string): # returns list of all regex match counts for this string
    my_list = []
    for my_ranware in RE_LIST:
        my_re = my_ranware.my_re
        count = analyze_string(my_string, my_re)
        my_list.append(count)

    return my_list


def analyze_string(my_string, my_re): # returns regex match count for this string
    count = 0
    for match in re.finditer(my_re, my_string):
        count += 1

    return count


# print(make_header())
# print(make_header2())