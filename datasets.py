import sys
import os
from util import err


dataset_table = {
    'benign1':'',
    'benign2':'',
    'benign3':'',
    'crypto2':'8d2f2ee24882afe11f50e3d6d9400e35fa66724b321cb9f5a246baf63cbc1788',
    'Cryptolocker':'8d2f2ee24882afe11f50e3d6d9400e35fa66724b321cb9f5a246baf63cbc1788',
    'Dharma':'324cb383fd7f47c079b162b725215bb4badfd4c0b2e41d330fa38344e59e77ce',
    'dharma2':'42732ad450696b816913753fa9f53b52ac10922a1df1b5795693db77d532ffbc',
    'globeimposter2':'70fa0e970a0c29da67b5f1468996eecf7116256c2b7212fb6667b0fb92ad839d',
    'GlobelImposter':'185fafbeb00cd8238fdabee088763e27012dd3a0076e04dddca6266f129f0430',
    'hive':'eba2f0afd491ee595cd6908494e9e2a2115ed71c053c6d7b94970f1985830ada',
    'hive2':'88f7544a29a2ceb175a135d9fa221cbfd3e8c71f32dd6b09399717f85ea9afd1',
    'Jigsaw':'615d9d4fe030c0f34589c63b31e865e2e28267bdaa1ec6df6a3632ec54911209',
    'Lockdown':'6b2eef51eb8d2da78055f70b99a85766ba6731a99a5c1b90eaaa80a47ca42702',
    'Nefilim':'511fee839098dfa28dd859ffd3ece5148be13bfb83baa807ed7cac2200103390',
    'nefilim2':'45e35c9b095871fbc9b85afff4e79dd36b7812b96a302e1ccc65ce7668667fe6',
    'Phobos':'265d1ae339e9397976d9328b2c84aca61a7cb6c0bca9f2f8dc213678e2b2ad86',
    'Rapid':'1f1a072cd749503399a11f5cf75ee70295b4281dcf8fac0f27275b600571a699',
    'rapid2':'323077b0012c49c9f5e9cbef513475072433d0f96e421ae1763347f8ee839ecc',
    'REvil':'735ff072077023765e445b284f072946ffad2e36fa8aba9f1b8f93fef885352c',
    'revil2':'6295da1218817aaac71447d83d2221d251724dd33751d94581e3f10e76da1280',
    'sugar':'09ad72ac1eedef1ee80aa857e300161bc701a2d06105403fb7f3992cbf37c8b9',
    'sugar2':'1d4f0f02e613ccbbc47e32967371aa00f8d3dfcf388c39f0c55a911b8256f654',
    'thanos':'ef97bf49a9bd00a994143852590cc3a2d20227e510dc2b5968704d8f100b4d3c',
    'thanos2':'d29abe6ed086a5508c54df31010c36cc19fea3bdc5d521ee7c0d7063a51bb131',
    'Troldesh':'5013dc9e2ddbe9ddd90af638466379f876b70ebe504d62e72ed166480a4d4f83',
    'wannacry':'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa',
    'wannacry2':'eceb2f25bac4cbca1da5f4e390124912cd91f541ad1ccada2ae2b46f4aceb414'
}

ransomware_proc_list = dataset_table.values()
ransomware_name_list = dataset_table.keys()


def check_proc_name(set_name, proc_name):  # returns True => benign
    table_proc_name = dataset_table.get(set_name)
    if table_proc_name is not None: #  found set name
        if proc_name == table_proc_name:
            return False #  proc_name is ransomware for this dataset
        else:  #  proc_name isn't ransomware for this dataset
            # look to see if it matches any other ransomware
            if proc_name in ransomware_proc_list:
                err("other dataset ransomware in this dataset -- " + proc_name, fatal=True)
            else:
                return True

    else:
        err("bad dataset name -- " + set_name, fatal=True)

