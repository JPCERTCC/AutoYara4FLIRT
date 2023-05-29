#---------------------------------------------------------------------------------
# This tool has been tested in the following versions and environments.
# IDA Pro Version 8.2, Windows10
#---------------------------------------------------------------------------------
__date__ = "20230501"
__author__ = "Yuma Masubuchi JPCERT/CC"
#---------------------------------------------------------------------------------


from idautils import *
from idc import *
from idaapi import *
from ida_funcs import *


def get_funcAddrAll():
    lcounter = 0
    fcounter = 0
    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            fcounter += 1
            flags = idc.get_func_flags(funcea)            
            if (flags & FUNC_LIB) != 0:
                lcounter += 1
    
    result_str = " {} / {} ".format(lcounter, fcounter)
    return result_str


def overwritefile(result_log):
    textfile = open("result.txt", "a")
    textfile.write(result_log)
    textfile.close()


if __name__ == '__main__': 
    # batch mode
    ida_auto.auto_wait()
    print("[*] Start!!")

    match_str = get_funcAddrAll()

    result_str = "[*] {}:\t{}\n".format(idaapi.get_root_filename(), match_str)
    
    overwritefile(result_str)

    print("[*] Finish!!")
    # batch mode
    idc.exit()
