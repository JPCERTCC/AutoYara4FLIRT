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
import time

BATCH_MODE = True

if __name__ == '__main__': 
    # batch mode
    if BATCH_MODE: ida_auto.auto_wait()
    print("[*] Start!!")

    if 2 <= len(idc.ARGV):
        signame = idc.ARGV[1]
        signum = idc.ARGV[2]
        for i in range(int(signum)):
            ida_funcs.plan_to_apply_idasgn( signame + str(i + 1) )

    # save idb file
    idc.save_database( idaapi.get_root_filename() + ".idb")

    print("[*] Finish!!")
    # batch mode
    if BATCH_MODE: idc.exit()

