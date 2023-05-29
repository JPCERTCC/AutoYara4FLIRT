#---------------------------------------------------------------------------------
# This tool has been tested in the following versions and environments.
# IDA Pro Version 8.2, Windows10
#---------------------------------------------------------------------------------
__date__ = "20230501"
__author__ = "Yuma Masubuchi JPCERT/CC"
#---------------------------------------------------------------------------------

#---------------------------------------------------------------------------------
import os
import sys
import time
import glob
import shutil

#---------------------------------------------------------------------------------
# Config
#---------------------------------------------------------------------------------
class ConfigVar:
    """
    ===================== sigmake filepath ===========================
    """
    SIGMAKE_DIR = "C:\\sigmake.exe"                                     # <<<<<<------------------ !!!
    IDA_INSTAll_PATH = "C:\\\"Program Files\"\\\"IDA Pro 8.2\""
    IDA_SIG_PATH      = r"C:\Program Files\IDA Pro 8.2\sig"
    """
    ==================================================================
    """
#---------------------------------------------------------------------------------


#---------------------------------------------------------------------------------
class Init:
    # exist folder
    workingTargetELF = ""
    workingHuntELF = ""

    # Generated folder
    workingGeneratedYara = ""
    workingGeneratedYaraAll = ""
    workingPAT = ""
    workingSIG = ""
    workingOutputIDB = ""
    workingOutputResult = ""

    # Tools
    workingTools  = ""
    idb2pat_path  = ""
    AutoYara_path = ""
    adapt_sig_path = ""
    output_result_path = ""

    # for initialize_var()
    idat_path = ""
    idat_path_script = ""
    idat_path_makeidb = ""

    # This file path
    CLI_AutoYara_Path = ""

def initialize_var(bitN):
    if bitN == "32":
        Init.idat_path = ConfigVar.IDA_INSTAll_PATH + "\\idat.exe "
    elif bitN == "64":
        Init.idat_path = ConfigVar.IDA_INSTAll_PATH + "\\idat64.exe "
    else:
        print('[*] Error, exit!')
        exit()

    Init.idat_path_script = Init.idat_path + "-c -A -S"
    Init.idat_path_script_noclear = Init.idat_path + "-A -S"
    Init.idat_path_makeidb = Init.idat_path + "-B "

    Init.CLI_AutoYara_Path = os.path.dirname(os.path.abspath(__file__))

    # exist folder
    Init.workingTargetELF = Init.CLI_AutoYara_Path + "\\" + "TargetELF" + "\\"
    Init.workingHuntELF = Init.CLI_AutoYara_Path + "\\" + "HuntedELF" + "\\"

    # Generated folder
    Init.workingGeneratedYara = Init.CLI_AutoYara_Path + "\\GeneratedYara"
    Init.workingGeneratedYaraAll = Init.CLI_AutoYara_Path + "\\GeneratedYaraAll"
    Init.workingPAT = Init.CLI_AutoYara_Path + "\\GeneratedPAT"
    Init.workingSIG = Init.CLI_AutoYara_Path + "\\GeneratedSIG"
    Init.workingOutputIDB = Init.CLI_AutoYara_Path + "\\GeneratedIDB"
    Init.workingOutputResult = Init.CLI_AutoYara_Path + "\\GeneratedResult"

    # Tools
    Init.workingTools = Init.CLI_AutoYara_Path + "\\_Tools\\"
    Init.idb2pat_path = "\"" + Init.workingTools + "idb2pat_Fix.py\""
    Init.AutoYara_path = "\"" + Init.workingTools + "AutoYara4FLIRT.py\""
    Init.adapt_sig_path = "\"" + Init.workingTools +  "ApplySig.py"
    Init.output_result_path = "\"" + Init.workingTools +  "OutputResult.py"


def movefile(oldpath, newpath):
    shutil.move(oldpath, newpath)


def copyfile(oldpath, newpath):
    shutil.copy(oldpath, newpath)


class pre_argv:
    signame_str = ""


def pre_argv_idapython(signature_name):
    pre_argv.signame_str = signature_name


def getfile_on_folder(folderpath):
    files = glob.glob(folderpath + "\\*")
    return files


def do_make_yara_all():
    files = glob.glob(Init.workingGeneratedYara + "\\" + "*.yara")
    with open(Init.workingGeneratedYaraAll + "\\" + "all.yara", "wb") as f_new:
        for f in files:
            with open(f,'rb') as f_org:
                f_new.write(f_org.read())
                print("[+] Generate YaraAll")


def do_autoyara():
    try:
        os.makedirs(Init.workingGeneratedYara)
        os.makedirs(Init.workingGeneratedYaraAll)
    except:
        print("[-] The folder already exist. {}".format(Init.workingGeneratedYara))
        print("[-] The folder already exist. {}".format(Init.workingGeneratedYaraAll))

    os.chdir(Init.workingGeneratedYara)

    files = getfile_on_folder(Init.workingTargetELF)
    for filepath in files:
        if filepath.endswith(('id0','id1','id2','nam','til','asm','idb','i64','pat')) == False:
            cmd = Init.idat_path_script + Init.AutoYara_path + " \"" + filepath + "\""
            print("[+] Generate Yara")
            os.system(cmd)


def do_elf2pat():
    try:
        os.makedirs(Init.workingPAT)
    except:
        print("[-] The folder already exist. {}".format(Init.workingPAT))


    files = getfile_on_folder(Init.workingHuntELF)
    for filepath in files:
        if filepath.endswith(('id0','id1','id2','nam','til','asm','idb','i64','pat')) == False:
            cmd = Init.idat_path_script + Init.idb2pat_path + " \"" + filepath + "\""
            os.system(cmd)

    files = getfile_on_folder(Init.workingHuntELF)
    for filepath in files:
        if filepath.endswith(('.pat')) == True:
            movefile(filepath, Init.workingPAT + "\\" )
            print("[+] Generate pat")

def do_pat2sig():
    try:
        os.makedirs(Init.workingSIG)
    except:
        print("[-] The folder already exist. {}".format(Init.workingSIG))

    os.chdir(Init.workingPAT + "\\" )

    counter = 0
    cmdlist = []

    files = getfile_on_folder(Init.workingPAT + "\\" )
    for filepath in files:
        if filepath.endswith(('pat')) == True:
            counter += 1
            signamefull = pre_argv.signame_str + str(counter)
            cmd = ConfigVar.SIGMAKE_DIR + ' -n"' + signamefull + '" ' + filepath + ' ' + signamefull +".sig"
            os.system(cmd)
            cmdlist.append(cmd)

    files = getfile_on_folder(Init.workingPAT + "\\" )
    for filepath in files:
        if filepath.endswith(('exc')) == True:
            deletelines = []
            with open(filepath) as f:
                lines = f.readlines()
            for line in lines:
                if line[0] == ";":
                    deletelines.append(line)
            for delline in deletelines:
                lines.remove(delline)
            with open(filepath, "w") as f:
                f.writelines(lines)

    time.sleep(2)

    for cmd_on_cmdlinst in cmdlist:
        os.system(cmd_on_cmdlinst)

    files = getfile_on_folder(Init.workingPAT)
    for filepath in files:
        if filepath.endswith(('sig')) == True:
            movefile(filepath, Init.workingSIG + "\\")
            print("[+] Generate sig")


def do_sig4targetelf(arch):
    try:
        os.makedirs(Init.workingOutputIDB)
    except:
        print("[-] The folder already exist. {}".format(Init.workingOutputIDB))

    os.chdir(Init.workingOutputIDB + "\\")

    files = getfile_on_folder(Init.workingSIG + "\\")
    sig_num = 0
    for filepath in files:
        if filepath.endswith(('sig')) == True:
            copyfile(filepath, ConfigVar.IDA_SIG_PATH + "\\" + arch + "\\")
            sig_num += 1

    files = getfile_on_folder(Init.workingTargetELF)
    for filepath in files:
        if filepath.endswith(('id0','id1','id2','nam','til','asm','idb','i64','pat')) == False:
            cmd = Init.idat_path_script + Init.adapt_sig_path +" "+ pre_argv.signame_str +" "+ str(sig_num) + "\" \"" + filepath + "\""
            os.system(cmd)
            print("[+] Generate idb")


def do_output_result():
    try:
        os.makedirs(Init.workingOutputResult)
    except:
        print("[-] The folder already exist. {}".format(Init.workingOutputResult))

    os.chdir(Init.workingOutputResult + "\\")

    files = getfile_on_folder(Init.workingTargetELF)
    for filepath in files:
        if filepath.endswith(('id0','id1','id2','nam','til','asm','idb','i64','pat','txt')) == False:

            cmd = Init.idat_path_script_noclear + Init.output_result_path + "\" \"" + filepath + "\""
            os.system(cmd)
            print("[+] Generate result")

# ------------------------------------------------------------------------------
USAGE_STR = ["Usage:",
            "\t --autoyara [BIT: 32 or 64]",
            "\t --elf2sig [BIT: 32 or 64] [SIGNATURE-NAME] [SIG: pc, arm... ]",]
# --------------------------------

if __name__ == '__main__':
    print("[+] Start!")

    args = sys.argv
    if 2 <= len(args):
        if (args[1] == "--autoyara") and (3 == len(args)):
            initialize_var(args[2])
            do_autoyara()
            do_make_yara_all()
        elif (args[1] == "--elf2sig") and (5 == len(args)):
            initialize_var(args[2])
            pre_argv_idapython(args[3])
            do_elf2pat()
            do_pat2sig()
            do_sig4targetelf(args[4])
            do_output_result()
        else:
            for x in USAGE_STR:
                print(x)
    else:
        for x in USAGE_STR:
            print(x)

    print("[+] Finish!")
# -------------------------------------------------------------------------------