#---------------------------------------------------------------------------------
# TOOL Name: AutoYara4FLIRT
# This tool has been tested in the following versions and environments.
# IDA Pro Version 8.2, Windows10

#---------------------------------------------------------------------------------
__date__ = "20230426"
__version__ = "1.0"
__author__ = "Yuma Masubuchi JPCERT/CC"
#---------------------------------------------------------------------------------
# Import module
#---------------------------------------------------------------------------------
from idautils import *
from idaapi import *
from idc import *
import idaapi
import ida_kernwin
import ida_nalt
import os
import re
#---------------------------------------------------------------------------------

#---------------------------------------------------------------------------------
# Config
#---------------------------------------------------------------------------------
class ConfigVar:
    """
    A number that determines whethre the hunt is acceptable or not based on how many of
    the byte sequences created match by AutoYara4FLIRT.
    """
    matchNumber = 4
    
    """
    To hit the various libraries, this tool extracts a sequence of bytes from among all
    functions divided into quarters.A number determines how many byte sequences to use
    for each quarter.
    ie 
    """
    NumFunc_eachPart = 2
    
    """
    In yara conditions, the file size to be hit is detemined in Mega Bytes.
    """
    LessthanSize_MB = 6

    """
    Output filename
    """
    YaraFileName = "Rule_AutoYara.yara"

    """
    Other
    """
    Other_RuleName = "AutoYaraRule"
    Other_Description = "Hunting no stripped ELF Binaries by AutoYara4FLIRT JPCERT/CC"
    Other_Auther = "AutoYara4FLIRT"
    Other_Usage = "Hunting"

    # On command prompt by use of idat.exe or idat64.exe
    BATCH_MODE = False

    # Target only Sub_* Functions
    TARGET_SUBFUNC = True
#---------------------------------------------------------------------------------
  
#---------------------------------------------------------------------------------


class YaraCompo:
    GENERATED_YARA = ""
    TEMPLATE = '''

import "[MODULE]"

rule [RULENAME] {
    meta:
        description = "[DESCRIPTION]"
        author = "[AUTHOR]"
        rule_usage = "[USAGE]"
        hash = "[HASH]"
    
    strings:
[STRINGS]
    condition:
        [CONDITION]
}
    '''
    MODULE = ""
    #RULENAME = ConfigVar.Other_RuleName
    DESCRIPTION = ConfigVar.Other_Description
    AUTHOR = ConfigVar.Other_Auther
    USAGE = ConfigVar.Other_Usage
    HASH = ""
    STRINGS = ""
    CONDITION = ""

    def set_RULENAME(self, in_Rulename):
        self.RULENAME = in_Rulename

    def set_MODULE(self, in_module):
        self.MODULE = in_module

    def set_HASH(self, in_hash):
        self.HASH = in_hash

    def set_STRINGS(self, in_strings):
        self.STRINGS = in_strings

    def set_CONDITION(self, in_condition):
        self.CONDITION = in_condition

    def print_all_compo(self):
        print("[*] INFO MODULE: {}".format(self.MODULE))
        print("[*] INFO RULENAME: {}".format(self.RULENAME))
        print("[*] INFO DESCRIPTION: {}".format(self.DESCRIPTION))
        print("[*] INFO AUTHOR: {}".format(self.AUTHOR))
        print("[*] INFO USAGE: {}".format(self.USAGE))
        print("[*] INFO HASH: {}".format(self.HASH))
        print("[*] INFO STRINGS:\n{}".format(self.STRINGS))
        print("[*] INFO CONDITION:\n{}".format(self.CONDITION))

    def print_generated_yara_text(self):
        print("[*] GENERATED_YARA:\n{}".format(self.GENERATED_YARA))

    def get_generated_yara_text(self):
        return self.GENERATED_YARA

    def generate_yara_text(self):
        self.GENERATED_YARA = self.TEMPLATE 
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[MODULE]", self.MODULE)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[RULENAME]", self.RULENAME)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[DESCRIPTION]", self.DESCRIPTION)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[AUTHOR]", self.AUTHOR)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[USAGE]", self.USAGE)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[HASH]", self.HASH)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[STRINGS]", self.STRINGS)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[MODULE]", self.MODULE)
        self.GENERATED_YARA = self.GENERATED_YARA.replace("[CONDITION]", self.CONDITION)
         
   
class YaraModule():
    import_module = ""
    
    def set_import_module(self):
        fileformat = idaapi.get_file_type_name()
        if "ELF" in fileformat:
            self.import_module = "elf"
        elif "PE" in fileformat:
            self.import_module = "pe"
        else:
            self.import_module == "elf" # default
            print("[*] Warning: The file is not PE or ELF format. please check the file format.")
        
    def get_import_module(self):
        return self.import_module
        
        
class YaraHash():
    sha256hash = ""
    
    def Convert_str_from_Hex_bytes(self, bytes):
        for byte in bytes:
            self.sha256hash += '{:02X}'.format(byte)
    
    def set_hash_sha256(self):
        sha256_bytes = ida_nalt.retrieve_input_file_sha256()
        if sha256_bytes != None:
            self.Convert_str_from_Hex_bytes(sha256_bytes)
        else:
            self.sha256hash = "NoFile"

    def get_hash_sha256(self):
        return self.sha256hash


class IDAPythoOperandCtrl:
    opTypeDict = { 0:"NoOp",  # No Operand
                   1:"GER",   # General Register 
                   2:"DATA",  # Direct Memory Reference (DATA)
                   3:"MEM",   # Memory Ref [Base Reg + Index Reg]
                   4:"VAR",   # Memory Reg [Base Reg + Index Reg + Displacement]
                   5:"IMM",   # Immediate Value
                   6:"FADDR", # Immediate Far Address (CODE)
                   7:"NADDR", # Immediate Near Address (CODE)
                   8:"PSY1",  # processor specific type
                   9:"PSY2",  # processor specific type
                   10:"PSY3", # processor specific type
                   11:"PSY4", # processor specific type
                   12:"PSY5", # processor specific type
                   13:"PSY6", # processor specific type
                 }

    ReplaceNumOperand = [2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13]


class YaraStrings:
    yara_strings = ''

    instructions_offset = 2 
    convert_flag_offset = 0
    inst_length_offset = 1
    bytes_offset = 2
    instruction_offset = 3
    function_all_info = []
    extracted_most_long_inst = []
    yara_bytes = []

    sp8 = ' ' * 8
    func_comment01 = sp8 + '/* Function Address: '
    func_comment02 = sp8 + '*/\n'
    func_bytes01 = sp8 + '$func'
    func_bytes02 = ' = { '
    func_bytes03 = '}\n\n'
 
    def Convert_Hex_bytes_to_Yaraformat(self, bytes):
        ret_str = ''
        for byte in bytes:
            ret_str += '{:02X} '.format(byte)
        return ret_str
    
    def inst_extract(self, funcea):    
        ret_extracted = []
        f = ida_funcs.get_func(funcea)

        for ea in Heads(f.start_ea, f.end_ea):
            insn = idaapi.insn_t()
            # get length 
            length = decode_insn(insn, ea)
            # get bytes(strings)
            inst_bytes = get_bytes(ea, length)   
            if inst_bytes == None:
                break
            inst_bytes_str = self.Convert_Hex_bytes_to_Yaraformat(inst_bytes)            
            # get instruction
            re_inst = generate_disasm_line(ea, 0)

            # get convert instruction
            convert_flag = 0 
            re_inst_conv = re_inst
            for opNo in range(0, 3):
                if ( get_operand_type(ea, opNo) in IDAPythoOperandCtrl.ReplaceNumOperand ):
                    re_inst_conv = re_inst.replace( print_operand(ea, opNo),
                                            IDAPythoOperandCtrl.opTypeDict[get_operand_type(ea, opNo)],
                                            1)
                    convert_flag = 1
            ret_extracted.append([convert_flag, length, inst_bytes_str, re_inst, re_inst_conv])
        return ret_extracted
    
    def get_all_function_info(self):
        for segea in Segments():
            for funcea in Functions(segea, get_segm_end(segea)):
                functionName = get_func_name(funcea)

                # Target functions are sub_* 
                if (ConfigVar.TARGET_SUBFUNC == True):
                    if ((functionName.startswith("sub_")) == False):
                        continue

                # get a flag status on functions to exclude library functions for making yara rule
                flags = idc.get_func_flags(funcea)
                if (flags & FUNC_LIB) == 0:
                    function_info = []
                    function_info = self.inst_extract(funcea)
                    
                    self.function_all_info.append(["0x{:02x}".format(funcea), functionName, function_info])
 
    def extract_long_inst4yara(self):        
        numberOfFunc = len(self.function_all_info)
        for fnum in range(numberOfFunc):
            noConvINst_count = max_noConv_count = max_inum = 0
            
            numberOfInst = len(self.function_all_info[fnum][self.instructions_offset])
            
            # extract most long instrunction length and the inum into the function
            current_inum_head = current_len = max_len = max_inum_head = 0
            for inum in range(numberOfInst):
                convert_flag = self.function_all_info[fnum][self.instructions_offset][inum][self.convert_flag_offset]
                inst_length = self.function_all_info[fnum][self.instructions_offset][inum][self.inst_length_offset]
                if convert_flag == 0:
                    current_len += inst_length
                    if max_len < current_len:
                        max_len = current_len
                        max_inum_head = current_inum_head
                elif convert_flag == 1:
                    current_inum_head = inum + 1
                    current_len = 0
                else:
                    print("[*] Error: extract_long_inst4yara()")
                    return             
            self.extracted_most_long_inst.append([fnum, max_inum_head, max_len])    
    
    def pickup_yara_bytes(self): 
        split_len = len(self.extracted_most_long_inst) // 4
        
        part1 = self.extracted_most_long_inst[:split_len]
        part2 = self.extracted_most_long_inst[split_len:2*split_len]
        part3 = self.extracted_most_long_inst[2*split_len:3*split_len]
        part4 = self.extracted_most_long_inst[3*split_len:]
        
        part1.sort(key=lambda x:x[2], reverse=True)   
        part2.sort(key=lambda x:x[2], reverse=True)   
        part3.sort(key=lambda x:x[2], reverse=True)
        part4.sort(key=lambda x:x[2], reverse=True)   
            
        concat_allpart = [part1[:ConfigVar.NumFunc_eachPart], part2[:ConfigVar.NumFunc_eachPart], part3[:ConfigVar.NumFunc_eachPart], part4[:ConfigVar.NumFunc_eachPart]]
        concat_allpart = sum(concat_allpart, [])
        
        for long_funcinfo in concat_allpart:
            fnum = long_funcinfo[0]
            inum = long_funcinfo[1]
            
            bytes_strings = ""
            instructions_strings = ""
        
            funcAddr = self.function_all_info[fnum][0]
            funcName = self.function_all_info[fnum][1]

            func_Addr_and_Name = funcAddr +" : "+ funcName
            for n in range(300):
                try:
                    convert_flag = self.function_all_info[fnum][self.instructions_offset][inum + n][self.convert_flag_offset]
                except:
                    break
                if convert_flag == 1:
                    break
    
                current_bytes = self.function_all_info[fnum][self.instructions_offset][inum + n][self.bytes_offset]
                bytes_strings += current_bytes
                instructions_strings += self.sp8 + "{:36}".format(current_bytes) + "{:30}".format(self.function_all_info[fnum][self.instructions_offset][inum + n][self.instruction_offset]) + "\n"

            # exclude same bytes_strings in the list(yara_bytes)
            sameFlag = True
            for ele in self.yara_bytes:
                if bytes_strings == ele[1]:
                    sameFlag = False
            if sameFlag:
                self.yara_bytes.append([func_Addr_and_Name, bytes_strings, instructions_strings])
    
    
    def print_main_list(self):
        print("[*] INFO function_all_info[] : {}".format(self.function_all_info))
        print("[*] INFO extracted_most_long_inst[] : {}".format(self.extracted_most_long_inst))
        print("[*] INFO yara_bytes[] : {}".format(self.yara_bytes))

    def generate_yara_strings(self):
        # set each function bytes
        numberOfFunction = len(self.yara_bytes)
        for num in range(numberOfFunction):
            self.yara_strings += self.func_comment01
            # function addr
            self.yara_strings += self.yara_bytes[num][0] + "\n"
            # function instructions
            self.yara_strings += self.yara_bytes[num][2]
            self.yara_strings += self.func_comment02
            self.yara_strings += self.func_bytes01
            self.yara_strings += str(num)
            self.yara_strings += self.func_bytes02
            # funciton bytes
            self.yara_strings += self.yara_bytes[num][1]
            self.yara_strings += self.func_bytes03

    def get_yara_strings(self):
        return self.yara_strings


class YaraCondition():
    yara_condition = ""
    file_format = ""
    sp8 = ' ' * 8

    filefomrmat_elf = '(uint32(0) == 0x464C457F)\n'
    filefomrmat_dos = '(uint16(0) == 0x5A4D)\n'

    elf_x64 = sp8+ 'and (elf.machine == elf.EM_X86_64)\n'
    elf_x86 = sp8+ 'and (elf.machine == elf.EM_386)\n'
    elf_ARM = sp8+ 'and (elf.machine == elf.EM_ARM)\n'
    elf_MIPS = sp8+ 'and (elf.machine == elf.EM_MIPS)\n'
    elf_arch = ""

    con_filesize = sp8+ 'and (filesize < ' + str(ConfigVar.LessthanSize_MB) + 'MB)\n'
    elf_symbol = '''        and for 2 i in (0 .. elf.number_of_sections) : (
            ((elf.sections[i].name == ".symtab") and (elf.sections[i].type == elf.SHT_SYMTAB))
		    or ((elf.sections[i].name == ".strtab") and (elf.sections[i].type == elf.SHT_STRTAB))
	    )
        and not ( for 1 i in (0 .. elf.number_of_sections) : (
		            ( (elf.sections[i].name == ".dynamic") and (elf.sections[i].type == elf.SHT_DYNAMIC) )
	            )
        )
'''
    func_number01 = sp8 + 'and ( '
    match_numberOfFunc = ""
    func_number02 = ' of ($func*) )\n'
    
    def set_file_format(self):
        file_t = idaapi.get_file_type_name()
        if "ELF" in file_t:
            self.file_format = "ELF"
        elif "PE" in file_t:
            self.file_format = "PE"
        else:
            self.file_format == "None"

    def set_condition_arch(self):
        info = get_inf_structure()
        self.proc_name = info.procname
        if self.proc_name == "metapc":
            if info.is_64bit() == True:
                self.elf_arch = self.elf_x64
            elif info.is_32bit() == True:
                self.elf_arch = self.elf_x86
            else:
                print("[*] Error: cpu architecture is not found()")
        elif self.proc_name == "ARM":
            self.elf_arch = self.elf_ARM
        elif self.proc_name == "mipsb":
            self.elf_arch = self.elf_MIPS
        else:
            print("[*] Error: cpu architecture is not found. detect cpu: {}".format(info.procname))

    def set_yara_condition_matchNumber(self):
        self.match_numberOfFunc = str(ConfigVar.matchNumber)

    def generate_yara_condition(self): 
        if self.file_format == "ELF":
            self.yara_condition += self.filefomrmat_elf
            self.yara_condition += self.elf_arch
            self.yara_condition += self.con_filesize
            self.yara_condition += self.elf_symbol
        elif self.file_format == "PE":
            self.yara_condition += self.filefomrmat_dos
            self.yara_condition += self.con_filesize
        else:
            self.yara_condition += self.con_filesize
            
        self.yara_condition += self.func_number01
        self.yara_condition += self.match_numberOfFunc
        self.yara_condition += self.func_number02

    def get_yara_condition(self):
        return self.yara_condition
    

class OutputYaraFile:
    yarafilename = ConfigVar.YaraFileName
    currentdir = ""
    filepath = ""
    yara_strings = ""

    def __init__(self):
        self.currentdir = os.getcwd()
        self.filepath = self.currentdir + "\\" + self.yarafilename

    def reset_filepath(self, input_text):
        self.filepath = self.currentdir + "\\" + input_text

    def set_yara_text(self, input_text):
        self.yara_strings = input_text
        
    def get_filepath(self):
        return self.filepath

    def output_yarafile(self):
        textfile = open(self.filepath, "w")
        textfile.write(self.yara_strings)
        textfile.close()
        print("[*] Generated Yara File! : {}".format(self.filepath))


class SimpleSubViewer(simplecustviewer_t):
    filepath = ""

    def set_filepath(self, in_filepath):
        self.filepath = in_filepath

    def Create(self):
        title = "Auto Yara Rule"
        simplecustviewer_t.Create(self, title)
        yarafile = open(self.filepath, "r")
        yaraLines = yarafile.readlines()
        yarafile.close()
        
        for line in yaraLines:
            self.AddLine(line)
        self.Show()

    def OnDblClick(self, value):
        curWord = self.GetCurrentWord()
        lineN = self.GetLineNo()
        if not curWord:
            curWord = "<None>"
        elif curWord[:2] == '0x':
            jumpto(int(curWord, 16))
            
        return True
    
    def OnKeydown(self, vkey, shift):
        if vkey == ord('E'):
            lineN = self.GetLineNo()
            if lineN is not None:
                lineS = self.GetCurrentLine(notags=1)
                lineSnew = ida_kernwin.ask_str("{}".format(lineS), 0, "Edit")
                self.edit_line(lineN, lineS, lineSnew)                
                
        elif vkey == ord('I'):
            lineN = self.GetLineNo()
            lineS = self.GetCurrentLine(notags=1)
            if lineN is not None:
                self.insert_line(lineN, lineS)
                            
        elif vkey == 46: # Delete
            lineN = self.GetLineNo()
            lineS = self.GetCurrentLine(notags=1)
            if lineN is not None:
                yn = True #ida_kernwin.ask_yn(0, "Delete line?")
                if yn == True:
                    self.delete_line(lineN, lineS)
                    print("[*] INFO delete >> {}".format(lineS))

        elif vkey == 27: # Escape
            print("[*] INFO window Quit")
            self.Close()

        return True

    def save_file(self, lines):
        yara_text = ""
        for line in lines:
            yara_text += line
        textfile = open(self.filepath, "w")
        textfile.write(yara_text)
        textfile.close()
        print("[*] Save Yara File! : {}".format(self.filepath))
        
    def refresh_file_contents(self):
        yaraLines = self.get_yarafile_lines()
        self.ClearLines()
        
        for line in yaraLines:
            self.AddLine(line)
        self.Refresh()
       
    def get_yarafile_lines(self):
        yarafile = open(self.filepath, "r")
        yaraLines = yarafile.readlines()
        yarafile.close()
        return yaraLines
        
    def edit_line(self, lineNum, oldcontents, newcontents):
        yaraLines = self.get_yarafile_lines()
        # check file contetnts
        if yaraLines[lineNum] == oldcontents:
            newcontents = newcontents.replace("\n", "")
            yaraLines[lineNum] = newcontents + "\n"
            self.save_file(yaraLines)    
            self.refresh_file_contents()

    def insert_line(self, lineNum, oldcontents):
        yaraLines = self.get_yarafile_lines()
        # check file contetnts
        if yaraLines[lineNum] == oldcontents:
            yaraLines[lineNum] = yaraLines[lineNum] + "\n"
            self.save_file(yaraLines)    
            self.refresh_file_contents()
            
    def delete_line(self, lineNum, oldcontents):
        yaraLines = self.get_yarafile_lines()       
        # check file contetnts
        if yaraLines[lineNum] == oldcontents:
            yaraLines[lineNum] = ""
            self.save_file(yaraLines)    
            self.refresh_file_contents()    
    
    def OnHint(self, lineno):
        return (6, "  E  : edit line\n  I  : insert line\n[Del]: delete line\n[ESC]: quit")


def main_run():
    print("[*] Start AutoYara4FLIRT!!")
    # batch mode
    if ConfigVar.BATCH_MODE:
        ida_auto.auto_wait()

    # Generate yaraCompo Class
    YaraCompoClass = YaraCompo()
    
    # Set MODULE
    YaraModuleClass = YaraModule()
    YaraModuleClass.set_import_module()
    module_t = YaraModuleClass.get_import_module()
    YaraCompoClass.set_MODULE(module_t)

    # Set HASH
    YaraHashClass = YaraHash()
    YaraHashClass.set_hash_sha256()
    hash_t = YaraHashClass.get_hash_sha256()
    YaraCompoClass.set_HASH(hash_t)

    # add!   batch mode
    YaraCompoClass.set_RULENAME("RULE_" + hash_t)
    
    # Set Strings
    YaraStringsClass = YaraStrings()
    YaraStringsClass.get_all_function_info()
    YaraStringsClass.extract_long_inst4yara()
    YaraStringsClass.pickup_yara_bytes()
    YaraStringsClass.generate_yara_strings()
    strings_t = YaraStringsClass.get_yara_strings()
    YaraCompoClass.set_STRINGS(strings_t)
    
    # Set Condition
    YaraConditionClass = YaraCondition()
    YaraConditionClass.set_file_format()
    YaraConditionClass.set_condition_arch()
    YaraConditionClass.set_yara_condition_matchNumber()
    YaraConditionClass.generate_yara_condition()
    condition_t = YaraConditionClass.get_yara_condition()
    YaraCompoClass.set_CONDITION(condition_t)

    # Generate yara text data
    YaraCompoClass.generate_yara_text()
    text_t = YaraCompoClass.get_generated_yara_text()

    
    # Output .yara file
    OutputYaraFileClass = OutputYaraFile()
     # add!   batch mode
    OutputYaraFileClass.reset_filepath("RULE_" + hash_t + ".yara")
    OutputYaraFileClass.set_yara_text(text_t)
    OutputYaraFileClass.output_yarafile()
    
    # Open Subviewer on IDA
    SimpleSubViewerClass = SimpleSubViewer()
    filepath_t = OutputYaraFileClass.get_filepath()
    SimpleSubViewerClass.set_filepath(filepath_t)
    SimpleSubViewerClass.Create()
    
    print("[*] Finish!!")

    # batch mode
    if ConfigVar.BATCH_MODE:
        idc.exit()


if __name__ == '__main__': 
    main_run()


class AutoYara4FLIRTPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_DRAW
    comment = ""
    help = "No help is needed"
    wanted_name = "AutoYara4FLIRT"
    wanted_hotkey = "" # = "Alt-F9"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        main_run()
        return

    def term(self):
        pass

def PLUGIN_ENTRY():
    return AutoYara4FLIRTPlugin()

