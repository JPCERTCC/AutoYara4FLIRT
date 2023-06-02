# AutoYara4FLIRT
AutoYara4FLIRT is a very simple IDA plugin that automatically generates yara rules from files.
The yara rules generated from ELF files can be used to create FLIRT signatures for the technique. For more information, see our blog post in **More Details** link.

## HOW TO INSTALL
- Move `AutoYara4FLIRT.py` to `IDA's plugin folder`
  - Ex) c:\Program files\IDA Pro 8.2\plugins\AutoYara4FLIRT.py

## USAGE
- Select `AutoYara4FLIRT` on IDA
  - Ex) Edit -> Plugins -> AutoYara4FLIRT

## DEMO
![](https://github.com/JPCERTCC/AutoYara4FLIRT/blob/main/image/demo.gif)

--- 

# CLI_AutoYara
CLI_AutoYara is a simple CLI tool that automates yara rule creation and the creation of sig files from hunted ELF binaries. In Addition, this tool can target multiple malware at once. It is also easy to use, requiring **no external modules** other than IDA related. Sample files are also available on this github for you to try out right away!

## HOW TO INSTALL
- Download `sigmake.exe` in `Flair` from https://hex-rays.com/download-center/
- Download AutoYara4FLIRT
```
$ git clone https://github.com/JPCERTCC/AutoYara4FLIRT.git
$ cd AutoYara4FLIRT\CLI_AutoYara
```
- Edit `CLI_AutoYara.py`
```py
class ConfigVar:
    """
    ===================== Filepath ===========================
    """
    SIGMAKE_DIR = "C:\\sigmake.exe"                            # <<<--- the path of `sigmake.exe` !!!
    IDA_INSTAll_PATH = "C:\\\"Program Files\"\\\"IDA Pro 8.2\""
    IDA_SIG_PATH      = r"C:\Program Files\IDA Pro 8.2\sig"
    """
    ==========================================================
    """
```

## USAGE
- `Targeted ELF` -> `.yara`
```
$ python CLI_AutoYara.py --autoyara [BITS-of-Arch-in-ELFfile]
# Example
$ python CLI_AutoYara.py --autoyara 32
```

- `Hunted ELF` -> `.sig`
```
$ python CLI_AutoYara.py --elf2sig [BITS-of-Arch-in-ELFfile] [Sig-Name] [Sig-Directory]
# Example
$ python CLI_AutoYara.py --elf2sig 32 SigName pc
```

## DEMO (About 3 minutes)
![](https://github.com/JPCERTCC/AutoYara4FLIRT/blob/main/image/demo_cli.gif)

--------

## Scope of tools

![](https://github.com/JPCERTCC/AutoYara4FLIRT/blob/main/image/image.png)

## More Details

- English ![https://blogs.jpcert.or.jp/en/2023/06/autoyara4flirt.html](https://blogs.jpcert.or.jp/en/2023/06/autoyara4flirt.html)
- Japanese ![https://blogs.jpcert.or.jp/ja/2023/06/autoyara4flirt.html](https://blogs.jpcert.or.jp/ja/2023/06/autoyara4flirt.html)

--------

## Reference
- F.L.I.R.T https://hex-rays.com/products/ida/tech/flirt/
- Generating FLAIR function patterns using IDAPython https://www.mandiant.com/resources/blog/flare-ida-pro-script
- idb2pat https://github.com/mandiant/flare-ida

## LICENSE
Please read the [LICENSE](https://github.com/JPCERTCC/AutoYara4FLIRT/blob/master/LICENSE.txt) page.

