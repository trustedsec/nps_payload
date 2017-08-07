This script will generate payloads for basic intrusion detection avoidance.
It utilizes publicly demonstrated techniques from several different sources.

Written by Larry Spohn (@Spoonman1091)
Payload written by Ben Mauch (@Ben0xA) aka dirty_ben
-------------------------------------------------------------------------------------------

Credits:

https://github.com/Ben0xA/nps
@Ben0xA

Bypassing Application Whitelisting using MSBuild.exe - Device Guard Example and Mitigations
http://subt0x10.blogspot.com/2016/09/bypassing-application-whitelisting.html
@subTee

Bypassing Virtualization and Sandbox Technologies
https://www.trustedsec.com/may-2015/bypassing-virtualization-and-sandbox-technologies/
@HackingDave

Sleeping Your Way out of the Sandbox
https://www.sans.org/reading-room/whitepapers/malicious/sleeping-sandbox-35797
Hassan.morad@gmail.com

-------------------------------------------------------------------------------------------
v1.02
  Fixed logic in creation of a new msbuild.rc resource script

v1.01
  Added "Custom PS1 Payload" option.

v1.0
  Initial Release

-------------------------------------------------------------------------------------------

Requirements:

`pip install -r requirements.txt`

-------------------------------------------------------------------------------------------

Setting up samba shares:

1. `apt-get install samba`
2. `vi/nano/whatever /etc/samba/smb.conf`
3. add the following to the bottom of the file (change as appropriate)

```
[payloads$]
   comment = Dirty Payloads
   path = /opt/shares/payloads
   browsable = yes
   guest ok = yes
   read only = yes
```
4. `service smbd restart`
