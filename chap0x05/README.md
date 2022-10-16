# 基于Scapy编写端口扫描器

## 实验目的

- 掌握网络扫描之端口状态探测的基本原理

## 实验环境

- `python`+`scapy`+`nmap`
- `kali`

## 实验要求

- 禁止探测互联网上的 `IP` ，严格遵守网络安全相关法律法规

- 完成以下扫描技术的编程实现
    - `TCP connect scan` / `TCP stealth scan`
    - `TCP Xmas scan` / `TCP fin scan` / `TCP null scan`
    - `UDP scan`
- 上述每种扫描技术的实现测试均需要测试端口状态为：开放、关闭 和 过滤 状态时的程序执行结果
- 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- 在实验报告中详细说明实验网络环境拓扑、被测试 `IP` 的端口状态是如何模拟的
- （可选）复刻 `nmap` 的上述扫描技术实现的命令行参数开关

## 实验过程

### 实验拓扑图

- 我们这里使用到的拓扑结构图与`chap0x04`的实验相同，其中`attacker`作为扫描端，`victim`为被扫描的靶机。

![net](img/net_struction.png)

### 端口状态模拟

- 查看当前防火墙的状态和现有规则
```
ufw status
```
- 关闭状态：对应端口没有开启监听, 防火墙没有开启
```
ufw disable
```
- 开启状态：对应端口开启监听,防火墙处于关闭状态。

    - apache2基于`TCP`, 在`80`端口提供服务; 
    - DNS服务基于`UDP`,在`53`端口提供服务;
```
systemctl start apache2 # port 80
systemctl start dnsmasq # port 53
```
- 过滤状态：对应端口开启监听, 防火墙开启
```
ufw enable && ufw deny 80/tcp
ufw enable && ufw deny 53/udp
```
### TCP connect scan

先发送一个`S`，然后等待回应。如果有回应且标识为`RA`，说明目标端口处于关闭状态；如果有回应且标识为`SA`，说明目标端口处于开放状态。这时`TCP connect scan`会回复一个`RA`，在完成三次握手的同时断开连接。

- `code`

```
from scapy.all import *


def tcpconnect(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=timeout)
    if pkts is None:
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):  #Flags: 0x012 (SYN, ACK)
            send_rst = sr(IP(dst=dst_ip)/TCP(dport=dst_port,flags="AR"),timeout=timeout)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):   #Flags: 0x014 (RST, ACK)
            print("Closed")

tcpconnect('172.16.111.117', 80)
```

#### 端口关闭
```
sudo ufw disable
```
![disable](img/tcp_connect_scan_disable_1.png)

![disable](img/tcp_connect_scan_disable_2.png)

- `nmap`复刻
```
nmap -sT -p 80 172.16.111.117
```
![namp](img/tcp_connect_scan_disable_nmap.png)

#### 端口开放

```
sudo ufw enable && sudo ufw allow 80/tcp
```

![enable](img/tcp_connect_scan_enable_1.png)
![enable](img/tcp_connect_scan_enable_2.png)


在抓包的结果中收到了被扫描端的`SYN/ACK`，扫描端也发出了`ACK`，是一个完整的握手过程，但`RST`与`ACK`同时发出，说明端口开启，和预期相符合。

- `nmap`复刻
```
nmap -sT -p 80 172.16.111.117
```
![nmap](img/tcp_connect_scan_enable_nmap.png)

#### 端口过滤
```
sudo ufw enable && sudo ufw deny 80/tcp
```
![deny](img/tcp_connect_scan_deny_1.png)

![deny](img/tcp_connect_scan_deny_2.png)
查看`wireshark`的抓包结果发现确实只有一个`TCP`包，说明端口处于过滤状态，与预期相符合

- `nmap`复刻
```
nmap -sT -p 80 172.16.111.117
```
### TCP stealth scan

先发送一个`S`，然后等待回应。如果有回应且标识为`RA`，说明目标端口处于关闭状态；如果有回应且标识为`SA`，说明目标端口处于开放状态。这时`TCP stealth scan`只回复一个`R`，不完成三次握手，直接取消建立连接。

- code 

```
from scapy.all import *


def tcpstealthscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="S"), timeout=10)
    if (pkts is None):
        print("Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip) /
                          TCP(dport=dst_port, flags="R"), timeout=10)
            print("Open")
        elif (pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
        elif(pkts.haslayer(ICMP)):
            if(int(pkts.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                print("Filtered")


tcpstealthscan('172.16.111.117', 80)
```

#### 端口关闭
```
sudo ufw disable
```
![disable](img/tcp_stealth_scan_disable_1.png)

- nmap复刻
```
sudo nmap -sS -p 80 172.16.111.117
```
![nmap](img/tcp_stealth_scan_disable_nmap.png)

#### 端口开放
```
sudo ufw enable && sudo ufw allow 80/tcp
```
![enable](img/tcp_stealth_scan_enable_1.png)

- nmap复刻
```
sudo nmap -sS -p 80 172.16.111.117
```
![nmap](img/tcp_stealth_scan_enable_nmap.png)

#### 端口过滤
```
sudo ufw enable && sudo ufw deny 80/tcp
```
![deny](img/tcp_stealth_scan_deny_1.png)

- nmap复刻
```
sudo nmap -sS -p 80 172.16.111.117
```
![nmap](img\tcp_stealth_scan_deny_nmap.png)

### TCP Xmas scan

一种隐蔽性扫描，当处于端口处于关闭状态时，会回复一个RST包；其余所有状态都将不回复。

- code

```
from scapy.all import *


def Xmasscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="FPU"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


Xmasscan('172.16.111.117', 80)
```

#### 端口关闭
```
sudo ufw disable
```
![disable](img/tcp_xmas_scan_disable_1.png)
- nmap复刻
```
sudo nmap -sX -p 80 172.16.111.117
```
![nmap](img/tcp_xmas_scan_disable_nmap.png)

#### 端口开放
```
sudo ufw enable && sudo ufw allow 80/tcp
```
![enable](img/tcp_xmas_scan_enable_1.png)
- nmap复刻
```
sudo nmap -sX -p 80 172.16.111.117
```
![nmap](img/tcp_xmas_scan_enable_nmap.png)
#### 端口过滤
```
sudo ufw enable && sudo ufw deny 80/tcp
```
![deny](img/tcp_xmas_scan_deny_1.png)
- nmap复刻
```
sudo nmap -sX -p 80 172.16.111.117
```
![nmap](img/tcp_xmas_scan_deny_nmap.png)

### TCP FIN scan
仅发送`FIN`包，`FIN`数据包能够通过只监测`SYN`包的包过滤器，隐蔽性较`SYN`扫描更⾼，此扫描与`Xmas`扫描也较为相似，只是发送的包为`FIN`包，同理，收到`RST`包说明端口处于关闭状态；反之说明为开启/过滤状态。

- code 

```
from scapy.all import *


def finscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags="F"), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


finscan('172.16.111.117', 80)
```

#### 端口关闭
```
sudo ufw disable
```
![disable](img/tcp_fin_scan_disable_1.png)
- nmap复刻
```
sudo nmap -sF -p 80 172.16.111.117
```
![nmap](img/tcp_fin_scan_disable_nmap.png)
#### 端口开放
```
sudo ufw enable && sudo ufw allow 80/tcp
```
![enable](img/tcp_fin_scan_enable_1.png)
靶机只收到了一个TCP包且没有响应，说明靶机端口处于过滤或开启状态，与预期相符合。
- nmap复刻
```
sudo nmap -sF -p 80 172.16.111.117
```
![nmap](img/tcp_fin_scan_enable_nmap.png)
#### 端口过滤
```
sudo ufw enable && sudo ufw deny 80/tcp
```
![deny](img/tcp_fin_scan_deny_1.png)
- nmap复刻
```
sudo nmap -sF -p 80 172.16.111.117
```
![nmap](img/tcp_fin_scan_deny_nmap.png)



### TCP NULL scan
发送的包中关闭所有`TCP`报⽂头标记，实验结果预期还是同理：收到`RST`包说明端口为关闭状态，未收到包即为开启/过滤状态.

- code
```
#! /usr/bin/python
from scapy.all import *


def nullscan(dst_ip, dst_port, timeout=10):
    pkts = sr1(IP(dst=dst_ip)/TCP(dport=dst_port, flags=""), timeout=10)
    if (pkts is None):
        print("Open|Filtered")
    elif(pkts.haslayer(TCP)):
        if(pkts.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif(pkts.haslayer(ICMP)):
        if(int(pkts.getlayer(ICMP).type) == 3 and int(pkts.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            print("Filtered")


nullscan('172.16.111.117', 80)
```

#### 端口关闭
```
sudo ufw disable
```
![disable](img/tcp_null_scan_disable_1.png)
- nmap复刻
```
sudo nmap -sN -p 80 172.16.111.117
```
![nmap](img/tcp_null_scan_disable_1.png)
#### 端口开放
```
sudo ufw enable && sudo ufw allow 80/tcp
```
![enable](img/tcp_null_scan_enable_1.png)
- nmap复刻
```
sudo nmap -sN -p 80 172.16.111.117
```
![nmap](img/tcp_null_scan_enable_nmap.png)
#### 端口过滤
```
sudo ufw enable && sudo ufw deny 80/tcp
```
![deny](img/tcp_null_scan_deny_1.png)
- nmap复刻
```
sudo nmap -sN -p 80 172.16.111.117
```
![nmap](img/tcp_null_scan_deny_nmap.png)


### UDP scan
一种开放式扫描，通过发送UDP包进行扫描。当收到`UDP`回复时，该端口为开启状态；否则即为关闭/过滤状态.

- code

```
from scapy.all import *
def udpscan(dst_ip, dst_port, dst_timeout=10):
    resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
    if (resp is None):
        print("Open|Filtered")
    elif (resp.haslayer(UDP)):
        print("Open")
    elif(resp.haslayer(ICMP)):
        if(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
            print("Closed")
        elif(int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            print("Filtered")
        elif(resp.haslayer(IP) and resp.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")
udpscan('172.16.111.117', 53)
```

#### 端口关闭
```
sudo ufw disable
```
![disable](img/udp_scan_disable_1.png)
- nmap复刻
```
sudo nmap -sU -p 53 172.16.111.117
```
![nmap](img/udp_scan_disable_nmap.png)
#### 端口开放
```
sudo ufw enable && sudo ufw allow 53/tcp
```
![enable](img/udp_scan_enable_1.png)
- nmap复刻
```
sudo nmap -sU -p 53 172.16.111.117
```
![nmap](img/udp_scan_enable_nmap.png)
#### 端口过滤
```
sudo ufw enable && sudo ufw deny 53/tcp
```
![deny](img/udp_scan_deny_1.png)
- nmap复刻
```
sudo nmap -sU -p 53 172.16.111.117
```
![nmap](img/udp_scan_deny_nmap.png)




## 实验反思

1.执行`sudo ufw status`指令时报错，提示的错误信息为`command not found`。应该是没有安装相关的包，故执行以下指令安装ufw

```
sudo apt-get update
sudo apt-get install ufw
sudo ufw enable
```
执行完毕后则可正常查看ufw状态。
![mistake](img/mistake_1.png)

![method](img/method_1.png)

2.此次实验探究几种扫描程序的特点，故结构也即操作步骤是大体相同的。因此我们可以提前把结构写好，然后`ctrl cv`，节省时间精力，更高效的进行实验。`

![method](img/method_2.png)

3.扫描方式与端口状态的对应关系：

| 扫描方式/端口状态             | 开放                            | 关闭            | 过滤            |
| ----------------------------- | ------------------------------- | --------------- | --------------- |
| TCP connect / TCP stealth     | 完整的三次握手，能抓到ACK&RST包 | 只收到一个RST包 | 收不到任何TCP包 |
| TCP Xmas / TCP FIN / TCP NULL | 收不到TCP回复包                 | 收到一个RST包   | 收不到TCP回复包 |
| UDP                           | 收到UDP回复包                   | 收不到UDP回复包 | 收不到UDP回复包 |

-  提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因； 

  结果是完全符合的，且具体结果也以截图的形式清晰给出。

## 参考链接

[TCP扫描类型](https://blog.51cto.com/professor/1701977)


[使用Scapy进行端口扫描](https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/)

[Nmap操作指南](https://nmap.org/man/zh/)