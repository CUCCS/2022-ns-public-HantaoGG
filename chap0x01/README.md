# 基于 VirtualBox 的网络攻防基础环境搭建

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；

- 掌握 VirtualBox 的虚拟网络类型和按需配置；

- 掌握 VirtualBox 的虚拟硬盘多重加载；

## 实验环境

- VirtualBox 虚拟机

- 攻击者主机（Attacker）：Kali Rolling 2019.2

- 网关（Gateway, GW）：Debian Buster

- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali

## 实验要求

- 虚拟硬盘配置成多重加载；

- 搭建满足作业拓扑图所示的虚拟机网络拓扑；

- 完成以下网络连通性测试：
    - 靶机可以直接访问攻击者主机
    - 攻击者主机无法直接访问靶机
    - 网关可以直接访问攻击者主机和靶机
    - 靶机的所有对外上下行流量必须经过网关
    - 所有节点均可以访问互联网

## 实验过程 

### 配置虚拟硬盘多重加载（`kali`为例）

1.从“管理——虚拟介质管理”打开虚拟介质管理器

2.选中`kali`对应的`vdi`文件，右键选择释放

![disk_release](img/disk_release.png)

3.修改类型为多重加载，并应用

![multiple_loading](img/multiple_loading.png)

4.添加虚拟硬盘

![add_hard_disk](img/add_hard_disk.png)

5.检查一下结果

![kali_check](img/kali_check.png)

6.对`Debian`和`XP`对应的虚拟硬盘进行同样操作

![all_check](img/all_check.png)

### 根据拓扑结构配置网络

1.配置网关的网卡，四张网卡的状态分别为：

- NAT网络，使网关可访问攻击者主机

- 仅主机（`Host-Only`）网络，进行网卡设置

- 内部网络`intnet1`，搭建局域网1

- 内部网络`intnet2`，搭建局域网2

![gateway_net](img/gateway_net.png)

2.配置攻击者`attacker`的网络状态为：

- `NAT`

- 两块不同的`Host-Only`网卡

![attacker_net](img/attacker_net.png)

3.这4台`victim`靶机分别在两个局域网内，仅需配置内部网络的一张网卡即可：

- `victim-kali-1`和`victim-xp-1`在局域网`intnet1`内

- `victim-debian-2`和`victim-xp-2`在局域网`intnet2`内

![victim_net](img/victim_net.png)

### 连通性测试 

- 获取IP地址时需要打开`Debian-gateway-1`，也即打开网关。
- 对应系统的查看`IP`指令为

```
    Windows XP : ipconfig
    Debian: ip addr show 
    kali:  ip add
```

|        主机        |     IP地址     |
| :----------------: | :------------: |
|  attacker-kali  |    10.0.2.6    |
|  victim-kali-1  | 172.16.111.117 |
|   victim-xp-1    | 172.16.111.138 |
| victim-debian-2 | 172.16.222.133 |
|   victim-xp-2    | 172.16.222.118 |

#### 靶机可以直接访问攻击者主机

- 局域网1内的靶机
![victim_attacker_1](img/victim_attacker_1.png)

- 局域网2内的靶机
![victim_attacker_2](img/victim_attacker_2.png)

#### 攻击者主机无法直接访问靶机

- 局域网1内的靶机

![attacker_victim_1](img/attacker_victim_1.png)

- 局域网2内的靶机

![attacker_victim_1](img/attacker_victim_2.png)

#### 网关可以直接访问攻击者主机和靶机

- 局域网1内的靶机

![gateway_victim_1](img/gateway_victim_1.png)

- 局域网2内的靶机

![gateway_victim_2](img/gateway_victim_2.png)

- 攻击者主机

![gateway_attacker](img/gateway_attacker.png)

#### 靶机的所有对外上下行流量必须经过网关

- 在网关对应的主机上安装`tcpdump`和`tmux`

```
apt install tcpdump
apt update && apt install tmux
```

网关抓包指令为 `sudo tcpdump -c 5`

- 局域网1内的靶机

![flow_rate_1](img/flow_rate_1.png)

- 局域网2内的靶机

![flow_rate_2](img/flow_rate_2.png)

##### `wireshark`分析

利用vscode远程连接网关对应的主机，使用指令`tcpdump -i enp0s9 -n -w 20220914.pcap`将抓取到的包放到`pcap`文件中，在本地用`wireshark`进行分析

- 抓取文件

![get_enp0s9](img/get_enp0s9.png)

- `wireshark`分析

![wireshark](img/wireshark.png)

发现对应的ip数据均符合靶机和目标网址等信息，证明靶机的所有上下行流量必须经过网关。

#### 所有节点均可以访问互联网

- 局域网1内的靶机

![net_free_victim_1](img/net_free_victim_1.png)

- 局域网2内的靶机

![net_free_victim_2](img/net_free_victim_2.png)

- 攻击者主机

![net_free_attacker](img/net_free_attacker.png)

## 问题及反思

- 网关不能访问局域网1内的`xp`

局域网1内的`xp`系统能正常访问互联网，则考虑是防火墙的问题，关闭防火墙即可。
![question_1](img/question_1.png)

## 参考链接

[Virtualbox 多重加载 高级功能介绍](https://blog.csdn.net/jeanphorn/article/details/45056251)

[XP系统查看`IP`地址](https://jingyan.baidu.com/article/86fae346b9b86e3c49121a22.html)