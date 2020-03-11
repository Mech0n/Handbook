---
title: Computer-Networking-Chapter-1
date: 2019-11-17 22:58:20
tags: Computer_Networking
mathjax: true

---

# Chapter 1

因为复习计算机网络，记录一下每一章的复习题答案。

**主要参考**：

https://www.cnblogs.com/tanshaoshenghao/p/10638488.html

还有英文版的题解 Solutions to Review Questions and Problems

#### R1

端系统和主机没有不同。本书中端系统和主机和交换使用。

端系统包括：工作站、PC、网络服务器、邮件服务器、游戏终端

#### R2

>In [international politics](https://en.wikipedia.org/wiki/International_politics), **protocol** is the [etiquette](https://en.wikipedia.org/wiki/Etiquette) of [diplomacy](https://en.wikipedia.org/wiki/Diplomacy) and [affairs](https://en.wiktionary.org/wiki/affair) of [state](https://en.wikipedia.org/wiki/Sovereign_state). It may also refer to an international agreement that supplements or amends a treaty.
>
>A protocol is a [rule](https://en.wiktionary.org/wiki/rule) which describes how an activity should be performed, especially in the field of diplomacy. In diplomatic services and governmental fields of endeavor protocols are often unwritten guidelines. Protocols specify the proper and generally accepted behavior in matters of state and [diplomacy](https://en.wikipedia.org/wiki/Diplomacy), such as showing appropriate respect to a head of state, ranking diplomats in chronological order of their accreditation at court, and so on. One definition is:

> **Protocol** is commonly described as a set of international courtesy rules. These well-established and time-honored rules have made it easier for nations and people to live and work together. Part of protocol has always been the acknowledgment of the hierarchical standing of all present. Protocol rules are based on the principles of civility.—Dr. P.M. Forni on behalf of the International Association of Protocol [Consultants](https://en.wikipedia.org/wiki/Consultants) and Officers.
>
> ​																														--Wiki

#### R3

协议的标准之所以重要，在于，人们可以遵循标准协议在创造的网络系统中交互。

#### R4

1.通过电话线**拨号**调制解调器：家庭

2.通过电话线的**DSL**：家庭或小型办公室；

3.到HFC的**电缆**：家庭； 

4.100 Mbps交换**以太网**：企业；

5.**Wifi**（802.11）：家庭和企业

6.**3G**和**4G**：广域无线。

#### R5

**HFC** 带宽在用户之间共享。 在下行信道上，所有数据包均来自单一来源。因此，在下游通道中没有冲突。

#### R7

用户通常以100Mbps接入以太网，服务器可能具有1Gbps甚至10Gbps。

#### R8

双绞铜线，光纤

#### R9

拨号调制解调器：最高56 Kbps，专用带宽。 

ADSL：最高24 Mbps下行和上行2.5 Mbps，专用带宽。 

HFC：速率高达42.8Mbps，上行速率高达30.7 Mbps，共享带宽。 

FTTH：2-10Mbps上载 10-20 Mbps下载， 带宽不共享。

#### R10

当今有两种流行的无线Internet访问技术：
a）Wifi（802.11）。无线用户在几十米的半径内向基站（即无线接入点）发送/接收数据包。 基站通常连接到有线互联网，因此用于将无线用户连接到有线网络。
b）3G和4G广域无线接入网。 在这些系统中，分组在用于蜂窝电话的相同无线基础设施上传输，因此基站由电信提供商管理。 这为基站半径几十公里内的用户提供了无线访问。

#### R11

​		在时间t0，发送主机开始发送。 在时间t1 = L / R1时，发送主机完成传输，并在路由器上接收到整个数据包（无传播延迟）。 由于路由器在时间t1拥有整个数据包，因此它可以在时间t1开始将数据包发送到接收主机。 在时间t2 = t1 + L / R2时，路由器完成传输，并且整个数据包在接收主机处接收（再次，没有传播延迟）。 因此，端到端延迟为L / R1 + L / R2。

#### R12

**电路交换**网络可以在通话期间**保证**一定量的端到端带宽。 当今大多数分组交换网络（包括Internet）无法对带宽进行任何端到端保证。 

FDM需要复杂的模拟硬件才能将信号移入适当的频带。

#### R13

a）可以支持2个用户，因为每个用户需要一半的链路带宽。

b）由于每个用户在传输时需要1Mbps，因此，如果两个或更少的用户同时传输，则最大需要2Mbps。 由于共享链接的可用带宽为2Mbps，因此在链接之前不会有排队延迟。 而如果三个用户同时传输，则所需带宽将为3Mbps，这比共享链接的可用带宽还大。 在这种情况下，链接之前会有排队延迟。

c）给定用户正在传输的概率为 0.2

d）三个用户同时传输的概率为0.008。由于队列在所有用户都在传输时都在增长，因此队列增长的时间比例（等于所有三个用户同时在传输的概率）为0.008。

#### R14

如果两个ISP不相互对等，则当它们彼此发送流量时，它们必须通过提供商ISP（中间商）发送流量，而他们必须为携带流量而向其付费。 通过直接相互对等，两个ISP可以减少向其提供商ISP的付款。

 Internet交换点（IXP）（通常在具有自己的交换机的独立建筑物中）是多个ISP可以连接和/或对等连接的汇合点。 ISP通过向连接到IXP的每个ISP收取相对较小的费用来赚钱，这可能取决于发送给IXP或从IXP接收的流量。

#### R15

Google的专用网络将其所有大小数据中心连接在一起。 Google数据中心之间的流量通过其专用网络而不是公共Internet传递。这些数据中心中的许多位于或靠近较低层的ISP。因此，当Google向用户交付内容时，它通常可以绕过更高级别的ISP。 

是什么促使内容提供商创建这些网络？ 首先，由于内容提供者只需使用很少的中间ISP，因此可以更好地控制用户体验。 其次，它可以通过向提供商网络发送更少的流量来节省资金。 第三，如果ISP决定向高利润的内容提供商收取更多的钱（在没有净中性的国家），则内容提供商可以避免这些额外的付款。

#### R16

延迟成分是处理延迟，传输延迟，传播延迟和排队延迟。

 除了**排队延迟**（可变）之外，所有其他延迟都是固定的。

#### R18

**注意**：这个问题问的是传播时间.

10msec; d/s; no

#### R19

一个文件传送的吞吐量取决于端到端路径上瓶颈链路的传输速率. 也就是说路径上有多条链路, 但是吞吐量的值是其中传输速率最小的链路的传输速率.

a）该文件传送的吞吐量为500kbps.

b）8 * 4Mb / 500kbps = 32Mb / 0.5Mbps = 64s

c）8 * 4Mb / 100kbps = 320s

#### R20

端系统A将大文件分成多个块。 它将标头添加到每个块，从而从文件生成多个数据包。 每个数据包中的标头都包含目的地（端系统B）的IP地址。 数据包交换机使用数据包中的目标IP地址来确定传出链路。 在给定数据包的目标地址的情况下，询问走哪条路类似于一个数据包，询问该数据包应转发到哪个出站链路。

#### R22

五个常规任务是差错检查，流量控制，分组和重组，多路复用和连接设置。 

是的，这些任务可以在不同的层重复。 例如，通常在不止一层上提供差错检查。

 #### R23

1. 应用层: 应用层协议用于各个端系统中的应用程序交换信息分组, 该信息分组称为报文.
2. 运输层: 运输层的作用是在应用程序端点之间传送应用层报文段. 在因特网中有TCP和UDP两种运输协议, 任一个都能封装并运输应用层报文, 运输层的分组称为报文段.
3. 网络层: 网络层负责将运输层的报文段和目的地址封装成数据报, 用于下一层的传输.
4. 链路层: 链路层会把网络层的数据报封装成链路层的帧, 并把该帧传递给下一个结点.
5. 物理层: 物理层的任务是将链路层每帧中的一个个比特移动到下一个节点,, 具体会落实到不同的物理媒介(双绞铜线, 光纤等).

#### R24

应用层消息：应用程序要发送并传递到传输层的数据，在端系统的应用程序之间按照某种协议进行信息交换的分组.

运输层段：由传输层生成，并用传输层头封装应用层消息，通过TCP/UDP等运输层协议对应用层报文进行封装后所形成的分组, 报文段对报文的传输参数进行了一定的设置, 使其具有了某种特性, 比如面向连接, 确保传递等.

网络层数据报：将传输层段与网络层报头封装在一起，数据报确定了分组的目的地, 使得分组可以通过网络层从发送方传送到接收方. 

链路层帧：用链路层头封装网络层数据报。

 ####  R25

路由器处理网络，链路和物理层。 （这是一个trick，因为现代路由器有时充当防火墙或缓存组件，并且还处理传输层。）

链路层交换机处理链路和物理层。 

主机处理所有五个层。

#### R26

a）病毒
需要某种形式的人类互动才能传播。 经典示例：电子邮件病毒。
b）蠕虫
无需用户复制。 感染主机中的蠕虫会扫描IP地址和端口号，以寻找容易感染的进程。

#### R27

创建僵尸网络需要攻击者发现某些应用程序或系统中的漏洞（例如，利用应用程序中可能存在的缓冲区溢出漏洞）。 找到漏洞后，攻击者需要扫描容易受到攻击的主机。 目标基本上是通过利用特定漏洞来破坏一系列系统。任何系统的僵尸网络的一部分，可以自动扫描其环境，并通过利用该漏洞传播。 这种僵尸网络的一个重要属性是，僵尸网络的发起者可以远程控制并向僵尸网络中的所有节点发出命令。 因此，攻击者有可能向以单个节点为目标的所有节点发出命令（例如，攻击者可能命令僵尸网络中的所有节点向目标发送TCP SYN消息，这可能导致 在目标的TCP SYN泛洪攻击中）。

#### R28

Trudy可以假装是Bob到Alice（反之亦然），并且部分或完全修改了从Bob到Alice发送的消息。 例如，她可以轻松地将短语“爱丽丝，我欠您\$ 1000”更改为“爱丽丝，我欠您 \$ 10,000”。 此外，即使从Bob到Alice的数据包已加密，Trudy甚至可以丢弃Bob所发送到Alice的数据包（反之亦然）。

#### P1

答案不唯一，很多协议都可以

#### P2

$N*(L/R)+(P-1)*(L/R)$

#### P3

a）电路交换网络将非常适合该应用程序，因为该应用程序涉及长会话且具有可预测的平滑带宽要求。 由于传输速率是已知的并且不是突发性的，因此可以为每个应用程序会话保留带宽，而不会造成大量浪费。 此外，建立和拆除连接的开销费用在典型应用程序会话的整个使用期间内分摊。
b）在最坏的情况下，所有应用程序同时通过一个或多个网络链路进行传输。 但是，由于每个链路都具有足够的带宽来处理所有应用程序数据速率的总和，所以不会发生拥塞（很少排队）。 考虑到这种充足的链路容量，网络不需要拥塞控制机制。

#### P4

a）在左上方的交换机和右上方的交换机之间，我们可以有4个连接。 类似地，我们可以在其他3对相邻交换机中的每对之间具有四个连接。因为，每条链路都有可以有4个并行的电路。 因此，该网络最多可支持16个连接。
b）我们可以在右上角通过交换机进行4个连接，在左下角通过交换机进行另外4个连接，总共有8个连接。
c）可以。 对于A和C之间的连接，我们通过B路由两个连接，并且通过D路由两个连接。对于B和D之间的连接，我们通过A路由两个连接，并且通过C路由两个连接。这样，最多有4个连接 通过任何链接。

#### P5

收费站相距75公里，汽车以100km/h的速度传播。 收费站为汽车提供服务，时间为每12秒一辆汽车。
a）有十辆车。 第一个收费站需要2分钟的时间来服务这10辆车。 这些汽车中的每辆汽车在到达第二个收费站之前，都有45分钟的传播延迟（行驶75公里）。 因此，所有车厢在47分钟后的第二个收费站之前排好队。 整个过程在第二和第三收费站之间重复进行。 第三个收费站也需要2分钟才能为10辆车服务。 因此，总延迟为96分钟。
b）收费站之间的延迟是$8 * 12$秒加45分钟，即46分钟和36秒。 总延迟是此数量的两倍加上$8 * 12$秒，即94分48秒。

#### P6

a.$m/s$

b.$L/R$

c.$(m/s + L/ R)$

d.该bit刚离开主机A

e.第一bit位于链接中，尚未到达主机B。

f.第一bit到达主机B。

g.$d_{prop} = (m / s) = m/(2.5*10^8)$

  $d_{trans} = (L/R) = 120/56000$

所以，$m \approx 536$km

#### P7

$t = d_{prop}+d_{trans}+t_{transmit}$

#### P8

a.用户数$N = 3*10^6 / (150*10^3) = 20$

b.$p=0.1$

c .${120\choose n}p^n(1-p)^{120-n}$

d.$$\sum_{21}^{120}{120\choose n}p^n(1-p)^{120-n}\approx 0.003$$ 

#### P9

a.$N = (1*10^9)/(100*10^3) = 10000$个用户

b.$1-\sum_{i = 0}^{N}{M\choose N}p^N(1-p)^{M-N}$

#### P10

....待续



