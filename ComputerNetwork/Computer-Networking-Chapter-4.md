# Chapter 4

#### R1

网络层数据包是一个数据报。 

路由器根据数据包的IP（第3层）地址转发数据包。 链路层交换机(没有网络层)根据数据包的MAC（第2层）地址转发数据包。

#### R2

两个功能：**转发**和**路由选择**

数据平面的主要功能是转发，即将数据报从其输入链接转发到其输出链接。 例如，数据平面的输入端口执行以下物理层功能：在路由器处终止传入的物理链路；执行链路层功能以与传入链路另一侧的链路层进行互操作；并在输入端口执行查找功能 。
控制平面的主要功能是路由选择，即确定数据包从其源到目的地所采用的路径。 控制平面负责执行路由协议，响应连接的上行或下行链路，与远程控制器通信以及执行管理功能。

#### R3

路由和转发之间的主要区别在于，转发是路由器将数据包从其输入接口传输到其输出接口的本地操作，并且转发发生在非常短的时间范围内（通常为几纳秒），因此通常在硬件中实现。 

路由是指整个网络确定数据包从源到目的地的端到端路径的过程。 路由发生在更长的时间范围内（通常为几秒钟），并且通常在软件中实现。

#### R4

路由器中转发表的作用是保存表项，以确定通过交换结构将到达的数据包转发到的出站链路接口。

#### R5

互联网网络层的服务模型是**尽力而为服务**。 

使用这种服务模型，不能保证将按照发送顺序接收数据包，也不能保证最终发送，也不能保证端到端的延迟，也不能保证最小的带宽。

#### R6

输入端口，交换结构和输出端口在硬件中实现，因为它们的数据报处理功能对于软件实现而言太快了。 传统路由器内部的路由处理器使用软件来执行路由协议，维护路由表和附加的链接状态信息以及计算路由器的转发表。（ 此外，SDN路由器中的路由处理器还依赖于与遥控器进行通信的软件，以便接收转发表条目并将其安装在路由器的输入端口中。）

由于需要快速处理，例如在纳秒级的时间尺度上，数据平面通常在硬件中实现。 控制平面通常以软件实现，并以毫秒或秒为单位运行，例如，用于执行路由协议，响应上升或下降的连接链路，与远程控制器通信以及执行管理功能。

#### R7

使用副本可以在每个输入端口在本地进行转发查找，而无需调用集中式路由处理器。 这种分散的方法避免了在路由器内的单个点处创建查找处理瓶颈。

#### R9

如果数据包的目标地址与转发表中的两个或多个条目匹配，则路由器使用**最长前缀匹配**来确定将数据包转发到哪个链路接口。 也就是说，该数据包将被转发到前缀最长与该数据包的目的地匹配的链接接口。

#### R10

经内存交换； 

经总线切换； 

经互连网络交换。 

经互连网络可以并行转发数据包，只要所有数据包都被转发到不同的输出端口即可。

#### R11

如果输入线路速度速率超过了交换结构传输速率，则数据包将需要在输入端口排队。 如果此速率不匹配情况持续存在，则队列将变得越来越大，并最终使输入端口缓冲区溢出，从而导致数据包丢失。 如果交换结构传输速率至少是输入线路速率的n倍，则可以消除数据包丢失，其中n是输入端口的数量。

#### R12

假设输入和输出线速度相同，如果数据包到达单个输出端口的速率超过了线速度，则仍然可能发生数据包丢失。 如果此速率不匹配持续存在，则队列将变得越来越大，最终会使输出端口缓冲区溢出，从而导致数据包丢失。 增加交换结构速度不能防止出现此问题。

#### R13

线路前部拥塞（HOL）,如图。

![](https://i.loli.net/2019/11/25/FMn24HqlIrfvV5e.png)

左下角浅色分组需要传送到右中侧端口，即使其目的输出端口无竞争，但是由于左下角排在前面的深色分组正在等待左上角分组传输，所以左下角浅色分组被阻塞，这种现象叫做输入队列交换机中的**线路前部阻塞**。

发生在输入端口

#### R14

FIFO

#### R15

例如，承载**网络管理信息的数据包**应比普通用户流量具有更高的优先级。 

另一个示例是，**实时IP语音包**可能需要优先于非实时流量（例如电子邮件）。

#### R16

使用RR，所有服务类别均得到同等对待，即任何服务类别都不比其他任何服务类别具有更高的优先级。 

使用WFQ，对服务类别的处理方式有所不同，即每个类别在任何时间间隔内都可能收到不同数量的服务。 当WFQ的所有类别具有相同的服务权重时，WFQ与RR相同。

#### R17

IP数据报中的8位**协议字段**包含有关目标主机应将该段传递到的传输层协议的信息。

#### R18

TTL（Time-To-Live）字段

#### R19

不会。IP首头校验和仅计算IP数据包的IP首头字段。

#### R20

IP数据报分片工作在路由器中进行，IP数据报的片段的重组是在数据报的目标主机中完成的。

#### R21

有，且有多个网卡接口，有多个IP。

#### R22

11011111 00000001 00000011 00011100.

#### R24

8个接口； 3个转发表。

#### R25

$1/2$,一共80字节

#### R26

通常，无线路由器包括DHCP服务器。 DHCP用于为5台PC和路由器接口分配IP地址。 

无线路由器也使用NAT，因为它仅从ISP获取一个IP地址。

#### R27

路由聚合意味着ISP使用单个前缀来通告多个网络。 路由聚合很有用，因为ISP可以使用此技术向Internet的其余部分通告ISP拥有的多个网络的单个前缀地址。

#### R28

即插即用或零配置协议意味着该协议能够自动配置主机的网络相关方面，以将主机连接到网络。

#### R29

网络中设备的专用网络地址是指仅对该网络中的那些设备有意义的网络地址。 

具有专用网络地址的数据报永远不应出现在较大的公共Internet中，因为专用网络地址可能会被其专用网络中的许多网络设备使用。

#### R30

IPv6具有固定长度的标头，其中不包括IPv4标头可以包含的大多数选项。 即使IPv6标头包含两个128位地址（源IP地址和目标IP地址），整个标头也只有40个字节的固定长度。 几个字段在意思上是相似的。 

IPv6中的流量类别，有效载荷长度，下一报头和跳数限制分别类似于服务类型，数据报长度，上层协议和IPv4生存时间。

#### R31

是的，整个IPv6数据报（包括标头字段）都封装在IPv4数据报中。

#### R32

转发具有两个主要操作：匹配和操作。 

使用基于目标的转发时，路由器的匹配操作仅查找要转发的数据报的目标IP地址，并且路由器的操作涉及将数据包发送到交换结构中到指定的输出端口。 

使用通用转发，可以在协议栈中不同层的与不同协议关联的多个标头字段上进行匹配，并且操作可以包括将数据包转发到一个或多个输出端口，在多个传出接口上负载均衡数据包，重写标头值（如NAT），有目的地阻止/丢弃数据包（如在防火墙中），将数据包发送到特殊服务器以进行进一步处理和操作等。

#### P8

223.1.17.0/26 

223.1.17.128/25 

223.1.17.192/28

#### P11

128.119.40.128 to 128.119.40.191

128.119.40.64/28,

128.119.40.80/28, 

128.119.40.96/28, 

128.119.40.112/28