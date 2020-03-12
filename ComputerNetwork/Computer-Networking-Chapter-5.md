# Chapter 5

#### R1

每个路由器的控制意味着在每个路由器中都运行一种路由算法。 转发和路由功能都限制在每个路由器内。 每个路由器都有一个路由组件，该组件与其他路由器中的路由组件进行通信，以计算其转发表的值。 在这种情况下，我们说网络控制和数据平面是单一化实现的，因为每个路由器作为一个独立的实体，实现它自己的控制和数据平面。

#### R2

逻辑上集中的控制意味着逻辑上中央路由控制器计算并分配要由每个路由器使用的转发表，与每个路由器的控制不同，每个路由器都不计算其转发表。 在逻辑集中控制的情况下，数据平面和控制平面在单独的设备中实现； 控制平面在一个中央服务器或多个服务器中实现，数据平面在每个路由器中实现。

#### R3

集中式路由算法通过使用有关网络的完整的全局知识来计算源与目标之间成本最低的路径。该算法需要完全了解所有节点之间的连通性以及所有链接的成本。实际计算可以在一个站点上运行，也可以复制到每个路由器的路由组件。分布式路由算法由路由器以迭代，分布式的方式计算租用成本路径。使用分散算法，任何节点都无法获得有关所有网络链路成本的完整信息。每个节点仅从了解自己直接连接的链接的成本开始，然后通过迭代计算过程以及与其相邻节点的信息交换，节点逐渐计算出到达某个目标或一组目标的成本最低的路径。

OSPF协议是集中式路由算法的示例，而BGP是分布式路由算法的示例。

#### R4

链路状态算法：使用关于网络的完整的全局知识，计算源和目标之间的成本最低的路径。 

距离矢量路由：最小成本路径的计算以迭代，分布式的方式进行。 节点仅知道它应该转发数据包以便沿着最小开销路径到达给定目的地的邻居，以及从自身到目的地的路径开销。

#### R5

计数到无穷大问题是指距离矢量路由的问题。 

该问题意味着，当链路成本增加时，距离矢量路由算法收敛需要很长时间。 例如，考虑由三个节点x，y和z组成的网络。 假设最初的链路成本为d（x，y）= 4，d（x，z）= 50和d（y，z）= 1。 距离矢量路由算法的结果表明，z到x的路径为z→y→x，成本为5（= 4 + 1）。 当链接（x，y）的开销从4增加到60时，将花费44次迭代来运行节点z的距离矢量路由算法，以实现其到x的新的最小开销路径是通过直接链接到x ，因此y也将通过z实现其到达x的最小成本路径。

#### R6

没有必要。每个自治系统都具有管理自治权，可以在自治系统内进行路由。

#### R7

**政策**：在自治系统中，**政策问题**占主导地位。源自给定的AS的流量不能通过另一个特定AS的要求可能很重要。类似地，给定的AS可能希望控制其在其他AS之间承载的传输流量。在一个自治系统内，所有事物名义上都处于相同的管理控制之下。

**可扩展性**：路由算法及其数据结构可扩展以处理路由到大量网络的能力是AS间路由的关键问题。在自治系统内，可伸缩性不再是问题。一方面，如果单个管理域太大，则始终可以将其划分为两个AS，并在两个新AS之间执行AS间路由。

**性能**：由于跨域路由是面向策略的，因此所用路由的质量（例如，性能）通常是次要的考虑（即满足某些策略标准的更长或更昂贵的路由很可能会被采用）。确实，我们看到在AS中，甚至没有与路由相关的成本（AS跳数除外）概念。但是，在单个自治系统内，此类策略问题的重要性就不那么重要了，它使路由可以将更多的注意力集中在路由上实现的性能水平上。

#### R8

❌

使用OSPF，路由器会将其链路状态信息广播到其所属的自治系统中的所有其他路由器，而不仅是其相邻路由器。 这是因为使用OSPF，每台路由器都需要构建整个AS的完整拓扑图，然后在本地运行Dijkstra的最短路径算法，以确定到达同一AS中所有其他节点的成本最低的路径。

#### R9

OSPF自治系统中的区域是指一组路由器，其中每个路由器向同一组中的所有其他路由器广播其链接状态。 可以将OSPF AS分层配置为多个区域，每个区域都运行自己的OSPF链路状态路由算法。 在每个区域内，一个或多个**区域边界路由器**负责将数据包路由到该区域之外。 出于可扩展性的原因引入了区域的概念，即我们想为大规模OSPF AS构建分层路由，而区域是分层路由中的重要构建块。

#### R10

**子网**是较大网络的一部分。 **子网不包含路由器**； 它的边界由路由器和主机接口定义。 

**前缀**是CDIR地址的网络部分； 它以a.b.c.d / x的形式编写； 前缀覆盖一个或多个子网。 

当路由器在BGP会话中发布前缀时，它会在该前缀中包含许多BGP属性。 在BGP会话中，前缀及其属性是BGP路由（或简称为路由）。

#### R11

路由器使用AS-PATH属性来检测和防止循环播发。 他们还使用它在多个路径中选择相同的前缀。 

NEXT-HOP属性指示沿到给定前缀的通告路径（接收通告的AS的外部）的第一个路由器的IP地址。 路由器在配置其转发表时会使用NEXT-HOP属性。

#### R12

一级ISP B可能不会在B与之建立对等协议的两个其他一级ISP（例如A和C）之间传送传输流量。 为了实施该策略，ISP B不会向通过C向A路由发布通告。 并且不会在通过A向C的路由上通告。

#### R13

❌

BGP路由器可以选择不将自己的身份添加到接收的路径中，然后将该新路径发送到其所有邻居，因为BGP是基于策略的路由协议。 在以下情况下可能会发生这种情况。 接收路径的目的地是其他一些AS，而不是BGP路由器的AS，并且BGP路由器不想充当转接路由器。

#### R19

#### R20

ICMP TTL消息（类型11代码0）和 目标端口不可达的ICMP消息（类型3代码3）。

#### P
