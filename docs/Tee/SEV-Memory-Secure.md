
| **论文名称** | Secure Encrypted Virtualization is Unsecure |
| --- | --- |
| BIB | @article{DuZhaohui2017SecureEV, title={Secure Encrypted Virtualization is Unsecure}, author={Du Zhaohui and Ying Zhiwei and Ma Zhenke and Mai Yufei and Phoebe Wang and Jesse Liu and Jesse Fang}, journal={arXiv: Cryptography and Security}, year={2017} } |
| **Tag** | Security , Programming ,Cryptography,Tee |

## **Related work**
> 这篇论文总结的相关工作

这篇论文总结了一些SEV关于内存上的一些漏洞点。

- SEV Guest VM缺少内存完整性保护，意味着hypervisor可以修改cipher-texts来注入恶意命令来攻击VM，这也是本文的攻击的基础。
- [<Security Analysis of Encrypted Virtual Machines>](https://arxiv.org/pdf/1612.01119.pdf)证明了可以对VM发起重放攻击，也就是说hypervisor能够使用过去的数据来覆盖新的内存数据
- 虚拟机启动之后，虚拟机的加密密钥VEK(VM Encryption Key)一直持续到虚拟机关闭
- nested page table由hypervisor维护，因此hypervisor可以随时修改NTP表
- 由于SEV使用physical address-based tweak是基于host的物理地址而不是VM的的物理地址，这就导致hypervisor可以通过计算来交换不同VM的加密页表，VM也能成功解密，但是数据都被交换了。(这个也有相关工作研究)
- 后续还有一篇工作是介绍AES-XEX的暴力破解
## Summary
> 写完全部之后再填写，概况文章的内容，以后查阅笔记的时候，先看这一段。
> 在写summary的时候切记需要通过自己的思考，用自己的语言描述，切忌Ctrl+C 原文

这篇论文是第一篇证明2017年SEV的内存加密模式不安全,推导出了AES-XE的tweak value，根据tweak value来计算加密之后的恶意shellcode，注入恶意的shellcode到SEV VM里面从而达到攻击。
## 
## Evaluation
> 作者如何实现自己的方法？实验是怎么进行的？有没有问题以及有没有值得借鉴的地方？

首先作者先进行了两个实验用来判断当前SEV使用了什么类型的加密方式。

第一个实验是通过写入等差序列(arithmetic sequence)到同一物理地址，启动C bit加密，观察密文序列。
采用NIST. Statistical Test Suite.来验证密文序列是采用ECB模式而不是CTR。

第二个实验就是将同一密文(cipher-texts)写入到不同的物理地址，发现输出的明文和物理地址成线性关系
使用相同密文经过多次实验，获得大量类似如下格式的数据

**<cipher-texts, physical addresses, plaintexts>**

这样一个表，通过计算公式

$T(x)=⊕_{x_i=1}t_i其中xi是x的第i位，⊕是异或，t_i是tweak的值$
对于明文$m_1$在地址$p_1$和明文$m_2$在地址$p_2$，可以等价于$m_1⊕T(P_1) = m_2 ⊕T(P_2) 或者m_2=m_1⊕T(p_1⊕p_2)$
计算输出，得到tweak value。

在得到全部的tweak value之后，我们就能够修改VM中任意地址的cipher-texts，这也为我们的注入提供的先决条件。


在得到tweak value之后，作者使用sshd程序，计算tweak value来向对应的位置注入shellcode。

### 怎么执行shellcode？怎么定位触发？
TODO

## Notes
> 有什么自己需要记录的，没有可以不写

### TEE Attack碎碎念
一般而言，针对TEE框架，攻击者拥有很强大的权限，譬如攻击者可以修改os kernel，中断TEE程序以及重启服务器。在这样的威胁模型下，诞生出了基于进程的TEE，SGX；基于虚拟化的SEV和CSV。

无论是基于进程和基于虚拟化，都存在内存加密方案，在SGX上，攻击者上不被允许修改内存，因为内存是基于页表做了隔离，host无法访问哪块内存;在低版本的SEV中，譬如SEV1、SEV-es，攻击者能够修改和读取TEE VM的密文内存，但是在SEV-SNP上由于增加了完整性的保护，所以攻击者没办法修改密文。

本文是第一篇针对SEV内存加密方案的分析，通过对相同明文加密，获取密文，比较密文的规律性，最后推导出SEV内存加密的模式，计算出模式的Tweak value。(本文作者是来自致象尔微电子公司，查了一下好像是海光的子公司，估计当初海光购买了AMD架构，也在整自己的TEE方案，于是乎后来就诞生出了CSV方案，CSV方案我也研究过，和SEV的相差非常大，等论文出来了，再详细介绍CSV。)


### 推到XE的过程
假设存在明文$m_1在地址p_1上计算会得到密文c_1$，公式如下：


$m_1 \xrightarrow[]{Enc+p_1}  c_1 = E(m_1 \oplus T(p_1))$

若攻击者将密文$c_1$放到地址$p_2$去解密，解密函数如下：

$c_1^1 \xrightarrow[]{Dec+p_2}  m_1^1 = D[E(m_1 \oplus T(p_1))]  \oplus T(p_2) = m_1 \oplus T(p_1) \oplus T(p_2)$

重复此操作，将$m_2的密文c_2放到p_1解密，得到$

$c_2^1 \xrightarrow[]{Dec+p_1}  m_2^1 = D[E(m_2 \oplus T(p_1))]  \oplus T(p_2) = m_2 \oplus T(p_1) \oplus T(p_2)$

此时，将$c_1^1 \oplus c_2^1 = m_2 \oplus m_2$ 若等式相等，即可证明使用AES-XE模式。

### 计算Tweak Value
回到上面的推到，T(t)在加密过程中至关重要，回到加解密的操作中，不妨设c为密文，将c解密的公式为，不妨将整个page的密文都改成c，然后送去解密，其中

$c  \xrightarrow[]{Dec+p_i}  m = D(c) \oplus T(p_i) $

此时，我们收集不同地址解密的明文，回归定义，$T(x) = \oplus_{bit(i)}t_i，其中bit(i)为物理地址p的第i位，t_i为$ tweak value的值，在SEV的实现中，tweak function是对16byte密文进行计算，所以bit 0-3是不会被考虑进去，实现上为0

如果我们将物理地址控制，比如从$t_4开始，想要计算t_4，将p的bit 4位设置为0 和 1，然后在异或消去解密的字符串，这样就可以得到t_4$.

举个例子，对于地址

`0x1234000` 其bit位如下：`0b1001000110100000000000000`,$T(x) = \oplus_{bit(i)}t_i$

`0x1234010` 其bit位如下：`0b1001000110100000000010000`,$T(x) = \oplus_{bit(i)}t_i$

解密相同密文

$c \xrightarrow[]{Dec+0x1234000}  m_0 = D(c) \oplus T(0x1234000)$

$c \xrightarrow[]{Dec+0x1234010}  m_1 = D(c) \oplus T(0x1234010)$

将$m_0 \oplus m_1 = T(0x1234000) \oplus T(0x1234010)$, 由于只有bit 4不一样，其他bit完全一样，所以可以通过$\oplus$得到$t_4$的值，如果要计算往后，则bit向后推即可

## Conclusion
> 作者的结论是什么？哪些是作者确定的结论？哪些是作者也不确定的结论？

研究SEV的SME方案，最终得出，SEV—SME使用AES-XE模式，该模式及其容易推导出tweak value，从而让攻击者利用tweak value进行注入恶意攻击shellcode


## Methods
> 作者解决问题的方法是什么？是否基于前人的方法进行优化？

观察明密文，得出加密模式规律，利用加密规律去计算并注入恶意shellcode。



