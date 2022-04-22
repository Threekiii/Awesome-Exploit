# CVE-2022-22947-POC
欢迎关注chaosec公众号，禁止一切违法操作

CVE-2022-22947批量检测脚本，已完善正则和超时异常跳出

将脚本路径下放上url.txt，将需要检测的漏洞目标放到txt里面

直接执行python 脚本.py 

演示：

![image](https://user-images.githubusercontent.com/75511051/156873754-c6ac9531-dc65-47e5-96f5-4a86d0adb6ce.png)


检测完成之后会生成一个成功的txt

2022.3.8更新反弹shellEXP

用法

python EXP.py http://target.com:8080 "反弹命令"

![A 70U% ~ER_HN 7UE05{ADV](https://user-images.githubusercontent.com/75511051/157210595-6348ba23-a06e-46a7-b4ba-ba889bb10fc2.png)


该脚本会将代码进行注入，刷新路由，回显命令，删除注入命令，大佬们勿喷，有什么bug可以在公众号联系我，一定全力解决，最后希望师傅们点点star

