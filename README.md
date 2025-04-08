用于绿盟态势感知快速检索情报IP和域名，并且检查是否已经存在于防火墙黑名单IP和域名中
------- 

notice：  
>将威胁情报IP文件命名为 riskip.txt  
>将威胁情报domain文件命名为 riskdomain.txt  
>将防火墙上的黑名单IP文件命名为 blacklist.txt  
>将防火墙上的恶意域名文件命名为 blackdomain.txt  
>IP和domain地址需要是一行一条，不能有其他字符  

安装依赖包：
* pip install tldextract  
>>
use：  
* python checkrisk.py  
