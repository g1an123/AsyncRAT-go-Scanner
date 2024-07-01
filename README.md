# AsyncRAT-go-Scanner
AsyncRAT Server 公网探测
之前使用python写的主机发现脚本，本来想着直接加多线程也许速度也差不多。但是后来试过优化，但是效果不佳。最终决定使用go语言重写。

## 功能修改
保留
1. TLS证书
2. ping包
jarm检测相对耗时，故暂时去掉。
## 使用方法

在target.txt port.txt中分别输入检测的ip和端口。

target.txt
```
#支持：
ip:port
ip
ip/24
```

port.txt
```text
80,443,4443,6606,7707
或
1-65536
#二者不能同时出现
```

## 运行
```shell
go run main.go target.txt port.txt 
```

最后会生成output.txt
![](https://cdn.jsdelivr.net/gh/g1an123/blogimage@main/202407012139177.png)
