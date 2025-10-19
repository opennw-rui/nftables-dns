# nftables-dns
nftables dns是一个基于azlux/nft-dns的项目，根据MIT许可证进行了修改，原作者链接：https://github.com/azlux/nft-dns
## 有哪些改动？
* 原项目必须在nftables中set已创建的情况下才可以使用，否则进程会报错退出。而本项目新增了`set_type=`，并且可以根据tables, family, set_name, set_type在set不存在时自动创建set（请注意： 这只是为了防止程序退出而改动的，真正要实现set功能的过滤，最好先创建set,否则后期手动添加的规则无法在服务重启后还留存！！！目前在考虑是否留存这个功能！！！）
* 内存管理与性能优化
  * 新增了MemoryOptimizer类，实现了定期垃圾回收和内存清理
  * 调整了GC阈值(gc.set_threshold(700, 10, 10))
  * 使用更高效的数据结构和列表推导式

* 错误处理与健壮性
  * 增加了更完善的异常处理机制
  * run_command函数增加了超时机制(30秒)
  * 支持可选的错误退出(exit_on_error参数)
  * 自动创建缺失的nftables表和set

* 配置处理改进
  * 新增check_and_create_set函数自动创建set
  * 改进了set类型检测逻辑
  * 使用常量定义(SET_TYPES, FAMILIES)

* 代码结构与可维护性
  * 函数职责更单一，模块化更好
  * 增加了类型提示和文档字符串
  * 改进了日志格式和输出
## 安装方法
到 release 中下载最新的deb二进制安装包后
```bash
apt install ./nft-dns*.deb
```
## 使用方法
首先确保你的nftables配置存在，完整的nftables如下，并运行
```bash
#!/usr/sbin/nft -f

flush ruleset

table inet filter {

	set domain {
		type ipv4_addr
		size 65536
		flags interval
		elements = {
		127.0.0.233/32
}
}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state { established, related } counter accept
		iif "lo" accept
		ip protocol icmp accept
		ip saddr @domain ip protocol tcp tcp dport { 22 }  accept

		ip6 nexthdr ipv6-icmp accept
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state { established, related }  accept
	}
	chain output {
		type filter hook output priority filter; policy accept;
		ct state { established, related } counter accept
	}
}
```
随后，创建nft-dns配置文件
```bash
cp /etc/nft-dns.conf /etc/nft-dns.d/nft-dns.conf
```
```bash
vim /etc/nft-dns.d/nft-dns.conf
```
写入下面类似实例文件
```bash
[GLOBAL]
max_ttl = 86400
min_ttl = 300
custom_resolver = 223.5.5.5
#dry_run = false
#verbose = true

[ubuntu]
set_name = domain
enable = true
family = inet
table = filter
set_type = ipv4_addr
domains = deb.debian.org,security.debian.org
```
启动服务，并设置为开机自动运行
```bash
systemctl start nft-dns
systemctl enable nft-dns
```
检查状态
```bash
systemctl status nft-dns.service 
● nft-dns.service - NFTABLES DNS support
     Loaded: loaded (/etc/systemd/system/nft-dns.service; disabled; preset: enabled)
     Active: active (running) since Sun 2025-10-19 10:22:02 CST; 17s ago
 Invocation: baec032fe04545e7a95dcbe99a04d3ad
   Main PID: 13865 (python3)
      Tasks: 1 (limit: 37496)
     Memory: 25.5M (peak: 34M)
        CPU: 186ms
     CGroup: /system.slice/nft-dns.service
             └─13865 python3 /opt/nft-dns/nft-dns.py

10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,596 INFO:Only config file with prefix .conf is read
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,596 INFO:Reading config directory : /etc/nft-dns.d
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,596 INFO:   /etc/nft-dns.d/nft-dns.conf
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,597 INFO:# Parsing the configuration
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,603 INFO:Set domain_test does not exist in table filter, creating it
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,606 INFO:Successfully created set domain_test with type ipv4_addr and flags interval
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,618 INFO:# End of Parsing
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,630 INFO:Updating the IPv4 for deb.debian.org with ['146.75.114.132']
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,643 INFO:Updating the IPv4 for security.debian.org with ['151.101.130.132', '151.101.194.132', '151.101.2.132', '151.101.66.132']
10月 19 10:22:02 ubuntu nft-dns.py[13865]: 2025-10-19 10:22:02,646 INFO:Sleeping for 301s
```
```bash
nft list 
----------------------------------------------------------------------------------------------
table inet filter {
	set domain {
		type ipv4_addr
		size 65536
		flags interval
		elements = { 127.0.0.233, 146.75.114.132,
			     151.101.2.132, 151.101.66.132,
			     151.101.130.132, 151.101.194.132 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state { established, related } counter packets 2198 bytes 211112 accept
		iif "lo" accept
		ip protocol icmp accept
		ip saddr @domain ip protocol tcp tcp dport 22 accept
		ip6 nexthdr ipv6-icmp accept
	}

	chain forward {
		type filter hook forward priority filter; policy accept;
		ct state { established, related } accept
	}

	chain output {
		type filter hook output priority filter; policy accept;
		ct state { established, related } counter packets 2175 bytes 167294 accept
	}
}
```
