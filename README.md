# DNT

David Network Toolkit

## What

根据预定义的 yaml 剧本，对剧本中给出的链接做以下可选测试：

- dns query, naked/DoH/DoT/DoQ
- ip direct tcp connection
- tls handshake with/without sni/ech
- http/https connection
- quic connection
- traceroute/ping

示例配置可见 [docs/config.example.yaml](docs/config.example.yaml) 目录。

## Architecture

模块化设计：

- parser：负责解析 yaml 配置文件，生成测试任务
- dns：负责各种 dns 查询
- ip-direct：负责 ip 直连测试
- tls：负责 tls 握手测试
- http：负责 http/https 测试
- quic：负责 quic 测试
- network-probes：负责 traceroute/ping 测试
