# RouteLens 本机流量地图

两页版系统介绍、功能说明与技术方法见：[系统介绍及使用手册](./系统介绍及使用手册.md)。

现在包含三个模式：实时网卡抓包、PCAP 离线分析、真实网站访问验证。页面地址为 http://127.0.0.1:4318/。

## 运行

Windows + Python 3.10 或更新版本 + Node.js 20 或更新版本 + 已安装的 Npcap。Python 使用标准库通过 ctypes 调用 Npcap，不需要 pip 安装依赖。本机已用 Python 3.14.7 验证；当前普通用户权限可以抓包。如果 Npcap 安装时启用了管理员限制，界面会显示打开网卡失败的原因。

```powershell
cd D:\Codex\Route\route-demo
node server.mjs
```

如 Python 不在 PATH 中，可设置 ROUTELENS_PYTHON 为 python.exe 的完整路径再启动服务。

## 实时流量

1. 进入“实时流量”，选择网卡。默认推荐已连接的物理网卡，也可选择多张网卡。
2. 点击“开始抓包”，正常浏览百度、B 站等网站。地图和排行每秒收到一次聚合更新。
3. 点击“停止”。若勾选“保留 PCAP”，停止后可下载各网卡的 PCAP，随后导入离线模式复核。

采集使用非混杂模式和内核 BPF 源地址过滤器，只读取所选网卡上源地址属于本机的 IPv4 / IPv6 包。目的 IP 来自真实网络头部，不依赖预置网站列表。使用 VPN / 代理时，物理网卡上可能看到隧道服务器 IP；要观察隧道内的目的地址，请选择相应虚拟网卡。多层网卡可重复观察同一流量，当前不对跨网卡帧去重。

实时地图按国家与地区汇总。每个地区标记使用该地区包数最多的目的 IP 的第三方估计坐标，圆大小反映包数；点击标记或排行可查看目的 IP、包数、字节数和定位来源。中国 / 世界底图切换、地图拖动与缩放、按包数 / 字节排序、IP / 地区搜索和完整 JSON 导出均可用。出现国外目的地址时会自动切换世界地图；也可手动选择范围。

公网源位置由第三方当前 IP 服务观测，不是本机的精确物理位置，也不能证明不同目的连接使用同一 NAT 出口。地图箭头仅表示源到目的地区的方向。私网和未知位置保持未知，参与地区排行，不伪造坐标。

## PCAP 离线分析

选择 .pcap 或 .pcapng 文件后点击“分析文件”。文件以流的方式传给本机 Python 读取，不整包加载到内存。单文件上限 256 MB。

- “全部包的目的 IP”包含请求和响应，每帧计入其网络头部的目的 IP。
- “指定源 IP 的出站包”仅统计源地址命中的帧，可填写多个源 IP（逗号分隔）。源 IP 应来自该文件，不应直接假设是当前电脑地址。
- 历史源地址是私网或无法确定时，只展示目的地区，不用当前公网出口代替历史出口。如果明确指定一个公网源 IP，则可查询其位置并绘制箭头。

Npcap / libpcap 流式读取 PCAP 与同链路类型的 PCAPNG；支持 Ethernet、单层 / 多层 VLAN、RAW IP、BSD NULL / LOOP、Linux cooked v1 / v2，以及 IPv4 / IPv6 网络头部和常见 IPv6 扩展头。损坏文件和不支持的链路类型明确报错。

## 统计口径与效率

包数表示可解析目的地址的 IP 帧数量；重传和分片仍分别计数。字节数采用 PCAP 元数据的原始帧长度，包含链路头，不等于网页下载量或去重后的有效载荷。抓取前 128 字节足够提取常见 IP 头；较长扩展头的协议可标记为未知，但已识别的目的地址仍计数。网卡分段卸载导致的 IPv4 长度零值已处理。

- Python 不创建完整协议对象、不保留包列表；读取后直接聚合，再每 750 ms 输出累计变化。抓包使用非阻塞读取，空闲时也能及时停止。
- Node 与抓包解耦。页面通过 SSE 每秒接收聚合快照；底图只构建一次，不为每包创建地图节点。
- 定位使用 IPWHOIS 与 IPinfo 双源核对。24 小时缓存优先；单源结果短暂缓存，地址重复查询合并。只有新公网 IP 进入查询队列，最大并发 2、每分钟最多启动 30 个新 IP 的核对，每会话最多自动核对 250 个新公网 IP。超额、私网、保留地址、等待和失败均明确标为未知，不影响抓包计数。
- 页面显示包数最多的前 200 个目的 IP；地区统计使用全部已跟踪的目的 IP。内存最多跟踪 10,000 个不同目的 IP，容量外包数和字节仍归入未知地区，导出会标明溢出量。
- PCAP 默认不落盘；可选记录每帧前 128 字节，每张网卡文件最大 256 MB，达到上限后停止记录文件而继续统计。截短记录会明确计数，记录文件可能含应用头部的起始字节，请按原始抓包文件管理。
- 未解析、范围外忽略、截短帧及停止时的 Npcap 丢包报告均显示。吞吐能力取决于网卡和机器，未把一次验证结果当作任意负载下的零丢包保证。

定位服务有免费额度和网络故障的可能。失败不阻塞采集，不推测缺失位置。参考 [IPWHOIS 文档](https://ipwhois.io/documentation)、[IPinfo IPv6 说明](https://support.ipinfo.io/hc/en-us/articles/30792495690642-Does-IPinfo-Support-IPv6)、[Npcap API](https://npcap.com/guide/wpcap/)。世界底图来自 [Natural Earth](https://github.com/nvkelso/natural-earth-vector)，国内省级底图沿用 DataV；资源保存在本机，不加载远程地图瓦片。

## 真实验证

本轮在本机实际访问 www.baidu.com、www.bilibili.com、www.qq.com，全部 HTTP 200。抓包中分别识别到实际远端 182.61.200.108、106.13.245.216、175.27.8.138；这些地址是本轮 DNS / CDN 选择的结果，后续可变。

真实抓包文件 75,862 字节，记录 793 个出站包、881,830 原始帧字节、19 个目的 IP、0 个未解析帧，驱动报告丢包为 0。对该文件离线分析，包数、原始帧字节、各 IP 的协议 / 源地址 / 首末时间与实时聚合完全一致，解析约 0.75 秒。

另用同一真实文件的帧记录重复重放做性能测试，约 9.63 MB、100,711 帧，含 Python 启动耗时约 0.87 秒。此重放文件仅用于性能检查，不作为地图业务数据。

```powershell
node --test scripts/*.test.mjs
python -m unittest discover -s python -v
node --check dist/traffic-ui.js
node --check server.mjs
```

Python 测试覆盖 VLAN、IPv6 扩展头、Linux cooked、出站过滤、截短字节口径、网卡卸载、PCAP / PCAPNG 一致性与损坏文件。Node 测试覆盖地区聚合守恒、公网 IPv6 / 保留地址过滤和既有网站验证回归。

## Python 单独运行

```powershell
python python/traffic.py interfaces
python python/traffic.py offline --file "D:\captures\example.pcap" --scope outgoing --sources "192.168.112.44"
# 网卡 ID 从 interfaces 输出获取；限时采集会自行停止。
python python/traffic.py live --interfaces '\Device\NPF_{你的网卡GUID}' --seconds 15 --record-dir .local/manual-capture
```

Python 输出 JSON Lines 聚合事件。仅用 CLI 时不查询地理位置；页面后台在聚合后完成定位。

## 保存位置

- .local/traffic/<会话ID>/summary.json：完整统计；可选 adapter-N.pcap 是对应网卡记录。
- .local/traffic/latest-live.json / latest-offline.json：最后完成的统计，服务重启后恢复展示，不自动重新抓包。
- .local/traffic/uploads/：用户导入的原始文件。
- .local/validation/real-traffic.pcap、real-live.json、real-offline.json：本轮真实抓包与一致性验证。
- .local/validation/benchmark.json：性能重放验证记录。
- .local/ip-location-cache.json：位置与来源缓存。

服务仅绑定 127.0.0.1；控制接口校验本机 Origin 和专用请求头。上传、记录及真实数据不在 dist 静态目录，不能通过静态 URL 访问。第三方定位仅收到公网 IP；PCAP、私网地址、网络负载和汇总记录保留本机，.local 已排除 Git。本次开发不发布真实流量到历史云端演示。

---

## 自定义网站验证

进入“网站验证”，输入域名或 HTTP / HTTPS 网址并点击“验证网站”（也可按 Enter）。仅输入域名会补全 HTTPS；保留页面路径、查询参数和自定义端口，片段锚点不参与请求。百度、B 站与腾讯网按钮只负责快捷填入地址，实际验证仍需点击提交。

请求由本机 curl.exe 执行，使用系统 IPv4 / IPv6 连通性。HTTP 与 HTTPS 均可用；HTTPS 始终校验证书。自动跟随至多 5 次 HTTP / HTTPS 跳转，以最终连接的实际远端 IP 做第三方定位。页面显示输入网址、最终跳转地址、HTTP 状态、TCP 建连时间、请求耗时和原始错误。若使用环境代理，记录并提示实际远端可能属于代理。

明确区分以下结果：

- 访问成功：已经收到正常 HTTP 响应。
- HTTP 4xx / 5xx：网站已经响应，但页面、权限、频率或服务存在问题；与网络连接失败分开显示。
- DNS 解析失败 / 超时、TCP 连接失败 / 超时、TLS 协商失败 / 超时、证书校验失败、响应超时、中途断连、空响应、跳转过多：各自给出原因和处理提示，可展开原始 curl 错误。
- 即使收到 HTTP 200 后读取超时，仍标为访问失败，而不是正常完成。
- 没有 curl 实际远端 IP 时，不用 DNS 地址或上一条记录的 IP 补造目的位置，不画目的标记与连接箭头。已建立连接但位置未知时保留真实 IP，说明定位不可用。

结果按规范化网址去重，保留最近 30 个网址的最新记录，包括失败记录。“已有记录”可切换查看，“访问记录”显示成功 / 失败状态，“重试全部记录”并行复核历史网址（最多 4 个任务同时运行）。失败结果也支持访问凭据查看和 JSON 导出；位置缓存机制沿用实时模式。自定义境外网站的端点会切换为世界底图。

连接阶段上限 5 秒、单次请求上限 15 秒，响应读取上限 8 MB。批量重试的总耗时取决于记录数量与定位服务；外部定位只查询公网 IP，网址、访问结果和历史记录保留在 .local/measurements/，不发布到历史云端 Demo。

验证：node --test scripts/*.test.mjs。新增真实 curl 测试覆盖正常响应、跳转、HTTP 404、DNS 失败、端口无法连接、响应超时、HTTP 200 后的部分响应、空响应、循环跳转、响应大小限制和自签名 TLS 证书拒绝。本机另实际验证了 www.sina.com.cn，HTTP 200；页面验证 DNS 失败、连接失败和 HTTP 404 后没有沿用上一条的目的 IP。
