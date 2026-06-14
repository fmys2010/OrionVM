# OrionVM

从 [VPNGate](https://www.vpngate.net/) 拉取全球免费代理节点，对每个节点做 **TCP 握手 / ICMP 延迟 / IP 质量签名**，最后输出**综合评分排序**的可用节点列表。

## 设计目标

- **零外部依赖**：完全基于 Python 标准库
- **可重写骨架**：fetcher / probe / geo / scorer 各模块解耦，便于替换任意一层
- **测试友好**：核心逻辑（评分、排序、解析）零网络依赖，可单元测试

## 模块结构

```
orionvm/
  cli.py        argparse CLI 入口
  pipeline.py   fetch → probe → geo → sort 总编排
  fetcher.py    VPNGate CSV 拉取 + base64 OpenVPN 配置解码
  probe.py      TCP 握手延迟 / ICMP ping / jitter / loss
  geo.py        多源 IP 地理 (ip-api 主, ipinfo 备)
  scorer.py     综合评分 (延迟 + IP 类型 + 信任度 + 自报带宽)
  models.py     dataclass: Node / ProbeResult / GeoInfo
  utils.py      编码修正 / 重试 / safe_int / OpenVPN remote 解析
tests/
  test_smoke.py 纯逻辑单测（不触网）
```

## 安装

```bash
git clone https://github.com/fmys2010/OrionVM.git
cd OrionVM
pip install -e .
# 或直接在源码运行
python -m orionvm.cli --help
```

需要 Python 3.10+。

## 用法

```bash
# 拉 80 个节点 + 16 worker 测速 + 写 data/nodes.json
python -m orionvm.cli

# 拉更多节点，指定输出路径
python -m orionvm.cli --max-scan 150 --output results.json

# 跳过 IP 质量查询（更快）
python -m orionvm.cli --no-geo

# 只看 top 5
python -m orionvm.cli --top 5
```

## 输出字段

每个节点 (`data/nodes.json`) 包含：

| 字段 | 说明 |
|------|------|
| `ip` | VPNGate 公布 IP |
| `country_code` | 国家码（ISO 短码） |
| `remote_host` / `remote_port` / `protocol` | 从 OpenVPN 配置提取的真实入口 |
| `openvpn_config_b64` | base64 编码的 OpenVPN 配置 |
| `geo.ip_type` | `residential` / `mobile` / `hosting` / `datacenter` / `proxy` |
| `geo.trust_score` | 0-100 信任分 |
| `probe.latency_ms` | 综合延迟（优先 ICMP，否则 TCP） |
| `probe.jitter_ms` | TCP 多次握手 stddev |
| `probe.loss_pct` | TCP 握手失败率 |
| `probe.alive` | 是否通过 TCP 联通性 |

## 评分公式 (0~100)

| 维度 | 权重 | 评分函数 |
|------|------|---------|
| 是否可达 | 30 | 二元 |
| 延迟 | 30 | `1 / (1 + exp((ms-200)/120))` |
| IP 类型 | 15 | residential=1.0 / mobile=0.9 / hosting=0.4 / proxy=0.1 |
| 信任度 | 15 | ipapi trust_score/100 |
| API 自报带宽 | 10 | `log10(Mbps+1) / log10(101)` |

排序：分数降序 → 延迟升序 → 信任分降序 → API 带宽降序。

## 限制

- VPNGate 节点本质是单端口 TCP/UDP 转发，单次 TCP 握手不等于 OpenVPN 协议完成；要真正接管仍需在隧道内再测速（本版本未涵盖）
- IP 质量依赖第三方 API，免费版有 45 req/min 限流；`geo.py` 已自动 throttle
- ICMP 在 Windows 上需要管理员权限，否则直接回退到 TCP

## License

MIT
