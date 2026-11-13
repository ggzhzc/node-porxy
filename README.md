# vabc

基于 Node.js 的轻量 WebSocket 代理，支持 VLESS / Trojan / Shadowsocks 三种协议，附带订阅页和静态首页，可直接部署在支持 Node.js 的平台上。

## 文件结构

```
.
├── server.js      # 服务入口（协议解析、订阅生成、HTTP 服务）
├── index.html     # 首页，由 server.js 启动时读取，必须与 server.js 同目录
└── package.json   # 依赖与启动脚本
```

## 快速开始

```bash
npm install
npm start
```

默认监听 `SERVER_PORT` / `PORT`，都没有时使用 80；端口被占用会自动向后寻找可用端口。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `UUID` | `dacf8a92-401e-4061-84d9-14e0ef03738f` | 节点密钥，标准 UUID（带短横线） |
| `DOMAIN` | 空 | 站点域名，不带 `https://`。不填会查询本机公网 IP 并生成非 TLS 链接 |
| `SUB_PATH` | `sub` | base64 订阅路径 |
| `NAME` | 空 | 节点名前缀，最终显示为 `NAME-国家-运营商` |
| `WSPATH` | `UUID` 前 8 位 | WebSocket 路径 |
| `PORT` / `SERVER_PORT` | 80 | HTTP 与 WebSocket 端口，平台通常自动注入 |
| `DEBUG` | 关闭 | 设为 `true` 输出详细错误日志 |

最小配置示例：

```bash
DOMAIN=<YOUR DOMAIN>.cloudzyo.app
```

## 访问路径

| 路径 | 返回 |
|---|---|
| `/` | 首页 HTML |
| `/sub` | base64 订阅（客户端拉取用） |
| `/ip` | 明文订阅（浏览器查看、手动导入） |

`/ip` 是固定路径，不要与 `SUB_PATH` 重名。

## 部署

上传整个文件夹，项目类型选择 **Node.js**，平台会读取 `package.json`，执行 `npm install` 后通过 `npm start` 启动。

其他支持 Node.js 18+ 的平台同理。若平台存在空闲休眠，可自行用外部监控（如 UptimeRobot）每 5–10 分钟访问一次 `/` 保活。

## 混淆版

需要隐藏源码时，可只上传混淆后的 `server.js`（`index.html` 保持明文）。混淆方式为 32 层 `base64 + zlib + 字符串反转` 的 `eval` 加载，运行时不产生额外依赖。

部署目录结构不变，三个文件需放在同一层。

## 说明

- 订阅内容中的域名 / IP 由 `DOMAIN` 决定；未配置时会在访问 `/sub`、`/ip` 时实时查询公网 IP。
- 修改 `UUID`、`SUB_PATH` 后，旧订阅地址与已导入节点全部失效，需要重新获取。
- 已内置对常见测速域名的屏蔽。
- 本项目仅供个人学习与自用，请遵守所在地法律法规，勿用于任何违法用途。
