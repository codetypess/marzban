# Hysteria 2（Xray 原生入站）

Hysteria 2 复用现有 Xray 用户、节点下发、流量统计和配额处理。
面板中的协议名为 `hysteria2`；对应 Xray 的 `protocol: "hysteria"`、`version: 2`。
个人凭据仍保存在 `User.proxies.hysteria2.password`，下发时映射到 Xray 用户的 `auth`，
流量身份仍为 `email: "用户ID.用户名"`。重置订阅会按现有流程轮换个人密码。

## 配置

主机和节点均需要支持原生 Hysteria 入站及动态用户管理的 Xray。
本实现按官方 v26.10.21 配置和账户结构核对，旧版内核需要先升级。

1. 执行 `alembic upgrade head`。迁移仅扩展现有代理协议枚举，不新增流量表。
2. 参考根目录 `xray_hysteria2.example.json`，在现有 Xray 配置中加入 Hysteria 入站。
3. 将 `tlsSettings.certificates` 中的证书链和私钥路径替换成实际路径，并确保节点也能读取对应文件。
4. 在现有用户编辑页面启用 `hysteria2`，选择允许的入站。密码留空会自动生成。
5. 在现有代理节点页面选择该入站，填写访问地址、端口、标签和分组。

```json
{
  "tag": "Hysteria2 HK",
  "listen": "0.0.0.0",
  "port": 443,
  "protocol": "hysteria",
  "settings": {"version": 2, "users": []},
  "streamSettings": {
    "network": "hysteria",
    "security": "tls",
    "hysteriaSettings": {"version": 2},
    "tlsSettings": {
      "certificates": [{
        "certificateFile": "/etc/ssl/hysteria/fullchain.pem",
        "keyFile": "/etc/ssl/hysteria/privkey.pem"
      }]
    }
  }
}
```

`users` 由面板按现有用户体系填充，不设置入站共用的 `hysteriaSettings.auth`。
对外监听 **UDP**，需放行对应 UDP 端口；TLS 是必需的。
证书及私钥由 Xray 读取，订阅仅导出 SNI 和客户端证书校验选项。
公网证书可继续由现有证书工具签发、续期。

## 节点与订阅

代理节点继续使用原有 `name/server/port/inbound/tag/settings` 结构，
附加参数位于 `settings.hysteria2`，包括 SNI、证书校验、Salamander 和可选带宽。
节点不保存用户认证密码；导出时使用当前用户的个人凭据。
SNI 默认取入站证书域名；访问地址和证书域名不同时，在节点中填写正确 SNI。
优先使用证书的 DNS SAN，只有 IP SAN 时使用其字符串形式。
节点只保存手动覆盖的参数，未覆盖的字段在导出时使用当前入站配置。
点击“使用入站默认值”可清除已有节点的覆盖值；其他节点属性不受影响。

支持 Mihomo / Clash Meta YAML、`hysteria2://` 分享链接、sing-box JSON 和原生 Xray JSON。
传统 Clash 和 Outline 订阅过滤此协议。原有 `起始:结束` 端口范围仍展开为多个节点。

原生 Xray JSON 默认按 SNI 验证证书。若在主机配置中允许不安全连接，
此格式会改用入站叶子证书的 SHA256 指纹（`pinnedPeerCertSha256`），适用于自签证书；
不再导出新版 Xray 已移除的 `allowInsecure`。
其余客户端继续使用各自的证书校验选项。指纹从入站证书读取，证书更新后需重新加载面板配置并重新获取订阅；
使用的证书需与该主机实际提供的证书一致。

启用 Salamander 时，在 Xray 入站的 `streamSettings` 中加入以下配置；节点会继承该混淆配置：

```json
{
  "finalmask": {
    "udp": [{"type": "salamander", "settings": {"password": "replace-with-obfs-password"}}]
  }
}
```

停用、到期和配额处理沿用 Xray 用户移除逻辑。已建立会话的结束时机由 Xray 内核决定。

官方参考：[Hysteria 入站](https://xtls.github.io/config/inbounds/hysteria.html)、
[Hysteria 传输](https://xtls.github.io/config/transports/hysteria.html)、
[FinalMask](https://xtls.github.io/config/transports/finalmask.html)。

## 验证

开发环境额外需要 `pytest`，原生连接测试还需要 `PySocks`。
`python -m pytest tests -q` 使用隔离的临时数据库运行回归测试。
原生 Xray 配置校验、TLS 连接、混淆、动态用户和流量测试需要显式启用：

```sh
XRAY_TEST_EXECUTABLE=/path/to/xray \
XRAY_TEST_CERT_DIR=/path/to/certificate-directory \
python -m pytest tests -q
```

证书目录包含 `fullchain.pem` 和 `privkey.pem`。省略证书目录时使用临时自签证书，
跳过标准 CA 验证的连接用例。测试仅在回环地址启动临时进程，结束后自动清理。
