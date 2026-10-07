# Emby Cloudflare DNS 检查与优选

域名：`gzxgzxgzx.de5.net`，反代服务器：`s3.array2026.com`、`v1.uhdnow.com`。

## 已修复

- 用正确的反代前缀访问两台服务器，验证 HTTP 200、JSON 类型以及 Emby Id/Version/ServerName。
- TLS 始终校验自己的域名；指定连接 IP 只在脚本中生效，不改 hosts，不使用系统代理。
- CF 官方测速文件通过自己的 Worker 下载，错误页、不完整文件、超时不进入速度排名。
- 对前三名重复下载三次取中位数；当前 IP 有效且提升不足 20% 时保留它。
- 所有候选失败不写 DNS，不使用未经测试的兜底 IP。
- CF API 必须返回 success=true；仅 PATCH IP，保留 TTL、备注、标签和代理状态。
- 更新后立即及 30 秒后复查两台 Emby 公共接口；失败尝试恢复原 IP 并验证 CF 记录。无法确认回退会报失败。
- 已代理记录不会被强制改成“仅 DNS”；并发改动不会被覆盖。
- 输出不包含 Emby 账号、影片地址、CF 密钥或 API 响应。

## 测速地点与结果

测速反映的是 **运行脚本的机器** 到 CF Worker 的线路。GitHub、Muse 云端、家里电信是三种不同的网络。
测的是经 Worker 的 CF 测试文件，不是影片完整线路或持续播放；最终要在观看设备上验证影片。
候选表是有限采样；不会保证某个 IP 永远或全球最快。

按用户选择，每 30 分钟在 GitHub 测速并自动更新 CF。排名代表 GitHub 出口网络，不保证是家里电信最快的 IP。
手动运行工作流：

- `check`：检查当前域名，不更改 DNS。
- `scan`：当前 Runner 测速，仅出报告。
- `apply_ip`：填写在观看网络选出的 IP，检查通过后更新；密钥沿用仓库原有 Secrets。
- `auto`：GitHub 自动筛选、重复测速、更新与失败回退。

GitHub schedule 不保证准点；check 不更改 DNS；auto 在候选全部失败时保持原记录并明确报错。

## 在家里 Windows 测速

需要 Python 3.10+，只依赖标准库。克隆仓库后运行：

```powershell
python cf_dns.py
```

最后 `stage=selected` 给出 IP。在 GitHub Actions 中选 `apply_ip` 填入此 IP 即可更新公共 DNS，多设备按域名访问。
本机测速不用 CF 密钥。`--apply` 仅在已有三个 CF 环境变量时可用，勿将密钥写入仓库或聊天。

## Muse Linux

当前版本按用户选择使用 GitHub 托管 Runner，无需 Muse 或新增服务。
Muse 可运行 `python3 cf_dns.py` 生成云端测速报告，但结果反映 Muse 的网络，不代表家里的电信。
没有在 Muse 安装任何服务，也没有修改或新增 CF Secrets。

## 验证

```bash
python3 -m unittest test_cf_dns -v
python3 cf_dns.py --check-current
```

仅 DNS 的 CF IP 优选依赖账号路由实际可用性，不能保证长期受支持。保留已验证的正常反代配置用于恢复。
