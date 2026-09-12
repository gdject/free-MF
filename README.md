# free-MF

本仓库只保存项目源码、订阅源配置和 GitHub Actions 工作流，不再保存自动生成的订阅产物。

## 自动发布架构

GitHub Actions 从本仓库运行节点抓取、测活、分类和导出。每次成功运行后，将以下生成文件发布到私有仓库 [`gdject/free-MF-output`](https://github.com/gdject/free-MF-output)：

```text
README.md
output/
├── clash.yaml
├── v2ray.txt
├── singbox.json
├── residential.txt
├── residential-clash.yaml
├── residential-singbox.json
├── by-country/
└── residential-by-country/
```

源仓库不会再接收自动生成的 `README.md` 或 `output/` 提交。发布工作流使用 `OUTPUT_REPOSITORY=gdject/free-MF-output`，并通过源仓库 Actions Secret `OUTPUT_REPO_TOKEN` 写入私有输出仓库。

## 维护订阅源

上游订阅地址位于 [`config/source_urls.txt`](config/source_urls.txt)，一行一个地址。空行和以 `#` 开头的整行会被忽略。新增或删除来源时只需修改该文件。

## 私有输出仓库访问说明

由于 `free-MF-output` 是私有仓库，GitHub Raw 和 jsDelivr 链接通常不能被未授权的客户端直接访问。不要把 `OUTPUT_REPO_TOKEN` 写入订阅链接、代码或 README。若需要客户端订阅，请部署一个使用 Worker Secret 保存最小只读 Token 的 Cloudflare Worker/自有网关，或将输出仓库改为公开仓库；网关应限制路径、做好限流并支持 Token 轮换。

## GitHub Actions Secret

在 `gdject/free-MF` 的仓库设置中添加：

```text
Settings → Secrets and variables → Actions → New repository secret
Name: OUTPUT_REPO_TOKEN
```

该 Secret 只应拥有 `gdject/free-MF-output` 的 `Contents: Read and write` 权限，不要把 Token 提交到仓库。

## 手动运行与检查

在源仓库的 **Actions → Update Subscriptions → Run workflow** 手动运行。成功后检查私有输出仓库的最新提交和 `output/` 文件树。清理 Actions 运行记录请使用 **Cleanup Actions Runs**，默认先以 dry-run 预览。

## 本地测试

```bash
pip install -r scripts/requirements.txt
python scripts/test_parsers.py
```

节点测活使用 sing-box，并会在运行时下载所需内核和 GeoLite 数据库。
