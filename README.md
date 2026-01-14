# gfwlist_merge

一个强大的GFWList合并与处理工具，用于生成多种格式的代理规则列表。

## 项目简介

gfwlist_merge 是一个 Python 脚本，用于合并多个 GFWList 和国内域名白名单源，并根据自定义规则进行处理，最终输出适用于不同代理软件的规则文件。

## 功能特点

- 支持多种格式的输入源（Base64编码、纯文本、Clash、V2Ray等）
- 自动解析和验证域名格式
- 支持自定义修改规则，灵活调整域名分类
- 输出多种格式的规则文件（SmartDNS、Clash、纯域名列表等）
- 支持完整版和精简版（仅根域名）两种模式

## 工作流程

1. **数据获取阶段**
   - 从多个源地址下载 GFW 黑名单和国内域名白名单
   - 解析 Base64 编码的 GFWList 数据
   - 提取并验证所有域名的有效性

2. **数据分析阶段**
   - 根据自定义规则对域名进行分类
   - 应用添加/删除规则
   - 进行黑白名单交叉去重
   - 生成精简版（仅根域名）列表

3. **文件输出阶段**
   - 将处理后的域名列表输出为多种格式
   - 分别生成适用于 SmartDNS、Clash 等软件的规则文件

## 规则说明

项目支持以下自定义修改规则语法：

- `@+` : 强制走国内 (添加到 CN 列表, 从 GFW 列表移除) - 用于解决误杀
- `!+` : 强制走代理 (添加到 GFW 列表, 从 CN 列表移除) - 用于解决漏杀
- `@++` : 仅添加到国内列表
- `@--` : 仅从国内列表移除 (支持后缀匹配)
- `!++` : 仅添加到代理列表
- `!--` : 仅从代理列表移除 (支持后缀匹配)

## 使用方法

1. 确保系统已安装 Python 3
2. 运行脚本：
   ```bash
   python release.py
   ```
3. 输出文件将在 `./gfwlist2_output` 目录中生成

## 输出格式

脚本会生成以下目录结构：

```
gfwlist2_output/
├── gfwlist2smartdns/     # SmartDNS 格式
│   ├── blacklist_full.conf
│   ├── blacklist_lite.conf
│   ├── whitelist_full.conf
│   └── whitelist_lite.conf
├── gfwlist2clash/        # Clash 格式
│   ├── blacklist_full.yaml
│   ├── blacklist_lite.yaml
│   ├── whitelist_full.yaml
│   └── whitelist_lite.yaml
└── gfwlist2domain/       # 纯域名格式
    ├── blacklist_full.txt
    ├── blacklist_lite.txt
    ├── whitelist_full.txt
    └── whitelist_lite.txt
```

## 配置文件

- [data_modify.conf](./data_modify.conf) - 自定义修改规则配置文件
- [release.py](./release.py) - 主程序脚本

## 输入源

项目默认从以下源获取数据：

- 国内域名白名单源（来自 v2ray-rules-dat、dnsmasq-china-list 等）
- GFW 黑名单源（来自 gfwlist/gfwlist、Loyalsoldier/v2ray-rules-dat 等）
- 自定义修改规则（来自本项目[data_modify.conf](./data_modify.conf)文件）

## 许可证

本项目采用 MIT 许可证。