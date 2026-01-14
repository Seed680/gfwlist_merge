#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import os
import re
import shutil
import ssl
import time
import urllib.error
import urllib.request

# ================= 配置区域 =================

# 工作目录
WORK_DIR = "./gfwlist2_output"
TEMP_DIR = "./Temp_Python"

# [验证用正则] 严格校验 (完美支持 0.com)
VALID_DOMAIN_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$')
# [提取用正则] 粗略提取 (用于从乱七八糟的文本中把域名抠出来)
EXTRACT_PATTERN = re.compile(rb'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# 简易正则 (用于匹配 lite 模式的顶级后缀)
LITE_DOMAIN_PATTERN = re.compile(r'^([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$')

# 忽略 SSL 验证
ssl._create_default_https_context = ssl._create_unverified_context

# 源列表定义 (已合并)
SOURCES = {
    # 所有的国内域名源 (Clash/V2Ray/Dnsmasq/Text 混用)
    "cnacc_domain": [
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/apple-cn.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Apple/Apple_Classical_No_Resolve.yaml",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
        "https://raw.githubusercontent.com/madswaord/surgejourney/refs/heads/main/Clash/Ruleset/Binance.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GoogleFCM/GoogleFCM.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/GovCN/GovCN.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/China/China_Domain.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMaxNoIP/ChinaMaxNoIP_Domain.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/DouYin/DouYin.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Tencent/Tencent.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/UnionPay/UnionPay.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/OPPO/OPPO.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Vivo/Vivo.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/XiaoMi/XiaoMi.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/XiaoHongShu/XiaoHongShu.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaUnicom/ChinaUnicom.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaTelecom/ChinaTelecom.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaMobile/ChinaMobile.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/ChinaNoMedia/ChinaNoMedia_Domain.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/JingDong/JingDong.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/SteamCN/SteamCN.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Binance/Binance_No_Resolve.yaml",
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
        "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf",
        "https://raw.githubusercontent.com/neodevpro/neodevhost/refs/heads/master/allow",
    ],
    "gfwlist_base64": [
        "https://raw.githubusercontent.com/Loukky/gfwlist-by-loukky/master/gfwlist.txt",
        "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
        "https://raw.githubusercontent.com/poctopus/gfwlist-plus/master/gfwlist-plus.txt",
    ],
    "gfwlist_domain": [
 "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/greatfire.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/proxy-list.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Proxy/Proxy_Domain_For_Clash.txt",
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/google-cn.txt",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Crypto/Crypto.yaml",
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Global/Global_Domain.list",
        "https://raw.githubusercontent.com/pexcn/gfwlist-extras/master/gfwlist-extras.txt",
    ],
    "modify": [
        "https://raw.githubusercontent.com/Seed680/gfwlist_merge/refs/heads/main/data_modify.conf"
    ]
}

# 全局数据存储
DATA_STORE = {
    "cnacc_raw": set(),
    "gfwlist_raw": set(),
    "modify_rules": []
}

# ================= 辅助函数 =================

def download_url(url, retries=3):
    """下载 URL 内容，带重试机制"""
    print(f"正在下载: {url}")
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.read()
        except Exception as e:
            print(f"下载失败 ({i+1}/{retries}): {e}")
            time.sleep(1)
    return None

def clean_domain(domain):
    """清洗域名并验证"""
    if isinstance(domain, bytes):
        domain = domain.decode('utf-8', errors='ignore')

    if not domain:
        return ""

    d = domain.strip().lower()

    # 移除常见杂质 (虽然正则提取已经过滤了大半，但清洗一下更保险)
    d = re.sub(r'^https?://', '', d)
    d = d.replace('domain:', '').replace('full:', '').replace('server=/', '')
    d = d.replace('/114.114.114.114', '').replace('|', '')

    # 移除行首的点
    if d.startswith('.'):
        d = d[1:]

    # 严格校验：确保提取出来的是合法域名
    if VALID_DOMAIN_PATTERN.match(d):
        return d
    return ""

def get_root_domain(domain):
    """获取根域名"""
    parts = domain.split('.')
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return domain

def extract_domains_from_line(line_content):
    """从单行内容中提取多个域名，支持空格和逗号分隔"""
    raw_domains = line_content.replace(',', ' ').split()
    cleaned = []
    for d in raw_domains:
        cd = clean_domain(d)
        if cd:
            cleaned.append(cd)
    return cleaned

# ================= 核心逻辑 =================

def get_data():
    """下载并预处理数据"""
    print(">>> 开始下载数据...")

    # 1. 下载 cnacc_domain (合并后的列表，统一使用正则提取)
    for url in SOURCES["cnacc_domain"]:
        content = download_url(url)
        if content:
            # 暴力提取所有长得像域名的东西
            matches = EXTRACT_PATTERN.findall(content)
            for m in matches:
                d = clean_domain(m)
                if d: DATA_STORE["cnacc_raw"].add(d)

    # 2. 下载 gfwlist_base64
    for url in SOURCES["gfwlist_base64"]:
        content = download_url(url)
        if content:
            try:
                decoded = base64.b64decode(content)
                for line in decoded.splitlines():
                    d = clean_domain(line)
                    if d: DATA_STORE["gfwlist_raw"].add(d)
            except:
                print(f"Base64 解码失败: {url}")

    # 3. 下载 gfwlist_domain (也使用正则提取，兼容各种杂乱格式)
    for url in SOURCES["gfwlist_domain"]:
        content = download_url(url)
        if content:
            # 同样使用暴力提取，防止格式不统一
            matches = EXTRACT_PATTERN.findall(content)
            for m in matches:
                d = clean_domain(m)
                if d: DATA_STORE["gfwlist_raw"].add(d)

    # 4. 下载 Modify 文件
    for url in SOURCES["modify"]:
        content = download_url(url)
        if content:
            for line in content.splitlines():
                line_str = line.decode('utf-8', errors='ignore').strip()
                if line_str and not line_str.startswith("#"):
                    DATA_STORE["modify_rules"].append(line_str)

    print(f"下载完成。CN原始数量: {len(DATA_STORE['cnacc_raw'])}, GFW原始数量: {len(DATA_STORE['gfwlist_raw'])}")

def analyse_data():
    """分析、分类、去重、合并数据 (新规则)"""
    print(">>> 开始分析数据...")

    cn_add = set()      # 明确添加到 CN
    cn_remove = set()   # 从 CN 移除 (后缀匹配)
    gfw_add = set()     # 明确添加到 GFW
    gfw_remove = set()  # 从 GFW 移除 (后缀匹配)

    # 解析 Modify 规则
    for rule in DATA_STORE["modify_rules"]:
        if rule.startswith("@++"):
            for d in extract_domains_from_line(rule[3:]):
                cn_add.add(d)
        elif rule.startswith("@--"):
            for d in extract_domains_from_line(rule[3:]):
                cn_remove.add(d)
        elif rule.startswith("!++"):
            for d in extract_domains_from_line(rule[3:]):
                gfw_add.add(d)
        elif rule.startswith("!--"):
            for d in extract_domains_from_line(rule[3:]):
                gfw_remove.add(d)
        elif rule.startswith("@+"):
            for d in extract_domains_from_line(rule[2:]):
                cn_add.add(d)
                gfw_remove.add(d)
        elif rule.startswith("!+"):
            for d in extract_domains_from_line(rule[2:]):
                gfw_add.add(d)
                cn_remove.add(d)

    print(f"自定义规则统计: CN+{len(cn_add)}, CN-{len(cn_remove)}, GFW+{len(gfw_add)}, GFW-{len(gfw_remove)}")

    # 过滤函数：支持后缀匹配移除
    def filter_list_with_suffix(source_set, remove_set):
        result = set()
        remove_suffixes = tuple("." + d for d in remove_set)
        for d in source_set:
            if d in remove_set: continue
            if d.endswith(remove_suffixes): continue
            result.add(d)
        return result

    print("应用移除规则 (后缀匹配)...")
    cn_filtered = filter_list_with_suffix(DATA_STORE["cnacc_raw"], cn_remove)
    gfw_filtered = filter_list_with_suffix(DATA_STORE["gfwlist_raw"], gfw_remove)

    # 交叉去重：如果 CN 列表里有，就从 GFW 列表里删掉
    gfw_filtered = gfw_filtered - cn_filtered

    # 应用增加规则
    cn_final = cn_filtered | cn_add
    gfw_final = gfw_filtered | gfw_add

    # 生成 Lite 列表
    lite_cn_final = {get_root_domain(d) for d in cn_final}
    lite_gfw_final = {get_root_domain(d) for d in gfw_final}

    # 保存
    DATA_STORE["cn_final"] = sorted(list(cn_final))
    DATA_STORE["gfw_final"] = sorted(list(gfw_final))
    DATA_STORE["lite_cn_final"] = sorted(list(lite_cn_final))
    DATA_STORE["lite_gfw_final"] = sorted(list(lite_gfw_final))

    print(f"分析完成。CN最终: {len(DATA_STORE['cn_final'])}, GFW最终: {len(DATA_STORE['gfw_final'])}")

def output_data():
    """生成最终文件"""
    print(">>> 开始生成规则文件...")

    target_dirs = ["smartdns", "clash", "domain"]
    for sw in target_dirs:
        os.makedirs(os.path.join(WORK_DIR, f"gfwlist2{sw}"), exist_ok=True)

    tasks = [
        # SmartDNS (GFW / CN)
        {"sw": "smartdns", "file": "black", "mode": "full", "group": "GFW"},
        {"sw": "smartdns", "file": "black", "mode": "lite", "group": "GFW"},
        {"sw": "smartdns", "file": "white", "mode": "full", "group": "CN"},
        {"sw": "smartdns", "file": "white", "mode": "lite", "group": "CN"},
        # Clash
        {"sw": "clash", "file": "black", "mode": "full"},
        {"sw": "clash", "file": "black", "mode": "lite"},
        {"sw": "clash", "file": "white", "mode": "full"},
        {"sw": "clash", "file": "white", "mode": "lite"},
        # Domain
        {"sw": "domain", "file": "black", "mode": "full"},
        {"sw": "domain", "file": "black", "mode": "lite"},
        {"sw": "domain", "file": "white", "mode": "full"},
        {"sw": "domain", "file": "white", "mode": "lite"},
    ]

    for task in tasks:
        sw = task.get("sw")
        mode = task.get("mode")
        ftype = task.get("file")

        data_list = []
        is_lite = "lite" in mode

        if ftype == "black":
            data_list = DATA_STORE["lite_gfw_final"] if is_lite else DATA_STORE["gfw_final"]
        elif ftype == "white":
            data_list = DATA_STORE["lite_cn_final"] if is_lite else DATA_STORE["cn_final"]

        ext = "txt"
        if sw == "clash": ext = "yaml"
        elif sw == "smartdns": ext = "conf"

        filename = f"{ftype}list_{mode}.{ext}"
        filepath = os.path.join(WORK_DIR, f"gfwlist2{sw}", filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            if sw == "clash":
                f.write("payload:\n")

            for domain in data_list:
                if sw == "clash":
                    f.write(f"  - DOMAIN-SUFFIX,{domain}\n")
                elif sw == "smartdns":
                    f.write(f"nameserver /{domain}/{task.get('group')}\n")
                elif sw == "domain":
                    f.write(f"{domain}\n")

    print(f"所有规则已生成至: {WORK_DIR}")

# ================= 主程序 =================

def main():
    if os.path.exists(TEMP_DIR): shutil.rmtree(TEMP_DIR)
    get_data()
    analyse_data()
    output_data()

if __name__ == "__main__":
    main()