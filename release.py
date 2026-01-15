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
from collections import defaultdict

# ================= 配置区域 =================

# 🔴 Debug 开关：设置为 True 后，生成的文件将包含来源注释
DEBUG_MODE = True

# 工作目录
WORK_DIR = "./gfwlist2_output"
TEMP_DIR = "./Temp_Python"

# [验证用正则] 严格校验
VALID_DOMAIN_PATTERN = re.compile(r'^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.([a-z]{2,13}|[a-z0-9-]{2,30}\.[a-z]{2,3})$')
# [提取用正则] 粗略提取
EXTRACT_PATTERN = re.compile(rb'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# 忽略 SSL 验证
ssl._create_default_https_context = ssl._create_unverified_context

# 源列表定义
SOURCES = {
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

# 🟢 溯源追踪器： { "google.com": {"gfwlist.txt", "google-cn.txt"} }
SOURCE_TRACKER = defaultdict(set)

# ================= 辅助函数 =================

def download_url(url, retries=3):
    """下载 URL 内容"""
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

    if not domain: return ""
    d = domain.strip().lower()

    # 移除常见前缀/干扰
    d = re.sub(r'^https?://', '', d)
    d = d.replace('domain:', '').replace('full:', '').replace('server=/', '')
    d = d.replace('/114.114.114.114', '').replace('|', '')

    if d.startswith('.'): d = d[1:]

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
    """从单行文本提取域名 (用于 modify 规则)"""
    raw_domains = line_content.replace(',', ' ').split()
    cleaned = []
    for d in raw_domains:
        cd = clean_domain(d)
        if cd: cleaned.append(cd)
    return cleaned

def get_filename_from_url(url):
    """从 URL 提取文件名用于标识"""
    if not url: return "unknown"
    return url.split('/')[-1]

# ================= 核心逻辑 =================

def get_data():
    """下载并预处理数据 (带溯源功能)"""
    print(">>> 开始下载数据...")

    # 通用处理函数：按行处理 + 记录来源
    def process_content_by_line(content, target_set, source_tag):
        if not content: return
        try:
            text = content.decode('utf-8', errors='ignore')
            for line in text.splitlines():
                line = line.strip()
                if not line: continue
                if line.startswith(("#", "//")): continue # 忽略注释
                
                matches = EXTRACT_PATTERN.findall(line.encode('utf-8'))
                for m in matches:
                    d = clean_domain(m)
                    if d: 
                        target_set.add(d)
                        # 🟢 记录来源
                        SOURCE_TRACKER[d].add(source_tag)
        except Exception as e:
            print(f"处理出错: {e}")

    # 1. 下载 cnacc_domain
    for url in SOURCES["cnacc_domain"]:
        content = download_url(url)
        # 使用文件名作为来源标签
        fname = get_filename_from_url(url)
        process_content_by_line(content, DATA_STORE["cnacc_raw"], fname)

    # 2. 下载 gfwlist_base64
    for url in SOURCES["gfwlist_base64"]:
        content = download_url(url)
        fname = get_filename_from_url(url)
        if content:
            try:
                decoded = base64.b64decode(content)
                process_content_by_line(decoded, DATA_STORE["gfwlist_raw"], fname)
            except:
                print(f"Base64 解码失败: {url}")

    # 3. 下载 gfwlist_domain
    for url in SOURCES["gfwlist_domain"]:
        content = download_url(url)
        fname = get_filename_from_url(url)
        process_content_by_line(content, DATA_STORE["gfwlist_raw"], fname)

    # 4. 下载 Modify 文件
    for url in SOURCES["modify"]:
        content = download_url(url)
        if content:
            text = content.decode('utf-8', errors='ignore')
            for line in text.splitlines():
                line_str = line.strip()
                if line_str and not line_str.startswith(("#", "//")):
                    DATA_STORE["modify_rules"].append(line_str)

    print(f"下载完成。CN原始数量: {len(DATA_STORE['cnacc_raw'])}, GFW原始数量: {len(DATA_STORE['gfwlist_raw'])}")

def analyse_data():
    """分析数据"""
    print(">>> 开始分析数据...")

    cn_add = set()
    cn_remove = set()
    gfw_add = set()
    gfw_remove = set()

    # 辅助函数：记录自定义规则的来源
    def add_with_tracking(domain_set, domains, tag):
        for d in domains:
            domain_set.add(d)
            SOURCE_TRACKER[d].add(tag)

    # 解析 Modify 规则
    for rule in DATA_STORE["modify_rules"]:
        # 提取当前行的所有域名
        domains_in_line = []
        
        # 判断指令类型并去除指令前缀
        rule_body = ""
        action_type = ""
        
        if rule.startswith("@++"): 
            rule_body = rule[3:]
            action_type = "cn_add"
        elif rule.startswith("@--"):
            rule_body = rule[3:]
            action_type = "cn_remove"
        elif rule.startswith("!++"):
            rule_body = rule[3:]
            action_type = "gfw_add"
        elif rule.startswith("!--"):
            rule_body = rule[3:]
            action_type = "gfw_remove"
        elif rule.startswith("@+"):
            rule_body = rule[2:]
            action_type = "cn_force" # CN+ GFW-
        elif rule.startswith("!+"):
            rule_body = rule[2:]
            action_type = "gfw_force" # GFW+ CN-

        if action_type:
            domains_in_line = extract_domains_from_line(rule_body)
            # 标记来源为 [My_Custom_Rule]
            custom_tag = "[My_Custom_Rule]"
            
            if action_type == "cn_add":
                add_with_tracking(cn_add, domains_in_line, custom_tag)
            elif action_type == "cn_remove":
                add_with_tracking(cn_remove, domains_in_line, custom_tag)
            elif action_type == "gfw_add":
                add_with_tracking(gfw_add, domains_in_line, custom_tag)
            elif action_type == "gfw_remove":
                add_with_tracking(gfw_remove, domains_in_line, custom_tag)
            elif action_type == "cn_force":
                add_with_tracking(cn_add, domains_in_line, custom_tag)
                add_with_tracking(gfw_remove, domains_in_line, custom_tag)
            elif action_type == "gfw_force":
                add_with_tracking(gfw_add, domains_in_line, custom_tag)
                add_with_tracking(cn_remove, domains_in_line, custom_tag)

    # 过滤函数
    def filter_list_with_suffix(source_set, remove_set):
        result = set()
        remove_suffixes = tuple("." + d for d in remove_set)
        for d in source_set:
            if d in remove_set: continue
            if d.endswith(remove_suffixes): continue
            result.add(d)
        return result

    print("应用移除规则...")
    cn_filtered = filter_list_with_suffix(DATA_STORE["cnacc_raw"], cn_remove)
    gfw_filtered = filter_list_with_suffix(DATA_STORE["gfwlist_raw"], gfw_remove)

    # 交叉去重
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
    
    print(f"分析完成。CN: {len(DATA_STORE['cn_final'])}, GFW: {len(DATA_STORE['gfw_final'])}")

def output_data():
    """生成最终文件 (Debug 模式下包含注释)"""
    print(">>> 开始生成规则文件...")

    target_dirs = ["smartdns", "clash", "domain"]
    for sw in target_dirs:
        os.makedirs(os.path.join(WORK_DIR, f"gfwlist2{sw}"), exist_ok=True)

    tasks = [
        {"sw": "smartdns", "file": "black", "mode": "full", "group": "GFW"},
        {"sw": "smartdns", "file": "black", "mode": "lite", "group": "GFW"},
        {"sw": "smartdns", "file": "white", "mode": "full", "group": "CN"},
        {"sw": "smartdns", "file": "white", "mode": "lite", "group": "CN"},
        {"sw": "clash", "file": "black", "mode": "full"},
        {"sw": "clash", "file": "black", "mode": "lite"},
        {"sw": "clash", "file": "white", "mode": "full"},
        {"sw": "clash", "file": "white", "mode": "lite"},
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
                # 🟢 生成 Debug 注释
                comment = ""
                if DEBUG_MODE:
                    # 获取该域名的来源列表
                    sources = SOURCE_TRACKER.get(domain)
                    
                    # 只有在非 lite 模式，或者 lite 模式下域名正好存在于 tracker 中时才能准确显示
                    # (Lite 模式是通过 get_root_domain 计算出来的，可能在 Tracker 里没有直接键值)
                    if not sources and is_lite:
                        # 尝试在 Lite 模式下模糊匹配 (可选，但为了性能暂时只匹配精确的)
                        pass
                        
                    if sources:
                        # 将 set 转换为逗号分隔字符串
                        src_str = ", ".join(sorted(list(sources)))
                        comment = f" # [{src_str}]"
                
                # 写入文件
                if sw == "clash":
                    f.write(f"  - DOMAIN-SUFFIX,{domain}{comment}\n")
                elif sw == "smartdns":
                    f.write(f"nameserver /{domain}/{task.get('group')}{comment}\n")
                elif sw == "domain":
                    f.write(f"{domain}{comment}\n")

    print(f"所有规则已生成至: {WORK_DIR}")

# ================= 主程序 =================

def main():
    if os.path.exists(TEMP_DIR): shutil.rmtree(TEMP_DIR)
    get_data()
    analyse_data()
    output_data()

if __name__ == "__main__":
    main()