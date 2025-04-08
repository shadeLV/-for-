"""
 # 将威胁情报IP文件命名为 riskip.txt
 # 将威胁情报domain文件命名为 riskdomain.txt
 # 将防火墙上的黑名单IP文件命名为 blacklist.txt
 # 将防火墙上的恶意域名文件命名为 blackdomain.txt
 # IP和domain地址需要是一行一条，不能有其他字符
 # author：shadeLV
 # mail：shadely@qq.com
"""

def esp(ip, str_list):
    str_list = str_list + "sip:" + ip + " OR " + "dip:" + ip + " OR "
    return str_list

def nf(black_ip_list, rip, mask):
    def mask_check(m, bip, rip):
        if m == "/24":
            # 192.0.1.0/24
            compare_bip = bip.split(".")[:3]
            # print(compare_bip)
            compare_risk_ip = rip.split(".")[:3]
            # print(compare_risk_ip)
            if compare_bip == compare_risk_ip:
                return 1
        elif m == "/32":
            # 1.0.0.255/32
            compare_bip = bip.replace(m, "")
            if compare_bip == rip:
                return 1
        elif m == "/8":
            # 11.0.0.0/8
            compare_bip = bip.split(".")[0]
            compare_risk_ip = rip.split(".")[0]
            if compare_bip == compare_risk_ip:
                return 1
        elif m == "/12" or m == "/16":
            # 172.31.0.0/12
            compare_bip = bip.split(".")[:2]
            compare_risk_ip = rip.split(".")[:2]
            if compare_bip == compare_risk_ip:
                return 1

    for bip in black_ip_list:
        bip = bip.strip()
        rip = rip.strip()
        recycle = 0
        # risk_ip 不存在于带掩码的黑名单列表内，那就对每个黑名单 IP 进行遍历，
        # 查询是否封禁过该 IP， 如已封禁，则添加到已封禁集合当中
        # 注意：本项目未考虑 risk_ip 为带掩码 IP 的情况
        if bip == rip:
            result = f"威胁情报IP：{rip} 已存在当前黑名单列表当中。"
            discover_ip_in_black_list.add(result)
            discover_ip.add(rip)
            break
        else:
            for m in mask:
                # 带掩码的黑名单 IP 判断
                if m in bip:
                    mask_check_result = mask_check(m, bip, rip)
                    if mask_check_result:
                        result = f"威胁情报IP：{rip} 已存在当前黑名单列表当中，黑名单封禁的IP为：{bip}。"
                        discover_ip_in_black_list_mask.add(result)
                        discover_ip.add(rip)
                        recycle = 1
                        break
        if recycle == 1:
            # 跳出最外层循环，寻找下一个 risk_ip
            break

def domain_check():
    domain_ck_list = ""
    with open("./riskdomain.txt", "r", encoding="utf-8") as riskdomains:
        with open("./blackdomain.txt", "r", encoding="utf-8") as blackdomains:
            rdomains = riskdomains.readlines()
            bdomains = blackdomains.readlines()
            for rdm in rdomains:
                flag = 1
                rdm = rdm.strip()
                rdm_extract = tldextract.extract(rdm)
                rdm_root_domain = f"{rdm_extract.domain}.{rdm_extract.suffix}"
                domain_ck_list += ("domain:*." + rdm_root_domain + " OR ")

                for bdm in bdomains:
                    bdm = tldextract.extract(bdm)
                    bdm_root_domain = f"{bdm.domain}.{bdm.suffix}"

                    if rdm_root_domain == bdm_root_domain:
                        discover_domain_in_blackdomain_list.add(rdm)
                        flag = 0
                        break
                if flag == 1:
                    nofound_domain_in_blackdomain_list.add(rdm_root_domain)

    return domain_ck_list


if __name__ == '__main__':
    import tldextract

    esp_result = ""
    mask = ["/8", "/12", "/16", "/24", "/32"]
    discover_domain_in_blackdomain_list = set()
    nofound_domain_in_blackdomain_list = set()
    discover_ip_in_black_list_mask = set()
    discover_ip_in_black_list = set()
    discover_ip = set()
    new_black_ip_list = set()
    fw_input_str = ""

    with open("./riskip.txt", "r", encoding="utf-8") as iplist_raw:
        with open("./blacklist.txt", "r", encoding="utf-8") as black_ip_raw:
            risk_ip_list = iplist_raw.readlines()
            black_ip_list = black_ip_raw.readlines()
            for ip in risk_ip_list:
                # 态势感知筛查_ip
                esp_result = esp(ip.strip(), esp_result)

                # 防火墙黑名单IP查询
                # 检索威胁情报IP是否在黑名单列表出现过
                # 输出可用的封禁格式，注意特殊IP的掩码
                nf(black_ip_list, ip, mask)

                # 既不存在于带掩码的黑名单列表中，也不存在单独的黑名单列表中的IP
                if ip.strip() not in discover_ip:
                    new_black_ip_list.add(ip.strip())

    # 情报域名检测并追加态势感知筛查
    esp_result += domain_check()

    print("发现已存在黑名单列表的 domain 有：\n\t", discover_domain_in_blackdomain_list)
    print("\n发现已存在黑名单列表的IP有(黑名单带掩码)：\n\t", discover_ip_in_black_list_mask)
    print("\n发现已存在黑名单列表的IP有(黑名单不带掩码)：\n\t", discover_ip_in_black_list)

    print("\n态势感知中的日志检索筛查语句为：\n\t", esp_result.rstrip(" OR "))

    # 输出可以被防火墙直接封禁的IP字符串
    for p in new_black_ip_list:
        fw_input_str = fw_input_str + p + ","
    print("\n不存在黑名单列表的威胁情报IP有（可直接粘贴至防火墙进行封禁）：\n\t", fw_input_str.rstrip(","))

    # 输出可以被防火墙直接封禁的 domain 字符串
    print("\n不存在黑名单列表的威胁情报 domain 有（可直接粘贴至防火墙域名对象进行封禁）：\t")
    for p in nofound_domain_in_blackdomain_list:
        print("*."+p)

