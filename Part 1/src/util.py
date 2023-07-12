import ipaddress

def get_links_pair(link_ids):
    result_list = [(link_ids[i], link_ids[i + 1]) for i in range(len(link_ids) - 1)]
    return result_list

def get_key_from_value(my_dict, target):
    for key, value in my_dict.items():
        if value == target:
            return key

def check_same_network(ip1, ip2, subnet_mask):
    ip_network = ipaddress.IPv4Network(f"{str(ip1)}/{subnet_mask}", strict=False)
    return ipaddress.IPv4Address(str(ip2)) in ip_network