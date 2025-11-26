# coding=utf-8
# 提取连续TCP包的特征：Payload（含TCP头部分，不包括端口和序列号）、Payload长度、时间间隔、TTL、IPFlag、TCPFlag
import glob
from scapy.all import PcapReader
import numpy as np
import binascii
from tqdm import tqdm
import os
import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract TCP packet features from pcaps for different datasets",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="CipherSpectrum",
        choices=["CipherSpectrum", "ISCXVPN", "ISCXTor"],
        help="Which dataset to extract (CipherSpectrum, ISCXVPN, ISCXTor)",
    )
    parser.add_argument(
        "--cipher_root",
        type=str,
        default="traffic_data/CipherSpectrum",
        help="Root directory of CipherSpectrum pcaps (can be absolute, e.g. /mnt1/lb/Datasets/CipherSpectrum)",
    )
    parser.add_argument(
        "--iscxvpn_root",
        type=str,
        default="/mnt1/zs/Dataset/VPN",
        help="Root directory of ISCX-VPN pcaps (per-class subfolders)",
    )
    parser.add_argument(
        "--iscxtor_root",
        type=str,
        default="/mnt1/zs/Dataset/Tor",
        help="Root directory of ISCXTor pcaps (per-class subfolders)",
    )
    return parser.parse_args()


args = parse_args()
if args.dataset == "CipherSpectrum":
    input_root = args.cipher_root.rstrip("/\\")
    raw_subdir = "CipherSpectrum"
elif args.dataset == "ISCXVPN":
    input_root = args.iscxvpn_root.rstrip("/\\")
    raw_subdir = "ISCXVPN"
else:  # ISCXTor
    input_root = args.iscxtor_root.rstrip("/\\")
    raw_subdir = "ISCXTor"

filenames = glob.glob(os.path.join(input_root, "*", "*.pcap"))
print("Dataset:", args.dataset, "input root:", input_root)
print("Found files:", len(filenames))

def extract(payload):
    dic = {payload.name: payload}
    payload = payload.payload
    while payload.name != "NoPayload":
        dic[payload.name] = payload
        payload = payload.payload
    return dic


for filename in tqdm(filenames):
    # 使用完整文件名去掉最后一个扩展名作为基名，避免多个 flow 覆盖同一个 npy 文件
    basename = os.path.splitext(os.path.basename(filename))[0]
    domain = os.path.basename(os.path.dirname(filename))
    new_dir = os.path.join("RawData", raw_subdir, domain)
    if not os.path.isdir(new_dir):
        os.makedirs(new_dir)
    # 逐包读取当前 pcap 文件中的报文，只保留 TCP 包，并提取一条流的各类序列特征
    with PcapReader(filename) as fdesc:
        length_sequence = []              # 每个 TCP 包的负载长度序列
        time_sequence = []               # 每个 TCP 包到达时间（后面会转成时间间隔）
        ttl_sequence = []                # 每个包的 IP TTL 序列
        ip_flag_sequence = []            # 每个包的 IP 标志位序列
        tcp_flag_sequence = []           # 每个包的 TCP 标志位序列
        packet_raw_string_sequence = []  # 每个 TCP 包的原始报文（截断为固定长度的十六进制串）
        tcp_count = 0                    # 调试：统计当前 pcap 中的 TCP 包数量
        while True:
            try:
                packet = fdesc.read_packet()   # 读取一个报文
                result = extract(packet)       # 按层次展开，提取各协议层（IP/TCP 等）
                # 只保留同时包含 IP 层和 TCP 层的报文，避免因为没有 IP 层而访问出错
                if "TCP" in result and "IP" in result:
                    tcp_count += 1
                    time = float(packet.time)  # 报文时间戳
                    if result["TCP"].payload.name == "NoPayload":
                        length = 0            # 没有负载时，长度记为 0
                    else:
                        length = len(result["TCP"].payload)  # TCP 负载长度
                    ttl = result["IP"].ttl                     # IP 层 TTL
                    data = (binascii.hexlify(bytes(result["TCP"])))  # TCP 报文转为十六进制串
                    packet_string = data.decode()[24:24+128*2+2]      # 截取固定长度的载荷部分
                    ip_flag = result["IP"].flags.value               # IP 标志位
                    tcp_flag = result["TCP"].flags.value             # TCP 标志位

                    # 将当前包的各个字段追加到对应序列中
                    time_sequence.append(time)
                    length_sequence.append(length)
                    packet_raw_string_sequence.append(packet_string)
                    ttl_sequence.append(ttl)
                    ip_flag_sequence.append(ip_flag)
                    tcp_flag_sequence.append(tcp_flag)
            except EOFError:
                break
            except Exception as e:
                # 单个报文解析错误时跳过，避免导致整个 pcap 处理终止
                print("[WARN] error parsing packet in", filename, ":", repr(e))
                continue
        # 调试输出：当前 pcap 中被识别为 TCP 的包的数量
        print("[DEBUG]", filename, "TCP packets:", tcp_count)
    if len(time_sequence) > 0:
        time_sequence = np.array(time_sequence)
        time_sequence -= time_sequence[0]
        time_sequence = time_sequence[1:] - time_sequence[:-1]
        time_sequence = np.insert(time_sequence, 0, 0)

        length_sequence = np.array(length_sequence)
        packet_raw_string_sequence = np.array(packet_raw_string_sequence)
        ttl_sequence = np.array(ttl_sequence)
        ip_flag_sequence = np.array(ip_flag_sequence)
        tcp_flag_sequence = np.array(tcp_flag_sequence)

        np.save(new_dir + "/" + basename + "_L.npy", length_sequence)
        np.save(new_dir + "/" + basename + "_T.npy", time_sequence)
        np.save(new_dir + "/" + basename + "_P.npy", packet_raw_string_sequence)
        np.save(new_dir + "/" + basename + "_O.npy", ttl_sequence)
        np.save(new_dir + "/" + basename + "_F.npy", ip_flag_sequence)
        np.save(new_dir + "/" + basename + "_C.npy", tcp_flag_sequence)
