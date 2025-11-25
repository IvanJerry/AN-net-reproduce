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
        description="Extract TCP packet features from CipherSpectrum pcaps",
    )
    parser.add_argument(
        "--cipher_root",
        type=str,
        default="traffic_data/CipherSpectrum",
        help="Root directory of CipherSpectrum pcaps (can be absolute, e.g. /mnt1/lb/Datasets/CipherSpectrum)",
    )
    return parser.parse_args()


args = parse_args()
cipher_root = args.cipher_root.rstrip("/\\")
filenames = glob.glob(os.path.join(cipher_root, "*", "*.pcap"))
print("Found files:", len(filenames))

def extract(payload):
    dic = {payload.name: payload}
    payload = payload.payload
    while payload.name != "NoPayload":
        dic[payload.name] = payload
        payload = payload.payload
    return dic


for filename in tqdm(filenames):
    basename = os.path.basename(filename).split(".")[0]
    domain = os.path.basename(os.path.dirname(filename))
    new_dir = os.path.join("RawData", "CipherSpectrum", domain)
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
        while True:
            try:
                packet = fdesc.read_packet()   # 读取一个报文
                result = extract(packet)       # 按层次展开，提取各协议层（IP/TCP 等）
                if "TCP" in result:           # 只保留包含 TCP 层的报文
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
