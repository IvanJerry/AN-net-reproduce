import glob
import numpy as np
import os
from tqdm import tqdm
from collections import defaultdict
from numpy import fft
import scipy.stats as st
import random
import argparse

# 固定随机种子，保证每次预处理结果一致
SEED = 2023
np.random.seed(SEED)
random.seed(SEED)


# 支持的特征方法名称，和目录名、main.py 中的 --method 一一对应
METHOD_CHOICES = [
    "ShortTerm",      # 论文主方法使用的特征：长度/时间/TTL/IPFlag/TCPFlag/载荷等六类信息拼接
    "ETBert",         # 把载荷转成 bigram token 序列，写入 txt，用于 Bert 类方法
    "Flowlens",       # 统计每个流中长度直方图（bucket 分布），写入 csv
    "Fs-net",         # 只保留长度序列，按窗口 reshape 成 [N, 100]
    "AttnLSTM",       # 把载荷转成 64 维整数序列，reshape 成 [N, 100, 64]
    "Whisper",        # 对长度序列做 FFT，取前 51 维频谱幅值
    "Characterize",   # 对时间间隔做统计特征（均值/方差/偏度/峰度/中位数/最小/最大）
    "Robust",         # 对长度序列做统计特征（同上），更鲁棒的长度特征
]


def parse_args():
    # 通过命令行参数控制要生成哪些方法的数据
    # --methods ALL              -> 生成所有方法（默认，等价于原始脚本行为）
    # --methods ShortTerm        -> 只生成 ShortTerm 特征
    # --methods ShortTerm,Whisper -> 同时生成多个方法
    parser = argparse.ArgumentParser(description="Preprocess raw data into method-specific features")
    parser.add_argument(
        "--methods",
        type=str,
        default="ALL",
        help=(
            "Comma-separated list of methods to process, e.g. "
            "'ShortTerm,Whisper'. Use 'ALL' to process all methods."
        ),
    )
    return parser.parse_args()


def cut(obj):
    # 每 4 个字符切一段（用于 16 进制串分块）
    return [obj[i:i + 4] for i in range(0, len(obj), 4)]


def cut2(obj):
    # 每 2 个字符切一段（1 字节 = 2 个 16 进制字符）
    return [obj[i:i + 2] for i in range(0, len(obj), 2)]


def cut_origin(obj, sec):
    result = [obj[i:i + sec] for i in range(0, len(obj), sec)]
    try:
        remanent_count = len(result[0]) % 4
    except Exception as e:
        remanent_count = 0
    if remanent_count == 0:
        pass
    else:
        result = [obj[i:i + sec + remanent_count] for i in range(0, len(obj), sec + remanent_count)]
    return result


def bigram_generation(packet_datagram, packet_len=64, flag=True):
    # 把 16 进制串按 1 字节滑动，生成 bigram token 序列
    result = []
    generated_datagram = cut_origin(packet_datagram, 1)
    token_count = 0
    for sub_string_index in range(len(generated_datagram)):
        if sub_string_index != (len(generated_datagram) - 1):
            token_count += 1
            if token_count > packet_len:
                break
            else:
                merge_word_bigram = generated_datagram[sub_string_index] + generated_datagram[sub_string_index + 1]
        else:
            break
        result.append(merge_word_bigram)

    return result


def int_generation(packet_datagram, packet_len=64):
    # 把 16 进制载荷转换为定长整数序列（长度 64，不足补 0）
    result = []
    generated_datagram = cut2(packet_datagram)
    token_count = 0
    for sub_string_index in range(len(generated_datagram)):
        token_count += 1
        if token_count > packet_len:
            break
        else:
            result.append(int(generated_datagram[sub_string_index], 16))
    result = np.array(result)
    result = np.pad(result, (0, packet_len - len(result)), "constant", constant_values=0).astype(np.int64)
    return result


def RoundToNearest(n, m):
    if n > 0:
        r = n % m
        return n + m - r if r + r >= m else n - r
    else:
        return 0


def FlowLens(length_sequence, basename):
    data_csv = open(basename + ".csv", 'w')
    minBucket = 0
    maxBucket = 312 * 32
    binWidth = 32
    for size in range(minBucket, maxBucket + 1, binWidth):
        if size == maxBucket:
            data_csv.write("packetLengthBin_" + str(size) + "\n")
        else:
            data_csv.write("packetLengthBin_" + str(size) + ", ")

    for i in range(len(length_sequence) // 100):
        tmp_length_sequence = length_sequence[i * 100: (i + 1) * 100]
        bin_distribution = defaultdict(int)
        for packet_size in tmp_length_sequence:
            packet_size_binned = RoundToNearest(int(packet_size), binWidth)
            bin_distribution[packet_size_binned] += 1

        bin_list = []
        for size in range(minBucket, maxBucket + 1, binWidth):
            bin_list.append(str(bin_distribution[size]))
        data_csv.write(",".join(bin_list) + "\n")

    data_csv.close()


def FSNet(length_sequence, basename):
    instance_num = len(length_sequence) // 100
    length_sequence = length_sequence[: instance_num * 100]
    length_sequence = length_sequence.reshape(-1, 100)
    np.save(basename + ".npy", length_sequence)


def AttnLSTM(packet_data_int_sequence, basename):
    instance_num = len(packet_data_int_sequence) // 100
    packet_data_int_sequence = packet_data_int_sequence[: instance_num * 100]
    packet_data_int_sequence = packet_data_int_sequence.reshape(-1, 100, 64)
    np.save(basename + ".npy", packet_data_int_sequence)


def Whisper(length_sequence, basename):
    instance_num = len(length_sequence) // 100
    length_sequence = length_sequence[: instance_num * 100]
    length_sequence = length_sequence.reshape(-1, 100)
    spectral_arr = fft.fft(length_sequence, axis=-1)
    spectral_arr = np.abs(spectral_arr)
    result = spectral_arr[:, :51]
    np.save(basename + ".npy", result)


def extract_statistical(arr):
    statistical_arr = []

    statistical_arr.append(np.expand_dims(np.mean(arr, axis=-1), axis=-1))
    statistical_arr.append(np.expand_dims(np.std(arr, axis=-1), axis=-1))
    statistical_arr.append(np.expand_dims(st.skew(arr, axis=-1), axis=-1))
    statistical_arr.append(np.expand_dims(st.kurtosis(arr, axis=-1), axis=-1))
    statistical_arr.append(np.expand_dims(np.median(arr, axis=-1), axis=-1))
    statistical_arr.append(np.expand_dims(np.min(arr, axis=-1), axis=-1))
    statistical_arr.append(np.expand_dims(np.max(arr, axis=-1), axis=-1))

    statistical_arr = np.concatenate(statistical_arr, axis=-1)
    return statistical_arr


def Characterize(time_sequence, basename):
    time_delta = time_sequence
    instance_num = len(time_delta) // 100
    time_delta = time_delta[: instance_num * 100]
    time_delta = time_delta.reshape(-1, 100)

    statistics = extract_statistical(time_delta)
    np.save(basename + ".npy", statistics)


def Robust(length_sequence, basename):
    instance_num = len(length_sequence) // 100
    length_sequence = length_sequence[: instance_num * 100]
    length_sequence = length_sequence.reshape(-1, 100)

    statistics = extract_statistical(length_sequence)
    np.save(basename + ".npy", statistics)


def ETBert(packet_raw_string_sequence, basename):
    instance_num = len(length_sequence) // 100
    packet_raw_string_sequence = packet_raw_string_sequence[: instance_num * 100]
    packet_raw_string_sequence = packet_raw_string_sequence.reshape(-1, 100)
    f = open(basename + ".txt", "w")
    for i in range(instance_num):
        flow_raw_string = list(packet_raw_string_sequence[i])
        flow_data_string = []
        for packet_raw in flow_raw_string:
            flow_data_string.append(bigram_generation(packet_raw, packet_len=128, flag=True))
        ls_len = np.array([len(f) for f in flow_data_string])
        ls_len_cum = np.cumsum(ls_len)
        allow_position = np.argwhere(ls_len_cum > 512).reshape(-1)
        if len(allow_position) == 0:
            continue
        choice_position = np.random.choice(allow_position, size=1).item()

        flow_data_string = flow_data_string[:choice_position+1]
        ls_len = np.array([len(f) for f in flow_data_string])
        ls_len_cum = np.cumsum(ls_len[::-1])[::-1]
        allow_position = np.argwhere(ls_len_cum > 512).reshape(-1)
        start_position = allow_position[-1]

        flow_data_string = flow_data_string[start_position:]
        n = sum([len(f) for f in flow_data_string])
        assert n >= 512
        flow_data_string = [" ".join(f) for f in flow_data_string]
        flow_data_string = " ".join(flow_data_string)
        f.write(flow_data_string + "\n")
    f.close()


def ShortTerm(time_sequence, length_sequence, ttl_sequence, ip_flag_sequence, tcp_flag_sequence, packet_data_int_sequence, basename):
    instance_num = len(length_sequence) // 100
    length_sequence = length_sequence[: instance_num * 100]
    length_sequence = length_sequence.reshape(-1, 100, 1)

    time_delta = time_sequence
    time_delta = time_delta[: instance_num * 100]
    time_delta = time_delta.reshape(-1, 100, 1)

    instance_num = len(ttl_sequence) // 100
    ttl_sequence = ttl_sequence[: instance_num * 100]
    ttl_sequence = ttl_sequence.reshape(-1, 100, 1)

    instance_num = len(ip_flag_sequence) // 100
    ip_flag_sequence = ip_flag_sequence[: instance_num * 100]
    ip_flag_sequence = ip_flag_sequence.reshape(-1, 100, 1)

    instance_num = len(tcp_flag_sequence) // 100
    tcp_flag_sequence = tcp_flag_sequence[: instance_num * 100]
    tcp_flag_sequence = tcp_flag_sequence.reshape(-1, 100, 1)

    instance_num = len(packet_data_int_sequence) // 100
    packet_data_int_sequence = packet_data_int_sequence[: instance_num * 100]
    packet_data_int_sequence = packet_data_int_sequence.reshape(-1, 100, 64)

    result = np.concatenate(
        [length_sequence, time_delta, ttl_sequence, ip_flag_sequence, tcp_flag_sequence, packet_data_int_sequence], axis=-1)

    np.save(basename + ".npy", result)


args = parse_args()
if args.methods.upper() == "ALL":
    selected_methods = set(METHOD_CHOICES)
else:
    selected_methods = set(m.strip() for m in args.methods.split(",") if m.strip())


for noise in [0.0, "0.5_SIM", "0.5_TLS", "0.75_SIM", "0.75_TLS"]:
    if noise == 0.0:
        filenames = glob.glob(f"RawData/CipherSpectrum/*/*.npy")
    else:
        filenames = glob.glob(f"RawData_{noise}/CipherSpectrum/*/*.npy")
    filenames = [filename[:-6] for filename in filenames]
    filenames = sorted(set(filenames))

    for filename in tqdm(filenames):
        basename = "/" + filename.split("/")[-1]
        if noise == 0.0:
            new_dir = f"data_{noise}" + "/".join(filename.split(f"RawData")[-1].split("/")[:-1]) + "/"
        else:
            new_dir = f"data_{noise}" + "/".join(filename.split(f"RawData_{noise}")[-1].split("/")[:-1]) + "/"
        if not os.path.isdir(new_dir):
            os.makedirs(new_dir)
        time_sequence = np.load(filename + "_T.npy")
        length_sequence = np.load(filename + "_L.npy")
        ttl_sequence = np.load(filename + "_O.npy")
        packet_raw_string_sequence = np.load(filename + "_P.npy")
        ip_flag_sequence = np.load(filename + "_F.npy")
        tcp_flag_sequence = np.load(filename + "_C.npy")

        packet_data_int_sequence = np.asarray([
            int_generation(packet_raw_string)
            for packet_raw_string in packet_raw_string_sequence
        ])

        if "ShortTerm" in selected_methods:
            if not os.path.exists(new_dir + "ShortTerm"):
                os.mkdir(new_dir + "ShortTerm")
            ShortTerm(
                time_sequence,
                length_sequence,
                ttl_sequence,
                ip_flag_sequence,
                tcp_flag_sequence,
                packet_data_int_sequence,
                new_dir + "ShortTerm" + basename,
            )

        if "ETBert" in selected_methods:
            if not os.path.exists(new_dir + "ETBert"):
                os.mkdir(new_dir + "ETBert")
            ETBert(packet_raw_string_sequence, new_dir + "ETBert" + basename)

        if "Flowlens" in selected_methods:
            if not os.path.exists(new_dir + "Flowlens"):
                os.mkdir(new_dir + "Flowlens")
            FlowLens(length_sequence, new_dir + "Flowlens" + basename)

        if "Fs-net" in selected_methods:
            if not os.path.exists(new_dir + "Fs-net"):
                os.mkdir(new_dir + "Fs-net")
            FSNet(length_sequence, new_dir + "Fs-net" + basename)

        if "AttnLSTM" in selected_methods:
            if not os.path.exists(new_dir + "AttnLSTM"):
                os.mkdir(new_dir + "AttnLSTM")
            AttnLSTM(packet_data_int_sequence, new_dir + "AttnLSTM" + basename)

        if "Whisper" in selected_methods:
            if not os.path.exists(new_dir + "Whisper"):
                os.mkdir(new_dir + "Whisper")
            Whisper(length_sequence, new_dir + "Whisper" + basename)

        if "Characterize" in selected_methods:
            if not os.path.exists(new_dir + "Characterize"):
                os.mkdir(new_dir + "Characterize")
            Characterize(time_sequence, new_dir + "Characterize" + basename)

        if "Robust" in selected_methods:
            if not os.path.exists(new_dir + "Robust"):
                os.mkdir(new_dir + "Robust")
            Robust(length_sequence, new_dir + "Robust" + basename)
