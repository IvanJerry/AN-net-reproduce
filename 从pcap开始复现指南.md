# 从 PCAP 开始复现 AN-Net 全流程指南

本指南说明如何 **不依赖作者提供的 formatted data**，而是从原始 PCAP 文件开始，完成全部预处理并运行 `main.py` 进行训练与测试。

> 建议先只做 **SJTU-AN21（dataset=0）+ 无噪声 (`noise=0.0`)** 跑通流程，再扩展到噪声场景和其他数据集。

---

## 1. 目录结构约定

在项目根目录 `AN-Net/` 下，原始 PCAP 需要放在 `traffic_data/` 目录中，后续脚本会在此基础上生成 `RawData*` 和 `data_*`。

### 1.1 SJTU-AN21（dataset=0）

假设你已经下载并解压了 SJTU-AN21 pcap（只包含匿名流量 I2P / JonDonym / Tor）。

如果原始压缩包本身**已经给出了 train/test 划分**，直接保持即可；如果没有，你需要自己拆分。推荐的最终结构为：

```text
AN-Net/
  traffic_data/
    0_SJTUAN21/
      train/
        I2P/*.pcap or *.cap
        JonDonym/*.pcap or *.cap
        Tor/*.pcap or *.cap
      test/
        I2P/*.pcap or *.cap
        JonDonym/*.pcap or *.cap
        Tor/*.pcap or *.cap
```

说明：

- `0_SJTUAN21` 是数据集编号，对应 `--dataset 0`。
- `train/` 与 `test/` 目录名会一路保留，最终被 `main.py` 用来区分训练集和测试集。
- `I2P`、`JonDonym`、`Tor` 等子目录名会被当作 **类别名**。

#### 如果原始数据没有给 train/test：

1. 对于每个类别（例如 `I2P`）：
   - 将所有 pcap 文件先放在一个临时目录下；
   - 随机按 8:2（或其他比例）划分为 `train` 与 `test`；
2. 将它们按上面的目录结构挪到 `traffic_data/0_SJTUAN21/train/I2P/` 与 `traffic_data/0_SJTUAN21/test/I2P/` 等目录下。

> 注意：这样得到的划分不一定和论文完全一致，但流程是正确的，精度会在同一数量级。

### 1.2 CIC-IoT 5-Active（噪声源，可选）

如果你要复现实验中的噪声场景（`noise = 0.5_TLS / 0.75_TLS / 0.5_SIM / 0.75_SIM`），还需要从 CIC-IoT 2022 数据集中选择一批“主动攻击流量”作为 TLS 噪声源。

在目录上，AN-Net 期望你把这些 PCAP 放在：

```text
AN-Net/
  traffic_data/
    4_CICIOT/
      5-Active/
        Active/*.pcap
```

做法建议：

- 从 CIC-IoT 提供的各个攻击场景子目录中，把 pcap 文件复制到 `Active/` 目录；
- 不需要再区分 train/test；
- 这一批流量只是用来提供 TLS 包，用于给 SJTU-AN21 注入噪声，不参与分类。

如果你暂时只跑 **无噪声实验（`noise=0.0`）**，可以先不准备 CIC-IoT，跳过这一步和后面的加噪步骤。

---

## 2. 第一步：从 PCAP 提取基础序列（RawData）

在 `AN-Net/` 根目录下执行：

```bash
python data_extract.py
```

该脚本会：

- 从 `traffic_data/0_SJTUAN21/*/*.cap` 或 `*.pcap` 中读取 SJTU-AN21 流量；
- 从 `traffic_data/4_CICIOT/5-Active/Active/*.pcap` 中读取 CIC-IoT 流量（如存在）；
- 为每个原始 pcap 生成以下 `.npy` 文件：
  - `_T.npy`：每个包的到达时间差序列（flow 内时间间隔）；
  - `_L.npy`：每个包的 payload 长度；
  - `_P.npy`：截断后的 TCP 头 + payload 的 16 进制字符串；
  - `_O.npy`：TTL 序列；
  - `_F.npy`：IP 标志位；
  - `_C.npy`：TCP 标志位。

目录示意：

```text
RawData/
  0_SJTUAN21/
    train/I2P/xxx_T.npy, xxx_L.npy, xxx_P.npy, xxx_O.npy, xxx_F.npy, xxx_C.npy
    test/I2P/ ...
  4_CICIOT/
    5-Active/Active/yyy_T.npy, yyy_L.npy, ...
```

> 此时你仍然不需要自己“切 flow”或“合并 train/test”，脚本只是在包级别提取信息并保持原有路径结构。

---

## 3. 第二步：注入噪声（RawData_0.5_TLS / RawData_0.5_SIM 等，可选）

如果你只想做无噪声实验（`noise=0.0`），可以跳过本节，直接看第 4 部分。

要生成噪声版本数据，在 `AN-Net/` 下执行：

```bash
python add_noise.py
```

该脚本分两部分：

1. **构造 TLS 噪声池**：
   - 将 `RawData/4_CICIOT/5-Active/Active/` 下面所有的 `*_T.npy` / `*_L.npy` / ... 读入，拼接为一长条序列；
   - 这些包被当作“TLS 背景流量”。

2. **对 SJTU-AN21 流量注入噪声**：
   - 对 `RawData/0_SJTUAN21/...` 中的每条流，以 100 个包为一个窗口；
   - 对于 `noise ∈ {0.5, 0.75}`，在每个窗口中随机选出 `100 * noise` 个位置，用 TLS 噪声数据（或基于其统计特征的模拟数据）替换原始包；
   - 生成以下新目录：

```text
RawData_0.5_TLS/0_SJTUAN21/...
RawData_0.75_TLS/0_SJTUAN21/...
RawData_0.5_SIM/0_SJTUAN21/...
RawData_0.75_SIM/0_SJTUAN21/...
```

> `_TLS` 表示直接插入真实 TLS 包；`_SIM` 表示根据 TLS 的均值 / 方差等统计量模拟时间、长度、TTL、标志位等特征。

---

## 4. 第三步：从 RawData* 生成方法特征（data_*）

无论是否加噪声，最终训练时都会使用 `data_*` 目录下的特征文件。为此，在 `AN-Net/` 下执行：

```bash
python data_process.py
```

脚本中会循环处理多种噪声设置：

```python
for noise in [0.0, "0.5_SIM", "0.5_TLS", "0.75_SIM", "0.75_TLS"]:
    if noise == 0.0:
        filenames = glob.glob("RawData/0_SJTUAN21/*/*.npy")
    else:
        filenames = glob.glob(f"RawData_{noise}/0_SJTUAN21/*/*.npy")
```

对每个 `filename`（对应同一流量的 `_T.npy` / `_L.npy` 等）：

1. 读取对应的时间、长度、TTL、标志位和 payload；
2. 以 **100 个包为一个样本窗口**，切分并 reshape；
3. 为不同方法生成不同形式的特征：
   - `ShortTerm`：输出形状大致为 `(num_flows, 100, 1+1+1+1+1+64)` 的张量；
   - `Fs-net` / `AttnLSTM` / `Whisper` / `Characterize` / `Robust`：生成各自方法需要的二维 / 三维数组；
   - `Flowlens`：生成带表头的 `.csv` 文件；
   - `ETBert`：生成按行存储 token 序列的 `.txt` 文件。

生成的数据会被写入如下结构：

```text
AN-Net/
  data_0.0/
    0_SJTUAN21/
      train/
        I2P/
          ShortTerm/*.npy
          ETBert/*.txt
          Flowlens/*.csv
          Fs-net/*.npy
          AttnLSTM/*.npy
          Whisper/*.npy
          Characterize/*.npy
          Robust/*.npy
      test/
        I2P/...
  data_0.5_TLS/
    0_SJTUAN21/...
  data_0.5_SIM/
  data_0.75_TLS/
  data_0.75_SIM/
```

> 重要：你**不需要自己手动合并 npy 或切分样本**，`data_process.py` 已经根据包序列自动完成了这些工作。

---

## 5. 第四步：运行 main.py 进行训练与测试

完成前面步骤后，就可以像使用 formatted data 一样，通过 `main.py` 训练和评估模型。

### 5.1 基本命令示例

在 `AN-Net/` 下执行：

```bash
# SJTU-AN21，dataset=0，无噪声，ShortTerm 方法
python -u main.py --dataset 0 --noise 0.0 --method ShortTerm

# SJTU-AN21，0.5 TLS 噪声，ShortTerm 方法
python -u main.py --dataset 0 --noise 0.5_TLS --method ShortTerm

```python
# ===== ShortTerm, dataset=0，所有 noise 配置 =====
# 在 AN-Net 目录下执行： cd ~/snap/reproduce/AN-Net

# 1. 无噪声，GPU 5
CUDA_VISIBLE_DEVICES=5 nohup \
python -u main.py --dataset 0 --noise 0.0 --method ShortTerm \
> log_dataset0_0.0_shortterm_gpu5.out 2>&1 &

# 2. 0.5 TLS 噪声，GPU 5
CUDA_VISIBLE_DEVICES=5 nohup \
python -u main.py --dataset 0 --noise 0.5_TLS --method ShortTerm \
> log_dataset0_0.5TLS_shortterm_gpu5.out 2>&1 &

# 3. 0.5 SIM 噪声，GPU 6
CUDA_VISIBLE_DEVICES=5 nohup \
python -u main.py --dataset 0 --noise 0.5_SIM --method ShortTerm \
> log_dataset0_0.5SIM_shortterm_gpu5.out 2>&1 &
# 查看日志
tail -f log_dataset0_0.5SIM_shortterm_gpu5.out

# 4. 0.75 TLS 噪声，GPU 5
CUDA_VISIBLE_DEVICES=5 nohup \
python -u main.py --dataset 0 --noise 0.75_TLS --method ShortTerm \
> log_dataset0_0.75TLS_shortterm_gpu5.out 2>&1 &
#查看日志
tail -f log_dataset0_0.75TLS_shortterm_gpu5.out

# 5. 0.75 SIM 噪声，GPU 5
CUDA_VISIBLE_DEVICES=5 nohup \
python -u main.py --dataset 0 --noise 0.75_SIM --method ShortTerm \
> log_dataset0_0.75SIM_shortterm_gpu5.out 2>&1 &
#查看日志
tail -f log_dataset0_0.75SIM_shortterm_gpu5.out
```



# 其它对比方法（同样可以切换 noise）
python -u main.py --dataset 0 --noise 0.0 --method Whisper
python -u main.py --dataset 0 --noise 0.0 --method Characterize
python -u main.py --dataset 0 --noise 0.0 --method Robust
python -u main.py --dataset 0 --noise 0.0 --method Flowlens
python -u main.py --dataset 0 --noise 0.0 --method AttnLSTM
python -u main.py --dataset 0 --noise 0.0 --method Fs-net
python -u main.py --dataset 0 --noise 0.0 --method ETBert
```

关键参数含义：

- `--dataset`：
  - `0` → `data_*/0_SJTUAN21/`（当前我们只从这个数据集开始）；
  - 其他值（1,2,3,5）对应 ISCXVPN / ISCXTor / USTC-TFC / Cross-Platform，需要你额外准备相应的 `traffic_data/<id>_XXX/` 目录并扩展预处理流程。
- `--noise`：对应 `data_<noise>/` 目录名：
  - `0.0`、`0.5_TLS`、`0.5_SIM`、`0.75_TLS`、`0.75_SIM`；
- `--method`：特征方法名称：`ShortTerm`, `Whisper`, `Characterize`, `Robust`, `Flowlens`, `Fs-net`, `AttnLSTM`, `ETBert`。

`main.py` 内部会：

1. 通过 `glob` 搜索 `data_<noise>/0_SJTUAN21/*/<method>/*.*`；
2. 根据路径 / 文件名中是否包含 `"train"` / `"test"` 划分训练集与测试集；
3. 从文件名解析类别名，并将其映射到标签索引；
4. 训练指定方法的模型，计算 ACC / PR / RC / F1，并将日志写入 `result/` 目录。

---

## 6. 建议的复现顺序

1. **先跑无噪声 + 单数据集**：
   - 只准备 `traffic_data/0_SJTUAN21/`；
   - 跑 `data_extract.py` → `data_process.py`；
   - 用 `--dataset 0 --noise 0.0` 跑 `ShortTerm` 和若干对比方法；
2. **再加噪声**：
   - 准备 `traffic_data/4_CICIOT/5-Active/Active/*.pcap`；
   - 再跑一次 `data_extract.py`（补充 CICIOT 部分）；
   - 跑 `add_noise.py` → `data_process.py`；
   - 用 `--noise 0.5_TLS` / `0.75_TLS` / `0.5_SIM` / `0.75_SIM` 跑实验；
3. **最后扩展到更多数据集**：
   - 按 `0_SJTUAN21` 的方式组织 `1_ISCXVPN`、`2_ISCXTor`、`3_USTC-TFC`、`5_Cross-Platform` 的原始 pcap；
   - 相同脚本重新跑一遍预处理即可。

如果你在任一步遇到具体报错（例如找不到某个 `RawData` / `data_*` 目录、`np.load` 或维度不匹配等），可以把 **完整命令 + 报错栈** 贴出来，方便进一步定位。
