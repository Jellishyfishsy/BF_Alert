"""Chuyen dac trung tu thu vien cicflowmeter (Python) sang dinh dang CIC-IDS2017.

Dataset CIC-IDS2017 duoc tao bang CICFlowMeter ban Java, con o day dung ban
Python (pip install cicflowmeter==0.5.0). Hai ban khac nhau o nhieu diem, deu duoc
xu ly trong file nay:

1. Ten cot: "flow_duration" <-> "Flow Duration", ...
2. Don vi thoi gian: ban Python tinh bang GIAY, ban Java tinh bang MICRO GIAY.
   Neu khong nhan 1e6 thi cac dac trung thoi gian lech 1 trieu lan.
3. Init_Win_bytes: ban Java ghi -1 khi khong co goi TCP theo chieu do,
   ban Python ghi 0.
4. Cac dac trung do dai / header / IAT duoc TINH LAI tu goi tin (java_style_features),
   vi ban Python lech he thong so voi ban Java (da doi chieu khop 100% voi dataset):
   - Do dai goi: Java = do dai PAYLOAD TCP/UDP; Python = len(ca goi, gom ca header
     Ethernet/IP/TCP) -> lech ~54-66 byte moi goi.
   - Header: Java = TCP header (thuong 32 byte co option timestamp); Python = IP header (20).
   - Std/Var: Java = do lech chuan MAU (n-1); Python = tong the (n).
   - IAT khi chi co 1 khoang: Java = gia tri do; Python = 0 het.
   - Thong ke do dai cap luong (Packet Length Mean/Std/Var, Average Packet Size):
     Java dem goi DAU TIEN 2 lan (loi cua CICFlowMeter, nhung mo hinh da hoc theo no).
   - Down/Up Ratio: Java chia lay phan nguyen.
"""

import numpy as np
import pandas as pd

# scapy/cicflowmeter chi can khi doc goi tin (live/pcap). Bat loi import de buoc huan
# luyen/kiem thu tren X_test (predictor -> check_feature_names) van chay khi thieu chung.
try:
    from cicflowmeter.features.context import PacketDirection
    from scapy.layers.inet import IP, TCP, UDP
except ImportError:  # pragma: no cover
    PacketDirection = IP = TCP = UDP = None

# Ten cot CIC-IDS2017 -> ten truong cua cicflowmeter (Python)
FEATURE_MAP = {
    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Length": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",
    "CWE Flag Count": "cwr_flag_count",
    "ECE Flag Count": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",
    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",
    # Cot bi trung ten trong CIC-IDS2017, pandas doi thanh ".1"
    "Fwd Header Length.1": "fwd_header_len",
    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}

# Cac truong thoi gian can doi tu giay sang micro giay
TIME_FIELDS = {
    "flow_duration",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
}

# Cac cot co TCP trong CIC-IDS2017 la artefact cua CICFlowMeter Java, KHONG tai tao duoc
# tu goi tin: chi nhan 0/1 (khong phai so dem), "Fwd PSH Flags" phan phoi trung khit
# "SYN Flag Count", voi SSH thi PSH va ACK khong bao gio cung bang 1 (thuc te goi du lieu
# nao cung co ca hai). Ban Python dem dung nen luon lech -> nen bo khi huan luyen
# (python src/04_huan_luyen_mo_hinh.py --bo-co-tcp).
TCP_FLAG_FEATURES = (
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
)

# Thong tin nhan dien luong, khong dua vao mo hinh
META_COLUMNS = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol"]

TCP_PROTOCOL = 6


def _payload_len(pkt) -> int:
    """Do dai payload tang 4 nhu Java: tinh tu truong do dai IP, bo qua padding Ethernet
    (goi ACK rong bi dem toi 60 byte, scapy coi phan dem la payload)."""
    ip = pkt[IP]
    if TCP in pkt:
        tcp = pkt[TCP]
        if ip.len is not None and tcp.dataofs is not None:
            return max(int(ip.len) - ip.ihl * 4 - tcp.dataofs * 4, 0)
        return len(tcp.payload)
    if UDP in pkt:
        udp = pkt[UDP]
        return max(int(udp.len) - 8, 0) if udp.len is not None else len(udp.payload)
    return 0


def _header_len(pkt) -> int:
    """Header tang 4 nhu Java: TCP header (data offset * 4) hoac 8 byte voi UDP."""
    if TCP in pkt:
        return (pkt[TCP].dataofs or 5) * 4
    if UDP in pkt:
        return 8
    return 0


def _stats(values):
    """Thong ke kieu SummaryStatistics (Java): std/var MAU (n-1); n=1 -> std 0; rong -> 0."""
    if len(values) == 0:
        return {"total": 0.0, "max": 0.0, "min": 0.0, "mean": 0.0, "std": 0.0, "var": 0.0}
    a = np.asarray(values, dtype=float)
    var = float(a.var(ddof=1)) if len(a) > 1 else 0.0
    return {"total": float(a.sum()), "max": float(a.max()), "min": float(a.min()),
            "mean": float(a.mean()), "std": float(np.sqrt(var)), "var": var}


def _iat(times):
    return np.diff(np.asarray(times, dtype=float)) if len(times) > 1 else []


def java_style_features(flow) -> dict:
    """Tinh lai cac dac trung do dai / header / IAT tu danh sach goi cua luong, theo dung
    cong thuc CICFlowMeter Java (xem docstring dau file). Thoi gian tra ve bang GIAY,
    records_to_frames se doi sang micro giay nhu cac truong thoi gian khac."""
    goi = [(pkt, d, float(pkt.time)) for pkt, d in flow.packets]
    fwd = [g for g in goi if g[1] == PacketDirection.FORWARD]
    bwd = [g for g in goi if g[1] == PacketDirection.REVERSE]

    L = [_payload_len(p) for p, _, _ in goi]
    Lf = [_payload_len(p) for p, _, _ in fwd]
    Lb = [_payload_len(p) for p, _, _ in bwd]
    sf, sb = _stats(Lf), _stats(Lb)
    # Java cong goi dau tien vao thong ke do dai cap luong 2 lan
    s_luong = _stats(L + L[:1])
    so_goi = len(goi)

    thoi_luong = goi[-1][2] - goi[0][2] if so_goi > 1 else 0.0
    tong_byte = sf["total"] + sb["total"]

    it, itf, itb = _stats(_iat([t for *_, t in goi])), \
        _stats(_iat([t for *_, t in fwd])), _stats(_iat([t for *_, t in bwd]))

    hf = [_header_len(p) for p, _, _ in fwd]
    hb = [_header_len(p) for p, _, _ in bwd]

    return {
        "totlen_fwd_pkts": sf["total"], "totlen_bwd_pkts": sb["total"],
        "fwd_pkt_len_max": sf["max"], "fwd_pkt_len_min": sf["min"],
        "fwd_pkt_len_mean": sf["mean"], "fwd_pkt_len_std": sf["std"],
        "bwd_pkt_len_max": sb["max"], "bwd_pkt_len_min": sb["min"],
        "bwd_pkt_len_mean": sb["mean"], "bwd_pkt_len_std": sb["std"],
        "pkt_len_max": float(max(L)), "pkt_len_min": float(min(L)),
        "pkt_len_mean": s_luong["mean"], "pkt_len_std": s_luong["std"],
        "pkt_len_var": s_luong["var"],
        "pkt_size_avg": s_luong["total"] / so_goi,
        "fwd_seg_size_avg": sf["mean"], "bwd_seg_size_avg": sb["mean"],
        "subflow_fwd_byts": sf["total"], "subflow_bwd_byts": sb["total"],
        "flow_byts_s": tong_byte / thoi_luong if thoi_luong > 0 else 0.0,
        "fwd_act_data_pkts": sum(1 for x in Lf if x > 0),
        "fwd_header_len": float(sum(hf)), "bwd_header_len": float(sum(hb)),
        "fwd_seg_size_min": float(min(hf)) if hf else 0.0,
        "flow_iat_mean": it["mean"], "flow_iat_std": it["std"],
        "flow_iat_max": it["max"], "flow_iat_min": it["min"],
        "fwd_iat_tot": itf["total"], "fwd_iat_mean": itf["mean"], "fwd_iat_std": itf["std"],
        "fwd_iat_max": itf["max"], "fwd_iat_min": itf["min"],
        "bwd_iat_tot": itb["total"], "bwd_iat_mean": itb["mean"], "bwd_iat_std": itb["std"],
        "bwd_iat_max": itb["max"], "bwd_iat_min": itb["min"],
        "down_up_ratio": float(len(bwd) // len(fwd)) if fwd else 0.0,
    }


def flow_to_record(flow) -> dict:
    """Lay dac trung cua mot luong (cicflowmeter.flow.Flow) va chinh cho giong ban Java."""
    data = flow.get_data()
    data.update(java_style_features(flow))

    if int(data["protocol"]) != TCP_PROTOCOL:
        data["init_fwd_win_byts"] = -1
        data["init_bwd_win_byts"] = -1
    elif int(data["tot_bwd_pkts"]) == 0:
        data["init_bwd_win_byts"] = -1

    return data


def check_feature_names(feature_names) -> None:
    """Bao loi som neu mo hinh can dac trung ma bang anh xa chua co."""
    thieu = [name for name in feature_names if name not in FEATURE_MAP]
    if thieu:
        raise ValueError(f"Chua co anh xa cho cac dac trung: {thieu}")


def records_to_frames(records, feature_names, ports):
    """Tach danh sach record thanh (bang thong tin luong, ma tran dac trung X).

    Bang thong tin co them client_ip/client_port/server_ip/server_port: luong co the
    bat dau tu phia may chu (vd. manh luong sau goi FIN), nen khong the coi src_ip
    luon la ke tan cong. Ben nao dung cong dich vu (`ports`) la may chu.
    """
    df = pd.DataFrame.from_records(records)

    meta = df[META_COLUMNS].copy()
    meta["src_port"] = meta["src_port"].astype(int)
    meta["dst_port"] = meta["dst_port"].astype(int)

    # Phan biet luong mo ket noi that voi manh luong vun (vd. goi FIN tach ra sau khi
    # dong ket noi). Mot ket noi that bat dau bang goi SYN; manh vun thi khong co.
    def _so(truong):
        return pd.to_numeric(df[truong], errors="coerce").fillna(0)

    meta["n_packets"] = (_so("tot_fwd_pkts") + _so("tot_bwd_pkts")).astype(int)
    meta["has_syn"] = _so("syn_flag_cnt").astype(int) > 0

    dao = meta["src_port"].isin(ports) & ~meta["dst_port"].isin(ports)
    meta["client_ip"] = meta["src_ip"].where(~dao, meta["dst_ip"])
    meta["client_port"] = meta["src_port"].where(~dao, meta["dst_port"])
    meta["server_ip"] = meta["dst_ip"].where(~dao, meta["src_ip"])
    meta["server_port"] = meta["dst_port"].where(~dao, meta["src_port"])

    X = pd.DataFrame(index=df.index)
    for name in feature_names:
        nguon = FEATURE_MAP[name]
        cot = pd.to_numeric(df[nguon], errors="coerce").astype(float)
        if nguon in TIME_FIELDS:
            cot = cot * 1e6
        X[name] = cot

    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return meta, X
