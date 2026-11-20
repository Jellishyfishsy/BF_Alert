"""Giao dien dong lenh.

    python -m detector live -i enp0s8               # che do mac dinh: thoi gian thuc
    python -m detector pcap capture.pcap            # phan tich file pcap
    python -m detector pcap capture.pcap --attacker-ip 192.168.56.101
    python -m detector test-discord                 # kiem tra webhook
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

from detector.config import (
    ALERT_COOLDOWN,
    BENIGN_LABEL,
    DEFAULT_PORTS,
    FLOW_TIMEOUT,
    IDLE_TIMEOUT,
    MODEL_NAMES,
    RESULTS_DIR,
    SERVICES,
    load_env_file,
)
from detector.features import records_to_frames
from detector.flow_tracker import FlowTracker
from detector.notifier import AlertManager, DiscordNotifier, build_info_embed, build_pcap_embed
from detector.predictor import EnsemblePredictor


# ======================================================================
# Ham dung chung
# ======================================================================

def parse_ports(text):
    try:
        return tuple(int(p) for p in text.split(",") if p.strip())
    except ValueError:
        raise argparse.ArgumentTypeError("Danh sach cong khong hop le, vd: 21,22")


def make_notifier(enabled=True):
    if not enabled:
        return DiscordNotifier(None)
    load_env_file()
    url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if not url:
        print("[!] Chua cau hinh DISCORD_WEBHOOK_URL (file .env) -> chi in canh bao ra man hinh.")
    return DiscordNotifier(url or None)


def predict_records(predictor, records, ports):
    meta, X = records_to_frames(records, predictor.feature_names, ports)
    pred = predictor.predict(X)
    return pd.concat([meta, pred], axis=1)


def format_row(row, predictor):
    phan = [f"{'*' if m.is_primary else ''}{m.name}: {m.label} {m.conf * 100:.1f}%"
            for m in predictor.results(row)]
    nhan = "CANH BAO " if row["is_attack"] else "binh thuong"
    return (f"[{row['timestamp']}] {nhan:<11} {row['src_ip']}:{row['src_port']} -> "
            f"{row['dst_ip']}:{row['dst_port']} | " + " | ".join(phan))


def print_model_info(predictor):
    print("Thu tu mo hinh (xep hang theo Recall tan cong roi F1-macro, * = mo hinh chinh):")
    for i, name in enumerate(predictor.order, 1):
        sao = "*" if name == predictor.primary else " "
        print(f"  {sao} {i}. {name:<14} {predictor.score_text(name, ascii_only=True)}")


# ======================================================================
# Che do 1: thoi gian thuc
# ======================================================================

def build_bpf(ports, all_ports):
    if all_ports:
        return "ip and (tcp or udp)"
    return "ip and tcp and (" + " or ".join(f"port {p}" for p in ports) + ")"


def run_live(args):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Che do live can quyen root de bat goi tin. Hay chay: sudo ./scripts/run_live.sh ...")
        sys.exit(1)

    from scapy.sendrecv import AsyncSniffer

    predictor = EnsemblePredictor(primary=args.primary_model)
    notifier = make_notifier(not args.no_discord)
    ports = args.ports
    nguon = f"live · {args.interface or 'interface mặc định'}"
    alerts = AlertManager(notifier, predictor, args.cooldown, nguon)

    tracker = FlowTracker(
        ports=None if args.all_ports else ports,
        flow_timeout=args.flow_timeout,
        idle_timeout=args.idle_timeout,
    )

    RESULTS_DIR.mkdir(exist_ok=True)
    log_path = RESULTS_DIR / f"live_log_{datetime.now():%Y%m%d_%H%M%S}.csv"

    sniff_kwargs = {"prn": tracker.process, "store": False}
    if args.interface:
        sniff_kwargs["iface"] = args.interface
    bpf = build_bpf(ports, args.all_ports)
    try:
        from scapy.arch.common import compile_filter
        compile_filter(bpf, iface=args.interface)
        sniff_kwargs["filter"] = bpf
    except Exception as exc:  # thieu libpcap/tcpdump: loc bang Python thay the
        print(f"[!] Khong dung duoc bo loc BPF ({exc}); loc goi tin bang Python.")
        bpf = "(loc bang Python)"

    print("=" * 70)
    print("HE THONG PHAT HIEN BRUTE-FORCE SSH/FTP - CHE DO THOI GIAN THUC")
    print("=" * 70)
    print_model_info(predictor)
    print(f"Interface: {args.interface or 'mac dinh'} | Bo loc: {bpf}")
    print(f"Dong luong khi: FIN, khong hoat dong {args.idle_timeout:.0f}s, hoac dai {args.flow_timeout:.0f}s")
    print(f"Discord: {'BAT' if notifier.enabled else 'TAT'} | Gom canh bao moi {args.cooldown:.0f}s")
    print(f"Nhat ky du doan: {log_path}")
    print("Nhan Ctrl+C de dung.\n")

    notifier.send_embed(build_info_embed(
        "🟢 IDS đã khởi động",
        "Đang giám sát lưu lượng brute-force SSH/FTP theo thời gian thực.",
        [
            {"name": "Interface", "value": args.interface or "mặc định", "inline": True},
            {"name": "Cổng", "value": ", ".join(map(str, ports)), "inline": True},
            {"name": "Mô hình chính", "value": predictor.primary, "inline": True},
        ],
    ))

    sniffer = AsyncSniffer(**sniff_kwargs)
    sniffer.start()

    tong_luong = 0
    tong_tan_cong = 0

    def xu_ly(now):
        """Du doan cac luong vua dong, in ra, gom canh bao va ghi nhat ky."""
        nonlocal tong_luong, tong_tan_cong
        records = tracker.drain()
        if not records:
            return
        res = predict_records(predictor, records, ports)
        for row in res.to_dict("records"):
            if row["is_attack"] or not args.quiet:
                print(format_row(row, predictor), flush=True)
            alerts.handle(row, now)
        tong_luong += len(res)
        tong_tan_cong += int(res["is_attack"].sum())
        res.to_csv(log_path, mode="a", header=not log_path.exists(), index=False, encoding="utf-8")

    try:
        while True:
            time.sleep(1.0)
            now = time.time()
            tracker.expire(now)
            xu_ly(now)
            alerts.tick(now)

            if sniffer.exception is not None or (sniffer.thread is not None
                                                 and not sniffer.thread.is_alive()):
                print(f"[!] Bo bat goi tin da dung: {sniffer.exception}")
                break
    except KeyboardInterrupt:
        print("\nDang dung...")
    finally:
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception:
            pass
        tracker.flush()
        xu_ly(time.time())
        alerts.flush()
        notifier.send_embed(build_info_embed(
            "⚪ IDS đã dừng",
            f"Đã phân tích {tong_luong} luồng, trong đó {tong_tan_cong} luồng brute-force "
            f"(theo {predictor.primary}).",
        ))
        notifier.close()

        print("\n===== TONG KET =====")
        print("Goi tin da xu ly:", tracker.packets_used)
        print("So luong da du doan:", tong_luong)
        print(f"So luong brute-force (theo {predictor.primary}):", tong_tan_cong)
        print("Canh bao chi tiet da gui:", alerts.alerts, "| tin tong hop:", alerts.summaries)
        if notifier.enabled:
            print("Discord: gui thanh cong", notifier.sent, "| that bai", notifier.failed)
        print("Nhat ky:", log_path if log_path.exists() else "(khong co luong nao)")


# ======================================================================
# Che do 2: phan tich file pcap
# ======================================================================

def read_pcap(path, tracker):
    """Doc file pcap, tra ve record cua tung luong."""
    from scapy.utils import PcapReader

    records = []
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader, 1):
            tracker.process(pkt)
            if i % 5000 == 0:
                # Chi de giai phong bo nho; luong da dong dung quy tac ngay trong process()
                tracker.expire(float(pkt.time))
                records += tracker.drain()
            if i % 100000 == 0:
                print(f"  ... da doc {i} goi tin", flush=True)
    tracker.flush()
    return records + tracker.drain()


def model_table(bang, predictor):
    """Bang co index la ten mo hinh -> them cot "Mo hinh" (danh dau mo hinh chinh) de in/luu."""
    ten = [name + (" (chinh)" if name == predictor.primary else "") for name in bang.index]
    return bang.set_axis(ten).rename_axis("Mo hinh").reset_index()


def evaluate(res, attacker_ip, predictor, chi_ket_noi=True):
    """So sanh du doan voi nhan thuc te: luong tu attacker_ip toi cong 21/22 la tan cong.

    chi_ket_noi=True: chi danh gia tren cac luong mo ket noi that (co goi SYN), bo qua
    cac manh luong vun (goi FIN tach ra khi dong ket noi) vi chung khong mang dau hieu
    brute-force. So luong con lai khop voi so ket noi ma `tcpdump ... syn` dem duoc.

    attacker_ip=None: file pcap chi chua luu luong binh thuong (kich ban 7, --benign),
    moi luong deu la BENIGN -> do ty le bao nham.
    """
    if attacker_ip is None:
        print("\n===== DANH GIA (nhan thuc te: TAT CA luong la binh thuong, --benign) =====")
    else:
        print(f"\n===== DANH GIA (nhan thuc te: luong tu {attacker_ip} toi cong 21/22 = tan cong) =====")

    if chi_ket_noi and "has_syn" in res.columns:
        so_manh = int((~res["has_syn"]).sum())
        res = res[res["has_syn"]]
        print(f"Chi tinh tren {len(res)} luong mo ket noi that (da bo {so_manh} manh luong vun; "
              f"dung --count-fragments de tinh ca manh vun).")

    nhan_tan_cong = {port: s.attack_label for port, s in SERVICES.items()}
    la_tan_cong = (res["client_ip"] == attacker_ip) & res["server_port"].isin(list(SERVICES))
    if attacker_ip is None:
        la_tan_cong = pd.Series(False, index=res.index)
    nhan_dung = res["server_port"].map(nhan_tan_cong).where(la_tan_cong, BENIGN_LABEL)

    print(f"Luong tan cong thuc te: {int(la_tan_cong.sum())} | binh thuong: {int((~la_tan_cong).sum())}")

    bang = {}
    for name, nhan in predictor.labels(res).items():
        bao_tan_cong = nhan != BENIGN_LABEL
        tp = int((la_tan_cong & bao_tan_cong).sum())
        fn = int((la_tan_cong & ~bao_tan_cong).sum())
        fp = int((~la_tan_cong & bao_tan_cong).sum())
        tn = int((~la_tan_cong & ~bao_tan_cong).sum())
        bang[name] = {
            "Phat hien (TP)": tp,
            "Bo sot (FN)": fn,
            "Bao nham (FP)": fp,
            "Dung binh thuong (TN)": tn,
            "Recall": tp / (tp + fn) if tp + fn else float("nan"),
            "Precision": tp / (tp + fp) if tp + fp else float("nan"),
            "Ty le bao nham": fp / (fp + tn) if fp + tn else float("nan"),
            "Dung loai tan cong": float((nhan == nhan_dung).mean()),
        }

    df = model_table(pd.DataFrame.from_dict(bang, orient="index"), predictor)
    print(df.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
    return df


def summarize(res, predictor):
    """Tong hop ket qua file pcap, dung chung cho man hinh va Discord.

    Tra ve (dem, dong_thuan, top):
      dem         so luong theo tung nhan cua moi mo hinh (index = ten mo hinh) + "Tong brute-force"
      dong_thuan  so luong ca 3 mo hinh cung nhan
      top         nguon tan cong nhieu nhat theo mo hinh chinh
    """
    labels = predictor.labels(res)
    dem = pd.DataFrame({name: nhan.value_counts() for name, nhan in labels.items()}).T
    dem = dem.reindex(columns=predictor.classes).fillna(0).astype(int)
    dem["Tong brute-force"] = len(res) - dem[BENIGN_LABEL]

    dong_thuan = int((labels.nunique(axis=1) == 1).sum())

    cot = ["client_ip", "server_ip", "server_port", "primary_label"]
    top = res.loc[res["is_attack"], cot].value_counts().head(10).reset_index(name="so_luong")
    return dem, dong_thuan, top


def print_summary(res, predictor, dem, dong_thuan, top):
    print("\nSo luong theo nhan du doan:")
    print(model_table(dem, predictor).to_string(index=False))

    so_tan_cong = int(res["is_attack"].sum())
    print(f"\n=> KET LUAN (theo {predictor.primary}): {so_tan_cong}/{len(res)} luong la brute-force "
          f"({so_tan_cong / len(res) * 100:.2f}%)")
    print(f"   Ca 3 mo hinh dong y nhau tren {dong_thuan}/{len(res)} luong.")

    if len(top):
        print("\nNguon tan cong (theo mo hinh chinh):")
        tieu_de = ["IP tan cong", "May chu", "Cong", "Loai", "So luong"]
        print(top.set_axis(tieu_de, axis=1).to_string(index=False))


def run_pcap(args):
    path = Path(args.pcap)
    if not path.is_file():
        print("Khong tim thay file:", path)
        sys.exit(1)

    predictor = EnsemblePredictor(primary=args.primary_model)
    ports = args.ports

    tracker = FlowTracker(
        ports=None if args.all_ports else ports,
        flow_timeout=args.flow_timeout,
        idle_timeout=args.idle_timeout,
    )

    print(f"Dang doc {path} ...")
    bat_dau = time.time()
    records = read_pcap(path, tracker)

    print("\n" + "=" * 70)
    print(f"KET QUA PHAN TICH: {path.name}")
    print("=" * 70)
    pham_vi = "tat ca cong" if args.all_ports else "cong " + ",".join(map(str, ports))
    print(f"Tong goi tin: {tracker.packets_seen} | goi tin thuoc {pham_vi}: {tracker.packets_used}")

    if not records:
        print("Khong co luong mang nao de phan tich.")
        return

    res = predict_records(predictor, records, ports).sort_values("timestamp").reset_index(drop=True)
    print(f"So luong (flow): {len(res)} | thoi gian xu ly: {time.time() - bat_dau:.2f}s")
    print()
    print_model_info(predictor)

    dem, dong_thuan, top = summarize(res, predictor)
    print_summary(res, predictor, dem, dong_thuan, top)

    danh_gia = None
    if args.attacker_ip or args.benign:
        danh_gia = evaluate(res, None if args.benign else args.attacker_ip, predictor,
                            chi_ket_noi=not args.count_fragments)

    RESULTS_DIR.mkdir(exist_ok=True)
    out = Path(args.output) if args.output else (
        RESULTS_DIR / f"pcap_{path.stem}_{datetime.now():%Y%m%d_%H%M%S}.csv")
    res.to_csv(out, index=False, encoding="utf-8-sig")
    print("\nDa luu du doan tung luong:", out)
    if danh_gia is not None:
        out_dg = out.with_name(out.stem + "_danh_gia.csv")
        danh_gia.to_csv(out_dg, index=False, encoding="utf-8-sig")
        print("Da luu bang danh gia:", out_dg)

    if args.notify:
        notifier = make_notifier()
        if notifier.enabled:
            ok = notifier.send_now(
                build_pcap_embed(path.name, predictor, len(res), dem["Tong brute-force"], top)
            )
            print("Da gui ket qua len Discord." if ok else "Gui Discord that bai.")


# ======================================================================
# Kiem tra webhook
# ======================================================================

def run_test_discord(args):
    notifier = make_notifier()
    if not notifier.enabled:
        sys.exit(1)
    ok = notifier.send_now(build_info_embed(
        "✅ Kết nối Discord thành công",
        "BruteForceML IDS sẽ gửi cảnh báo brute-force SSH/FTP vào kênh này.",
    ))
    print("Gui thanh cong!" if ok else "Gui that bai, kiem tra lai DISCORD_WEBHOOK_URL.")
    sys.exit(0 if ok else 1)


# ======================================================================

def main(argv=None):
    logging.basicConfig(level=logging.WARNING, format="[%(levelname)s] %(name)s: %(message)s")

    parser = argparse.ArgumentParser(
        prog="python -m detector",
        description="Phat hien brute-force SSH/FTP bang 3 mo hinh hoc may (DT, RF, XGBoost).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def them_tuy_chon_chung(p):
        p.add_argument("--ports", type=parse_ports, default=DEFAULT_PORTS,
                       help="Cong dich vu can giam sat (mac dinh: 21,22)")
        p.add_argument("--all-ports", action="store_true",
                       help="Phan tich luu luong moi cong thay vi chi 21/22")
        p.add_argument("--primary-model", choices=MODEL_NAMES,
                       help="Chon mo hinh chinh (mac dinh: hang 1 trong models/ket_qua_so_sanh.csv)")
        p.add_argument("--idle-timeout", type=float, default=IDLE_TIMEOUT,
                       help=f"Dong luong sau N giay khong co goi moi (mac dinh {IDLE_TIMEOUT:.0f})")
        p.add_argument("--flow-timeout", type=float, default=FLOW_TIMEOUT,
                       help=f"Do dai toi da cua mot luong (mac dinh {FLOW_TIMEOUT:.0f})")

    p_live = sub.add_parser("live", help="Bat goi tin thoi gian thuc va canh bao qua Discord")
    p_live.add_argument("-i", "--interface", help="Interface mang, vd: enp0s8")
    p_live.add_argument("--cooldown", type=float, default=ALERT_COOLDOWN,
                        help=f"Gom canh bao trong N giay (mac dinh {ALERT_COOLDOWN:.0f})")
    p_live.add_argument("--no-discord", action="store_true", help="Khong gui Discord")
    p_live.add_argument("-q", "--quiet", action="store_true", help="Chi in luong tan cong")
    them_tuy_chon_chung(p_live)

    p_pcap = sub.add_parser("pcap", help="Phan tich file .pcap/.pcapng")
    p_pcap.add_argument("pcap", help="Duong dan file pcap")
    nhan = p_pcap.add_mutually_exclusive_group()
    nhan.add_argument("--attacker-ip", help="IP may Kali de tinh Recall/Precision tung mo hinh")
    nhan.add_argument("--benign", action="store_true",
                      help="File chi co luu luong binh thuong (kich ban 7): do ty le bao nham")
    p_pcap.add_argument("--count-fragments", action="store_true",
                        help="Khi danh gia, tinh ca cac manh luong vun (mac dinh chi tinh luong co SYN)")
    p_pcap.add_argument("-o", "--output", help="File CSV ket qua (mac dinh: Results/pcap_<ten>_<gio>.csv)")
    p_pcap.add_argument("--notify", action="store_true", help="Gui tom tat ket qua len Discord")
    them_tuy_chon_chung(p_pcap)

    sub.add_parser("test-discord", help="Gui tin nhan thu toi Discord webhook")

    args = parser.parse_args(argv)
    {"live": run_live, "pcap": run_pcap, "test-discord": run_test_discord}[args.command](args)


if __name__ == "__main__":
    main()
