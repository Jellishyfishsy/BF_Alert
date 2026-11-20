"""Gui canh bao qua Discord webhook va gom canh bao theo IP tan cong."""

import logging
import queue
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from detector.config import ALERT_COOLDOWN, BENIGN_LABEL, SERVICES

log = logging.getLogger("detector.notifier")

MAU_TAN_CONG = {s.attack_label: s.color for s in SERVICES.values()}
MAU_TONG_HOP = 0xF1C40F
MAU_THONG_TIN = 0x3498DB


def _ten_dich_vu(port):
    return SERVICES[port].name if port in SERVICES else f"cổng {port}"


def _ket_qua_mo_hinh(m):
    dau = "🔴" if m.label != BENIGN_LABEL else "🟢"
    return (f"{dau} **{m.label}** · tin cậy {m.conf * 100:.2f}% "
            f"· P(tấn công) {m.attack_prob * 100:.2f}%")


def _ten_kem_chi_so(predictor, name):
    return f"{name} ({predictor.score_text(name)})"


def _embed(title, description, color, fields, nguon_du_lieu=None):
    footer = "BruteForceML IDS" + (f" · {nguon_du_lieu}" if nguon_du_lieu else "")
    return {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": footer},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def build_info_embed(title, description, fields=None):
    return _embed(title, description, MAU_THONG_TIN, fields or [])


def build_alert_embed(row, predictor, nguon_du_lieu):
    dich_vu = _ten_dich_vu(row["server_port"])
    so_dong_y = int(row["so_mo_hinh_bao_tan_cong"])

    fields = [
        {"name": "Nguồn tấn công", "value": f"`{row['client_ip']}:{row['client_port']}`",
         "inline": True},
        {"name": "Đích", "value": f"`{row['server_ip']}:{row['server_port']}` ({dich_vu})",
         "inline": True},
        {"name": "Thời điểm bắt đầu luồng", "value": str(row["timestamp"]), "inline": True},
    ]
    for m in predictor.results(row):
        vai_tro = "⭐ Mô hình chính" if m.is_primary else "Tham khảo"
        fields.append({
            "name": f"{vai_tro}: {_ten_kem_chi_so(predictor, m.name)}",
            "value": _ket_qua_mo_hinh(m),
            "inline": False,
        })
    fields.append({
        "name": "Đồng thuận",
        "value": f"{so_dong_y}/{len(predictor.order)} mô hình cho rằng đây là tấn công",
        "inline": False,
    })

    return _embed(
        f"🚨 Phát hiện brute-force {dich_vu}",
        f"Mô hình chính **{predictor.primary}** kết luận luồng này là **{row['primary_label']}**.",
        MAU_TAN_CONG.get(row["primary_label"], 0xE74C3C),
        fields,
        nguon_du_lieu,
    )


def build_summary_embed(key, window, predictor, cooldown, nguon_du_lieu):
    client_ip, server_ip, server_port, nhan = key
    dich_vu = _ten_dich_vu(server_port)

    gan_nhat = predictor.results(window.last_row)
    fields = []
    for m in gan_nhat:
        nhan_vai_tro = "⭐ Mô hình chính" if m.is_primary else "Tham khảo"
        fields.append({
            "name": f"{nhan_vai_tro}: {m.name}",
            "value": f"{window.model_counts[m.name]}/{window.pending} luồng bị coi là tấn công",
            "inline": True,
        })
    fields.append({
        "name": "Luồng gần nhất",
        "value": "\n".join(f"{m.name}: {_ket_qua_mo_hinh(m)}" for m in gan_nhat),
        "inline": False,
    })

    return _embed(
        f"📈 Tấn công {dich_vu} vẫn tiếp diễn từ {client_ip}",
        (f"Trong khoảng {int(cooldown)} giây vừa qua có thêm **{window.pending}** luồng "
         f"**{nhan}** tới `{server_ip}:{server_port}` (theo {predictor.primary})."),
        MAU_TONG_HOP,
        fields,
        nguon_du_lieu,
    )


def build_pcap_embed(ten_file, predictor, so_luong, tan_cong_theo_mo_hinh, top):
    """Tom tat ket qua phan tich file pcap.

    tan_cong_theo_mo_hinh: so luong brute-force cua tung mo hinh (index = ten mo hinh).
    top: nguon tan cong, cot client_ip, server_port, primary_label, so_luong.
    """
    fields = [{"name": name + (" (chinh)" if name == predictor.primary else ""),
               "value": f"{so} luồng brute-force", "inline": True}
              for name, so in tan_cong_theo_mo_hinh.items()]
    if len(top):
        fields.append({"name": "Nguồn tấn công", "value": "\n".join(
            f"`{r.client_ip}` → :{r.server_port} ({r.primary_label}): {r.so_luong}"
            for r in top.head(5).itertuples()), "inline": False})
    so_tan_cong = tan_cong_theo_mo_hinh[predictor.primary]
    return build_info_embed(
        f"📄 Kết quả phân tích {ten_file}",
        f"**{so_tan_cong}/{so_luong}** luồng là brute-force (theo {predictor.primary}).",
        fields,
    )


class DiscordNotifier:
    """Gui tin nhan qua webhook trong mot luong rieng de khong chan viec bat goi tin."""

    def __init__(self, webhook_url, username="BruteForceML IDS"):
        self.webhook_url = webhook_url or None
        self.username = username
        self.sent = 0
        self.failed = 0
        self._queue = queue.Queue()
        self._thread = None
        if self.enabled:
            self._thread = threading.Thread(target=self._worker, name="discord", daemon=True)
            self._thread.start()

    @property
    def enabled(self) -> bool:
        return self.webhook_url is not None

    def send_embed(self, embed) -> None:
        if self.enabled:
            self._queue.put({"username": self.username, "embeds": [embed]})

    def send_now(self, embed) -> bool:
        """Gui dong bo, tra ve True neu thanh cong (dung cho lenh test-discord)."""
        return self._post({"username": self.username, "embeds": [embed]})

    def close(self, timeout=15.0) -> None:
        if self._thread is not None:
            self._queue.put(None)
            self._thread.join(timeout)

    def _worker(self):
        while True:
            payload = self._queue.get()
            if payload is None:
                return
            self._post(payload)

    def _post(self, payload, max_retry=3) -> bool:
        for _ in range(max_retry):
            try:
                resp = requests.post(self.webhook_url, json=payload, timeout=10)
            except requests.RequestException as exc:
                log.warning("Khong gui duoc Discord: %s", exc)
                time.sleep(2)
                continue

            if resp.status_code == 429:
                # Discord gioi han toc do: doi dung thoi gian duoc yeu cau
                try:
                    cho = float(resp.json().get("retry_after", 1.0))
                except ValueError:
                    cho = 1.0
                time.sleep(cho + 0.1)
                continue

            if resp.ok:
                self.sent += 1
                return True

            log.warning("Discord tra ve loi %s: %s", resp.status_code, resp.text[:200])
            break

        self.failed += 1
        return False


@dataclass
class _Window:
    """Mot dot tan cong cua mot cap (IP tan cong, may chu, cong, loai tan cong)."""

    start: float
    pending: int = 0                # so luong tan cong them tu canh bao/tin tong hop truoc
    last_row: dict | None = None    # luong tan cong gan nhat
    model_counts: Counter = field(default_factory=Counter)  # ten mo hinh -> so luong bao tan cong


class AlertManager:
    """Gom canh bao: moi cap (IP tan cong, may chu, cong, loai tan cong) chi gui
    1 canh bao chi tiet; cac luong tan cong tiep theo trong `cooldown` giay duoc
    dem lai va gui thanh 1 tin tong hop."""

    def __init__(self, notifier, predictor, cooldown=ALERT_COOLDOWN, nguon_du_lieu="live"):
        self.notifier = notifier
        self.predictor = predictor
        self.cooldown = cooldown
        self.nguon_du_lieu = nguon_du_lieu
        self.windows = {}
        self.alerts = 0
        self.summaries = 0

    def handle(self, row, now) -> None:
        if not row["is_attack"]:
            return

        key = (row["client_ip"], row["server_ip"], row["server_port"], row["primary_label"])
        window = self.windows.get(key)

        if window is None:
            self.notifier.send_embed(build_alert_embed(row, self.predictor, self.nguon_du_lieu))
            self.alerts += 1
            self.windows[key] = _Window(start=now)
            return

        window.pending += 1
        window.last_row = row
        window.model_counts.update(
            m.name for m in self.predictor.results(row) if m.label != BENIGN_LABEL
        )

    def tick(self, now) -> None:
        for key, window in list(self.windows.items()):
            if now - window.start < self.cooldown:
                continue
            if window.pending > 0:
                self._send_summary(key, window)
                self.windows[key] = _Window(start=now)
            else:
                # Het tan cong: lan sau se gui canh bao chi tiet moi
                del self.windows[key]

    def flush(self) -> None:
        for key, window in self.windows.items():
            if window.pending > 0:
                self._send_summary(key, window)
        self.windows.clear()

    def _send_summary(self, key, window):
        self.notifier.send_embed(
            build_summary_embed(key, window, self.predictor, self.cooldown, self.nguon_du_lieu)
        )
        self.summaries += 1
