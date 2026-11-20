"""Gom goi tin thanh luong (flow) theo quy tac cua CICFlowMeter ban Java.

Thu vien cicflowmeter (Python) chi duoc dung de TINH dac trung (lop Flow).
Viec dong luong duoc lam lai o day vi FlowSession cua thu vien:
  - chi xuat luong sau 240 giay khong hoat dong -> canh bao den rat cham;
  - khi doc pcap lai so thoi gian goi tin voi gio hien tai -> cat vun luong.

Quy tac dong luong (giong CICFlowMeter Java dung de tao CIC-IDS2017):
  - Gap goi FIN trong mot luong da ton tai: them goi do roi dong luong ngay.
    Cac goi con lai cua phien (FIN/ACK cua ben kia) tao thanh mot luong moi.
    Dataset co rat nhieu "manh" luong 3 goi nhu vay, mo hinh da hoc ca chung.
  - Luong dai qua FLOW_TIMEOUT (120 giay) ke tu goi dau tien.
  - Bo sung: luong khong co goi moi qua IDLE_TIMEOUT de canh bao kip thoi.
"""

import threading

from cicflowmeter.features.context import PacketDirection, get_packet_flow_key
from cicflowmeter.flow import Flow
from scapy.layers.inet import IP, TCP, UDP

from detector.config import FLOW_TIMEOUT, IDLE_TIMEOUT
from detector.features import flow_to_record

FORWARD = PacketDirection.FORWARD
REVERSE = PacketDirection.REVERSE


class FlowTracker:
    def __init__(self, ports=None, flow_timeout=FLOW_TIMEOUT, idle_timeout=IDLE_TIMEOUT):
        """ports: chi giu goi tin co cong nguon/dich thuoc tap nay (None = tat ca)."""
        self.ports = set(ports) if ports else None
        self.flow_timeout = flow_timeout
        self.idle_timeout = idle_timeout

        # process() chay trong luong cua scapy, expire()/drain() trong luong chinh
        self.lock = threading.Lock()
        self.flows = {}
        self.finished = []

        self.packets_seen = 0
        self.packets_used = 0

    def _expired(self, flow, now: float) -> bool:
        """Quy tac dong luong duy nhat, dung ca khi co goi moi lan khi quet dinh ky.

        Nho vay noi dung luong khong phu thuoc vao tan suat goi expire()
        (live quet moi giay, pcap quet moi 5000 goi).
        """
        return (now - float(flow.latest_timestamp) > self.idle_timeout
                or now - float(flow.start_timestamp) > self.flow_timeout)

    def _accept(self, pkt) -> bool:
        if IP not in pkt:
            return False
        if TCP in pkt:
            l4 = pkt[TCP]
        elif UDP in pkt:
            l4 = pkt[UDP]
        else:
            return False
        if self.ports is None:
            return True
        return l4.sport in self.ports or l4.dport in self.ports

    def process(self, pkt) -> None:
        """Xu ly mot goi tin (dung lam prn cho scapy sniff)."""
        self.packets_seen += 1
        if not self._accept(pkt):
            return

        now = float(pkt.time)

        with self.lock:
            self.packets_used += 1

            key = get_packet_flow_key(pkt, FORWARD)
            direction = FORWARD
            flow = self.flows.get(key)

            if flow is None:
                reverse_key = get_packet_flow_key(pkt, REVERSE)
                flow = self.flows.get(reverse_key)
                if flow is not None:
                    key, direction = reverse_key, REVERSE

            if flow is not None and self._expired(flow, now):
                self.finished.append(self.flows.pop(key))
                flow = None

            if flow is None:
                # Goi dau tien quyet dinh chieu "forward" cua luong moi
                key = get_packet_flow_key(pkt, FORWARD)
                self.flows[key] = Flow(pkt, FORWARD)
            else:
                flow.add_packet(pkt, direction)
                if TCP in pkt and pkt[TCP].flags.F:
                    self.finished.append(self.flows.pop(key))

    def expire(self, now: float) -> None:
        """Dong cac luong het han. `now` cung he thoi gian voi pkt.time."""
        with self.lock:
            for key in [k for k, flow in self.flows.items() if self._expired(flow, now)]:
                self.finished.append(self.flows.pop(key))

    def flush(self) -> None:
        """Dong tat ca luong con lai (khi ket thuc chuong trinh / het file pcap)."""
        with self.lock:
            self.finished.extend(self.flows.values())
            self.flows.clear()

    def drain(self) -> list[dict]:
        """Lay cac luong da dong tu lan goi truoc, o dang record (xem features.flow_to_record)."""
        with self.lock:
            finished, self.finished = self.finished, []
        return [flow_to_record(flow) for flow in finished]
