####################################################
# DVrouter.py
# Name: Trần Lê Quân
# HUID: msv:24022716
#####################################################

import json
from router import Router
from packet import Packet

class DVrouter(Router):
    """Distance Vector routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        
        # --- Cấu trúc dữ liệu cục bộ ---
        self.local_links = {}          # port -> (neighbor_addr, cost)
        self.distance_vectors = {}     # neighbor -> {dst: cost} (Bảng lưu các vector hàng xóm gửi)
        self.current_costs = {}        # dst -> cost (Khoảng cách ngắn nhất hiện tại của bản thân)
        self.forwarding_table = {}     # dst -> port (Bảng chuyển tiếp thực tế)
        
        # Bản thân đi tới chính mình luôn có chi phí bằng 0
        self.current_costs[self.addr] = 0

    def send_distance_vector(self):
        """Gửi Vector khoảng cách của mình cho tất cả hàng xóm (Áp dụng Poison Reverse)."""
        for port, (neighbor, _) in self.local_links.items():
            poisoned_vector = {}
            
            for dst, cost in self.current_costs.items():
                # Poison Reverse: Nếu trạm kế tiếp để tới 'dst' chính là 'neighbor' này,
                # ta báo một chi phí cực lớn (99999) để chặn đứng vòng lặp định tuyến.
                if dst != self.addr and self.forwarding_table.get(dst) == port:
                    poisoned_vector[dst] = 99999
                else:
                    poisoned_vector[dst] = cost
            
            # Ép kiểu dữ liệu sang chuỗi JSON trước khi truyền đi qua link.py
            pkt = Packet(kind=Packet.ROUTING, src_addr=self.addr, dst_addr=None, content=json.dumps(poisoned_vector))
            self.send(port, pkt)

    def recompute_routes(self):
        """Thuật toán Bellman-Ford cập nhật bảng định tuyến và xử lý Tie-breaking."""
        old_costs = dict(self.current_costs)
        
        # Thu thập tất cả các điểm đích khả thi trong mạng
        all_dsts = set()
        for port, (neighbor, _) in self.local_links.items():
            all_dsts.add(neighbor)
        for neighbor, vec in self.distance_vectors.items():
            all_dsts.update(vec.keys())
            
        # Khởi tạo lại bảng chi phí cơ sở
        self.current_costs = {self.addr: 0}
        self.forwarding_table = {}
        
        # Tính toán đường đi ngắn nhất đến từng đích
        for dst in all_dsts:
            if dst == self.addr:
                continue
                
            min_cost = float('inf')
            best_port = None
            best_neighbor = None
            
            for port, (neighbor, link_cost) in self.local_links.items():
                # Trường hợp 1: Đường trực tiếp đến hàng xóm liền kề
                if dst == neighbor:
                    cost_via_neighbor = link_cost
                # Trường hợp 2: Đường đi vòng qua hàng xóm để tới đích
                elif neighbor in self.distance_vectors and dst in self.distance_vectors[neighbor]:
                    cost_via_neighbor = link_cost + self.distance_vectors[neighbor][dst]
                else:
                    continue
                
                # Áp dụng quy tắc Tie-breaking: Ưu tiên chi phí nhỏ hơn; 
                # Nếu bằng nhau, chọn node hàng xóm có thứ tự alphabet nhỏ hơn.
                if cost_via_neighbor < min_cost:
                    min_cost = cost_via_neighbor
                    best_port = port
                    best_neighbor = neighbor
                elif cost_via_neighbor == min_cost:
                    if best_neighbor is None or neighbor < best_neighbor:
                        min_cost = cost_via_neighbor
                        best_port = port
                        best_neighbor = neighbor
            
            # Chỉ ghi nhận các tuyến đường hợp lệ (không bị nhiễm độc vô hạn)
            if min_cost < 99999:
                self.current_costs[dst] = min_cost
                self.forwarding_table[dst] = best_port

        # Nếu sơ đồ mạng có biến động về chi phí, lập tức kích hoạt Triggered Update gửi đi luôn
        if self.current_costs != old_costs:
            self.send_distance_vector()

    def handle_packet(self, port, packet):
        """Xử lý gói tin nhận vào."""
        if packet.is_traceroute:
            # Gói tin dữ liệu di chuyển -> Chuyển tiếp theo bảng định tuyến hiện hành
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            # Gói tin định tuyến -> Giải mã chuỗi JSON nhận từ hàng xóm
            try:
                vector = json.loads(packet.content)
            except:
                return
                
            if isinstance(vector, dict):
                neighbor = packet.src_addr
                self.distance_vectors[neighbor] = vector
                self.recompute_routes()

    def handle_new_link(self, port, endpoint, cost):
        """Xử lý khi phát hiện liên kết mới thiết lập."""
        self.local_links[port] = (endpoint, cost)
        self.recompute_routes()

    def handle_remove_link(self, port):
        """Xử lý khi một liên kết bị đứt/rút dây."""
        if port in self.local_links:
            neighbor, _ = self.local_links[port]
            del self.local_links[port]
            # Xóa bỏ vector cũ của hàng xóm này vì liên kết không còn tồn tại
            if neighbor in self.distance_vectors:
                del self.distance_vectors[neighbor]
            self.recompute_routes()

    def handle_time(self, time_ms):
        """Gửi cập nhật định kỳ (Heartbeat) theo thời gian của hệ thống."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.send_distance_vector()

    def __repr__(self):
        """Chuỗi hiển thị phục vụ quá trình in kiểm thử trực quan."""
        return f"DVrouter(addr={self.addr}) | Table: {self.forwarding_table}"