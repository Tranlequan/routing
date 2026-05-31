####################################################
# LSrouter.py
# Name: Trần Lê Quân
# HUID: msv:24022716
#####################################################

import json
from router import Router
from packet import Packet

class LSrouter(Router):
    """Link state routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        
        # --- Cấu trúc dữ liệu cục bộ ---
        self.local_links = {}          # port -> (endpoint_addr, cost)
        self.topology = {}             # Bản đồ mạng: router -> {neighbor: cost}
        self.forwarding_table = {}     # Bảng chuyển tiếp: dst_addr -> port
        self.sequence_numbers = {}     # Quản lý số thứ tự gói tin: router_addr -> max_seq
        self.my_seq = 0                # Số thứ tự gói tin tự tăng của bản thân

    def broadcast_link_state(self):
        """Tạo gói tin Link State Packet (LSP) dạng chuỗi JSON và gửi cho hàng xóm."""
        self.my_seq += 1
        neighbors_data = {endpoint: cost for port, (endpoint, cost) in self.local_links.items()}
        
        # Cập nhật thông tin cục bộ của chính mình vào topo mạng
        self.topology[self.addr] = neighbors_data
        
        lsp_content = {
            "router": self.addr,
            "seq": self.my_seq,
            "neighbors": neighbors_data
        }
        
        # BẮT BUỘC: Chuyển đổi dict sang String JSON để vượt qua kiểm tra của link.py
        lsp_string = json.dumps(lsp_content)
        
        for port in self.local_links.keys():
            pkt = Packet(kind=Packet.ROUTING, src_addr=self.addr, dst_addr=None, content=lsp_string)
            self.send(port, pkt)

    def recompute_routes(self):
        """Thuật toán Dijkstra chuẩn hóa, duyệt theo alphabet để xử lý Tie-breaking."""
        self.forwarding_table = {}
        
        # Thu thập toàn bộ các node đang hiện diện trong hệ thống mạng
        nodes = set(self.topology.keys())
        for neighbors in self.topology.values():
            nodes.update(neighbors.keys())
            
        if self.addr not in nodes:
            return

        # Khởi tạo bảng khoảng cách ban đầu (vô hạn)
        dist = {node: float('inf') for node in nodes}
        dist[self.addr] = 0
        
        # Lưu trạm kế tiếp đầu tiên (Next Hop) từ router này đi ra
        first_hop = {node: None for node in nodes}
        visited = set()

        # Thuật toán tìm kiếm đường đi ngắn nhất Dijkstra
        while len(visited) < len(nodes):
            u = None
            min_d = float('inf')
            
            # Tie-breaking 1: Duyệt theo danh sách node đã xếp alphabet để chọn node có tên nhỏ trước
            for n in sorted(nodes):
                if n not in visited and dist[n] < min_d:
                    min_d = dist[n]
                    u = n
                    
            if u is None or dist[u] == float('inf'):
                break
                
            visited.add(u)
            
            neighbors_dict = self.topology.get(u, {})
            for v in sorted(neighbors_dict.keys()):
                cost = neighbors_dict[v]
                if v in visited:
                    continue
                    
                new_dist = dist[u] + cost
                potential_first_hop = v if u == self.addr else first_hop[u]
                    
                if new_dist < dist[v]:
                    dist[v] = new_dist
                    first_hop[v] = potential_first_hop
                elif new_dist == dist[v]:
                    # Tie-breaking 2: Nếu khoảng cách bằng nhau, chọn đường qua Next Hop nhỏ hơn theo alphabet
                    if first_hop[v] is None or (potential_first_hop is not None and potential_first_hop < first_hop[v]):
                        first_hop[v] = potential_first_hop

        # Đổ dữ liệu từ sơ đồ Next Hop vào bảng Forwarding Table thực tế của router
        for target, f_hop in first_hop.items():
            if target == self.addr or f_hop is None:
                continue
            for port, (endpoint, _) in self.local_links.items():
                if endpoint == f_hop:
                    self.forwarding_table[target] = port
                    break

    def handle_packet(self, port, packet):
        """Xử lý gói tin đi vào cổng."""
        if packet.is_traceroute:
            # Gói tin dữ liệu di chuyển (Traceroute) -> Chuyển tiếp dựa theo bảng định tuyến
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            # Gói tin định tuyến (LSP) -> Đọc từ chuỗi JSON
            content_str = packet.content
            if not isinstance(content_str, str):
                return
                
            try:
                content = json.loads(content_str)
            except:
                return
            
            if isinstance(content, dict):
                origin = content.get("router")
                incoming_seq = content.get("seq")
                neighbors = content.get("neighbors")
                
                if origin is None or incoming_seq is None or neighbors is None:
                    return

                # Chỉ xử lý và cập nhật nếu gói tin này có số thứ tự (Sequence number) mới hơn
                if origin not in self.sequence_numbers or incoming_seq > self.sequence_numbers[origin]:
                    self.sequence_numbers[origin] = incoming_seq
                    self.topology[origin] = neighbors
                    self.recompute_routes()
                    
                    # Flooding: Lan truyền tiếp gói tin này ra tất cả các cổng khác (trừ cổng nhận vào)
                    for out_port in self.local_links.keys():
                        if out_port != port:
                            self.send(out_port, packet)

    def handle_new_link(self, port, endpoint, cost):
        """Xử lý khi có liên kết mới cắm vào."""
        self.local_links[port] = (endpoint, cost)
        self.topology[self.addr] = {e: c for p, (e, c) in self.local_links.items()}
        self.recompute_routes()
        self.broadcast_link_state()

    def handle_remove_link(self, port):
        """Xử lý khi một liên kết bị rút ra."""
        if port in self.local_links:
            del self.local_links[port]
            self.topology[self.addr] = {e: c for p, (e, c) in self.local_links.items()}
            self.recompute_routes()
            self.broadcast_link_state()

    def handle_time(self, time_ms):
        """Xử lý sự kiện thời gian gửi gói tin định kỳ."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.broadcast_link_state()

    def __repr__(self):
        """Chuỗi hiển thị để debug trực quan."""
        return f"LSrouter(addr={self.addr}) | Table: {self.forwarding_table}"