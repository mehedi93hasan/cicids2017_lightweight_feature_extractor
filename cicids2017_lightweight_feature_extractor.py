import customtkinter as ctk
import threading
import pandas as pd
import numpy as np
import os
import time
import sys
from collections import defaultdict, deque
from scapy.all import PcapReader, IP, TCP, UDP
from datetime import datetime

# Try to import psutil, but don't fail if it's not available
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Fix for PyInstaller
try:
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
except:
    pass


class LightweightFlowTracker:
    """
    Extracts 30 Lightweight Features for Adversarial Defense from CICIDS2017 PCAP files.
    Memory-optimized with 100 packets per flow limit (deque).
    Tracks PER-FEATURE computational cost in nanoseconds.
    """
    
    def __init__(self, timeout=120):
        self.flows = {}
        self.timeout = timeout
        self.packet_count = 0
        self.start_time = None
        
        # PER-FEATURE Computational Cost Tracking (Nanoseconds)
        self.feature_costs = defaultdict(float)
        self.feature_counts = defaultdict(int)

    def get_flow_key(self, pkt):
        """Create bidirectional flow key"""
        if IP not in pkt:
            return None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        
        if TCP in pkt:
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif UDP in pkt:
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        else:
            sport, dport = 0, 0
        
        # Bidirectional key
        if (src_ip, sport) < (dst_ip, dport):
            return (src_ip, sport, dst_ip, dport, proto)
        else:
            return (dst_ip, dport, src_ip, sport, proto)

    def process_packet(self, pkt):
        """Process packet and update flow statistics."""
        if self.start_time is None:
            self.start_time = time.time()
            
        flow_key = self.get_flow_key(pkt)
        if flow_key is None:
            return

        timestamp = float(pkt.time)
        pkt_len = len(pkt)
        
        # Initialize flow if new
        if flow_key not in self.flows:
            src_ip, sport, dst_ip, dport, proto = flow_key
            self.flows[flow_key] = {
                # Identifiers
                'src_ip': src_ip, 'sport': sport,
                'dst_ip': dst_ip, 'dport': dport, 
                'proto': proto,
                
                # State
                'start_time': timestamp, 'last_time': timestamp,
                
                # Counters
                'fwd_pkts': 0, 'bwd_pkts': 0,
                'fwd_bytes': 0, 'bwd_bytes': 0,
                
                # Deques with maxlen=100 for Raspberry Pi optimization
                'timestamps': deque(maxlen=100),
                'pkt_lengths': deque(maxlen=100),
                'header_lengths': deque(maxlen=100),
                'fwd_iats': deque(maxlen=100),
                'bwd_iats': deque(maxlen=100),
                'ttl_values': deque(maxlen=100),
                'window_sizes': deque(maxlen=100),
                'active_periods': deque(maxlen=100),
                'idle_periods': deque(maxlen=100),
                
                # TCP Flags
                'syn_count': 0, 'urg_count': 0, 'fin_count': 0,
                
                # Trackers
                'last_fwd_time': None, 'last_bwd_time': None,
                'active_start': timestamp
            }
            self.flows[flow_key]['timestamps'].append(timestamp)

        flow = self.flows[flow_key]
        src_ip, sport, dst_ip, dport, proto = flow_key
        
        # Direction
        direction = 'fwd' if pkt[IP].src == src_ip else 'bwd'
        
        # Update lists
        flow['pkt_lengths'].append(pkt_len)
        flow['timestamps'].append(timestamp)
        
        # Direction-specific updates
        if direction == 'fwd':
            flow['fwd_pkts'] += 1
            flow['fwd_bytes'] += pkt_len
            if flow['last_fwd_time']:
                flow['fwd_iats'].append(timestamp - flow['last_fwd_time'])
            flow['last_fwd_time'] = timestamp
        else:
            flow['bwd_pkts'] += 1
            flow['bwd_bytes'] += pkt_len
            if flow['last_bwd_time']:
                flow['bwd_iats'].append(timestamp - flow['last_bwd_time'])
            flow['last_bwd_time'] = timestamp
        
        # Active/Idle periods
        if flow['last_time']:
            gap = timestamp - flow['last_time']
            if gap > 1.0:  # Idle threshold > 1 second
                flow['idle_periods'].append(gap)
                if flow['active_start']:
                    active = flow['last_time'] - flow['active_start']
                    if active > 0:
                        flow['active_periods'].append(active)
                flow['active_start'] = timestamp
        
        flow['last_time'] = timestamp
        
        # IP Header
        if IP in pkt:
            flow['ttl_values'].append(pkt[IP].ttl)
            ip_header_len = pkt[IP].ihl * 4 if hasattr(pkt[IP], 'ihl') else 20
            flow['header_lengths'].append(ip_header_len)

        # TCP specifics
        if TCP in pkt:
            if pkt[TCP].flags & 0x02: flow['syn_count'] += 1  # SYN
            if pkt[TCP].flags & 0x20: flow['urg_count'] += 1  # URG
            if pkt[TCP].flags & 0x01: flow['fin_count'] += 1  # FIN
            flow['window_sizes'].append(pkt[TCP].window)
            
        self.packet_count += 1

    def measure_feature(self, feature_name, func):
        """Measure execution time for a SINGLE feature in nanoseconds"""
        t0 = time.perf_counter_ns()
        result = func()
        t1 = time.perf_counter_ns()
        self.feature_costs[feature_name] += (t1 - t0)
        self.feature_counts[feature_name] += 1
        return result

    def extract_features(self, flow_key):
        """Extract all 30 lightweight features with PER-FEATURE cost measurement"""
        flow = self.flows[flow_key]
        features = {}
        
        # Convert deques to lists
        ts = list(flow['timestamps'])
        pkt_lens = list(flow['pkt_lengths'])
        fwd_iats = list(flow['fwd_iats'])
        bwd_iats = list(flow['bwd_iats'])
        ttls = list(flow['ttl_values'])
        wins = list(flow['window_sizes'])
        hdrs = list(flow['header_lengths'])
        
        dur = max(flow['last_time'] - flow['start_time'], 1e-6)
        total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
        
        # Identifiers (no cost tracking)
        features['src_ip'] = flow['src_ip']
        features['sport'] = flow['sport']
        features['dst_ip'] = flow['dst_ip']
        features['dport'] = flow['dport']
        features['proto'] = flow['proto']
        
        # === CATEGORY 1: Time Dynamics (The "Rhythm" Defense) ===
        
        # 1. iat_mean
        features['iat_mean'] = self.measure_feature('iat_mean', 
            lambda: np.mean([ts[i+1] - ts[i] for i in range(len(ts)-1)]) if len(ts) > 1 else 0)
        
        # 2. iat_std
        features['iat_std'] = self.measure_feature('iat_std',
            lambda: np.std([ts[i+1] - ts[i] for i in range(len(ts)-1)]) if len(ts) > 1 else 0)
        
        # 3. iat_min
        features['iat_min'] = self.measure_feature('iat_min',
            lambda: np.min([ts[i+1] - ts[i] for i in range(len(ts)-1)]) if len(ts) > 1 else 0)
        
        # 4. iat_max
        features['iat_max'] = self.measure_feature('iat_max',
            lambda: np.max([ts[i+1] - ts[i] for i in range(len(ts)-1)]) if len(ts) > 1 else 0)
        
        # 5. flow_duration
        features['flow_duration'] = self.measure_feature('flow_duration', lambda: dur)
        
        # 6. active_time_mean
        features['active_time_mean'] = self.measure_feature('active_time_mean',
            lambda: np.mean(flow['active_periods']) if flow['active_periods'] else 0)
        
        # 7. idle_time_mean
        features['idle_time_mean'] = self.measure_feature('idle_time_mean',
            lambda: np.mean(flow['idle_periods']) if flow['idle_periods'] else 0)
        
        # 8. fwd_iat_mean
        features['fwd_iat_mean'] = self.measure_feature('fwd_iat_mean',
            lambda: np.mean(fwd_iats) if fwd_iats else 0)
        
        # === CATEGORY 2: Header Invariants (The "Spoofing" Defense) ===
        
        # 9. ttl_mean
        features['ttl_mean'] = self.measure_feature('ttl_mean',
            lambda: np.mean(ttls) if ttls else 0)
        
        # 10. ttl_std
        features['ttl_std'] = self.measure_feature('ttl_std',
            lambda: np.std(ttls) if ttls else 0)
        
        # 11. win_size_mean
        features['win_size_mean'] = self.measure_feature('win_size_mean',
            lambda: np.mean(wins) if wins else 0)
        
        # 12. win_size_std
        features['win_size_std'] = self.measure_feature('win_size_std',
            lambda: np.std(wins) if wins else 0)
        
        # 13. syn_count
        features['syn_count'] = self.measure_feature('syn_count',
            lambda: flow['syn_count'])
        
        # 14. urg_count
        features['urg_count'] = self.measure_feature('urg_count',
            lambda: flow['urg_count'])
        
        # 15. fin_ratio
        features['fin_ratio'] = self.measure_feature('fin_ratio',
            lambda: flow['fin_count'] / total_pkts if total_pkts > 0 else 0)
        
        # 16. header_len_mean
        features['header_len_mean'] = self.measure_feature('header_len_mean',
            lambda: np.mean(hdrs) if hdrs else 0)
        
        # === CATEGORY 3: Traffic Symmetry (The "Interaction" Defense) ===
        
        # 17. pkt_ratio
        features['pkt_ratio'] = self.measure_feature('pkt_ratio',
            lambda: flow['fwd_pkts'] / (flow['bwd_pkts'] + 1))
        
        # 18. byte_ratio
        features['byte_ratio'] = self.measure_feature('byte_ratio',
            lambda: flow['fwd_bytes'] / (total_bytes + 1))
        
        # 19. size_asymmetry
        features['size_asymmetry'] = self.measure_feature('size_asymmetry',
            lambda: abs(flow['fwd_bytes'] - flow['bwd_bytes']) / (total_bytes + 1))
        
        # 20. response_rate
        features['response_rate'] = self.measure_feature('response_rate',
            lambda: flow['bwd_pkts'] / dur)
        
        # === CATEGORY 4: Payload Dynamics (The "Padding" Defense) ===
        
        # 21. pkt_len_mean
        features['pkt_len_mean'] = self.measure_feature('pkt_len_mean',
            lambda: np.mean(pkt_lens) if pkt_lens else 0)
        
        # 22. pkt_len_std
        features['pkt_len_std'] = self.measure_feature('pkt_len_std',
            lambda: np.std(pkt_lens) if pkt_lens else 0)
        
        # 23. pkt_len_var_coeff
        mean_len = np.mean(pkt_lens) if pkt_lens else 0
        std_len = np.std(pkt_lens) if pkt_lens else 0
        features['pkt_len_var_coeff'] = self.measure_feature('pkt_len_var_coeff',
            lambda: std_len / (mean_len + 1e-6))
        
        # 24. small_pkt_ratio
        features['small_pkt_ratio'] = self.measure_feature('small_pkt_ratio',
            lambda: sum(1 for x in pkt_lens if x < 64) / len(pkt_lens) if pkt_lens else 0)
        
        # 25. large_pkt_ratio
        features['large_pkt_ratio'] = self.measure_feature('large_pkt_ratio',
            lambda: sum(1 for x in pkt_lens if x > 1200) / len(pkt_lens) if pkt_lens else 0)
        
        # 26. header_payload_ratio
        features['header_payload_ratio'] = self.measure_feature('header_payload_ratio',
            lambda: sum(hdrs) / (total_bytes - sum(hdrs) + 1))
        
        # === CATEGORY 5: Velocity (The "Load" Defense) ===
        
        # 27. flow_pps
        features['flow_pps'] = self.measure_feature('flow_pps',
            lambda: total_pkts / dur)
        
        # 28. flow_bps
        features['flow_bps'] = self.measure_feature('flow_bps',
            lambda: total_bytes * 8 / dur)
        
        # 29. fwd_bps
        features['fwd_bps'] = self.measure_feature('fwd_bps',
            lambda: flow['fwd_bytes'] * 8 / dur)
        
        # 30. bwd_pps
        features['bwd_pps'] = self.measure_feature('bwd_pps',
            lambda: flow['bwd_pkts'] / dur)
        
        return features

    def get_feature_costs(self):
        """Return average cost per feature in microseconds"""
        avg_costs = {}
        for feature_name, total_ns in self.feature_costs.items():
            count = self.feature_counts[feature_name]
            if count > 0:
                avg_costs[feature_name] = (total_ns / count) / 1000.0  # ns to μs
        return avg_costs

    def get_all_features(self):
        return [self.extract_features(fk) for fk in self.flows.keys()]


class PacketToolApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CICIDS2017 Lightweight Feature Extractor")
        self.geometry("950x800")
        
        # Header
        self.lbl_title = ctk.CTkLabel(
            self, 
            text="CICIDS2017 - 30 Lightweight Features Extractor", 
            font=("Arial", 20, "bold")
        )
        self.lbl_title.pack(pady=20)

        # Subtitle
        self.lbl_subtitle = ctk.CTkLabel(
            self, 
            text="Adversarial Defense Feature Set with Per-Feature Cost Analysis", 
            font=("Arial", 12),
            text_color="gray"
        )
        self.lbl_subtitle.pack()

        # File Input Frame
        self.frame_files = ctk.CTkFrame(self)
        self.frame_files.pack(fill="x", padx=20, pady=15)
        
        # PCAP Input
        ctk.CTkLabel(self.frame_files, text="PCAP File:", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        self.entry_pcap = ctk.CTkEntry(
            self.frame_files, 
            placeholder_text="Select CICIDS2017 PCAP file...", 
            width=600
        )
        self.entry_pcap.grid(row=1, column=0, padx=10, pady=5)
        self.btn_pcap = ctk.CTkButton(
            self.frame_files, 
            text="Browse", 
            command=lambda: self.browse_file(self.entry_pcap, "pcap"),
            width=100
        )
        self.btn_pcap.grid(row=1, column=1, padx=10, pady=5)

        # Progress Bar
        self.progress = ctk.CTkProgressBar(self, width=830)
        self.progress.pack(padx=20, pady=10, fill="x")
        self.progress.set(0)
        
        self.progress_label = ctk.CTkLabel(self, text="Ready to process", font=("Arial", 11))
        self.progress_label.pack()

        # Process Button
        self.btn_process = ctk.CTkButton(
            self, 
            text="EXTRACT 30 LIGHTWEIGHT FEATURES", 
            fg_color="#2CC985", 
            hover_color="#229C68",
            text_color="black", 
            height=50, 
            font=("Arial", 14, "bold"),
            command=self.start_processing
        )
        self.btn_process.pack(padx=20, pady=15, fill="x")

        # Log Window
        self.textbox = ctk.CTkTextbox(self, height=450, font=("Consolas", 10))
        self.textbox.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Welcome Message
        self.log("="*90)
        self.log("CICIDS2017 Lightweight Feature Extractor for Adversarial Defense")
        self.log("="*90)
        self.log("\n30 Lightweight Features Organized in 5 Categories:")
        self.log("  1. Time Dynamics (8 features)    - The 'Rhythm' Defense")
        self.log("  2. Header Invariants (8 features) - The 'Spoofing' Defense")
        self.log("  3. Traffic Symmetry (4 features)  - The 'Interaction' Defense")
        self.log("  4. Payload Dynamics (6 features)  - The 'Padding' Defense")
        self.log("  5. Velocity (4 features)          - The 'Load' Defense")
        self.log("\nOptimizations:")
        self.log("  • 100 packets max per flow (Memory efficient for Raspberry Pi)")
        self.log("  • Per-feature computational cost tracking (nanosecond precision)")
        self.log("  • Designed for real-time adversarial attack detection")
        self.log("\nOutputs:")
        self.log("  • CSV 1: Complete feature dataset with all 30 features")
        self.log("  • CSV 2: Individual feature computational costs (not grouped)")
        self.log("\nReady. Please select a CICIDS2017 PCAP file to begin.")
        self.log("="*90 + "\n")

    def log(self, msg):
        self.textbox.insert("end", msg + "\n")
        self.textbox.see("end")
        self.update_idletasks()
    
    def update_progress(self, value, message=""):
        self.progress.set(value)
        if message:
            self.progress_label.configure(text=message)
        self.update_idletasks()

    def browse_file(self, entry, ftype):
        filetypes = [("PCAP Files", "*.pcap"), ("PCAPNG", "*.pcapng"), ("All Files", "*.*")]
            
        filename = ctk.filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            entry.delete(0, "end")
            entry.insert(0, filename)
            try:
                file_size = os.path.getsize(filename) / 1024 / 1024
                self.log(f"✓ Selected: {os.path.basename(filename)} ({file_size:.2f} MB)")
            except:
                self.log(f"✓ Selected: {os.path.basename(filename)}")

    def start_processing(self):
        pcap_path = self.entry_pcap.get()
        
        if not pcap_path:
            self.log("❌ Error: Please select a PCAP file.")
            return
            
        if not os.path.exists(pcap_path):
            self.log(f"❌ Error: PCAP file not found: {pcap_path}")
            return
        
        self.btn_process.configure(state="disabled", text="Processing...")
        self.update_progress(0, "Initializing...")
        threading.Thread(target=self.run_logic, args=(pcap_path,), daemon=True).start()

    def run_logic(self, pcap_path):
        try:
            self.log("\n" + "="*90)
            self.log("STARTING LIGHTWEIGHT FEATURE EXTRACTION")
            self.log("="*90 + "\n")
            
            tracker = LightweightFlowTracker()
            
            # Process PCAP
            self.update_progress(0.05, "Reading PCAP file...")
            self.log("[1/3] Processing PCAP and Extracting Features...")
            self.log(f"File: {os.path.basename(pcap_path)}\n")
            
            count = 0
            
            for pkt in PcapReader(pcap_path):
                tracker.process_packet(pkt)
                count += 1
                if count % 10000 == 0:
                    progress = 0.05 + (0.7 * min(count / 100000, 1.0))
                    self.update_progress(progress, f"Processed {count:,} packets...")
                    self.log(f"  → Processed {count:,} packets...")
            
            self.log(f"\n✓ Finished reading PCAP")
            self.log(f"✓ Total packets: {count:,}")
            self.log(f"✓ Total flows: {len(tracker.flows):,}\n")

            # Extract Features
            self.update_progress(0.8, "Extracting features from flows...")
            self.log("[2/3] Extracting 30 Lightweight Features from Flows...")
            
            feature_list = tracker.get_all_features()
            df = pd.DataFrame(feature_list)
            
            self.log(f"✓ Extracted features from {len(df):,} flows\n")

            # Save Outputs
            self.update_progress(0.9, "Generating output files...")
            self.log("[3/3] Generating Output Files...")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save Feature Dataset
            dataset_file = f"CICIDS2017_30Features_{timestamp}.csv"
            df.to_csv(dataset_file, index=False)
            self.log(f"✓ Saved Feature Dataset: {dataset_file}")
            self.log(f"  → Total Flows: {len(df):,}")
            self.log(f"  → Features: 30 (+ 5 identifiers)")
            self.log(f"  → File Size: {os.path.getsize(dataset_file) / 1024:.2f} KB")

            # Save Per-Feature Computational Cost Analysis
            costs = tracker.get_feature_costs()
            
            cost_data = []
            self.log(f"\n" + "="*90)
            self.log("PER-FEATURE COMPUTATIONAL COST ANALYSIS")
            self.log("="*90)
            
            # Define feature categories
            categories = {
                'iat_mean': 'Time Dynamics',
                'iat_std': 'Time Dynamics',
                'iat_min': 'Time Dynamics',
                'iat_max': 'Time Dynamics',
                'flow_duration': 'Time Dynamics',
                'active_time_mean': 'Time Dynamics',
                'idle_time_mean': 'Time Dynamics',
                'fwd_iat_mean': 'Time Dynamics',
                'ttl_mean': 'Header Invariants',
                'ttl_std': 'Header Invariants',
                'win_size_mean': 'Header Invariants',
                'win_size_std': 'Header Invariants',
                'syn_count': 'Header Invariants',
                'urg_count': 'Header Invariants',
                'fin_ratio': 'Header Invariants',
                'header_len_mean': 'Header Invariants',
                'pkt_ratio': 'Traffic Symmetry',
                'byte_ratio': 'Traffic Symmetry',
                'size_asymmetry': 'Traffic Symmetry',
                'response_rate': 'Traffic Symmetry',
                'pkt_len_mean': 'Payload Dynamics',
                'pkt_len_std': 'Payload Dynamics',
                'pkt_len_var_coeff': 'Payload Dynamics',
                'small_pkt_ratio': 'Payload Dynamics',
                'large_pkt_ratio': 'Payload Dynamics',
                'header_payload_ratio': 'Payload Dynamics',
                'flow_pps': 'Velocity',
                'flow_bps': 'Velocity',
                'fwd_bps': 'Velocity',
                'bwd_pps': 'Velocity'
            }
            
            # Sort by cost
            sorted_costs = sorted(costs.items(), key=lambda x: x[1], reverse=True)
            
            self.log(f"\nTop 10 Most Computationally Expensive Features:\n")
            for i, (feature_name, cost_us) in enumerate(sorted_costs[:10], 1):
                category = categories.get(feature_name, 'Unknown')
                
                if cost_us < 1:
                    status = 'EXCELLENT'
                    complexity = 'O(1)'
                elif cost_us < 10:
                    status = 'GOOD'
                    complexity = 'O(1)'
                elif cost_us < 50:
                    status = 'ACCEPTABLE'
                    complexity = 'O(n)'
                else:
                    status = 'CAUTION'
                    complexity = 'O(n)'
                
                self.log(f"{i:2d}. {feature_name:25s} {cost_us:10.6f} μs  [{status:10s}] ({category})")
            
            self.log(f"\n... and {len(costs)-10} more features\n")
            
            # Create full cost table
            for feature_name, cost_us in costs.items():
                category = categories.get(feature_name, 'Unknown')
                
                if cost_us < 1:
                    status = 'EXCELLENT'
                    complexity = 'O(1)'
                elif cost_us < 10:
                    status = 'GOOD'
                    complexity = 'O(1)'
                elif cost_us < 50:
                    status = 'ACCEPTABLE'
                    complexity = 'O(n)'
                else:
                    status = 'CAUTION'
                    complexity = 'O(n)'
                
                cost_data.append({
                    'Feature_Name': feature_name,
                    'Category': category,
                    'Avg_Cost_Microseconds': round(cost_us, 6),
                    'Total_Executions': tracker.feature_counts[feature_name],
                    'Raspberry_Pi_Status': status,
                    'Estimated_Complexity': complexity
                })
            
            cost_file = f"Feature_Costs_{timestamp}.csv"
            df_cost = pd.DataFrame(cost_data)
            # Sort by category, then by cost
            df_cost = df_cost.sort_values(['Category', 'Avg_Cost_Microseconds'], ascending=[True, False])
            df_cost.to_csv(cost_file, index=False)
            self.log(f"✓ Saved Per-Feature Cost Report: {cost_file}")
            self.log(f"  → Total Features Analyzed: {len(cost_data)}")
            self.log(f"  → File Size: {os.path.getsize(cost_file) / 1024:.2f} KB")
            
            # Cost Statistics
            total_cost = sum(costs.values())
            avg_cost = np.mean(list(costs.values()))
            
            self.log(f"\nCost Statistics:")
            self.log(f"  Total Cost (all 30 features):  {total_cost:.6f} μs per flow")
            self.log(f"  Average Cost per feature:      {avg_cost:.6f} μs")
            self.log(f"  Minimum Cost:                  {min(costs.values()):.6f} μs")
            self.log(f"  Maximum Cost:                  {max(costs.values()):.6f} μs")
            
            # Category-wise summary
            self.log(f"\nCategory-wise Cost Summary:")
            category_costs = defaultdict(list)
            for fname, cost in costs.items():
                cat = categories.get(fname, 'Unknown')
                category_costs[cat].append(cost)
            
            for cat in ['Time Dynamics', 'Header Invariants', 'Traffic Symmetry', 'Payload Dynamics', 'Velocity']:
                if cat in category_costs:
                    cat_avg = np.mean(category_costs[cat])
                    cat_total = sum(category_costs[cat])
                    self.log(f"  {cat:25s}: {cat_avg:10.6f} μs avg  ({cat_total:10.6f} μs total)")
            
            # Raspberry Pi Analysis
            self.log(f"\n" + "="*90)
            self.log("RASPBERRY PI FEASIBILITY ANALYSIS")
            self.log("="*90)
            
            excellent = sum(1 for c in costs.values() if c < 1)
            good = sum(1 for c in costs.values() if 1 <= c < 10)
            acceptable = sum(1 for c in costs.values() if 10 <= c < 50)
            caution = sum(1 for c in costs.values() if c >= 50)
            
            self.log(f"\nFeature Performance Distribution:")
            self.log(f"  EXCELLENT (< 1 μs):       {excellent} features ({excellent/30*100:.1f}%)")
            self.log(f"  GOOD (1-10 μs):           {good} features ({good/30*100:.1f}%)")
            self.log(f"  ACCEPTABLE (10-50 μs):    {acceptable} features ({acceptable/30*100:.1f}%)")
            self.log(f"  CAUTION (>50 μs):         {caution} features ({caution/30*100:.1f}%)")
            
            if caution == 0 and acceptable <= 5:
                verdict = "✓ HIGHLY SUITABLE for Raspberry Pi deployment"
            elif caution <= 2:
                verdict = "✓ SUITABLE for Raspberry Pi deployment"
            else:
                verdict = "⚠ May require optimization for Raspberry Pi"
            
            self.log(f"\nVerdict: {verdict}")
            
            # Final Summary
            processing_time = time.time() - tracker.start_time
            
            self.log("\n" + "="*90)
            self.log("EXTRACTION SUMMARY")
            self.log("="*90)
            self.log(f"PCAP File:                   {os.path.basename(pcap_path)}")
            self.log(f"Total Packets Processed:     {tracker.packet_count:,}")
            self.log(f"Total Flows Extracted:       {len(df):,}")
            self.log(f"Features per Flow:           30 lightweight features")
            self.log(f"Memory Limit per Flow:       100 packets (deque optimization)")
            self.log(f"Processing Time:             {processing_time:.2f} seconds")
            self.log(f"Throughput:                  {tracker.packet_count/processing_time:.0f} packets/second")
            if PSUTIL_AVAILABLE:
                try:
                    memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
                    self.log(f"Memory Usage:                {memory_mb:.2f} MB")
                except:
                    pass
            self.log(f"\nOutput Files:")
            self.log(f"  1. {dataset_file}")
            self.log(f"     → Complete feature dataset for ML training")
            self.log(f"  2. {cost_file}")
            self.log(f"     → Per-feature computational costs for optimization")
            
            self.log("\n" + "="*90)
            self.log("✓ FEATURE EXTRACTION COMPLETED SUCCESSFULLY")
            self.log("="*90)
            self.log("\nNext Steps:")
            self.log("  • Use CSV 1 for training adversarial-robust ML models")
            self.log("  • Analyze CSV 2 to identify bottlenecks for Raspberry Pi deployment")
            self.log("  • Combine multiple PCAP files for comprehensive dataset creation")
            self.log("="*90 + "\n")
            
            self.update_progress(1.0, "✓ Complete!")
            
        except Exception as e:
            self.log(f"\n❌ Critical Error: {e}")
            import traceback
            self.log(traceback.format_exc())
            
        finally:
            self.btn_process.configure(state="normal", text="EXTRACT 30 LIGHTWEIGHT FEATURES")


if __name__ == "__main__":
    app = PacketToolApp()
    app.mainloop()
