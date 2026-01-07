CICIDS2017 Lightweight Feature Extractor
Extract 30 adversarial-robust lightweight features from CICIDS2017 PCAP files with per-feature computational cost analysis.

🎯 Overview
This tool extracts 30 carefully selected lightweight features from network traffic PCAP files, specifically designed for adversarial attack defense in Network Intrusion Detection Systems (NIDS).
Each feature is computationally tracked at nanosecond precision to ensure real-time feasibility on Raspberry Pi devices.

✨ Features
30 Lightweight Features (5 Categories)
1️⃣ Time Dynamics (8 features) - The "Rhythm" Defense

iat_mean - Mean Inter-Arrival Time
iat_std - IAT Standard Deviation (Jitter)
iat_min - Minimum IAT (Detects "Machine Speed")
iat_max - Maximum IAT (Detects "Keep-Alive" evasion)
flow_duration - Total flow duration
active_time_mean - Average active time
idle_time_mean - Average idle time
fwd_iat_mean - Forward IAT mean

2️⃣ Header Invariants (8 features) - The "Spoofing" Defense

ttl_mean - Average Time-To-Live
ttl_std - TTL variance (Detects IP spoofing)
win_size_mean - Mean TCP Window Size
win_size_std - Window size variance
syn_count - SYN flag count (SYN Flood detection)
urg_count - URG flag count
fin_ratio - FIN packet ratio
header_len_mean - Average header length

3️⃣ Traffic Symmetry (4 features) - The "Interaction" Defense

pkt_ratio - Forward/Backward packet ratio
byte_ratio - Forward/Backward byte ratio
size_asymmetry - Size asymmetry metric
response_rate - Response packet rate

4️⃣ Payload Dynamics (6 features) - The "Padding" Defense

pkt_len_mean - Average packet length
pkt_len_std - Packet length std dev
pkt_len_var_coeff - Coefficient of variation
small_pkt_ratio - Ratio of packets < 64 bytes
large_pkt_ratio - Ratio of packets > 1200 bytes
header_payload_ratio - Header/Payload ratio

5️⃣ Velocity (4 features) - The "Load" Defense

flow_pps - Packets per second
flow_bps - Bytes per second
fwd_bps - Forward bytes per second
bwd_pps - Backward packets per second


🚀 Quick Start
Option 1: Download Pre-built EXE (Windows)

Go to Actions tab in GitHub
Click on latest successful workflow run
Download CICIDS2017-Feature-Extractor artifact
Extract and run CICIDS2017_Feature_Extractor.exe

Option 2: Run from Source
bash# Clone the repository
git clone <your-repo-url>
cd <your-repo>

# Install dependencies
pip install -r requirements.txt

# Run the application
python cicids2017_lightweight_feature_extractor.py

📊 Output Files
CSV 1: Feature Dataset
Filename: CICIDS2017_30Features_YYYYMMDD_HHMMSS.csv
Contains:

5 Flow identifiers (src_ip, sport, dst_ip, dport, proto)
30 Lightweight features
One row per flow

Example:
src_ip,sport,dst_ip,dport,proto,iat_mean,iat_std,...,bwd_pps
192.168.1.100,443,10.0.0.5,12345,6,0.025,0.012,...,15.3
CSV 2: Per-Feature Computational Costs
Filename: Feature_Costs_YYYYMMDD_HHMMSS.csv
Contains:

Feature_Name - Name of each feature
Category - Which defense category
Avg_Cost_Microseconds - Average computational cost (μs)
Total_Executions - Number of times calculated
Raspberry_Pi_Status - Performance rating (EXCELLENT/GOOD/ACCEPTABLE/CAUTION)
Estimated_Complexity - Algorithmic complexity (O(1) or O(n))

Example:
Feature_Name,Category,Avg_Cost_Microseconds,Total_Executions,Raspberry_Pi_Status,Estimated_Complexity
iat_mean,Time Dynamics,2.345,1523,GOOD,O(n)
flow_duration,Time Dynamics,0.123,1523,EXCELLENT,O(1)

🔧 Usage

Launch the application
Click "Browse" and select your CICIDS2017 PCAP file
Click "EXTRACT 30 LIGHTWEIGHT FEATURES"
Wait for processing - Progress bar shows real-time status
Check output files in the same directory as the application


🧠 Memory Optimization

100 packets max per flow using Python deque(maxlen=100)
Automatic memory cleanup
Suitable for Raspberry Pi 3B+ and Raspberry Pi 4 deployment


⚡ Performance
Typical performance on a modern laptop:

Processing Speed: ~50,000-100,000 packets/second
Memory Usage: ~100-200 MB for typical CICIDS2017 files
Per-Feature Cost: 0.1-10 microseconds per feature


🎓 Research Context
These 30 features are specifically designed for adversarial attack defense in NIDS:

Hard to manipulate - Features like TTL variance and IAT jitter are difficult for attackers to fake
Computationally lightweight - All features execute in < 50 microseconds
Adversarially robust - Designed to detect both traditional and adversarial attacks


📁 Project Structure
.
├── cicids2017_lightweight_feature_extractor.py  # Main application
├── requirements.txt                             # Python dependencies
├── .github/
│   └── workflows/
│       └── build.yml                           # GitHub Actions for EXE build
└── README.md                                   # This file

🛠️ Building Standalone EXE
The GitHub Actions workflow automatically builds a Windows EXE on every push to main.
Manual build:
bashpip install pyinstaller
pyinstaller --onefile --console --name "CICIDS2017_Feature_Extractor" --collect-all customtkinter --hidden-import=PIL._tkinter_finder cicids2017_lightweight_feature_extractor.py
The EXE will be in the dist/ folder.

🐛 Troubleshooting
EXE doesn't open

Make sure you downloaded the artifact from GitHub Actions
Extract the ZIP file completely
Right-click the EXE → Properties → Unblock (if from internet)
Try running as Administrator

"Missing DLL" errors

Download and install Visual C++ Redistributable

Processing is slow

PCAP files larger than 1GB may take several minutes
Close other applications to free up memory
Consider splitting large PCAP files


📚 Citation
If you use this tool in your research, please cite:
@software{cicids2017_lightweight_extractor,
  title={CICIDS2017 Lightweight Feature Extractor for Adversarial Defense},
  author={Your Name},
  year={2025},
  url={https://github.com/your-repo}
}

📄 License
This project is licensed under the MIT License.

🤝 Contributing
Contributions are welcome! Please:

Fork the repository
Create a feature branch
Submit a pull request


📧 Contact
For questions or support, please open an issue on GitHub.

🙏 Acknowledgments

CICIDS2017 Dataset - Canadian Institute for Cybersecurity
Scapy - Packet manipulation library
CustomTkinter - Modern GUI framework
