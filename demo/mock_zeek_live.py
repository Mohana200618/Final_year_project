import os
import sys
import json
import time
import random

# Base directory
DEMO_DIR = os.path.dirname(os.path.abspath(__file__))
LIVE_LOG_PATH = os.path.join(DEMO_DIR, 'live_conn.log')
SCENARIOS_PATH = os.path.join(DEMO_DIR, 'scenarios.json')

def load_scenarios():
    if not os.path.exists(SCENARIOS_PATH):
        print(f"Error: {SCENARIOS_PATH} not found.")
        sys.exit(1)
    with open(SCENARIOS_PATH, 'r') as f:
        return json.load(f)

def run_mock_live():
    scenarios = load_scenarios()
    
    # Initialize file with Zeek header if it doesn't exist or is empty
    header_line = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
    
    is_new = not os.path.exists(LIVE_LOG_PATH) or os.path.getsize(LIVE_LOG_PATH) == 0
    with open(LIVE_LOG_PATH, 'a', encoding='utf-8') as f:
        if is_new:
            f.write(header_line)
            f.flush()
    
    print("=" * 60)
    print(" ThreatScope — Mock Live Zeek Writer")
    print("=" * 60)
    print(f" Writing to: {LIVE_LOG_PATH}")
    print(" (Press Ctrl+C to stop)")
    print("=" * 60)

    try:
        idx = 0
        while True:
            # Pick the next scenario (looping)
            s = scenarios[idx % len(scenarios)]
            
            # Construct a raw Zeek TSV line from the scenario feature data
            ts = f"{time.time():.6f}"
            uid = f"C{''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=17))}"
            orig_h = s.get('source_ip', '192.168.1.100')
            orig_p = "12345"
            resp_h = s.get('dest_ip', '10.0.0.5')
            resp_p = str(s.get('Destination Port', 80))
            proto = "tcp"
            service = "-"
            
            duration_s = s.get('Flow Duration', 0) / 1_000_000.0  # US to S
            
            # Packets
            orig_pkts = s.get('Total Fwd Packets', 0)
            resp_pkts = s.get('Total Backward Packets', 0)
            
            # We don't have separate bytes in the 6-feature schema, just total. 
            # So let's split the total based on packets for the mock.
            total_bytes = s.get('Flow Bytes/s', 0) * duration_s if duration_s > 0 else 0
            
            if (orig_pkts + resp_pkts) > 0:
                orig_bytes = int(total_bytes * (orig_pkts / (orig_pkts + resp_pkts)))
                resp_bytes = int(total_bytes * (resp_pkts / (orig_pkts + resp_pkts)))
            else:
                orig_bytes, resp_bytes = 0, 0
                
            line = f"{ts}\t{uid}\t{orig_h}\t{orig_p}\t{resp_h}\t{resp_p}\t{proto}\t{service}\t{duration_s:.6f}\t{orig_bytes}\t{resp_bytes}\tSF\t-\t-\t0\tD\t{orig_pkts}\t{orig_bytes}\t{resp_pkts}\t{resp_bytes}\t-\n"
            
            with open(LIVE_LOG_PATH, 'a', encoding='utf-8') as f:
                f.write(line)
                f.flush()
                
            print(f"[{time.strftime('%H:%M:%S')}] Wrote flow: {s.get('name', 'Unknown')} ({orig_h} -> {resp_h})")
            
            idx += 1
            time.sleep(s.get('delay_seconds', 2.0))
            
    except KeyboardInterrupt:
        print("\nStopping mock live writer.")

if __name__ == "__main__":
    run_mock_live()
