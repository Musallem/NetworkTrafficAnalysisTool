import os
import sys
import subprocess
import nfstream
from nfstream import NFStreamer
import matplotlib.pyplot as plt
import tempfile
import shutil

def get_interfaces():
    interfaces = subprocess.check_output("ip -brief link show | awk '{print $1}'", shell=True).decode("utf-8").strip().split("\n")
    return interfaces

def capture_traffic(interface):
    pcap_temp = tempfile.NamedTemporaryFile(delete=False)
    pcap_temp.close()
    cmd = f"sudo tcpdump -i {interface} -w {pcap_temp.name}"
    process = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
    return process, pcap_temp.name

def stop_capture(process):
    os.killpg(os.getpgid(process.pid), 9)
              
def analyze_pcap(pcap_file):
    streamer = NFStreamer(source=pcap_file)
    total_bytes = 0
    for flow in streamer:
        total_bytes += flow.bidirectional_bytes
    return total_bytes

def plot_analysis(total_bytes):
    plt.bar(['Traffic'], [total_bytes], color='blue')
    plt.ylabel('Total Bytes')
    plt.title('Network Traffic Analysis')
    plt.show()

def main():
    interfaces = get_interfaces()
    print("\nAvailable network interfaces:")
    for index, interface in enumerate(interfaces):
        print(f"{index + 1}. {interface}")
    
    choice = int(input("\nSelect an interface to capture traffic: ")) - 1
    if choice >= len(interfaces):
        print("Invalid selection.")
        sys.exit(1)

    selected_interface = interfaces[choice]
    print(f"\nCapturing traffic on {selected_interface}...")

    process, pcap_file = capture_traffic(selected_interface)
    
    try:
        while True:
            action = input("\nType 'stop' to stop capturing traffic, 'start' to resume, 'analyze' to analyze captured traffic, or 'exit' to quit: ").lower()
            if action == "stop":
                print("Stopping traffic capture...")
                stop_capture(process)
            elif action == "start":
                print("Resuming traffic capture...")
                process, _ = capture_traffic(selected_interface)
            elif action == "analyze":
                stop_capture(process)
                total_bytes = analyze_pcap(pcap_file)
                print(f"Total bytes captured: {total_bytes}")
                plot_analysis(total_bytes)
            elif action == "exit":
                print("Exiting...")
                break
            else:
                print("Invalid command.")
    finally:
        stop_capture(process)
        os.remove(pcap_file)

if __name__ == "__main__":
    main()
