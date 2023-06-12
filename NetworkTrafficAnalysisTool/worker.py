from PyQt5.QtCore import QRunnable, pyqtSignal
import nfstream
import pandas as pd
# from suricata_scanner import SuricataScanner


from typing import Any, Dict, List, Tuple
from PyQt5.QtCore import pyqtSignal, QRunnable


class Worker(QRunnable):
    def __init__(self, pcap_file: str, *args: List[Any], **kwargs: Dict[str, Any]) -> None:
        super().__init__()
        self.pcap_file = pcap_file
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Set signals using list comprehension
        [setattr(self, signal, getattr(self.signals, signal)) for signal in self.signals.__dict__.keys() if not signal.startswith('__')]


class WorkerSignals:
    parsed = pyqtSignal(dict)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)
    progress = pyqtSignal(int)
# #############################################################################################
# #    Parsing the pcap file:
# #############################################################################################
    
#     # this is executed when .start() is called
#     # this is the main function of the thread
#     # this is where the work is done
#     # this is where the signals are emitted
    
    def run(self):
        signals = WorkerSignals()
        
        streamer = nfstream.NFStreamer(source=pcap_file,  
        decode_tunnels=True,
        bpf_filter=None,
        promiscuous_mode=False, # promiscuous mode is required for live capture, but not for pcap files, where it is ignored
        snapshot_length=1536,
        idle_timeout=120,
        active_timeout=1800,
        accounting_mode=0,
        udps=None,  # extending NFStream is simple. Adding new flow features or ML model outcomes can be achieved in just a few lines.
        n_dissections=20,
        statistical_analysis=False, # statistical analysis is disabled by default
        splt_analysis=1, #0 means disabled, 1 means enabled, 2 means enabled with ML, 3 means enabled with ML and real-time 
        n_meters=0,
        max_nflows=0, #0 means unlimited 
        performance_report=0, #0 means disabled, 1 means enabled, 2 means enabled with ML, 3 means enabled with ML and real-time
        system_visibility_mode=1, 
        system_visibility_poll_ms=100)
        for flow in streamer:
            flows.append(flow)
            
            self.signals.progress.emit(flow)
            self.parsed.emit(flows)
            self.signals.error.emit((e, traceback.format_exc()))
            self.signals.finished.emit()


# #############################################################################################            
# #       1. Detecting the top talkers on the network:
# #############################################################################################
    def top_talker(self):   
        streamer = NFStreamer(source='eth0', statistical_analysis=True)
        flows = {}
        for flow in streamer:
            if flow.src_ip not in flows:
                flows[flow.src_ip] = 0
            flows[flow.src_ip] += flow.bytes
    def top_talker(self):   
        top_talkers = sorted(flows.items(), key=lambda x: x[1], reverse=True)[:10]
        for talker, bytes in top_talkers:
            print(f"{talker} sent {bytes} bytes")
        for talker, bytes in top_talkers:
            print(f"{talker} sent {bytes} bytes")
#############################################################################################
#      2. Identifying the most common applications on the network:
#############################################################################################            
    def top_application(self):
        streamer = NFStreamer(source='eth0', decode_tunnels=True)
        protocols = {}
        for flow in streamer:
            if flow.proto not in protocols:
                protocols[flow.proto] = 0
            protocols[flow.proto] += 1
        most_common = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]
        for protocol, count in most_common:
            print(f"{protocol} was used in {count} flows")
#############################################################################################            
#    3. Monitoring network performance:
#############################################################################################   
    def monitor_network(self):
        streamer = NFStreamer(source='eth0', statistical_analysis=True)
        for flow in streamer:
            if flow.statistics['jitter'] > 20:
                print(f"Flow {flow} has high jitter ({flow.statistics['jitter']})")
            if flow.statistics['packet_loss'] > 0.1:
                print(f"Flow {flow} has high packet loss ({flow.statistics['packet_loss']})")
#############################################################################################            
#    4. Detecting anomalies on the network:
#############################################################################################   
    # def detect_anomalies(self):
    #     streamer = NFStreamer(source='eth0', statistical_analysis=True)
    #     scanner = SuricataScanner()
    #     for flow in streamer:
    #         stats[flow] = flow.statistics
    #     for flow, statistics in stats.items():
    #         scanner.detect_ddos(flow, statistics)
    #         scanner.detect_anomalies(flow, statistics)
    #         scanner.detect_covert(flow, statistics)
    #         scanner.detect_port_scan(flow, statistics)
    #         scanner.detect_malware(flow, statistics)
    #         scanner.detect_botnet(flow, statistics)
    #         scanner.detect_data_leakage(flow, statistics)
    #         scanner.detect_data_exfiltration(flow, statistics)
    #         scanner.detect_data_tampering(flow, statistics)
    #         scanner.detect_data_spoofing(flow, statistics)
    #         scanner.detect_data_replay(flow, statistics)
    #         scanner.detect_data_masking(flow, statistics)
    #         scanner.detect_data_obfuscation(flow, statistics)
    #         scanner.detect_data_flooding(flow, statistics)
    #         scanner.detect_data_injection(flow, statistics)
    #         # Print the detected anomalies
    #     for flow, anomalies in scanner.anomalies.items():
    #         print(f"Flow {flow} has the following anomalies: {anomalies}")
#############################################################################################            
# 5. Detecting malicious traffic on the network using Suricata:
#############################################################################################            
    # def detect_threat(self):
    #     streamer = NFStreamer(source="eth0", decode_tunnels=True)
    #     scanner = SuricataScanner()
    #     for flow in streamer:
    #         scanner.scan(flow)
    #         if scanner.threat_detected:
    #             # Take action to protect the network
    #             print(f"Threat detected on host {flow.src_ip}: {scanner.threat_description}")
#############################################################################################
#############################################################################################
    def to_pandas(self, pcap_file):
        nf = NFStreamer(source=self.pcap_file, decode_tunnels=True, statistical_analysis=True)
        for flow in streamer:
            flows = nf.to_pandas()
            print(flows)
            # print(flows.head())
            # print(flows.describe())
            # print(flows.info())
            # print(flows.columns)
            # print(flows.shape)
            # print(flows.dtypes)
            # print(flows.memory_usage())
            # print(flows.memory_usage(deep=True))
#############################################################################################
#############################################################################################
    def to_csv(self, pcap_file):    
        streamer = NFStreamer(source=self.pcap_file, decode_tunnels=False, statistical_analysis=True)
        for flow in streamer:
            streamer.to_csv('test.csv')
            #print(streamer.to_csv('test.csv'))
#############################################################################################
#############################################################################################
    # def to_pdf(self, pcap_file):
    #     pass