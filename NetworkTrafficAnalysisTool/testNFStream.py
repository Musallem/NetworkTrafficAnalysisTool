from multiprocessing.spawn import freeze_support

from nfstream import NFStreamer

# We display all streamer parameters with their default values.
# See documentation for detailed information about each parameter.
# https://www.nfstream.org/docs/api#nfstreamer
if __name__ == "__main__":
    freeze_support()
    my_streamer = NFStreamer(source="http-chunked-gzip.pcap",  # or network interface
                         decode_tunnels=True,
                         bpf_filter=None,
                         promiscuous_mode=True,
                         snapshot_length=1536,
                         idle_timeout=120,
                         active_timeout=1800,
                         accounting_mode=0,
                         udps=None,
                         n_dissections=20,
                         statistical_analysis=False,
                         splt_analysis=0,
                         n_meters=0,
                         performance_report=0,
                         system_visibility_mode=0,
                         system_visibility_poll_ms=100,
                         system_visibility_extension_port=28314)

    for flow in my_streamer:
        print(flow)  # print it.



# from nfstream import NFStreamer
#
# my_streamer = NFStreamer(source="WiFi",  # Live capture mode.
#                          # Disable L7 dissection for readability purpose only.
#                          n_dissections=0,
#                          system_visibility_poll_ms=100,
#                          system_visibility_mode=1)
#
# for flow in my_streamer:
#     print(flow)  # print it.