from nfstream import NFStreamer
import sys
import os

def get_interfaces():
    interfaces = os.listdir('/sys/class/net')
    return interfaces

if __name__ == "__main__":  # Mandatory if you are running on Windows Platform
    listOfInterfaces = []
    for path in get_interfaces():
        print(path)
        listOfInterfaces.append(path)

    print("Interfaces: \n")
    for i in range(len(listOfInterfaces)):
        print(str(i) + "- " + listOfInterfaces[i] + "\n")

    selected = int(input("select interface by writing the number: "))

    if len(listOfInterfaces) == 1:  # Single file / Interface
        input_filepaths = listOfInterfaces[0]

    for i in range(len(input_filepaths)):
        if i == selected:
            interface = input_filepaths[i]
    print(interface)
    flow_streamer = NFStreamer(source=interface,
                               statistical_analysis=False,
                               idle_timeout=1)

    result = {}
    try:
        for flow in flow_streamer:
            # flow = flow.to_pandas()[["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "bidirectional_packets", "bidirectional_bytes", "application_name"]]
            print(flow.head())
            try:
                result[flow.application_name] += flow.bidirectional_packets
            except KeyError:
                result[flow.application_name] = flow.bidirectional_packets
        print("\nSummary (Application Name: Packets):")
        print(result)
    except KeyboardInterrupt:
        print("\nSummary (Application Name: Packets):")
        print(result)
        print("Terminated.")

# from nfstream import NFStreamer
# import numpy
# import pandas as pd
# my_dataframe = NFStreamer(source='ens33')
#
# df = my_dataframe.to_pandas()[["src_ip",
#                                                             "src_port",
#                                                             "dst_ip",
#                                                             "dst_port",
#                                                             "protocol",
#                                                             "bidirectional_packets",
#                                                             "bidirectional_bytes",
#                                                             "application_name"]]
# df.head(5)


# class ModelPrediction(NFPlugin):
#     def on_init(self, packet, flow):
#         flow.udps.model_prediction = 0
#     def on_expire(self, flow):
#         # You can do the same in on_update entrypoint and force expiration with custom id.
#         to_predict = numpy.array([flow.bidirectional_packets,
#                                   flow.bidirectional_bytes]).reshape((1,-1))
#         flow.udps.model_prediction = self.my_model.predict(to_predict)
#
# ml_streamer = NFStreamer(source="eth0", udps=ModelPrediction(my_model=model))
# for flow in ml_streamer:
#     print(flow.udps.model_prediction)
from nfstream import NFStreamer

# We display all streamer parameters with their default values.
# See documentation for detailed information about each parameter.
# https://www.nfstream.org/docs/api#nfstreamer
