import nmap
import matplotlib.pyplot as plt

# initialize the port scanner
nm = nmap.PortScanner()

# scan the network for hosts and their open ports
nm.scan(hosts='192.168.1.0/24', arguments='-p 1-1000')

# store the host/port data in a dictionary
data = {}
for host in nm.all_hosts():
    data[host] = len(nm[host]['tcp'].keys())

# create a horizontal bar chart from the dictionary data
fig, ax = plt.subplots(figsize=(8, 6))
ax.barh(range(len(data)), list(data.values()), align='center')
ax.set_yticks(range(len(data)))
ax.set_yticklabels(list(data.keys()))
ax.invert_yaxis()  # labels read top-to-bottom
ax.set_xlabel('Open Ports')
ax.set_title('Scan Results by Host')
plt.show()
#
# import nmap
# import matplotlib.pyplot as plt
#
# def port_scan(ip):
#     nm = nmap.PortScanner()
#     nm.scan(ip, '1-65535')
#     open_ports = []
#     for host in nm.all_hosts():
#         for proto in nm[host].all_protocols():
#             lport = nm[host][proto].keys()
#             for port in lport:
#                 if nm[host][proto][port]['state'] == 'open':
#                     open_ports.append(port)
#                     print(f'Port {port} is open on {host}')
#     return open_ports
# open_ports = port_scan("192.168.1.1")
#
# def plot_graph(open_ports, total_ports):
#     closed_ports = total_ports - len(open_ports)
#
#     labels = ['Open Ports', 'Closed Ports']
#     sizes = [len(open_ports), closed_ports]
#
#     fig, ax = plt.subplots()
#     ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
#     ax.axis('equal')
#     ax.set_title(f'{total_ports} Total Ports\n{len(open_ports)} Open Ports')
#
#     plt.show()
#
# plot_graph(open_ports, 65535) # Assuming the total ports scanned are 65535