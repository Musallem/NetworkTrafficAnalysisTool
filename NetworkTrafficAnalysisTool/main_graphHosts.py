import matplotlib.pyplot as plt

# data for connected hosts ports with their status
hosts = ['host1','host2','host3','host4']
ports = [80, 443, 22, 3389]
status = ['up', 'down', 'up', 'up']

# create a bar chart with the data
plt.bar(range(len(hosts)), ports, color='red')

# add labels for each axis and title
plt.title('Connected Hosts Ports with Status')
plt.xlabel('Hosts')
plt.ylabel('Ports')

# add text showing the status of each host
for i in range(len(hosts)):
    plt.text(i, ports[i], status[i], ha='center')

# show the graph
plt.show()
