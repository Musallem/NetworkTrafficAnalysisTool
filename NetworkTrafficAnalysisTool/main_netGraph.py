import pandas as pd
import matplotlib.pyplot as plt
import networkx as nx

# Load data from CSV file
df = pd.read_csv('data.csv')

# Create networkx graph object
G = nx.Graph()
for index, row in df.iterrows():
    G.add_edge(row['hosts'], row['ports'], status=row['status'])

# Draw graph and save to file
pos = nx.spring_layout(G)
nx.draw(G, pos, with_labels=True)
plt.savefig('graph.png')

# show the graph
plt.show()
