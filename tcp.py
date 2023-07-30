import random
import networkx as nx
import matplotlib.pyplot as plt

def generate_random_topology(num_nodes):
    # Create an empty graph
    G = nx.Graph()

    # Add nodes to the graph
    nodes = range(5000, 5000+num_nodes)
    G.add_nodes_from(nodes)

    # Add random edges between nodes
    if(len(nodes)<=3):
        for node in nodes:
            # Randomly select the number of neighbors for each node

            num_neighbors = 1
            
            # Randomly select neighbors for the current node
            while(1):
                neighbors = random.sample(nodes, num_neighbors)
                if neighbors[0]!=node:
                    for neighbor in neighbors:
                        if neighbor != node:
                            G.add_edge(node, neighbor)
                    break
    else:
        for node in nodes:
        # Randomly select the number of neighbors for each node
            num_neighbors = random.randint(1, 2)
        # Randomly select neighbors for the current node
            neighbors = random.sample(nodes, num_neighbors)
        # Add edges between the current node and its neighbors
        for neighbor in neighbors:
            if neighbor != node:
                G.add_edge(node, neighbor)

            # Add edges between the current node and its neighbors
    return G

def print_topology(graph):
    # Print the nodes and their neighbors
    for node in graph.nodes():
        neighbors = list(graph.neighbors(node))
        print(f"Node {node}: Neighbors: {neighbors}")

def find_shortest_path(graph, source, destination):
    try:
        # Find the shortest path between the source and destination nodes
        shortest_path = nx.shortest_path(graph, source=source, target=destination)
        return shortest_path
    except nx.NetworkXNoPath:
        return None
