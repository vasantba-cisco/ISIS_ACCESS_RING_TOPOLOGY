import asyncio
import asyncssh
import config
import re
import networkx as nx
import plotly.graph_objects as go

class NetworkAnalyzer:
    def __init__(self, jumphost_ip, jumphost_port, jumphost_username, jumphost_password, router_username, router_password):
        self.jumphost_ip = jumphost_ip
        self.jumphost_port = jumphost_port
        self.jumphost_username = jumphost_username
        self.jumphost_password = jumphost_password
        self.router_username = router_username
        self.router_password = router_password

    async def execute_command(self, ssh_client, command):
        """Execute a command on the remote server via SSH"""
        try:
            async with ssh_client.create_process(command) as process:
                stdout, stderr = await process.communicate()
                return stdout.strip()
        except Exception:
            return None

    async def connect_to_router_via_jumphost(self, router_ip, command):
        """Connect to a router via jumphost and execute a command"""
        try:
            async with asyncssh.connect(self.jumphost_ip, port=self.jumphost_port, username=self.jumphost_username,
                                        password=self.jumphost_password, known_hosts=None) as jumphost_client:
                try:
                    async with jumphost_client.connect_ssh(host=router_ip, username=self.router_username,
                                                           password=self.router_password, known_hosts=None) as router_client:
                        return await self.execute_command(router_client, command)
                except asyncssh.misc.KeyExchangeFailed:
                    async with jumphost_client.connect_ssh(host=router_ip, username=self.router_username,
                                                           password=self.router_password, known_hosts=None,
                                                           kex_algs=['diffie-hellman-group-exchange-sha1', 'diffie-hellman-group1-sha1'],
                                                           encryption_algs=['aes256-cbc', 'aes128-cbc', '3des-cbc']) as router_client:
                        return await self.execute_command(router_client, command)
        except asyncssh.Error:
            return None

    def format_ip_address(self, output):
        if not isinstance(output, str):
            raise TypeError("Expected string or bytes-like object for output")

        netids = set(re.findall(r'\b\d{4}\.\d{4}\.\d{4}\b', output))
        ip_addresses = []
        for netid in netids:
            netid1 = netid.replace('.', '')
            if len(netid1) != 12:
                raise ValueError("Input must be a 12-digit string.")
            groups = [netid1[i:i + 3] for i in range(0, 12, 3)]
            formatted_ip = '.'.join(str(int(group)) for group in groups)
            ip_addresses.append(formatted_ip)

        return ', '.join(ip_addresses)

    async def get_router_model(self, ssh_client, router_ip):
        """Identify the router model"""
        command = f'grep -w "{router_ip}" /home/{config.JUMPHOST_USERNAME}/vasantba/cen-inv | awk \'{{print $4}}\''
        router_model = await self.execute_command(ssh_client, command)
        return router_model.strip()

    async def get_hostname(self, ssh_client, router_ip):
        """Convert IP address to hostname"""
        command = f'grep -w "{router_ip}" /home/{config.JUMPHOST_USERNAME}/vasantba/cen-inv | awk \'{{print $1}}\''
        return (await self.execute_command(ssh_client, command)).strip()

    async def get_ip_from_hostname(self, ssh_client, hostname):
        """Convert hostname to IP address"""
        command = f'grep -w "{hostname}" /home/{config.JUMPHOST_USERNAME}/vasantba/cen-inv | awk \'{{print $2}}\''
        return (await self.execute_command(ssh_client, command)).strip()

    async def get_router_ids(self, ssh_client, router_ip, ring_id):
        """Get the router IDs"""
        router_model = await self.get_router_model(ssh_client, router_ip)
        if router_model == "CISCO":
            command = f"show isis instance access{ring_id} database verbose | utility egrep -e '^  Router ID:' | utility cut -c 18-38"
        elif router_model == "HUAWEI":
            command = f"display isis {ring_id} lsdb verbose | i Router ID"
        else:
            raise ValueError(f"Unsupported router model: {router_model}")

        output = await self.connect_to_router_via_jumphost(router_ip, command)
        if output is None:
            return []

        router_ids = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
        return list(set(router_ids))

    async def get_neighbors(self, ssh_client, router_ip, ring_id, hring_id):
        """Get the neighbors for a router"""
        router_model = await self.get_router_model(ssh_client, router_ip)
        router_name = await self.get_hostname(ssh_client, router_ip)
        isis_data1  = []

        def extract_neighbors(data):
            system_id_interface_pattern_isis = re.compile(r'(\S+)\s+(\S+)\s+\*PtoP\*.*')
            system_id_interface_pattern_peer = re.compile(r'(\d{4}\.\d{4}\.\d{4})\s+(\S+)\s+')
            ipv4_address_pattern = re.compile(r'IPv4 Address\(es\):\s+(\S+)\*?')
            peer_ip_pattern = re.compile(r'Peer IP Address\(es\)\s+:\s+(\S+)')

            neighbors = []

            lines = data.splitlines()
            for i, line in enumerate(lines):
                if "Total neighbor count" in line or not line.strip():
                    continue
                sys_interface_match_isis = system_id_interface_pattern_isis.match(line)
                if sys_interface_match_isis:
                    system_id = sys_interface_match_isis.group(1)
                    interface = sys_interface_match_isis.group(2)
                    for j in range(i + 1, len(lines)):
                        ipv4_match = ipv4_address_pattern.search(lines[j])
                        if ipv4_match:
                            interface_ip = ipv4_match.group(1)
                            neighbors.append({
                                'Neighbour': system_id,
                                'Interface': interface,
                                'InterfaceIP': interface_ip
                            })
                            break
                sys_interface_match_peer = system_id_interface_pattern_peer.match(line)
                if sys_interface_match_peer:
                    system_id = sys_interface_match_peer.group(1)
                    interface = sys_interface_match_peer.group(2)

                    for j in range(i + 1, len(lines)):
                        peer_ip_match = peer_ip_pattern.search(lines[j])
                        if peer_ip_match:
                            interface_ip = peer_ip_match.group(1)
                            neighbors.append({
                                'Neighbour': system_id,
                                'Interface': interface,
                                'InterfaceIP': interface_ip
                            })
                            break
            return neighbors

        if router_model == "CISCO":
            if "AG_" in router_name.upper() or "NP_" in router_name.upper() or "CR_" in router_name.upper():
                command = f"show isis instance access{ring_id} neighbors detail"
            else:
                command = "show isis neighbors detail"

            outputs = await self.connect_to_router_via_jumphost(router_ip, command)
            if outputs is None:
                return []

        elif router_model == "HUAWEI":
            if "AG_" in router_name.upper() or "NP_" in router_name.upper() or "CR_" in router_name.upper():
                command = f"display isis {hring_id} peer verbose | no-more"
            else:
                command = "display isis peer verbose | include ."
            outputs = await self.connect_to_router_via_jumphost(router_ip, command)
            if outputs is None:
                return []

        isis_neighbor = extract_neighbors(str(outputs))

        for match in isis_neighbor:
            hostname = await self.get_hostname(ssh_client, router_ip)
            system_ids = match['Neighbour']
            if re.match(r'^\d{4}\.\d{4}\.\d{4}$', system_ids):
                neig_ip = self.format_ip_address(system_ids)
                neighbor = await self.get_hostname(ssh_client, neig_ip)
            else:
                neighbor = system_ids
            interfaces = match['Interface']
            neighbor_ip = match['InterfaceIP']
            isis_data1.append({'hostname': hostname, 'IPaddress': router_ip, 'Neighbour': neighbor, 'Interface': interfaces, 'NeighborIP': neighbor_ip})
        return isis_data1

    async def analyze_network(self, router_ip, ring_id, hring_id):
        """Main function to analyze the network"""
        async with asyncssh.connect(self.jumphost_ip, port=self.jumphost_port, username=self.jumphost_username,
                                    password=self.jumphost_password, known_hosts=None) as ssh_client:

            # Identify router model
            router_model = await self.get_router_model(ssh_client, router_ip)
            print(f"Router model: {router_model}")

            # Get hostname
            hostname = await self.get_hostname(ssh_client, router_ip)
            print(f"Hostname: {hostname}")

            # Validate router model before proceeding
            if router_model not in ["CISCO", "HUAWEI"]:
                return

            # Get router IDs
            router_ids = await self.get_router_ids(ssh_client, router_ip, ring_id)
            print(f"Router IDs: {router_ids}")

            # Get neighbors
            isis_data = []
            for router_id in router_ids:
                neighbor_pairs = await self.get_neighbors(ssh_client, router_id, ring_id, hring_id)
                isis_data.extend(neighbor_pairs)
            print(isis_data)

            # Draw the network graph using the isis_data
            self.draw_network_graph(isis_data, ring_id)

    def draw_network_graph(self, isis_data, ring_id):
        """Draw the network graph using Plotly"""
        G = nx.DiGraph()
        for entry in isis_data:
            if 'IPaddress' in entry:
                G.add_node(entry['hostname'], IP=entry['IPaddress'])
                G.add_edge(entry['hostname'], entry['Neighbour'], interface=entry['Interface'], neighbor_ip=entry['NeighborIP'])

        pos = nx.spring_layout(G)

        edge_x = []
        edge_y = []
        edge_annotations = []
        
        for edge in G.edges(data=True):
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

            offset = 0.18  # Reduced offset to place labels closer to nodes

            # Label for the edge in one direction
            edge_annotations.append(
                dict(
                    x=x0 + offset * (x1 - x0),  # Offset position for better visibility
                    y=y0 + offset * (y1 - y0),
                    text=f"Interface: {edge[2]['interface']}<br>NeighborIP: {edge[2]['neighbor_ip']}",
                    showarrow=False,
                    font=dict(color='blue', size=10),
                    align='center',
                    ax=0,
                    ay=0
                )
            )

            # Label for the edge in the reverse direction (if exists)
            if G.has_edge(edge[1], edge[0]):
                rev_interface = G[edge[1]][edge[0]]['interface']
                rev_neighbor_ip = G[edge[1]][edge[0]]['neighbor_ip']
                edge_annotations.append(
                    dict(
                        x=x1 + offset * (x0 - x1),  # Offset position for better visibility
                        y=y1 + offset * (y0 - y1),
                        text=f"Interface: {rev_interface}<br>NeighborIP: {rev_neighbor_ip}",
                        showarrow=False,
                        font=dict(color='green', size=10),
                        align='center',
                        ax=0,
                        ay=0
                    )
                )

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')

        node_x = []
        node_y = []
        node_color = []
        node_size = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            if "AG_" in node.upper() or "NP_" in node.upper():
                node_color.append('darkgreen')
                node_size.append(20)
            elif "AC" in node.upper() or re.match(r'A[0-9]', node.upper()):
                node_color.append('red')
                node_size.append(15)
            else:
                node_color.append('blue')
                node_size.append(10)

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            textposition='top center',
            hoverinfo='text',
            marker=dict(
                showscale=True,
                colorscale='YlGnBu',
                size=node_size,
                color=node_color,
                colorbar=dict(
                    thickness=15,
                    title='Node Connections',
                    xanchor='center',
                    titleside='right'
                ),
                line_width=2))

        node_text = []
        for node, data in G.nodes(data=True):
            node_text.append(f"{node}<br>{data['IP']}")

        node_trace.text = node_text

        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
                            title=f"Network Topology of ISIS ring {ring_id}",
                            titlefont_size=16,
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=20, l=5, r=5, t=40),
                            annotations=edge_annotations + [dict(
                                text=f"ISIS Ring {ring_id}",
                                showarrow=False,
                                xref="paper", yref="paper"
                            )],
                            xaxis=dict(showgrid=False, zeroline=False),
                            yaxis=dict(showgrid=False, zeroline=False))
                        )

        fig.show()


async def main():
    router_ip = input("Enter the router IP address: ")
    ring_id = input("Enter the access ring ID: ")
    hring_id = input("Enter the ring ID merged in Huawei: ")

    analyzer = NetworkAnalyzer(
        config.JUMPHOST_IP, config.JUMPHOST_PORT, config.JUMPHOST_USERNAME, config.JUMPHOST_PASSWORD,
        config.ROUTER_USERNAME, config.ROUTER_PASSWORD
    )
    await analyzer.analyze_network(router_ip, ring_id, hring_id)

if __name__ == "__main__":
    asyncio.run(main())