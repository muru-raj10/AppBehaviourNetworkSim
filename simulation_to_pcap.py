import random
import string
from typing import List, Dict
from scapy.all import Ether, IP, TCP, Raw, UDP, wrpcap, rdpcap
from scipy.stats import beta
import math
import time
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import psutil
from app_distribution import server_ips, client_ips, app_traffic_config
from scapy.all import rdpcap, wrpcap

############################
# Helper Functions
############################

def is_system_overloaded():
    memory_usage = psutil.virtual_memory().percent
    cpu_usage = psutil.cpu_percent()
    return memory_usage > 90 or cpu_usage > 90

def wait_until_system_not_overloaded(start_time,duration):
    """Pause execution until the system is not overloaded."""
    while is_system_overloaded():
        print("System overloaded. Waiting...")
        time.sleep(3)
        if duration < (time.time() - start_time):
            break

def generate_random_ip():
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_response_codes(num_codes: int, codes: List[int], weights: List[float]) -> List[int]:
    total_weight = sum(weights)
    scaled_weights = [int(weight / total_weight * num_codes) for weight in weights]
    response_code_pool = []
    for code, count in zip(codes, scaled_weights):
        response_code_pool.extend([code] * count)
    random.shuffle(response_code_pool)
    return response_code_pool

def generate_random_method_distribution():
    """
    Generate a random method distribution:
    - GET + POST + MYSQL = 0.65 (randomly split)
    - TCP + TEARDOWN = 0.12 (randomly split)
    - OPTIONS gets the remaining share to make the total 1.0
    """
    # Randomly split 0.65 among GET, POST, and MYSQL
    get_post_mysql = [random.uniform(0, 0.65) for _ in range(2)]
    get_post_mysql.append(0.65 - sum(get_post_mysql))  # Ensure they sum to 0.65
    random.shuffle(get_post_mysql)  # Shuffle to vary the order

    # Randomly split 0.12 among TCP and TEARDOWN
    tcp_teardown = [random.uniform(0, 0.12)]
    tcp_teardown.append(0.12 - tcp_teardown[0])  # Ensure they sum to 0.12
    random.shuffle(tcp_teardown)

    # OPTIONS takes the remaining value to sum to 1.0
    options = 1.0 - (sum(get_post_mysql) + sum(tcp_teardown))

    # Map the values to method names
    return {
        "GET": get_post_mysql[0],
        "POST": get_post_mysql[1],
        "MYSQL": get_post_mysql[2],
        "OPTIONS": options,
        "TCP": tcp_teardown[0],
        "TEARDOWN": tcp_teardown[1],
    }


def modify_pcap_timestamps(input_pcap: str, output_pcap: str, base_time_str: str):
    """
    Modify the timestamps of packets in a PCAP file to start within the first
    30 seconds of a given base timestamp.

    :param input_pcap: The input PCAP file path.
    :param output_pcap: The output PCAP file path.
    :param base_time_str: Base timestamp in the format 'YYYY-MM-DD-HH-mm'.
    """
    # Parse the base timestamp
    base_time = datetime.strptime(base_time_str, "%Y-%m-%d-%H-%M")
    base_time_epoch = int(base_time.timestamp())

    # Generate a random start time within the first 30 seconds
    random_offset = random.uniform(0, 30)
    random_start_time = base_time_epoch + random_offset

    # Read packets from the input PCAP file
    packets = rdpcap(input_pcap)

    # Calculate the time adjustment
    if packets:
        first_packet_time = packets[0].time
        time_adjustment = random_start_time - first_packet_time

        # Adjust timestamps for all packets
        for packet in packets:
            packet.time += time_adjustment

    # Write the modified packets to the output PCAP file
    wrpcap(output_pcap, packets)
    #print(f"Modified PCAP file saved to {output_pcap}")


############################
# Simulation Code
############################

class ApplicationTrafficSimulator:
    def __init__(self,
                 server_ips: List[str],
                 client_ips: List[str],
                 server_ports: List[int],
                 client_port_range: List[int] = [1, 2, 3]):
        self.server_ips = server_ips
        self.client_ips = client_ips
        self.server_ports = server_ports
        self.client_port_range = client_port_range

        self.response_codes = [200, 304, 302, 401, 400, 500, 404, 303]
        self.response_code_weights = [0.8, 0.02, 0.04, 0.04, 0.04, 0.02, 0.03, 0.01]
        self.response_code_pool = generate_response_codes(
            num_codes=10000,
            codes=self.response_codes,
            weights=self.response_code_weights
        )

    def payload_chunks(self, payload: str, chunk_size: int = 100) -> List[str]:
        return [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    def generate_random_payload(self, length: int = 180) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

    def get_random_response_code(self) -> int:
        return random.choice(self.response_code_pool)

    def simulate_request_response(self, payload: str,
                                  client_ip: str, server_ip: str,
                                  client_port: int, server_port: int,
                                  current_time: float) -> List:
        packets = []
        payload_chunks = self.payload_chunks(payload)
        # Add small random delay before sending request packets to simulate network jitter
        time_increment = current_time

        for chunk in payload_chunks:
            time_increment += random.uniform(0.001, 0.005)
            packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                            IP(src=client_ip, dst=server_ip) /
                            TCP(sport=client_port, dport=server_port, flags='PA') /
                            Raw(load=chunk)))
            # Duplicate packet with probability 0.06
            if random.random() < 0.06:
                dup_pkt = packets[-1][1].copy()
                dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
                packets.append((dup_time, dup_pkt))

        # Introduce server response delay to simulate Svr_Rsp_Wait
        time_increment += random.uniform(0.01, 0.05)

        response_code = self.get_random_response_code()
        response_payload = f"HTTP/1.1 {response_code} OK\r\nContent-Type: text/html\r\n\r\n<html>...</html>"
        response_payload += self.generate_random_payload(int(round(1 + 799 * beta.rvs(5.0, 24.0))))
        response_chunks = self.payload_chunks(response_payload)

        for chunk in response_chunks:
            time_increment += random.uniform(0.001, 0.005)
            packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                            IP(src=server_ip, dst=client_ip) /
                            TCP(sport=server_port, dport=client_port, flags='PA') /
                            Raw(load=chunk)))
            # Duplicate packet with probability 0.06
            if random.random() < 0.06:
                dup_pkt = packets[-1][1].copy()
                dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
                packets.append((dup_time, dup_pkt))

        return packets

    def tcp_handshake(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        time_increment = current_time
        # SYN
        time_increment += random.uniform(0.001,0.005)
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=client_ip, dst=server_ip) /
                        TCP(sport=client_port, dport=server_port, flags='S') /
                        Raw(load='TCP')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        # Introduce SYN wait at the server side
        time_increment += random.uniform(0.01,0.05) # server SYN wait
        # SYN-ACK
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=server_ip, dst=client_ip) /
                        TCP(sport=server_port, dport=client_port, flags='SA') /
                        Raw(load='TCP')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        time_increment += random.uniform(0.001,0.005)
        # ACK
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=client_ip, dst=server_ip) /
                        TCP(sport=client_port, dport=server_port, flags='A') /
                        Raw(load='TCP')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        return packets

    def teardown_connection(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        time_increment = current_time
        # FIN
        time_increment += random.uniform(0.001,0.005)
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=client_ip, dst=server_ip) /
                        TCP(sport=client_port, dport=server_port, flags='F') /
                        Raw(load='TEARDOWN')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        time_increment += random.uniform(0.01,0.03)
        # FIN-ACK
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=server_ip, dst=client_ip) /
                        TCP(sport=server_port, dport=client_port, flags='FA') /
                        Raw(load='TEARDOWN')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        time_increment += random.uniform(0.001,0.005)
        # ACK
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=client_ip, dst=server_ip) /
                        TCP(sport=client_port, dport=server_port, flags='A') /
                        Raw(load='TEARDOWN')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        return packets

    def tcp_method_connection(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        time_increment = (packets[-1][0] if packets else current_time)
        # Add a tiny data packet with 'P' flag:
        time_increment += random.uniform(0.001,0.005)
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=client_ip, dst=server_ip) /
                        TCP(sport=client_port, dport=server_port, flags='PA') /
                        Raw(load='METHOD: TCP\r\n')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        # teardown
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def teardown_only_connection(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        time_increment = packets[-1][0]
        # Add one data packet indicating TEARDOWN method
        time_increment += random.uniform(0.001,0.005)
        packets.append((time_increment, Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") /
                        IP(src=client_ip, dst=server_ip) /
                        TCP(sport=client_port, dport=server_port, flags='PA') /
                        Raw(load='METHOD: TEARDOWN\r\n')))
        if random.random() < 0.06:
            dup_pkt = packets[-1][1].copy()
            dup_time = packets[-1][0] + random.uniform(0.000001,0.00001)
            packets.append((dup_time, dup_pkt))

        # teardown
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def short_transaction(self, client_ip, server_ip, client_port, server_port, current_time, method):
        # 1 request, 1 response
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        t = packets[-1][0]
        payload = f"METHOD: {method}\r\n"
        data_pkts = self.simulate_request_response(payload, client_ip, server_ip, client_port, server_port, t)
        packets.extend(data_pkts)
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def long_session(self, client_ip, server_ip, client_port, server_port, current_time):
        # Session: POST (login), multiple GET, then TEARDOWN
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        t = packets[-1][0]
        # POST login
        payload = "METHOD: POST\r\nPOST /login HTTP/1.1\r\nHost: {}\r\nContent-Length: 20\r\n\r\nuser=foo&pass=bar".format(server_ip)
        post_pkts = self.simulate_request_response(payload, client_ip, server_ip, client_port, server_port, t)
        packets.extend(post_pkts)

        # Multiple GET requests
        num_gets = random.randint(2,5)
        for _ in range(num_gets):
            t = packets[-1][0]
            payload = f"METHOD: GET\r\nGET /data HTTP/1.1\r\nHost: {server_ip}\r\n\r\n"
            get_pkts = self.simulate_request_response(payload, client_ip, server_ip, client_port, server_port, t)
            packets.extend(get_pkts)

        # TEARDOWN at end
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def options_request(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        payload = "METHOD: OPTIONS\r\nOPTIONS * HTTP/1.1\r\nHost: {}\r\n\r\n".format(server_ip)
        payload += self.generate_random_payload(int(round(1 + 989 * beta.rvs(5.0, 24.0))))
        packets.extend(self.simulate_request_response(payload, client_ip, server_ip, client_port, server_port, current_time))
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def mysql_connection(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        t = packets[-1][0]
        query = "METHOD: MYSQL\r\nSELECT * FROM users WHERE id=1;"
        query += self.generate_random_payload(int(round(1 + 303 * beta.rvs(5.0, 24.0))))
        data_pkts = self.simulate_request_response(query, client_ip, server_ip, client_port, server_port, t)
        packets.extend(data_pkts)
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def post_request(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        t = packets[-1][0]
        payload = "METHOD: POST\r\nPOST /submit HTTP/1.1\r\nHost: {}\r\nContent-Length: 20\r\n\r\nkey=value&data=example".format(server_ip)
        payload += self.generate_random_payload(int(round(1 + 799 * beta.rvs(5.0, 24.0))))
        data_pkts = self.simulate_request_response(payload, client_ip, server_ip, client_port, server_port, t)
        packets.extend(data_pkts)
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def get_request(self, client_ip: str, server_ip: str, client_port: int, server_port: int, current_time: float) -> List:
        packets = []
        packets.extend(self.tcp_handshake(client_ip, server_ip, client_port, server_port, current_time))
        t = packets[-1][0]
        payload = "METHOD: GET\r\nGET /index.html HTTP/1.1\r\nHost: {}\r\n\r\n".format(server_ip)
        payload += self.generate_random_payload(int(round(1 + 203 * beta.rvs(5.0, 24.0))))
        data_pkts = self.simulate_request_response(payload, client_ip, server_ip, client_port, server_port, t)
        packets.extend(data_pkts)
        teardown_pkts = self.teardown_connection(client_ip, server_ip, client_port, server_port, packets[-1][0])
        packets.extend(teardown_pkts)
        return packets

    def generate_application_traffic(self, app_name: str, method_distribution: Dict[str, float], num_connections: int, current_time: float, server_ips, client_ips) -> List:
        packets = []
        # Poisson process for starting connections:
        # Let's say mean inter-arrival time = 0.5 seconds
        lambda_rate = random.choice([1.1,1.5,2.0,2.4])  # 2,3 or 4 connections per second on average
        # We'll generate inter-arrival times from exponential distribution
        for _ in range(num_connections):
            inter_arrival = random.expovariate(lambda_rate)
            current_time += inter_arrival
            # Uniform distribution for choosing client and server
            client_ip = random.choice(client_ips)
            server_ip = random.choice(server_ips)
            client_port = int(app_name)
            server_port = random.choice(self.server_ports)
            method = random.choices(["GET", "POST", "MYSQL", "OPTIONS", "TCP", "TEARDOWN"],
                                    weights=[method_distribution[m] for m in ["GET","POST","MYSQL","OPTIONS","TCP","TEARDOWN"]])[0]

            val = random.random()
            is_session = val < 0.3
            is_short = val > 0.95
            if method in ["GET","POST","MYSQL","OPTIONS"] and is_session:
                packets.extend(self.long_session(client_ip, server_ip, client_port, server_port, current_time))
            elif method in ["GET","POST","MYSQL","OPTIONS"] and is_short:
                packets.extend(self.short_transaction(client_ip, server_ip, client_port, server_port, current_time, method))
            else:
                if method == "GET":
                    packets.extend(self.get_request(client_ip, server_ip, client_port, server_port, current_time))
                elif method == "POST":
                    packets.extend(self.post_request(client_ip, server_ip, client_port, server_port, current_time))
                elif method == "MYSQL":
                    packets.extend(self.mysql_connection(client_ip, server_ip, client_port, server_port, current_time))
                elif method == "OPTIONS":
                    packets.extend(self.options_request(client_ip, server_ip, client_port, server_port, current_time))
                elif method == "TCP":
                    packets.extend(self.tcp_method_connection(client_ip, server_ip, client_port, server_port, current_time))
                elif method == "TEARDOWN":
                    packets.extend(self.teardown_only_connection(client_ip, server_ip, client_port, server_port, current_time))

        return packets

    def simulate_traffic(self, app_traffic_config: Dict[str, Dict], output_pcap: str):
        all_packets = []
        current_time = 0.0
        app_keys = list(app_traffic_config.keys())  # List of application keys (e.g., "1", "2", etc.)
        ctr = 1
        # 'app_name' used as application name (e.g. "App1", "App2")
        while ctr < 50:  # Run for 50 apps out of 100
            app_num = random.choice(app_keys)  # Randomly pick an application
            app_keys.remove(app_num)  # Remove it from the list to avoid repetition

            # Fetch the application's traffic configuration
            app_name = app_num
            method_distribution = app_traffic_config[app_num]["method_distribution"]
            num_connections = app_traffic_config[app_num]["num_connections"]+random.randint(0, 40)

            # Generate traffic for the randomly selected application
            packets = self.generate_application_traffic(app_name, method_distribution, num_connections, current_time, self.server_ips, self.client_ips)

            # Update current_time to reflect the end of the last generated connection
            if packets:
                current_time = max(current_time, packets[-1][0])
            all_packets.extend(packets)
            ctr += 1

        # sort packets by time
        all_packets.sort(key=lambda x: x[0])
        # write them with correct timestamps
        final_pkts = []
        for t, p in all_packets:
            p.time = t
            final_pkts.append(p)
        wrpcap(output_pcap, final_pkts)
        print(f"PCAP file '{output_pcap}' generated.")


############################
# Main Execution
############################
def run_simulation(server_ips, client_ips, server_ports, time_start):
    """
    Run a single simulation and save the output with a unique filename.
    """
    simulator = ApplicationTrafficSimulator(server_ips, client_ips, server_ports)

    # Generate a unique file name with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    pcap_file = f"simulation/simulated_data/application_traffic_{timestamp}.pcap"

    simulator.simulate_traffic(app_traffic_config, output_pcap=pcap_file)
    modify_pcap_timestamps(pcap_file, pcap_file, time_start)
    print(f"Simulation completed: {pcap_file}")


if __name__ == "__main__":
    # Simulation configuration
    server_ports = [80, 443, 3306, 17370, 17070, 17270, 17170, 17670, 17870,
                    17570, 17470, 17970, 554, 9090, 22]

    # Run simulations for one hour
    start_time = time.time()
    duration = 1*5  # One hour in seconds
    #max_parallel_simulations = 3  # Adjust based on system capacity
    time_start = "2024-12-01-12-12"

    while time.time() - start_time < duration:
        run_simulation(server_ips, client_ips, server_ports, time_start)
        #wait_until_system_not_overloaded(start_time,duration)  # Wait until system is ready
        #time.sleep(1)