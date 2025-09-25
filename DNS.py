import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, A

# Define the DNS server's IP and port
HOST_IP = '127.0.0.1'
DNS_PORT = 53

# The DNS server we will forward requests to
# Google's Public DNS is a common choice
FORWARD_DNS = ('8.8.8.8', 53)
LOGS = []

# A simple dictionary acting as our DNS zone file
ZONE_FILE = {
    'example.com': '93.184.216.34',
    'test.local': '192.168.1.100'
}

def resolve_forward(query_data):
    """
    Forwards a DNS query to an external DNS server and returns the response.
    """
    try:
        # Create a new socket to query the external DNS server
        forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_sock.settimeout(5)  # Set a timeout for the forward request
        forward_sock.sendto(query_data, FORWARD_DNS)
        response_data, _ = forward_sock.recvfrom(512)
        forward_sock.close()
        return response_data
    except socket.timeout:
        print("Forward query timed out.")
        return None
    except Exception as e:
        print(f"Error during forward query: {e}")
        return None

def handle_query(data, addr, sock):
    """
    Handles an incoming DNS query, either locally or by forwarding.
    """
    try:
        query = DNSRecord.parse(data)
        q_name = str(query.q.qname)
        print(f"Received query for {q_name} from {addr}")

        # Check if the domain is in our local zone file
        if q_name in ZONE_FILE:
            # Create a response from our local zone
            reply = DNSRecord(
                DNSHeader(id=query.header.id, qr=1, aa=1, ra=1),
                q=DNSQuestion(q_name)
            )
            reply.add_answer(RR(q_name, A, rdata=A(ZONE_FILE[q_name]), ttl=60))
            sock.sendto(reply.pack(), addr)
            LOGS.append(f"Local lookup successful. Sent reply for {q_name}.\n")
            print(f"Local lookup successful. Sent reply for {q_name}.")
        elif q_name == "quit.local.":
            with open("logs.log", "w") as file:
                file.writelines(LOGS)
            quit()
        else:
            LOGS.append(f"Domain not in local zone. Forwarding query for {q_name} to {FORWARD_DNS[0]}.\n")
            print(f"Domain not in local zone. Forwarding query for {q_name} to {FORWARD_DNS[0]}.")
            
            # Forward the query to the external DNS server
            forward_response = resolve_forward(data)

            if forward_response:
                # Send the external server's response back to the client
                sock.sendto(forward_response, addr)
                print(f"Forwarded lookup successful. Sent reply for {q_name}.")
            else:
                # If forward lookup fails, send an NXDOMAIN response
                reply = DNSRecord(
                    DNSHeader(id=query.header.id, qr=1, ra=1, rcode=3),
                    q=DNSQuestion(q_name)
                )
                sock.sendto(reply.pack(), addr)
                LOGS.append(f"Forwarded lookup failed. Sent NXDOMAIN for {q_name}.\n")
                print(f"Forwarded lookup failed. Sent NXDOMAIN for {q_name}.")

    except Exception as e:
        print(f"Error handling query: {e}")

def run_dns_server():
    """
    Starts the UDP DNS server.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST_IP, DNS_PORT))

    print(f"DNS server listening on {HOST_IP}:{DNS_PORT}")

    try:
        while True:
            try:
                data, addr = sock.recvfrom(512)
                handle_query(data, addr, sock)
            except ConnectionResetError:
                print("Client forcibly closed the connection. Continuing to listen.")
    except KeyboardInterrupt:
        print("Server shut down.")
    finally:
        sock.close()

if __name__ == '__main__':
    run_dns_server()