from flask import Flask, render_template, jsonify, request
from scapy.all import ARP, Ether, srp
import socket

app = Flask(__name__)

def get_devices_in_network(ip_range):
    print(f"Scanning Network Range: {ip_range}")
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        # Get the IP and MAC address
        ip_address = received.psrc
        mac_address = received.hwsrc

        # Attempt to get the hostname (PC name) via reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            hostname = "Unknown"  # If the hostname can't be determined

        # Add the device information
        devices.append({
            'ip': ip_address,
            'mac': mac_address,
            'hostname': hostname
        })

    print("Finished Scanning")
    return devices

@app.route('/')
def scan_network():
    return render_template('listofip.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip_range = request.json.get('ip_range', '192.168.88.0/24')  # Default range if none provided
    devices = get_devices_in_network(ip_range)
    return jsonify(devices)

if __name__ == "__main__":
    app.run(debug=True)
