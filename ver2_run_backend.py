import threading 
import time 
from ids_backend.config import load_config_file
from ids_backend.capture import PacketCapture
from ids_backend.detectors.icmp_flood import icmp_counter_detector
from ids_backend.alerting import alert_manager

#newly added
from ids_backend.ssh_detector import ssh_detector

def main():
    app_config = load_config_file()
    alert_mngr = alert_manager(app_config)
    detector = icmp_counter_detector(app_config, alert_mngr)
    live_packet_sniffer = PacketCapture(app_config)
    live_packet_sniffer.add_detection(detector.analyze_packet)

    #newly added
    live_packet_sniffer.add_detection(ssh_detector) 
    
    # Start capture in background thread
    thread = threading.Thread(target=live_packet_sniffer.start_sniff, daemon=True)
    thread.start()

    print("ICMP flood detector is running. Stop program from running with Ctrl+C.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('Shutting down...\n')
        live_packet_sniffer.stop_sniff()

if __name__ == '__main__':
    main()