import csv
from collections import defaultdict
import os

def process_data(input_file, output_file):
    ip_data = defaultdict()

    with open(input_file, 'r') as file:
        reader = csv.reader(file)
        next(reader)
        for row in reader:
            source_ip, dest_ip, source_port, dest_port, packet_count, byte_count = row

            if source_ip not in ip_data:
                ip_data[source_ip] = {'received_packets': 0, 'received_bytes': 0, 'sent_packets': 0, 'sent_bytes': 0}
            ip_data[source_ip]['sent_packets'] += int(packet_count)
            ip_data[source_ip]['sent_bytes'] += int(byte_count)

            if dest_ip not in ip_data:
                ip_data[dest_ip] = {'received_packets': 0, 'received_bytes': 0, 'sent_packets': 0, 'sent_bytes': 0}
            ip_data[dest_ip]['received_packets'] += int(packet_count)
            ip_data[dest_ip]['received_bytes'] += int(byte_count)

    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP адрес', 'кол-во принятых пакетов', 'кол-во принятых байт', 'кол-во переданных пакетов', 'кол-в переданных байт'])
        for ip, data in ip_data.items():
            writer.writerow([ip, data['received_packets'], data['received_bytes'], data['sent_packets'], data['sent_bytes']])


if __name__ == "__main__":
    input_csv = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', "output.csv"))
    output_csv = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', "output_from_py.csv"))

    process_data(input_csv, output_csv)
    print(f"Data processed and stored in: {output_csv}")
