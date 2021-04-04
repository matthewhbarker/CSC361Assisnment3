import sys
import structs
import struct
import socket

first_packet = True
original_starting_time = 0
connections = []


def main():
    file = sys.argv[1]
    f = open(file, "rb")
    globalHeaderBits = f.read(24)  # get global header
    global_header = load_global_header(globalHeaderBits)

    while True:
        packet = load_packet(f)

        if packet is None:
            break

        check_packet(packet)

    #print("A) Total Number of connections:", len(connections))
    #print("--------------------------------------------")


    connection_details()


def check_packet(packet):
    source_ip = packet.IP_header.src_ip
    destination_ip = packet.IP_header.dst_ip
    source_port = packet.TCP_header.src_port
    destination_port = packet.TCP_header.dst_port

    buffer = (source_ip, source_port, destination_ip, destination_port)

    packet_id = struct.unpack("!I", socket.inet_aton(source_ip))[0] + \
                struct.unpack("!I", socket.inet_aton(destination_ip))[0] + source_port + destination_port

    global connections

    exists = False
    for connection in connections:
        if packet_id == connection["id"]:
            connection["packet_list"].append(packet)
            connection["SYN"] = packet.TCP_header.flags["SYN"] + connection["SYN"]
            connection["FIN"] = packet.TCP_header.flags["FIN"] + connection["FIN"]
            connection["RST"] = packet.TCP_header.flags["RST"] + connection["RST"]
            exists = True

    if not exists:
        connections.append(
            {
                "id": packet_id,
                "buffer": buffer,
                "packet_list": [packet],
                "SYN": packet.TCP_header.flags["SYN"],
                "FIN": packet.TCP_header.flags["FIN"],
                "RST": packet.TCP_header.flags["RST"]
            }
        )


def connection_details():
    connection_num = 1
    complete_connection_num = 0
    reset_connection_num = 0
    open_connection_num = 0
    complete_connections = []

    #print("B) Connection Details:")
    for connection in connections:
        #print("Connection:", connection_num)  # print con num
        connection_num += 1

        #print("Source Address:", connection["buffer"][0])  # printing addresses and ports
        #print("Source Port:", connection["buffer"][1])
        #print("Destination Address:", connection["buffer"][2])
        #print("Destination Port:", connection["buffer"][3])

        status = "S" + str(connection["SYN"]) + "F" + str(connection["FIN"])  # printing status
        if connection["RST"] > 0:
            status += "/R"
            reset_connection_num += 1
        #print("Status:", status)

        # check if connection is open
        if connection["SYN"] > 0 and connection["FIN"] == 0:
            open_connection_num += 1

        # if connection is complete
        if connection["SYN"] > 0 and connection["FIN"] > 0:

            complete_connections.append(connection)
            complete_connection_num += 1
            start_time = connection["packet_list"][0].timestamp
            end_time = connection["packet_list"][len(connection["packet_list"]) - 1].timestamp

            #print("Start time:", start_time)
            #print("End time:", end_time)
            #print("Duration: ", end_time - start_time)
            client_send = 0
            server_send = 0
            client_size = 0
            server_size = 0

            for packet in connection["packet_list"]:  # for loop to go through packet
                ip_length = packet.IP_header.ip_header_len
                ip_total = packet.IP_header.total_len
                tcp_offset = packet.TCP_header.data_offset
                size = ip_total - ip_length - tcp_offset

                if packet.IP_header.src_ip == connection["buffer"][0]:
                    client_send += 1
                    client_size += size
                else:
                    server_send += 1
                    server_size += size

            #print("Number of packets sent from Source to Destination:", client_send)
            #print("Number of packets sent from Destination to Source:", server_send)
            #print("Total number of packets:", client_send + server_send)
            #print("Number of data bytes sent from Source to Destination:", client_size)
            #print("Number of data bytes sent from Destination to Source:", server_size)
            #print("Total number of bytes sent:", client_size + server_size)
        #print("--------------------------------------------")

    #print("C) GENERAL")
    #print("Total number of complete TCP connections:", complete_connection_num)
    #print("Number of reset TCP connections:", reset_connection_num)
    #print("Number of TCP connections that were still open when the trace capture ended:", open_connection_num)

    TCP_connections(complete_connections)


def TCP_connections(complete_connections):
    #print("--------------------------------------------")
    #print("D) Complete TCP connections:")

    min_time = 999999
    max_time = 0
    mean_time = 0

    min_packets = 999999
    max_packets = 0
    mean_packet = 0

    min_window = 999999
    max_window = 0
    mean_window = 0

    i = 0
    f = 0

    for connection in complete_connections:
        start_time = connection["packet_list"][0].timestamp
        end_time = connection["packet_list"][len(connection["packet_list"]) - 1].timestamp
        duration = end_time - start_time
        time = duration
        min_time = min(time, min_time)
        max_time = max(time, max_time)
        mean_time += time

        num_packets = len(connection["packet_list"])
        min_packets = min(num_packets, min_packets)
        max_packets = max(num_packets, max_packets)
        mean_packet += num_packets

        for packet in connection["packet_list"]:
            min_window = min(packet.TCP_header.window_size, min_window)
            max_window = max(packet.TCP_header.window_size, max_window)
            mean_window += packet.TCP_header.window_size
            f += 1

        i += 1

    #print("Minimum time duration:", min_time)
    #print("Mean time duration:", mean_time / i)
    #print("Maximum time duration:", max_time)

    #print("\nMinimum number of packets sent/received:", min_packets)
    #print("Mean number of packets sent/received:", mean_packet / i)
    #print("Maximum number of packets sent/received:", max_packets)

    #print("\nMinimum receive window size including sent/received:", min_packets, "bytes")
    #print("Mean receive window size including sent/received:", mean_window / f, "bytes")
    #print("Maximum receive window size including sent/received:", max_window, "bytes")




def load_packet(f):
    packet_header = f.read(16)


    if not packet_header:
        return None

    global first_packet  # getting the original starting time if we are running through the first packet
    global original_starting_time
    if first_packet:
        orig_time_seconds = packet_header[0:4]
        orig_time_micro = packet_header[4:8]

        seconds = struct.unpack('I', orig_time_seconds)[0]
        microseconds = struct.unpack('I', orig_time_micro)[0]

        original_starting_time = seconds + microseconds / 1000000
        first_packet = False

    packet = structs.packet()

    buffer1 = packet_header[0:4]
    buffer2 = packet_header[4:8]
    incl_len = packet_header[8:12]
    original_len = packet_header[12:16]

    packet.timestamp_set(buffer1, buffer2, original_starting_time)
    packet.set_incl_len(incl_len)

    # read packet data using incel length
    packet_data = f.read(packet.incl_len)

    # create ipv4 header
    IPV4_header = structs.IP_Header()
    header_length = packet_data[14:15]
    total_length = packet_data[16:18]
    source_address = packet_data[26:30]
    destination_adress = packet_data[30:34]

    TTL = packet_data[22:23]
    protocol = packet_data[23:24]

    IPV4_header.get_IP(source_address, destination_adress)
    IPV4_header.get_total_len(total_length)
    IPV4_header.get_header_len(header_length)
    IPV4_header.get_TTL_and_protocol(TTL,protocol)

    #print("TTL:",IPV4_header.TTL)
    #print("protocol",IPV4_header.protocol)

    if IPV4_header.protocol == 1:
        icmp_type = packet_data[34:35]
        icmp_code = packet_data[35:36]
        checksum = packet_data[36:38]
        icmp_data = packet_data[38:42]

        IPV4_header.get_icmp(icmp_type, icmp_code, icmp_data)
        IPV4_header.get_checksum(checksum)



    # create TCP header
    TCP_header = structs.TCP_Header()
    src_port = packet_data[34:36]
    destination_port = packet_data[36:38]
    seq_number = packet_data[38:42]
    ack_number = packet_data[42:46]
    data_offset = packet_data[46:47]
    flags = packet_data[47:48]
    window_size1 = packet_data[48:49]
    window_size2 = packet_data[49:50]

    TCP_header.get_src_port(src_port)
    TCP_header.get_dst_port(destination_port)
    TCP_header.get_seq_num(seq_number)
    TCP_header.get_ack_num(ack_number)
    TCP_header.get_data_offset(data_offset)
    TCP_header.get_flags(flags)
    TCP_header.get_window_size(window_size1, window_size2)

    packet.IP_header = IPV4_header
    packet.TCP_header = TCP_header

    return packet


def load_global_header(globalHeaderBits):
    global_header = structs.pcap_header()
    global_header.set_magic_number(globalHeaderBits[0:4])
    global_header.set_version_major(globalHeaderBits[4:6])
    global_header.set_version_minor(globalHeaderBits[6:8])
    global_header.set_this_zone(globalHeaderBits[8:12])
    global_header.set_sigfigs(globalHeaderBits[12:16])
    global_header.set_snaplen(globalHeaderBits[16:20])
    global_header.set_network(globalHeaderBits[20:24])
    return global_header


if __name__ == '__main__':
    main()
