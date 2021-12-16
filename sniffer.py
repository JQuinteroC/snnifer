"""
Descripción: Sniffer
Autores:
    Fabian Enrique León Junco - 20171020015
    José Luis Quintero Cañizalez - 20181020061
    Yeisson Steven Cardozo Herran - 20192020131
"""

import socket
import struct
import textwrap
import binascii

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    #Ultimo argumento verifica que sea compatible entre todos los dispositivos
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    #ARP
    connarp = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = capture_packages(raw_data)
        if eth_proto != 1544:
            print('\nPaquete :')
            print(f'Destino: {dest_mac}, Origen: {src_mac}, Protocolo: {eth_proto}')
        # 8 / IP
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ip_packet(data)
            print(TAB_1 + 'Paquete IP: ')
            print(TAB_2 + f'Versión {version}, Longitud del encabezado: {header_length}, Time to live: {ttl}')
            print(TAB_2 + f'Protocolo {proto}, Origen: {src}, Destino: {target}')

            #ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'Paquete ICMP: ')
                print(TAB_2 + f'Tipo: {icmp_type}, Código: {code}, Checksum: {checksum}, ')
                print(TAB_2 + 'Datos: ')
                print(format_multi_line(DATA_TAB_3, data))

            #TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'Segmento TCP: ')
                print(TAB_2 + f'Puerto de origen: {src_port}, Puerto de destino: {dest_port}, ')
                print(TAB_2 + f'Secuencia: {sequence}, Número de acuse de recibo: {acknowledgement}, ')
                print(TAB_2 + 'Banderas: ')
                print(TAB_3 + f'URG: {flag_urg}, ACK, {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                print(TAB_2 + 'Datos: ')
                print(format_multi_line(DATA_TAB_3, data))
            
            #UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'Segmento UDP:')
                print(TAB_2 + f'Puerto de origen: {src_port}, Puerto de destino: {dest_port}, longitud: {length}')
                print(TAB_2 + 'Datos: ')
                print(format_multi_line(DATA_TAB_3, data))
            
            #Otro
            else:
                print(TAB_1 + 'Datos: ')
                print(format_multi_line(DATA_TAB_1, data))      
        
        elif eth_proto != 1544:
            print(TAB_1 + 'Datos: ')
            print(format_multi_line(DATA_TAB_1, data))

        paquete_arp = connarp.recvfrom(2048)
        ethernet_header = paquete_arp[0][:14]
        ethernet_detalles = struct.unpack('!6s6s2s', ethernet_header)

        cabecera_arp = paquete_arp[0][14:42]
        arp_detalles = struct.unpack('2s2s1s1s2s6s4s6s4s', cabecera_arp)
        ethertype = ethernet_detalles[2]

        #Paquete ARP
        if ethertype == b'\x08\x06':
            print('\nPaquete ARP:')
            print(TAB_1 + 'Tipo de hardware: {}, Tipo de protocolo: {}'.format(str(binascii.hexlify(arp_detalles[0]), 'utf-8'),
                                                                               str(binascii.hexlify(arp_detalles[1]), 'utf-8')))
            print(TAB_1 + 'Tamaño del hardware: {}, Tamaño del protocolo: {}, opcode: {}'.format(str(binascii.hexlify(arp_detalles[2]), 'utf-8'),
                                                                                     str(binascii.hexlify(arp_detalles[3]), 'utf-8'),
                                                                                                 str(binascii.hexlify(arp_detalles[4]), 'utf-8')))
            print(TAB_1 + 'Dirección MAC origen: {}, Dirección IP origen: {}'.format(str(binascii.hexlify(arp_detalles[5]), 'utf-8'),
                                                                                     socket.inet_ntoa(arp_detalles[6])))
            print(TAB_1 + 'Dirección MAC destino: {}, Dirección IP destino: {}'.format(str(binascii.hexlify(arp_detalles[7]), 'utf-8'),
                                                                                     socket.inet_ntoa(arp_detalles[8])))
    
def capture_packages(data):
    """Obtiene la información del paquete
        ---
        Sync -- Sincroniza el dispositivo y el router
        Receiver -- Quien lo recibe
        Sender -- Quien lo envía
        Type -- IP4, IP6, ARP, etc ...
        Payload -- (IP/ARP frame + padding), datos
        CRC -- manejo de errores, se asegura de que se reciba la información correctamente
        ---

    Args:
        data : paquete
    Returns:
        direcciones mac de destino, origen, tipo de protocolo y payload
    """
    destination, source, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(destination), get_mac_addr(source), socket.htons(protocol), data[14:]

def get_mac_addr(bytes_addr):
    """Pasa la dirección mac a formato legible

    Args:
        bytes_addr: dirección mac en bytes

    Returns:
        dirección mac en formato legible
    """
    bytes_string = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_string).upper()

def ip_packet(data):
    """    Información que viene antes del payload
           ---
           Version
           IHL -- Longitud del encabezado
           TTL -- Time To Live
           Procol -- protocolo usado TCP, UDP etc 
           Source address -- ip de origen
           Destination address -- ip de destino
           ---

    Args:
        data: paquete ip

    Returns:
        version, header_length, ttl, protocol, source ip, target ip, payload
    """
    version_header_length = data[0]
    version = version_header_length >> 4 
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return version, header_length, ttl, proto, ipv(src), ipv(target), data[header_length:]

def ipv(addr):
    """Pasa la dirección ip a formato legible

    Args:
        addr: dirección ip en bytes

    Returns:
        dirección ip en formato X.X.X.X
    """
    return '.'.join(map(str, addr))

def icmp_packet(data):
    """Obtiene la información para el protocolo ICMP

    Args:
        data: payload de tipo ICMP

    Returns:
        tipo de icmp, code, checksum, información del paquete
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    """Obtiene la información para el protocolo TCP/IP

    Args:
        data: datos de tipo TCP/IP

    Returns:
        puerto de origen, puerto de destino, sequence, acknowledgement, banderas, datos
    """
    (source_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    offset = (offset_reserved_flags >> 12) * 4
    bandera_urg = (offset_reserved_flags & 32) >> 5
    bandera_ack = (offset_reserved_flags & 16) >> 4
    bandera_psh = (offset_reserved_flags & 8) >> 3
    bandera_rst = (offset_reserved_flags & 4) >> 2
    bandera_syn = (offset_reserved_flags & 2) >> 1
    bandera_fin = offset_reserved_flags & 1
    
    return source_port, dest_port, sequence, acknowledgement, bandera_urg, bandera_ack, bandera_psh, bandera_rst, bandera_syn, bandera_fin, data[offset:]

def udp_segment(data):
    """Obtiene la información para el protocolo UDP

    Args:
        data:payload de tipo UDP 

    Returns:
        puerto de origen, puerto de destino, tamaño, información del paquete
    """
    source_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size= 80):
    """Identa lineas para strings de gran tamaño

    Args:
        prefix: prefijo
        string: data
        size: tamaño

    Returns:
        información identada
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()