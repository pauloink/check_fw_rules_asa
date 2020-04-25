# $language = "Python"
from netmiko import ConnectHandler
import getpass

ip = input("DIGITE O IP DE GERENCIA DO FIREWALL: ")
senha = getpass.getpass("DIGITE A SUA SENHA: ")
src_ip = input("DIGITE O IP DE ORIGEM: ")
dst_ip = input("DIGITE O IP DE DESTINO: ")
tcp_udp = input("PROTOCOLO TCP OU UDP: ")
dst_port = input("DIGITE A PORTA DE DESTINO: ")

ip = str(ip)
ip_addr = ip.split('.')
user = getpass.getuser()
print("CONECTANDO AO HOST %s..." % ip)

fw_asa = {
    'device_type':'cisco_asa'
}
fw_asa['ip'] = ip
fw_asa['password'] = senha
fw_asa['username'] = user
fw_asa['secret'] = senha

net_connect = ConnectHandler(**fw_asa)

net_connect.find_prompt()

nameif = net_connect.send_command("show nameif")
nameif_entry = nameif.split()
del nameif_entry[0:4]
nameif_edited = nameif_entry[::3]
nameif_edited_len = len(nameif_edited)

x = -1
if net_connect.send_command("show version").__contains__("Firepower"):
    for find_int in nameif_edited:
        x += 1
        try:
            find_int = net_connect.send_command("show route interface %s" (nameif_edited[x], src_ip))
        except:
            IndexError: find_int = "null"
        if x >= 10:
            break
        elif find_int.__contains__(nameif_edited[x]):
            interface_in_edited = nameif_edited[x]
            break
        else:
            continue

else:
    print("DEVIDO A LIMITAÇÃO DA VERSÃO DO ASA, É NECESSÁRIO CONFIRMAR A INTERFACE DE ENTRADA DO TRÁFEGO")
    for find_int in nameif_edited:
        x += 1
        try:
            find_int = net_connect.send_command("show route %s %s" (nameif_edited[x], src_ip))
        except:
            IndexError: find_int = "null"
        if x >= 10:
            break
        elif find_int.__contains__("S    1"):
            interface_in_edited = nameif_edited[x]
            break
        else:
            continue

try:
    interface_in_edited
except NameError:
    interface_in_edited = None

if interface_in_edited is None:
    print("NÃO HÁ ROTEAMENTO PARA A ORIGEM DESEJADA")
elif interface_in_edited.__contains__("0.0.0.0"):
    print("ORIGEM ALCANÇADA VIA ROTA DEFAULT. FAVOR VERIFICAR SE É NECESSÁRIO ROTA MAIS ESPECIFICA")

packet_tracer_output = net_connect.send_command("packet-tracer input %s %s %s 3333 %s %s" % (interface_in_edited, tcp_udp, src_ip, dst_ip, dst_port))
print(packet_tracer_output)

print("############################################################\n                      RESULTADO           \n############################################################")
if packet_tracer_output.__contains__("Action: allow"):
    print("-->TRAFEGO LIBERADO\n\n--->VERIFICAR A NECESSIDADE DE ROTA MAIS ESPECIFICA")

else:
    print("--->TRAFEGO BLOQUEADO!!! VERIFIQUE A RAZÃO DO DROP.\n--->TRAFEGO DE ORIGEM CHEGA PELA INTERFACE %s\n\n" % interface_in_edited)
    access_group = net_connect.send_command("show running-config access-group")
    access_group_split = access_group.split()

    print("--->LIBERAR TRAFEGO NA ACL %s\n\n" % access_group_split[1])
    print("--->SUGESTAO DE REGRA: access-list %s extended permit %s host %s host %s %s" % (access_group_split[1], tcp_udp, src_ip,dst_ip, dst_port))
