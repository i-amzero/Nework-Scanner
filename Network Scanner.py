import nmap

scanner = nmap.PortScanner()
print("*" * 100)
print("""

         _         _    ___________   ________    __      __         ______       __
         \ \      / /  |____   ____| |  ______|  |  |    |  |       /  /\  \     |  |
          \ \    / /        | |      |  |_____   |  |____|  |      /  /__\  \    |  |
           \ \  / /    _____| |____  |_____   |  |   ____   |     /  /____\  \   |  |
            \ \/ /     |___________|  _____|  |  |  |    |  |    /  /      \  \  |  |______
                                     |________|  |__|    |__|   /__/        \__\ |_________|
                                     
                                                                                               """)
print("*" * 100)
Ip_address = input("Enter the ip address: ")
# Ip_address = '192.168.1.1'
print("""\tWelcome To Cyber Ailment Tools pack
        1. SYN-ACK Scanning \n \t\t2. UDP Scanning \n \t\t3. COMPREHENSIVE Scanning \n \t\t4. Regular Scanning \n \t\t5. OS DETECTION \n \t\t6. Multiple IP Range  \n \t\t7. Ping Scan \n """)
Input = int(input("Choose the Service number :"))

# If user's input is 1, perform a SYN/ACK scan
if Input == 1:
    scanner.scan(Ip_address, '1-1024', '-v -sS')
    # Here, v is used for verbose, which means if selected it will give extra information
    # 1-1024 means the port number we want to search on
    # -sS means perform a TCP SYN connect scan, it send the SYN packets to the host
    print(scanner.scaninfo())
    print("Ip status :", scanner[Ip_address].state())
    print("Protocols :", scanner[Ip_address].all_protocols())
    print("Open ports :", list(scanner[Ip_address]['tcp'].keys()))

# If user's input is 2, perform a UDP Scan 
elif Input == 2:
    scanner.scan(Ip_address, '1-1024', '-v -sU')
    # -sU means perform a UDP SYN connect scan, it send the SYN packets to #the host
    print(scanner.scaninfo())
    print("Ip status :", scanner[Ip_address].state())
    print("Protocols :", scanner[Ip_address].all_protocols())
    print("Open ports :", list(scanner[Ip_address]['udp'].keys()))

# If user's input is 3, perform a Comprehensive scan
elif Input == 3:
    scanner.scan(Ip_address, '1-1024', '-v -sS -sV -sC -A -O')
    # sS for SYN scan, sv probe open ports to determine what service and version they are running on
    # O determine OS type, A tells Nmap to make an effort in identifying the target OS
    print(scanner.scaninfo())
    print("Ip status :", scanner[Ip_address].state())
    # here state() tells if target is up or down
    print("Protocols :", scanner[Ip_address].all_protocols())
    print("Open ports :", list(scanner[Ip_address]['tcp'].keys()))

# If user's input is 4, perform a Regular Scan
elif Input == 4:
    scanner.scan(Ip_address)
    print(scanner.scaninfo())
    print("Ip status :", scanner[Ip_address].state())
    print("Protocols :", scanner[Ip_address].all_protocols())
    print("Open ports :", list(scanner[Ip_address]['tcp'].keys()))
elif Input == 5:
    os_results = scanner.scan(hosts=Ip_address, arguments='-A')
    print("os_details :", os_results['scan'])
    # print(scanner.scan("192.168.1.6", arguments="-O")['scan']['192.168.1.6']['osmatch'][1])
elif Input == 6:
    Ip_address = input("Enter multiple IPs Here :")
    scanner.scan(Ip_address, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip status :", scanner[Ip_address].state())
    print("Protocols :", scanner[Ip_address].all_protocols())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("Open ports :", list(scanner[Ip_address]['tcp'].keys()))

elif Input == 7:
    scanner.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    for host, status in hosts_list:
        print('{0}:{1}'.format(host, status))

else:
    print("Please enter valid input from the Given choice :")
