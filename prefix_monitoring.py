def NLS_FUNC(Satirlar, Bölüm, DosyaAdi):
    from openpyxl import Workbook
    wb = Workbook()

    ws = wb.active
    ws.title = Bölüm
    # ws = wb.create_sheet(Bölüm)
    for x in Satirlar:
        ws.append(x)

    wb.save(DosyaAdi)

##################### Opening entry.txt #####################
    with open('entry.log') as f: 
        lines = f.readlines()

    giris1 = []
    for line in lines:
        if 'auto' in line and "leaf" not in line and "spine" not in line:
            giris1.append(line)
            
ExcelExport = [["Description", "PREFIX", "Advertised IP"]]
##################### Parsing desired data from entry.txt using REGEX #####################
    client_nmbr = []
    client_nm = []
    client_prfx = []

    my_regex = <snipped> # my_regex for regex. 

    for line in giris1:
        ip = re.findall(my_regex, line)
        ip40 = ''.join(ip)
        client_nmbr.append(ip40)

    # print(client_nmbr)

    my_regex2 = <snipped> # my_regex for regex. 

    for line in giris1:
        ip80 = re.findall(my_regex2, line)
        ip90 = ''.join(ip80)
        ip91 = ip90.split('__')[0]
        client_nm.append(ip91)

    # print(client_nm)

##################### Collected logs are converted to desired format #####################
    d = 0
    client_nmbr_name = []

    for line in client_prfx1:
        if type(line) == list:
            for i in line:
                client_nmbr_name.append(client_nmbr[d] + "-" + client_nm[d])
                # print(f"{client_nmbr[d]} -- {client_nm[d]} --> {i}")
                with open('result.txt', 'a') as f:
                    f.write(client_nmbr_name[d] + "$$" + i + "\n")
        else:
            # print(f"{client_nmbr[d]} -- {client_nm[d]} --> {line}")
            client_nmbr_name.append(client_nmbr[d] + "-" + client_nm[d])
            with open('result.txt', 'a') as f:
                f.write(client_nmbr_name[d] + "$$" + line + "\n")
        d = d + 1

##################### Established to the Cisco Box #####################
    try:
        ssh.connect(NEXUS, port=22, username=username, password=password, timeout=15)
        remote_connection = ssh.invoke_shell()
        
        print(colored("Connected_NEXUS:" + NEXUS, "red"))
        remote_connection.send(" terminal length 0" + " \n")
        time.sleep(3)
        remote_connection.send(" show route vrf ddos-mpls" + " \n")
        time.sleep(90)
        output = remote_connection.recv(65000)
        result = output.decode('ascii').strip("\n")
        output_function1 = result.splitlines()

        first_prefix = []
        The_IP = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d\d?'

        for line in output_function1:
            ip3 = re.findall(The_IP, line)
            ip4 = "".join(ip3)
            first_prefix.append(ip4)

  ##################### ip_address is used to announced prefix #####################
        for i in last_IP:
            for d in son_prefix:
                if ipaddress.ip_address(f"{i}") in ipaddress.ip_network(f"{d}"):
                    print( i + " " + d)
                    if i in advervised_true:
                        continue
                    advervised_true.append(i)
                    continue

        for k in advervised_true:
            if k in last_IP:
                last_IP.remove(k)

        print(last_IP)

        for x in last_IP:
            remote_connection.send(" show route {}".format(x) + " \n")
            time.sleep(8)
            output3 = remote_connection.recv(65535)
            result3 = output3.decode('ascii').strip("\n")
            output_list_fnk3 = result3.splitlines()

            ID2, kelimeler70 = "", ""
            for output_list_fnk4 in output_list_fnk3:
                dds12 = []

                Regex2 = "^( )*(?P<IP>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*(from).*$"
                IPSearch2 = re.search(Regex2, output_list_fnk4)
                if IPSearch2 is not None:
                    ID2 = IPSearch2.group("IP")
                    dds12.append(ID2)

                if ("Routing entry for" in output_list_fnk4):
                    kelimeler12 = output_list_fnk4
                    kelimeler13 = kelimeler12.split(" ")
                    kelimeler70 = kelimeler13[3]
                    dds12.append(kelimeler70)

                if ID2 != "" and kelimeler70 != "":
                    IP_Durumu2 = "Announce False" if kelimeler70 == "0.0.0.0/0" else "Announce True"
                    Color = "red" if kelimeler70 == "0.0.0.0/0" else "green"
                    if IP_Durumu2 == "Announce True" and "100.23.70.20" not in ID2 and "100.23.70.21":
                        ExcelExport.append([HostName, x, kelimeler70, ID2])
                        Flag = True if IP_Durumu2 == "Announce True" else Flag
                    print(colored(x  + " " + IP_Durumu2, Color))
                    ID2, kelimeler70 = "", ""

    NLS_FUNC(ExcelExport, "DDOS", "My_output.xlsx")

    if Flag:
        SendMailwAttachment_(ExcelExport, "My_output.xlsx")
    else:
        print("No mail needs to be sent.")


attack_analyzer()
