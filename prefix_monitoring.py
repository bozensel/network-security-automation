def XLSExport(Rows, SheetName, FileName):
    from openpyxl import Workbook
    wb = Workbook()

    ws = wb.active
    ws.title = SheetName
    # ws = wb.create_sheet(SheetName)
    for x in Rows:
        ws.append(x)

    wb.save(FileName)

#-------------Opening entry.txt--------------#
    with open('entry.log') as f: 
        lines = f.readlines()

    input1 = []
    for line in lines:
        if 'customer' in line and "cloud" not in line and "spine" not in line:
            input1.append(line)
            
ExcelExport = [["CI", "IP", "Global Prefix", "Global Next IP", "TEC"]]
#-------------Parsing desired data from entry.txt using REGEX--------------#
    cus_nmbr = []
    cus_nm = []
    cus_prfx = []

    pattern = <snipped> # pattern for regex. 

    for line in input1:
        id = re.findall(pattern, line)
        id33 = ''.join(id)
        cus_nmbr.append(id33)

    # print(cus_nmbr)

    pattern2 = '(?<=\d_)(.*?)(?=\|)'

    for line in input1:
        id2 = re.findall(pattern2, line)
        id30 = ''.join(id2)
        id31 = id30.split('__')[0]
        cus_nm.append(id31)

    # print(cus_nm)

#-------------Data needs to be in required format--------------#
    j = 0
    cus_nmbr_name = []

    for line in cus_prfx1:
        if type(line) == list:
            for i in line:
                cus_nmbr_name.append(cus_nmbr[j] + "-" + cus_nm[j])
                # print(f"{cus_nmbr[j]} -- {cus_nm[j]} --> {i}")
                with open('sonuc.txt', 'a') as f:
                    f.write(cus_nmbr_name[j] + "**" + i + "\n")
        else:
            # print(f"{cus_nmbr[j]} -- {cus_nm[j]} --> {line}")
            cus_nmbr_name.append(cus_nmbr[j] + "-" + cus_nm[j])
            with open('sonuc.txt', 'a') as f:
                f.write(cus_nmbr_name[j] + "**" + line + "\n")
        j = j + 1

#-------------Established to the Cisco Box--------------#
    try:
        ssh.connect(ASR, port=2222, username=username, password=password, timeout=20)
        remote_connection = ssh.invoke_shell()
        
        print(colored("Connected_ASR:" + ASR, "blue"))
        remote_connection.send(" terminal length 0" + " \n")
        time.sleep(3)
        remote_connection.send(" show route vrf ddos-clean-traffic" + " \n")
        time.sleep(30)
        output = remote_connection.recv(9999999)
        result = output.decode('ascii').strip("\n")
        output_function1 = result.splitlines()

        first_prefix = []
        The_IP = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d\d?'

        for line in output_function1:
            id3 = re.findall(The_IP, line)
            id4 = "".join(id3)
            first_prefix.append(id4)

  #-------------Using "ip_address" Module to control announce of prefixes in VRF layer (with command show route vrf ddos-clean-traffic)--------------#
        for i in last_IP:
            for j in son_prefix:
                if ipaddress.ip_address(f"{i}") in ipaddress.ip_network(f"{j}"):
                    print( i + " " + j)
                    if i in anons_var:
                        continue
                    anons_var.append(i)
                    continue

        for k in anons_var:
            if k in last_IP:
                last_IP.remove(k)

        print(last_IP)

        for x in last_IP:
            remote_connection.send(" show route {}".format(x) + " \n")
            time.sleep(8)
            output3 = remote_connection.recv(65535)
            result3 = output3.decode('ascii').strip("\n")
            output_list_fnk3 = result3.splitlines()

            IP2, words14 = "", ""
            for output_list_fnk4 in output_list_fnk3:
                dds12 = []

                Regex2 = "^( )*(?P<IP>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*(from).*$"
                IPSearch2 = re.search(Regex2, output_list_fnk4)
                if IPSearch2 is not None:
                    IP2 = IPSearch2.group("IP")
                    dds12.append(IP2)

                if ("Routing entry for" in output_list_fnk4):
                    words12 = output_list_fnk4
                    words13 = words12.split(" ")
                    words14 = words13[3]
                    dds12.append(words14)

                if IP2 != "" and words14 != "":
                    IPStatus2 = "Announce False" if words14 == "0.0.0.0/0" else "Announce True"
                    Color = "red" if words14 == "0.0.0.0/0" else "green"
                    if IPStatus2 == "Announce True" and "92.44.0.146" not in IP2 and "92.44.0.251":
                        ExcelExport.append([HostName, x, words14, IP2, TAC])
                        Flag = True if IPStatus2 == "Announce True" else Flag
                    print(colored(x  + " " + IPStatus2, Color))
                    IP2, words14 = "", ""

    XLSExport(ExcelExport, "DDOS", "My_output.xlsx")

    if Flag:
        SendMailwAttachment_(ExcelExport, "My_output.xlsx")
    else:
        print("No mail needs to be sent.")

attack_analyzer()
