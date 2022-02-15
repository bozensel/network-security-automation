def ddos_update():
    
#-------------Opening Input.txt--------------#
    with open('input.log') as f: 
        lines = f.readlines()

    input1 = []
    for line in lines:
        if 'cus' in line and "cloud" not in line and "profiled" not in line and "profiled_router" not in line and "parent" not in line:
            input1.append(line)
            
ExcelExport = [["CI", "IP", "Global Network", "Global Next Hop", "TAC"]]

 #-------------Parsing required data from input.txt using REGEX--------------#
    customer_id = []
    customer_name = []
    customer_prefix = []

    pattern = '[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]?'

    for line in input1:
        id = re.findall(pattern, line)
        id33 = ''.join(id)
        customer_id.append(id33)

    # print(customer_id)

    pattern2 = '(?<=\d_)(.*?)(?=\|)'

    for line in input1:
        id2 = re.findall(pattern2, line)
        id30 = ''.join(id2)
        id31 = id30.split('__')[0]
        customer_name.append(id31)

    # print(customer_name)

    pattern3 = '(?<=\|)(.*)'

    for line in input1:
        id3 = re.findall(pattern3, line)
        customer_prefix.append(id3)

    customer_prefix1 = []

    for line in customer_prefix:
        id4 = ''.join(line)
        if ' ' not in id4:
            customer_prefix1.append(id4)
        else:
            id5 = id4.split()
            customer_prefix1.append(id5)

    customer_prefix2 = []
    
#-------------Data needs to be in required format--------------#
    j = 0
    customer_id_name = []

    for line in customer_prefix1:
        if type(line) == list:
            for i in line:
                customer_id_name.append(customer_id[j] + "-" + customer_name[j])
                # print(f"{customer_id[j]} -- {customer_name[j]} --> {i}")
                with open('sonuc.txt', 'a') as f:
                    f.write(customer_id_name[j] + "**" + i + "\n")
        else:
            # print(f"{customer_id[j]} -- {customer_name[j]} --> {line}")
            customer_id_name.append(customer_id[j] + "-" + customer_name[j])
            with open('sonuc.txt', 'a') as f:
                f.write(customer_id_name[j] + "**" + line + "\n")
        j = j + 1

    with open("sonuc.txt") as e:
        hosts = e.readlines()

    VRF_IP = []
    VRF_Cus = []

    format = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d\d?'

    for host in hosts:
        HostName = host.split("**")[0]
        VRF_Cus.append(HostName)

        HostIP2 = host.split("**")[1]
        if re.match(format, HostIP2):
            HostIP3 = HostIP2.split("/")[0]
            VRF_IP.append(HostIP3)

    print(VRF_IP)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ASR = "92.44.0.22"
    Flag = False
    
 #-------------Established to the Cisco ASR9K--------------#
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
        output_list_fnk1 = result.splitlines()

        ilk_prefix = []
        Anons_IP = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d\d?'

        for line in output_list_fnk1:
            id3 = re.findall(Anons_IP, line)
            id4 = "".join(id3)
            ilk_prefix.append(id4)

        while '' in ilk_prefix: #A method that removes specific characters. (for example "" > empty)
            ilk_prefix.remove('')

        while '0.0.0.0/0' in ilk_prefix:
            ilk_prefix.remove('0.0.0.0/0')

        son_prefix = []

        for pref in ilk_prefix:
            if pref not in son_prefix:
                son_prefix.append(pref)

        son_IP = []

        for i in VRF_IP:  # Removing concurrent IPs.
            if i not in son_IP:
                son_IP.append(i)

        anons_var = []
        anons_yok = []

  #-------------Using "ip_address" Module to control announce of prefixes in VRF layer (with command show route vrf ddos-clean-traffic)--------------#
        for i in son_IP:
            for j in son_prefix:
                if ipaddress.ip_address(f"{i}") in ipaddress.ip_network(f"{j}"):
                    print( i + " " + j)
                    if i in anons_var:
                        continue
                    anons_var.append(i)
                    continue

        for k in anons_var:
            if k in son_IP:
                son_IP.remove(k)

        print(son_IP)
        
  #-------------To control announce of prefixes in Global layer (with command show route X.X.X.X)--------------#
        for x in son_IP:
            remote_connection.send(" show route {}".format(x) + " \n")
            time.sleep(8)
            output3 = remote_connection.recv(65535)
            result3 = output3.decode('ascii').strip("\n")
            output_list_fnk3 = result3.splitlines()

            IP2, words14 = "", ""
            for output_list_fnk4 in output_list_fnk3:
                ddos3 = []

                Regex2 = "^( )*(?P<IP>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*(from).*$"
                IPSearch2 = re.search(Regex2, output_list_fnk4)
                if IPSearch2 is not None:
                    IP2 = IPSearch2.group("IP")
                    ddos3.append(IP2)

                if ("Routing entry for" in output_list_fnk4):
                    words12 = output_list_fnk4
                    words13 = words12.split(" ")
                    words14 = words13[3]
                    ddos3.append(words14)

                if IP2 != "" and words14 != "":
                    IPStatus2 = "Announce False" if words14 == "0.0.0.0/0" else "Announce True"
                    Color = "red" if words14 == "0.0.0.0/0" else "green"
                    if IPStatus2 == "Announce True" and "92.44.0.146" not in IP2 and "92.44.0.251":
                        ExcelExport.append([HostName, x, words14, IP2, TAC])
                        Flag = True if IPStatus2 == "Announce True" else Flag
                    print(colored(x  + " " + IPStatus2, Color))
                    IP2, words14 = "", ""


    except Exception as e:
        print("problem_" + "\n")

    XLSExport(ExcelExport, "DDOS 2.0", "Announce Control.xlsx")

    if Flag:
        SendMailwAttachment_(ExcelExport, "Announce Control.xlsx")
    else:
        print(" As there is no problem, no mail is send")

    os.remove('result.txt')


ddos_update()
