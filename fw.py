import sys

def bin_to_IP(ipBin):
    original_ip=""
    ip_1 = int(ipBin[:8],2)
    ip_2 = int(ipBin[8:16],2)
    ip_3 = int(ipBin[16:24],2)
    ip_4 = int(ipBin[24:32],2)
    #print(ipBin)
    original_ip=str(ip_1)+"."+str(ip_2)+"."+str(ip_3)+"."+str(ip_4)
    return original_ip

def findMatch(dir,ip,port,flag):
    #############reading rules
    line_count = 1
    try:
        file_object = open(ruleFile, 'r')
        for line in file_object:
            #print("line #" + str(line_count) + " : " + line)

            line_split = line.split()
            rule_dir = ""
            rule_action = ""
            rule_ip = ""
            rule_subnet_size=0
            rule_ports = []
            rule_flag = ""

            # does not contain flag
            if (len(line_split) == 4):
                pass
            # line contains flag
            elif (len(line_split) == 5):
                if(line_split[4]=="established"):
                    rule_flag=line_split[4]
                else:
                    #print("Invalid flag in rule "+ str(line_count))
                    line_count += 1
                    continue
                    #sys.exit(0)
            # error on reading line (formatting)
            else:
                #print("wrong line format on line in rule " + str(line_count))
                line_count += 1
                continue
                #sys.exit(0)

            #get rule dir
            if (line_split[0] == "in" or line_split[0] == "out"):
                rule_dir = line_split[0]
            else:
                #print("Invalid direction in rule "+str(line_count))
                line_count += 1
                continue
                #sys.exit(0)

            #get rule action
            if (line_split[1] == "accept" or line_split[1] == "drop" or line_split[1] == "deny"):
                rule_action = line_split[1]
            else:
                #print("Invalid action in rule "+str(line_count))
                line_count += 1
                continue
                #sys.exit(0)

            #get rule IP/subnet mask
            rule_ip = line_split[2]
            ip_subnet=rule_ip.split("/")
            if(len(ip_subnet)==2):
                ip_split=ip_subnet[0].split(".")
                if (len(ip_split) == 4):
                    ip_1 = '{0:08b}'.format(int(ip_split[0]))
                    ip_2 = '{0:08b}'.format(int(ip_split[1]))
                    ip_3 = '{0:08b}'.format(int(ip_split[2]))
                    ip_4 = '{0:08b}'.format(int(ip_split[3]))
                    #ip in binary
                    rule_ip = ip_1 + ip_2 + ip_3 + ip_4
                else:
                    #print("invalid ip at rule "+str(line_count))
                    line_count += 1
                    continue
                rule_subnet_size=int(ip_subnet[1])

            #get rule port(s)
            rule_port=line_split[3]
            rule_ports=rule_port.split(",")
            ##error check
            for ports in rule_ports:
                if (ports=="*"):
                    pass
                elif (int(ports)< 0 or int(ports) > 65535):
                    #print("invalid port number at rule "+str(line_count))
                    line_count += 1
                    continue



            ##has some bugs!
            if(rule_ip=="*" or (ip[:rule_subnet_size]==rule_ip[:rule_subnet_size])):
                for ports in rule_ports:
                    if(ports=="*" or (int(ports)==port)):
                        if(dir==rule_dir):
                            if ((flag==1 and rule_flag=="established") or (flag==0 and rule_flag=="") or (flag==1 and rule_flag=="")):
                                original_ip=bin_to_IP(ip)
                                file_object.close()
                                return (rule_action+"("+str(line_count)+") "+dir+" "+original_ip+" "+str(port))



            #print("Direction: " + rule_dir + " Action: " + rule_action + " IP: " + rule_ip + " Subnet Size: "+str(rule_subnet_size) + " Port: " +
            #  str(rule_ports) + " Flag: " + rule_flag)

            line_count += 1
            ##############

        file_object.close()
        return ("none")
    except FileNotFoundError:
        print("Could not find rule file")
        sys.exit(0)


#python fw.py rules.txt < packets.txt
if __name__ == '__main__':
    if len(sys.argv) == 2:
        ruleFile = sys.argv[1]
    else:
        print("wrong number of arguments")
        sys.exit(0)

    ###########reading packets from standard input
    for line2 in sys.stdin:
        line2_split = line2.split()
        if (len(line2_split) == 4):
            dir=""
            ip=""
            port=-1
            flag=-1

            if(line2_split[0]=="in" or line2_split[0]=="out"):
                dir=line2_split[0]
            else:
                print("Invalid packet direction")
                sys.exit(0)

            ip=line2_split[1]
            ip_split=ip.split(".")
            if(len(ip_split)==4):
                ip_1 = '{0:08b}'.format(int(ip_split[0]))
                ip_2 = '{0:08b}'.format(int(ip_split[1]))
                ip_3 = '{0:08b}'.format(int(ip_split[2]))
                ip_4 = '{0:08b}'.format(int(ip_split[3]))

                # ip in binary
                ip = ip_1 + ip_2 + ip_3 + ip_4
            else:
                print("invalid IP address in packet")
                sys.exit(0)

            if(int(line2_split[2])>=0 and int(line2_split[2])<=65535):
                port=int(line2_split[2])
            else:
                print("invalid port number in packet")
                sys.exit(0)
            if (int(line2_split[3]) == 0 or int(line2_split[3]) == 1):
                flag = int(line2_split[3])
            else:
                print("Invalid packet flag")
                sys.exit(0)

            #print("Direction: " + dir + " IP: " + ip + " Port: " + str(port) + " Flag: " +
            #     str(flag))
            result = findMatch(dir,ip,port,flag)
            if (result=="none"):
                original_ip=bin_to_IP(ip)
                print("drop() "+dir+" "+original_ip+" "+str(port)+" "+str(flag))
            else:
                print(result)

        else:
            print("wrong line format on line in packet")
            sys.exit(0)
    ###############

