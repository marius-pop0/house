import sys

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
                    print("Invalid flag in rule "+line_count)
                    sys.exit(0)
            # error on reading line (formatting)
            else:
                print("wrong line format on line in rule " + line_count)
                sys.exit(0)

            #get rule dir
            if (line_split[0] == "in" or line_split[0] == "out"):
                rule_dir = line_split[0]
            else:
                print("Invalid direction in rule "+line_count)
                sys.exit(0)

            #get rule action
            if (line_split[1] == "accept" or line_split[1] == "drop" or line_split[1] == "deny"):
                rule_action = line_split[1]
            else:
                print("Invalid action in rule "+line_count)
                sys.exit(0)

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
                    print("invalid ip at rule "+line_count)
                rule_subnet_size=int(ip_subnet[1])

            #get rule port(s)
            rule_port=line_split[3]
            rule_ports=rule_port.split(",")
            ##error check
            for ports in rule_ports:
                if (ports=="*"):
                    pass
                elif (int(ports)< 0 or int(ports) > 65535):
                    print("invalid port number at rule "+line_count)


            ##what to do when packet matches
            ###add here###
            ######

            print("Direction: " + rule_dir + " Action: " + rule_action + " IP: " + rule_ip + " Subnet Size: "+str(rule_subnet_size) + " Port: " +
              str(rule_ports) + " Flag: " + rule_flag)

            line_count += 1
            ##############
        file_object.close()

    except FileNotFoundError:
        print("Could not find rule file")
        sys.exit(0)

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

            print("Direction: " + dir + " IP: " + ip + " Port: " + str(port) + " Flag: " +
                  str(flag))
            findMatch(dir,ip,port,flag)

        else:
            print("wrong line format on line in packet")
            sys.exit(0)
    ###############

