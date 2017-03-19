import string, sys


if __name__ == '__main__':
    if len(sys.argv) == 2:
        ruleFile = sys.argv[1]
    else:
        print("wrong number of arguments")
        sys.exit(0)

    #############reading rules
    try:
        file_object=open(ruleFile,'r')
        line_count = 1
        for line in file_object:
            print("line #" + str(line_count) + " : " + line)
            line_split=line.split()
            dir=""
            action=""
            ip=""
            port=-1
            flag=""

            #does not contain flag
            if (len(line_split)==4):
                print("Direction: "+line_split[0]+" Action: "+line_split[1]+" IP: "+line_split[2]+" Port: "+line_split[3])
            #line contains flag
            elif (len(line_split)==5):
                print("Direction: "+line_split[0]+" Action: "+line_split[1]+" IP: "+line_split[2]+" Port: "+line_split[3]+" Flag: "+line_split[4])
            #error on reading line (formatting)
            else:
                print("wrong line format on line in rule "+line_count)
                sys.exit(0)
            line_count += 1

        file_object.close()
    except FileNotFoundError:
        print("Could not find rule file")
    ##############

    ###########reading packets from standard input
    for line2 in sys.stdin:
        line2_split = line2.split()
        if (len(line2_split) == 4):
            print("Direction: " + line2_split[0] + " IP: " + line2_split[1] + " Port: " + line2_split[2] + " Flag: " +line2_split[3])
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

            if(int(line2_split[2])>=1 and int(line2_split[2])<=65535):
                port=int(line2_split[2])
            else:
                print("invalid port number in packet")
                sys.exit(0)
            if (int(line2_split[3]) == 0 or int(line2_split[3]) == 1):
                flag = int(line2_split[3])
            else:
                print("Invalid packet flag")
                sys.exit(0)

        else:
            print("wrong line format on line in packet")
            sys.exit(0)
    ###############