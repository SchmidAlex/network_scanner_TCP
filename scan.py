#!/usr/bin/env python
# Author: Alexander Schmid
# Version: Alpha

# This should be a script, which searches alive hosts in a range
# With the result we make a versionscan on the alive hosts and create a short overview of it
# With the open ports of the versionscan we can automatically make a testssl (if installed)
# The cherry on the top is the copy paste preparation for an openvas scan based on the results

# Why? This should make the scanning so efficiant as possible and no step will be forgotten

import argparse
import io
import subprocess
import sys
import os
import xml.etree.ElementTree as elementTree
from datetime import datetime

def run_command(command):
    print("\nRunning command: "+' '.join(command))
    sp = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = ""
    while True:
        try:
            out = sp.stdout.read(1).decode('utf-8')
            if out == '' and sp.poll() != None:
                break
            if out != '':
                output += out
                sys.stdout.write(out)
                sys.stdout.flush()
        except UnicodeDecodeError as e:
            print("UnicodeDecodeError: ", e)
            continue
    return output

def search_alive_hosts(ip, directory, isList, tcp_ports):
    print("Checking given IP's or range for hosts that are alive\n")
    portlistTCP = "21,22,23,25,49,53,80,88,110,123,135,138,143,389,443,445,464,465,514,515,544,546,547,591,636,902,989,990,992,993,994,995,1433,1434,1503,1521,1630,1720,2375,2376,3128,3268,3389,3544,3939,5000,5061,5666,5667,5722,5986,6000,6443,6881,6882,6883,6884,6885,6886,6887,6888,6889,8080,8200,8443,8530,8531,9100,9800,10250,10259,10257,27017"

    if tcp_ports :
        portlistTCP = portlistTCP + "," +  tcp_ports

    if isList :
        cmd = ["sudo", "nmap", "-sT", "-Pn", "-p", portlistTCP, "-iL", ip, "-oA", directory + "/nmap/alive_hosts_tcp"]
        run_command(cmd)
    else :
        cmd = ["sudo", "nmap", "-sT", "-Pn", "-p", portlistTCP, ip, "-oA", directory + "/nmap/alive_hosts_tcp"]
        run_command(cmd)

def extract_alive_hosts(directory, openvasTCP):
    if os.path.isfile(directory + "/tcp_scan.txt") :
        cmd = ["rm", directory + "/tcp_scan.txt"]
        run_command(cmd)
    cmd = ["touch", directory + "/tcp_scan.txt"]
    run_command(cmd)

    try:
        treeTCP = elementTree.parse(directory + "/nmap/alive_hosts_tcp.xml")
    except elementTree.ParseError as e:
        print("Compare elementTree.ParseError: ", e)
        cleanedData = clean_xml_data(directory + "/nmap/alive_hosts_tcp.xml")
        treeTCP = elementTree.parse(io.StringIO(cleanedData))
        pass
    aliveHostsTCP = []
    
    tempHost = None
    rootTCP = treeTCP.getroot()
    for child in rootTCP.findall("host"):
        up = False
        for host in child.findall("address"):
            if host.attrib['addrtype'] == 'ipv4':
                tempHost = str(host.attrib['addr'])
        for states in child.findall("status") :
            if states.attrib['state'] == 'up' :
                up = True
        if up == True :
            for ports in child.findall('ports') :
                for port in ports.findall('port'):
                    if port.find('state').attrib['state'] == 'open' :
                        if tempHost not in aliveHostsTCP :
                            aliveHostsTCP.append(str(tempHost))
                
    outfile = open(directory + "/tcp_scan.txt", "at")
    if aliveHostsTCP:
        lastItem = aliveHostsTCP[-1]
        for host in aliveHostsTCP:
            outfile.write(host + "\n")
            openvasTCP.write(host)
            if host == lastItem :
                pass
            else :
                openvasTCP.write(',')
        openvasTCP.write("\n")
    outfile.close()

def the_real_scan(directory, isList = False, skip = False, ip = None) :
    if ip:
        if skip:
            if isList:
                print("Starting the versionscan on the alive hosts\n")
                cmd = ["sudo", "nmap", "-O", "-sV", "-sT", "-Pn", "-p-", "-iL", ip, "-oA", directory + "/nmap/versionscan_tcp"]
                run_command(cmd)
            else:
                print("Starting the versionscan on the alive hosts\n")
                cmd = ["sudo", "nmap", "-O", "-sV", "-sT", "-Pn", "-p-", ip, "-oA", directory + "/nmap/versionscan_tcp"]
                run_command(cmd)
    else:
        print("Starting the versionscan on the alive hosts\n")
        cmd = ["sudo", "nmap", "-O", "-sV", "-sT", "-Pn", "-p-", "-iL", directory + "/tcp_scan.txt", "-oA", directory + "/nmap/versionscan_tcp"]
        run_command(cmd)

def extract_information(directory, openvasTCP, skip = False) :
    if os.path.isfile(directory + "/overview.txt") :
        cmd = ["rm", directory + "/overview.txt"]
        run_command(cmd)
    cmd = ["touch", directory + "/overview.txt"]
    run_command(cmd)

    if os.path.isfile(directory + "/overview.csv") :
        cmd = ["rm", directory + "/overview.csv"]
        run_command(cmd)
    cmd = ["touch", directory + "/overview.csv"]
    run_command(cmd)

    try:
        treeTCP = elementTree.parse(directory + "/nmap/versionscan_tcp.xml")
    except elementTree.ParseError as e:
        print("Compare elementTree.ParseError: ", e)
        cleanedData = clean_xml_data(directory + "/nmap/versionscan_tcp.xml")
        treeTCP = elementTree.parse(io.StringIO(cleanedData))
        pass

    overview = {}
    tempHost = None
    rootTCP = treeTCP.getroot()
    portOpenvasTCP = []
    if skip:
        hostOpenvasTCP = []
    openvasTCP.write('T:')
    for child in rootTCP.findall("host") :
        for host in child.findall("address") :
            if host.attrib['addrtype'] == 'ipv4' :
                tempHost = str(host.attrib['addr'])
                if tempHost not in overview.keys() :
                    overview[tempHost] = {}
        for ports in child.findall('ports') :
            for port in ports.findall('port') :
                if port.find('state').attrib['state'] == 'open' :
                    if skip:
                        hostOpenvasTCP.append(str(tempHost))
                    if str(port.attrib['portid']) not in portOpenvasTCP:
                        portOpenvasTCP.append(str(port.attrib['portid']))
                    overview[tempHost][str(port.attrib['portid'])] = {
                        'protocol': str(port.attrib['protocol']),
                        'state': str(port.find('state').attrib['state']) if 'state' in port.find('state').attrib else "no_state",
                        'name': str(port.find('service').attrib['name']) if 'name' in port.find('service').attrib else "no_name",
                        'product': str(port.find('service').attrib['product']) if 'product' in port.find('service').attrib else "no_product",
                        'versionnumber': str(port.find('service').attrib['version']) if 'version' in port.find('service').attrib else "no_version",
                        'conf': str(port.find('service').attrib['conf']) if 'conf' in port.find('service').attrib else "no_conf"
                    }

    outfile = open(directory + "/overview.txt", "at")
    for key in overview : 
        outfile.write(key + ":\n")
        outfile.write("\tPort")
        outfile.write("\t\tProtocol")
        outfile.write("\tState")
        outfile.write("\t\tConfidence")
        outfile.write("\tName")
        outfile.write("\t\tProduct")
        outfile.write("\t\t\t\t\t\tversion\n")
        for port in overview[key] :
            outfile.write("\t" + port)
            outfile.write("\t\t\t" if len(port) < 4 else "\t\t")
            outfile.write(overview[key][port]['protocol'])
            outfile.write("\t\t\t" + overview[key][port]['state'])
            outfile.write("\t\t" + overview[key][port]['conf'])
            outfile.write("\t\t\t" + overview[key][port]['name'])
            outfile.write("\t" if len(overview[key][port]['name']) > 7 else "\t\t" if len(overview[key][port]['name']) > 3 else "\t\t\t")
            outfile.write(overview[key][port]['product'])
            outfile.write("\t" if len(overview[key][port]['product']) > 23 else "\t\t" if len(overview[key][port]['product']) > 19 else "\t\t\t" if len(overview[key][port]['product']) > 15 else "\t\t\t\t" if len(overview[key][port]['product']) > 11 else "\t\t\t\t\t" if len(overview[key][port]['product']) > 7 else "\t\t\t\t\t\t")
            outfile.write(overview[key][port]['versionnumber'] + "\n")
        outfile.write("\n\n")
    outfile.close()

    outfile = open(directory + "/overview.csv", "at")
    outfile.write("IP,")
    outfile.write("Port,")
    outfile.write("Protocol,")
    outfile.write("State,")
    outfile.write("Confidence,")
    outfile.write("Name,")
    outfile.write("Product,")
    outfile.write("Version\n")
    for key in overview : 
        for port in overview[key] :
            outfile.write(key + ",")
            outfile.write(port + ",")
            outfile.write(overview[key][port]['protocol'] + ",")
            outfile.write(overview[key][port]['state'] + ",")
            outfile.write(overview[key][port]['conf'] + ",")
            outfile.write(overview[key][port]['name'] + ",")
            outfile.write(overview[key][port]['product'] + ",")
            outfile.write(overview[key][port]['versionnumber'] + "\n")
    outfile.close()

    if skip:
        if hostOpenvasTCP:
            last = hostOpenvasTCP[-1]
            for host in hostOpenvasTCP:
                openvasTCP.write(host)
                if host == last:
                    pass
                else:
                    openvasTCP.write(',')
        openvasTCP.write('\n\n')

    if portOpenvasTCP :
        last = portOpenvasTCP[-1]
        for port in portOpenvasTCP:
            openvasTCP.write(port)
            if port == last:
                pass
            else:
                openvasTCP.write(',')
    
    return overview


def testssl(directory) :
    if os.path.exists("/testssl") :
        if not os.path.exists(directory + "/testssl") : 
            os.mkdir(directory + "/testssl")
        if os.path.isfile(directory + "/testssl/testssl_result.html") :
            cmd = ["sudo", "rm", directory + "/testssl/testssl_result.html"]
            run_command(cmd)
        cmd = ["sudo", "/testssl/testssl.sh", "--file", directory + "/nmap/versionscan_tcp.gnmap", "-oH", directory + "/testssl/testssl_result.html"]
        run_command(cmd)
    elif os.path.exists("/usr/bin/testssl") :
        if not os.path.exists(directory + "/testssl") : 
            os.mkdir(directory + "/testssl")
        if os.path.isfile(directory + "/testssl/testssl_result.html") :
            cmd = ["sudo", "rm", directory + "/testssl/testssl_result.html"]
            run_command(cmd)
        cmd = ["sudo", "/usr/bin/testssl/testssl.sh", "--file", directory + "/nmap/versionscan_tcp.gnmap", "-oH", directory + "/testssl/testssl_result.html"]
        run_command(cmd)
    


def getLastScanDirectory(timestamp, scriptDir, folder = False, subfolder = False):
    print("Get the directory of the last scan made:")
    if subfolder and folder :
        directory = scriptDir + "/result/" + folder + "/" + subfolder + "/"
    elif folder :
        directory = scriptDir + "/result/" + folder + "/"
    else :
        directory = scriptDir + "/result/"
    cmd = ["sudo", "ls", directory]
    result = run_command(cmd)

    if result:
        datearrayString = result.split()
        datearrayInt = []

        for val in datearrayString:
            try :
                datearrayInt.append(datetime.strptime(val, "%d_%m_%Y--%H_%M_%S"))
            except ValueError :
                print("please do not store different folders or files in here except of timestamps")
        try :
            return directory + min(datearrayInt, key=lambda sub: abs(sub - timestamp)).strftime("%d_%m_%Y--%H_%M_%S")
        except ValueError :
            print("please do not store different folders or files in here except of timestamps")
            return False
    else:
        return False


######### Compares the old scan and the new one and writes the difference into a txt-file #########
def compare(overview, oldResult, directory):
    cmd = ["touch", directory + "/nmap_result_difference.txt"]
    run_command(cmd)

    oldOverview = {}
    tempHost = None
    if os.path.isfile(oldResult + "/nmap/versionscan_tcp.xml") :
        try:
            oldTreeTCP = elementTree.parse(oldResult + "/nmap/versionscan_tcp.xml")
        except elementTree.ParseError as e:
            print("Compare elementTree.ParseError: ", e)
            cleanedData = clean_xml_data(oldResult + "/nmap/versionscan_tcp.xml")
            oldTreeTCP = elementTree.parse(io.StringIO(cleanedData))
            pass
        oldRootTCP = oldTreeTCP.getroot()
        for child in oldRootTCP.findall("host") :
            for host in child.findall("address") :
                if host.attrib['addrtype'] == 'ipv4' :
                    tempHost = str(host.attrib['addr'])
                    if tempHost not in oldOverview.keys() :
                        oldOverview[tempHost] = {}
            for ports in child.findall('ports') :
                for port in ports.findall('port') :
                    if port.find('state').attrib['state'] == 'open' :
                        oldOverview[tempHost][str(port.attrib['portid'])] = {
                            'protocol': str(port.attrib['protocol']),
                            'state': str(port.find('state').attrib['state']) if 'state' in port.find('state').attrib else "no_state",
                            'name': str(port.find('service').attrib['name']) if 'name' in port.find('service').attrib else "no_name",
                            'product': str(port.find('service').attrib['product']) if 'product' in port.find('service').attrib else "no_product",
                            'versionnumber': str(port.find('service').attrib['version']) if 'version' in port.find('service').attrib else "no_version",
                            'conf': str(port.find('service').attrib['conf']) if 'conf' in port.find('service').attrib else "no_conf"
                        }

    outfile = open(directory + "/nmap_result_difference.txt", "at")
    outfile.write("New detected Hosts and Ports: \n\n")

    for host in overview:
        if host in oldOverview:
            for port in overview[host]:
                if port in oldOverview[host]:
                    if overview[host][port]['protocol'] == oldOverview[host][port]['protocol']:
                        pass
                    else: 
                        outfile.write(host + ":\nport\t\twhats new\t\tname\n" + port + "/" + overview[host][port]['protocol'] + "\t\tprotocol\t\t\t" + overview[host][port]['name'] + "\n")
                        print("New Protocol for " + host + " detected: " + port + "/" + overview[host][port]['protocol'] + " name: " + overview[host][port]['name']) 
                else:
                    outfile.write(host + ":\nport\t\twhats new\t\tname\n" + port + "/" + overview[host][port]['protocol'] + "\t\tport\t\t\t" + overview[host][port]['name'] + "\n")
                    print("New Port for " + host + " detected: " + port + "/" + overview[host][port]['protocol'] + " name: " + overview[host][port]['name'])
        else:
            outfile.write("new host detected:")
            outfile.write(host + ":\nport\t\tname\n")
            for newPorts in overview[host]:
                outfile.write(newPorts + "/" + overview[host][newPorts]['protocol'] + "\t" + overview[host][newPorts]['name'] + "\n")

    outfile.write("\nPorts and hosts which got detected in the last scan, but not in the new one: \n\n")

    for host in oldOverview:
        if host in overview:
            for port in oldOverview[host]:
                if port in overview[host]:
                    if oldOverview[host][port]['protocol'] == overview[host][port]['protocol']:
                        pass
                    else:
                        outfile.write(host + ":\nport\t\twhats missing\t\tname\n" + port + "/" + oldOverview[host][port]['protocol'] + "\t\tprotocol\t\t\t" + oldOverview[host][port]['name'] + "\n")
                        print("Old Protocol for " + host + " not detected: " + port + "/" + oldOverview[host][port]['protocol'] + " name: " + oldOverview[host][port]['name'])
                else:
                    outfile.write(host + ":\nport\t\twhats missing\t\tname\n" + port + "/" + oldOverview[host][port]['protocol'] + "\t\tport\t\t\t" + oldOverview[host][port]['name'] + "\n")
                    print("Old Port for " + host + " not detected: " + port + "/" + oldOverview[host][port]['protocol'] + " name: " + oldOverview[host][port]['name'])
        else:
            outfile.write("old host not detected:\n")
            outfile.write(host + ":\nport\t\tname\n")
            for oldPorts in oldOverview[host]:
                outfile.write(oldPorts + "/" + oldOverview[host][oldPorts]['protocol'] + "\t" + oldOverview[host][oldPorts]['name'] + "\n")
            print("Old Host not detected: " + host + ":" + str(oldOverview[host]))

    outfile.flush()
    outfile.close()


######### Function to clean XML-Data, when there are some binary data in it like "ssl/radan-ht@" (happened once) #########
def clean_xml_data(filePath):
    with open(filePath, 'r') as file:
        data = file.read()
    cleanedData = ''.join(char if 32 <= ord(char) <= 126 else ' ' for char in data)
    return cleanedData

#
#            MAIN
#################################################################################

def main():
    parser = argparse.ArgumentParser(description="Port/Service enumaration tool.")
    
    # IP Range to scan
    parser.add_argument("-r", "--range", dest="range", help="An IP or range to scan")
    
    # Path to list of IP's
    parser.add_argument("-l", "--list", dest="list", help="Path to a list of IP's to scan")

    # Skip Host Discovery
    parser.add_argument("-Pn", "--skip-discovery", dest="skip", help="If you want to scan all hosts in given range TCP full and UDP top 1k", action="store_true")
    parser.set_defaults(skip=False)

    # Add extra ports for host discovery
    parser.add_argument("-tp", "--tcp-ports", dest="tcp_ports", help="Add some extra and exotic tcp ports, which should fulfill the host discovery part")
    parser.set_defaults(tcp_ports="")

    # Add naming, so we can track the scans and compare them
    parser.add_argument("-f", "--folder", dest="folder", help="choose a name, under which the scan will be stored")
    parser.set_defaults(folder=False)
    parser.add_argument("-sf", "--subfolder", dest="subfolder", help="More than one scan per name? create a subfolder to keep them apart")
    parser.set_defaults(subfolder=False)

    timestamp = datetime.now()
    args = parser.parse_args()
    scriptDir = os.path.dirname(__file__)
    isList = False
    skip = args.skip
    folder = args.folder
    subfolder = args.subfolder
    if args.range :
        ip = args.range
        isList = False
    elif args.list :
        ip = os.path.join(scriptDir, args.list)
        isList = True

    tcp_ports = args.tcp_ports

    if not os.path.exists(scriptDir + "/result"):
        os.mkdir(scriptDir + "/result")

    if subfolder and not folder:
        cmd = ["echo", "ACHTUNG der Parameter '-sf' darf nur verwendet werden, wenn der Parameter '-f' existiert"]
        run_command(cmd)
        pass
    else:
        if folder :
            if not os.path.exists(scriptDir + "/result/" + folder) :
                os.mkdir(scriptDir + "/result/" + folder)
            if subfolder : 
                if not os.path.exists(scriptDir + "/result/" + folder + "/" + subfolder) :
                    os.mkdir(scriptDir + "/result/" + folder + "/" + subfolder)
        else :
            oldResult = getLastScanDirectory(timestamp, scriptDir)
            os.mkdir(scriptDir + "/result/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S"))
            os.mkdir(scriptDir + "/result/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S") + "/nmap")
            directory = scriptDir + "/result/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S")

        if subfolder : 
            oldResult = getLastScanDirectory(timestamp, scriptDir, folder, subfolder)
            os.mkdir(scriptDir + "/result/" + folder + "/" + subfolder + "/"  + timestamp.strftime("%d_%m_%Y--%H_%M_%S"))
            os.mkdir(scriptDir + "/result/" + folder + "/" + subfolder + "/"  + timestamp.strftime("%d_%m_%Y--%H_%M_%S") + "/nmap")
            directory = scriptDir + "/result/" + folder + "/" + subfolder + "/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S")
        elif folder :
            oldResult = getLastScanDirectory(timestamp, scriptDir, folder)
            os.mkdir(scriptDir + "/result/" + folder + "/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S"))
            os.mkdir(scriptDir + "/result/" + folder + "/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S") + "/nmap")
            directory = scriptDir + "/result/" + folder + "/" + timestamp.strftime("%d_%m_%Y--%H_%M_%S")

        cmd = ["touch", directory + "/openvas_preparation_tcp.txt"]
        run_command(cmd)
        
        openvasTCP = open(directory + "/openvas_preparation_tcp.txt", "w")

        if skip:
            the_real_scan(directory, isList, skip, ip)
        else:
            search_alive_hosts(ip, directory, isList, tcp_ports)
            extract_alive_hosts(directory, openvasTCP)
            the_real_scan(directory)

        overview = extract_information(directory, openvasTCP, skip)

        if folder:
            if oldResult : 
                compare(overview, oldResult, directory)

        openvasTCP.close()
        print("\n\nYoure good to go, make manual verification or start the openvas scan\n")

if __name__ == '__main__' :
    main()