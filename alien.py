"""
Python 3
OTX API v2.0

__author__ = "Tomasz Aniszewski"
__copyright__ = "Copyright 2018, Tomasz Aniszewski"
__license__ = "Apache License"
__version__ = "1.0.0"
__maintainer__ = "Tomasz Aniszewski"
__email__ = "33432468+Erlopek@users.noreply.github.com"
__status__ = "Prototype"

"""

from OTXv2 import OTXv2
import IndicatorTypes
import argparse
import sys


# Your API key
API_KEY = 'xxx'
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)


parser = argparse.ArgumentParser(description='OTX CLI Example')
parser.add_argument('-i', '--ip', help='IP eg; 4.4.4.4', required=False)
parser.add_argument(
    '-d', '--domain', help='Domain eg; alienvault.com', required=False)
parser.add_argument('-ho', '--hostname',
                    help='Hostname eg; www.alienvault.com', required=False)
parser.add_argument(
    '-u', '--url', help='URL eg; http://www.alienvault.com', required=False)
parser.add_argument(
    '-m', '--md5', help='MD5 Hash of a file eg; 7b42b35832855ab4ff37ae9b8fa9e571', required=False)
parser.add_argument(
    '-p', '--pulse', help='Search pulses for a string eg; Dridex', required=False)
parser.add_argument(
    '-s', '--search', help='Search pulses with ID eg; 59faff6372c9e71f6fb7e3e0', required=False)

args = vars(parser.parse_args())

if len(sys.argv) <= 2:
    parser.print_help()
    sys.exit(1)


if args["ip"]:
    ip1 = (otx.get_indicator_details_full(IndicatorTypes.IPv4, args["ip"]))
    answer = input("Do you want (l)ong or (s)hort answer: ")
    if answer == "l" or answer == "L":
        if "count" in ip1["malware"] is not None:
            print("Number of malwares found: " + str(ip1["malware"]["count"]) + ".  Hashes are: ")
            for i in ip1["malware"]["data"]:
                print(i["hash"])
        print("----------------------------------------------------------")
        print("----------------------------------------------------------")

        print("Passive DNS of malware sites: \n")
        for i in ip1["passive_dns"]["passive_dns"]:
            print("First time: " + i["first"] + "     Last time: " + i["last"])
            print("Hostname: " + i["hostname"] + "     Address: " + i["address"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

        print("URL List of malware sites: \n")
        for i in ip1["url_list"]["url_list"]:
            print("Domain: " + i["domain"] + "     Date: " + i["date"])
            print("URL: " + i["url"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

        print("List of pulses; \n" + "Nr: " + str(ip1["general"]["pulse_info"]["count"]))
        for i in ip1["general"]["pulse_info"]["pulses"]:
            print("ID: " + i["id"])
            print("Description: " + i["description"] + "     Name: " + i["name"])
            print("Creation : " + i["created"] + "     Modified : " + i["modified"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")
        if ip1["reputation"]["reputation"] is not None:
            print("Reputation; " + "Spamming: " + str(ip1["reputation"]["reputation"]["counts"]["Spamming"])
                  + "Malware Domain: " + str(ip1["reputation"]["reputation"]["counts"]["Malware Domain"])
                  + "Malware IP: " + str(ip1["reputation"]["reputation"]["counts"]["Malware IP"])
                  + "C&C:  " + str(ip1["reputation"]["reputation"]["counts"]["C&C"]))
        if ip1["reputation"]["reputation"] is not None:
            for i in ip1["reputation"]["reputation"]["activities"]:
                print("Domain: " + i["domain"] + "     Name: " + i["name"])
                print("First Date : " + i["first_date"] + "     Last Date : " + i["last_date"])
                print("----------------------------------------------------------")
            print("----------------------------------------------------------\n")

    elif answer == "s" or answer == "S":
        if "count" in ip1["malware"] is not None:
            print("\nNumber of malwares found: " + str(ip1["malware"]["count"]) + ".  Hashes are: ")
            k = 1
            for i in ip1["malware"]["data"]:
                while k <= 3:
                    print(i["hash"])
                    k += 1
        print("----------------------------------------------------------")
        print("----------------------------------------------------------")

        print("Passive DNS of malware sites: \n")
        k = 1
        for i in ip1["passive_dns"]["passive_dns"]:
            while k <= 3:
                print("First time: " + i["first"] + "     Last time: " + i["last"])
                print("Hostname: " + i["hostname"] + "     Address: " + i["address"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")

        print("URL List of malware sites: \n")
        k = 1
        for i in ip1["url_list"]["url_list"]:
            while k <= 3:
                print("Domain: " + i["domain"] + "     Date: " + i["date"])
                print("URL: " + i["url"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")

        print("List of pulses; \n" + "Nr: " + str(ip1["general"]["pulse_info"]["count"]))
        k = 1
        for i in ip1["general"]["pulse_info"]["pulses"]:
            while k <= 3:
                print("ID: " + i["id"])
                print("Description: " + i["description"] + "     Name: " + i["name"])
                print("Creation : " + i["created"] + "     Modified : " + i["modified"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")
        if ip1["reputation"]["reputation"] is not None:
            print("Reputation; " + "Spamming: " + str(ip1["reputation"]["reputation"]["counts"]["Spamming"])
                  + "Malware Domain: " + str(ip1["reputation"]["reputation"]["counts"]["Malware Domain"])
                  + "Malware IP: " + str(ip1["reputation"]["reputation"]["counts"]["Malware IP"])
                  + "C&C:  " + str(ip1["reputation"]["reputation"]["counts"]["C&C"]))
        if ip1["reputation"]["reputation"] is not None:
            k = 1
            for i in ip1["reputation"]["reputation"]["activities"]:
                while k <= 3:
                    print("Domain: " + i["domain"] + "     Name: " + i["name"])
                    print("First Date : " + i["first_date"] + "     Last Date : " + i["last_date"])
                    print("----------------------------------------------------------")
                    k += 1
        print("----------------------------------------------------------\n")


if args["pulse"]:
    puls1 = otx.search_pulses(args["pulse"])
    answer = input("Do you want (l)ong or (s)hort answer: ")
    if answer == "l" or answer == "L":
        if puls1["results"] is not None:
            for i in puls1["results"]:
                print("Tags: " + str(i["tags"]) + ".  created:" + str(i["created"]))
                print("----------------------------------------------------------")
                print("----------------------------------------------------------")
                for k in i["indicators"]:
                    print("ID: " + str(k["id"]) + "     Created: " + k["created"])
                    print("IOC: " + k["indicator"] + "     Type: " + k["type"])
                    print("----------------------------------------------------------")
            print("----------------------------------------------------------")

    elif answer == "s" or answer == "S":
        if puls1["results"] is not None:
            m1 = 1
            for i in puls1["results"]:
                print("Tags: " + str(i["tags"]) + ".  created:" + str(i["created"]))
                print("----------------------------------------------------------")
                print("----------------------------------------------------------")
                for k in i["indicators"]:
                    while m1 <= 3:
                        print("ID: " + str(k["id"]) + "     Created: " + k["created"])
                        print("IOC: " + k["indicator"] + "     Type: " + k["type"])
                        print("----------------------------------------------------------")
                        m1 += 1


if args["domain"]:
    dom1 = (otx.get_indicator_details_full(IndicatorTypes.DOMAIN, args["domain"]))
    answer = input("Do you want (l)ong or (s)hort answer:  " + "\n")
    if answer == "l" or answer == "L":
        if "count" in dom1["malware"] is not None:
            print("Number of malwares found: " + str(dom1["malware"]["count"]) + ".  Hashes are: ")
            for i in dom1["malware"]["data"]:
                print(i["hash"])
        print("----------------------------------------------------------")
        print("----------------------------------------------------------")

        print("Passive DNS of malware sites: \n")
        for i in dom1["passive_dns"]["passive_dns"]:
            print("First time: " + i["first"] + "     Last time: " + i["last"])
            print("Hostname: " + i["hostname"] + "     Address: " + i["address"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

        print("URL List of malware sites: \n")
        for i in dom1["url_list"]["url_list"]:
            print("Domain: " + i["domain"] + "     Date: " + i["date"])
            print("URL: " + i["url"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

        print("List of pulses; \n" + "Nr: " + str(dom1["general"]["pulse_info"]["count"]))
        for i in dom1["general"]["pulse_info"]["pulses"]:
            print("ID: " + i["id"])
            print("Description: " + i["description"] + "     Name: " + i["name"])
            print("Creation : " + i["created"] + "     Modified : " + i["modified"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")
        if "reputation" in dom1 is not None:
            print("Reputation; " + "Spamming: " + str(dom1["reputation"]["reputation"]["counts"]["Spamming"])
                  + "Malware Domain: " + str(dom1["reputation"]["reputation"]["counts"]["Malware Domain"])
                  + "Malware IP: " + str(dom1["reputation"]["reputation"]["counts"]["Malware IP"])
                  + "C&C:  " + str(dom1["reputation"]["reputation"]["counts"]["C&C"]))
        if "reputation" in dom1 is not None:
            for i in dom1["reputation"]["reputation"]["activities"]:
                print("Domain: " + i["domain"] + "     Name: " + i["name"])
                print("First Date : " + i["first_date"] + "     Last Date : " + i["last_date"])
                print("----------------------------------------------------------")
            print("----------------------------------------------------------\n")

    elif answer == "s" or answer == "S":
        if "count" in dom1["malware"] is not None:
            print("\nNumber of malwares found: " + str(dom1["malware"]["count"]) + ".  Hashes are: ")
            k = 1
            for i in dom1["malware"]["data"]:
                while k <= 3:
                    print(i["hash"])
                    k += 1
        print("----------------------------------------------------------")
        print("----------------------------------------------------------")

        print("Passive DNS of malware sites: \n")
        k = 1
        for i in dom1["passive_dns"]["passive_dns"]:
            while k <= 3:
                print("First time: " + i["first"] + "     Last time: " + i["last"])
                print("Hostname: " + i["hostname"] + "     Address: " + i["address"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")

        print("URL List of malware sites: \n")
        k = 1
        for i in dom1["url_list"]["url_list"]:
            while k <= 3:
                print("Domain: " + i["domain"] + "     Date: " + i["date"])
                print("URL: " + i["url"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")

        print("List of pulses; \n" + "Nr: " + str(dom1["general"]["pulse_info"]["count"]))
        k = 1
        for i in dom1["general"]["pulse_info"]["pulses"]:
            while k <= 3:
                print("ID: " + i["id"])
                print("Description: " + i["description"] + "     Name: " + i["name"])
                print("Creation : " + i["created"] + "     Modified : " + i["modified"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")
        if "reputation" in dom1 is not None:
            print("Reputation; " + "Spamming: " + str(dom1["reputation"]["reputation"]["counts"]["Spamming"])
                  + "Malware Domain: " + str(dom1["reputation"]["reputation"]["counts"]["Malware Domain"])
                  + "Malware IP: " + str(dom1["reputation"]["reputation"]["counts"]["Malware IP"])
                  + "C&C:  " + str(dom1["reputation"]["reputation"]["counts"]["C&C"]))
        if "reputation" in dom1 is not None:
            k = 1
            for i in dom1["reputation"]["reputation"]["activities"]:
                while k <= 3:
                    print("Domain: " + i["domain"] + "     Name: " + i["name"])
                    print("First Date : " + i["first_date"] + "     Last Date : " + i["last_date"])
                    print("----------------------------------------------------------")
                    k += 1
        print("----------------------------------------------------------\n")


if args["hostname"]:
    host1 = (otx.get_indicator_details_full(IndicatorTypes.HOSTNAME, args["hostname"]))
    answer = input("Do you want (l)ong or (s)hort answer:  " + "\n")
    if answer == "l" or answer == "L":
        if "count" in host1["malware"] is not None:
            print("Number of malwares found: " + str(host1["malware"]["count"]) + ".  Hashes are: ")
            for i in host1["malware"]["data"]:
                print(i["hash"])
        else:
            print("No malware founds")
        print("----------------------------------------------------------")
        print("----------------------------------------------------------")

        print("Passive DNS of malware sites: \n")
        for i in host1["passive_dns"]["passive_dns"]:
            print("First time: " + i["first"] + "     Last time: " + i["last"])
            print("Hostname: " + i["hostname"] + "     Address: " + i["address"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

        print("URL List of malware sites: \n")
        for i in host1["url_list"]["url_list"]:
            print("Domain: " + i["domain"] + "     Date: " + i["date"])
            print("URL: " + i["url"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

        print("List of pulses; \n" + "Nr: " + str(host1["general"]["pulse_info"]["count"]))
        for i in host1["general"]["pulse_info"]["pulses"]:
            print("ID: " + i["id"])
            print("Description: " + i["description"] + "     Name: " + i["name"])
            print("Creation : " + i["created"] + "     Modified : " + i["modified"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")
        if "reputation" in host1 is not None:
            print("Reputation; " + "Spamming: " + str(host1["reputation"]["reputation"]["counts"]["Spamming"])
                  + "Malware Domain: " + str(host1["reputation"]["reputation"]["counts"]["Malware Domain"])
                  + "Malware IP: " + str(host1["reputation"]["reputation"]["counts"]["Malware IP"])
                  + "C&C:  " + str(host1["reputation"]["reputation"]["counts"]["C&C"]))
        if "reputation" in host1 is not None:
            for i in host1["reputation"]["reputation"]["activities"]:
                print("Domain: " + i["domain"] + "     Name: " + i["name"])
                print("First Date : " + i["first_date"] + "     Last Date : " + i["last_date"])
                print("----------------------------------------------------------")
            print("----------------------------------------------------------\n")

    elif answer == "s" or answer == "S":
        if "count" in host1["malware"] is not None:
            print("\nNumber of malwares found: " + str(host1["malware"]["count"]) + ".  Hashes are: ")
            k = 1
            for i in host1["malware"]["data"]:
                while k <= 3:
                    print(i["hash"])
                    k += 1
        else:
            print("No malware founds")
        print("----------------------------------------------------------")
        print("----------------------------------------------------------")

        print("Passive DNS of malware sites: \n")
        k = 1
        for i in host1["passive_dns"]["passive_dns"]:
            while k <= 3:
                print("First time: " + i["first"] + "     Last time: " + i["last"])
                print("Hostname: " + i["hostname"] + "     Address: " + i["address"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")

        print("URL List of malware sites: \n")
        k = 1
        for i in host1["url_list"]["url_list"]:
            while k <= 3:
                print("Domain: " + i["domain"] + "     Date: " + i["date"])
                print("URL: " + i["url"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")

        print("List of pulses; \n" + "Nr: " + str(host1["general"]["pulse_info"]["count"]))
        k = 1
        for i in host1["general"]["pulse_info"]["pulses"]:
            while k <= 3:
                print("ID: " + i["id"])
                print("Description: " + i["description"] + "     Name: " + i["name"])
                print("Creation : " + i["created"] + "     Modified : " + i["modified"])
                print("----------------------------------------------------------")
                k += 1
        print("----------------------------------------------------------\n")
        if "reputation" in host1 is not None:
            print("Reputation; " + "Spamming: " + str(host1["reputation"]["reputation"]["counts"]["Spamming"])
                  + "Malware Domain: " + str(host1["reputation"]["reputation"]["counts"]["Malware Domain"])
                  + "Malware IP: " + str(host1["reputation"]["reputation"]["counts"]["Malware IP"])
                  + "C&C:  " + str(host1["reputation"]["reputation"]["counts"]["C&C"]))
        if "reputation" in host1 is not None:
            k = 1
            for i in host1["reputation"]["reputation"]["activities"]:
                while k <= 3:
                    print("Domain: " + i["domain"] + "     Name: " + i["name"])
                    print("First Date : " + i["first_date"] + "     Last Date : " + i["last_date"])
                    print("----------------------------------------------------------")
                    k += 1
        print("----------------------------------------------------------\n")


if args["url"]:
    url1 = (otx.get_indicator_details_full(IndicatorTypes.URL, args["url"]))
    print("\nURL INfo: \n")
    if str(url1["url_list"]["url_list"]) != "[]":
        print("URL: " + url1["url_list"]["url_list"][0]["result"]["urlworker"]["url"] +
              "     IP: " + url1["url_list"]["url_list"][0]["result"]["urlworker"]["ip"])
        print("Server Type: " + url1["url_list"]["url_list"][0]["result"]["urlworker"]["http_response"]["Server"] +
              "     Last Modify: " + url1["url_list"]["url_list"][0]["result"]["urlworker"]
              ["http_response"]["Last-Modified"])
        print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

    print("Geo Info: \n")
    print("Country info: " + url1["url_list"]["country_code"])
    print("Country Name: " + url1["url_list"]["country_name"])
    print("----------------------------------------------------------")
    print("----------------------------------------------------------\n")
    print("Number of pulses:  " + str(url1["general"]["pulse_info"]["count"]))
    print("----------------------------------------------------------\n")
    print("----------------------------------------------------------\n")
    print("Alexa: " + url1["general"]["alexa"]+"\n")
    print("Whois: " + url1["general"]["whois"]+"\n")


if args["md5"]:
    try:
        md1 = (otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, args["md5"]))
    except AttributeError:
        print("Wrong data to analyse")
        sys.exit(1)
    print("\nAnalysis: ")
    if md1["analysis"]["analysis"] is not None:
        print("File Type: " + md1["analysis"]["analysis"]["info"]["results"]["file_type"])
        print("SSDEEP: " + md1["analysis"]["analysis"]["info"]["results"]["ssdeep"])

        print("\nNumber of pulses; \n" + "Nr: " + str(md1["general"]["pulse_info"]["count"]))
        for i in md1["general"]["pulse_info"]["pulses"]:
            print("\nPulse ID: " + i["id"])
            print("Description: " + i["description"] + "     Name: " + i["name"])
            print("Creation : " + i["created"] + "     Modified : " + i["modified"])
            print("----------------------------------------------------------")
        print("----------------------------------------------------------\n")

if args["search"]:
    try:
        search1 = otx.get_pulse_details(args["search"])
    except AttributeError:
        print("Wrong data to analyse")
        sys.exit(1)
    answer = input("Do you want (l)ong or (s)hort answer:  " + "\n")
    if answer == "l" or answer == "L":
        if search1["description"] is not None:
            print("Description of Pulse: " + str(search1["description"]))
            for i in search1["indicators"]:
                print(i["type"]+"   " + i["indicator"])
        else:
            print("No malware founds")

        print("----------------------------------------------------------")
        print("----------------------------------------------------------")
    elif answer == "s" or answer == "S":
        if search1["description"] is not None:
            print("Description of Pulse: " + str(search1["description"]))
            k = 1
            for i in search1["indicators"]:
                while k <= 3:
                    print(i["type"] + "   " + i["indicator"])
                    k += 1
        else:
            print("No malware founds")

        print("----------------------------------------------------------")
        print("----------------------------------------------------------")
