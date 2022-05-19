#!/usr/bin/env python3

""""
FortiManager UTM Policy Check

This program will scan all ADOMs on a FortiManager, scan all policy packages, then pull back
the policies UTM status.

by:
 ________         ____     _ __  ___           __              __
/_  __/ /  ___   / __/  __(_) / / _ )___ ____ / /____ ________/ /
 / / / _ \/ -_) / _/| |/ / / / / _  / _ `(_-</ __/ _ `/ __/ _  /
/_/ /_//_/\__/ /___/|___/_/_/ /____/\_,_/___/\__/\_,_/_/  \_,_/

afaulkner@fortinet.com / evil@evilbast.com

First commit to git 19May22
"""
import requests
import json
import urllib3
import logging
import csv
from getpass import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set flag to DEBUG to get full logging.
debug_flag = logging.INFO
logging_file = 'fmg_script.log'
logging.basicConfig(level=debug_flag, format='%(asctime)s:%(levelname)s:%(message)s')
# To log to file comment the line above and uncomment the line below.
# logging.basicConfig(filename=logging_file,level=logging.DEBUG,format='%(asctime)s:%(levelname)s:%(message)s')

#  If you want to hard code FMG IP, user and password do it here.  OR you can uncomment for prompt

#fmg_ip = input("Enter the IP address of your Fortimanager : ")
fmg_ip = "192.168.75.201"
#fmg_user = input("Enter the FortiManager API username: ")
fmg_user = "api-user"
try:
    fmg_passwd = getpass("Enter Password: ",stream=None)
except Exception as error:
    print('ERROR', error)

#fmg_passwd = "ENTER PASSWORD"

# Default is . the same directory as where the script resides.  Change if you want output file to write to
# different directory.
path = "/home/afaulkner/python/"

# This is an exclusion list of default ADOMs that are installed in FMG by default.  Adding to this list
# will remove any ADOM from adom choice.
adom_exclude = ["FortiAnalyzer", "FortiAuthenticator", "FortiCache", "FortiCarrier", "FortiClient",
                "FortiDDoS", "FortiDeceptor", "FortiFirewall", "FortiFirewallCarrier", "FortiMail",
                "FortiManager", "FortiNAC", "FortiProxy", "FortiSandbox", "FortiWeb", "Unmanaged_Devices",
                "rootp", "others", "Syslog"]

# STATIC global variables do not change
sid = ""
adom_choice = ""
adom_list = []
url_base = "https://" + fmg_ip + "/jsonrpc"

### CSV file creation
f = open(path + 'FGT_UTM_policy_status.csv', 'w', newline='')
writer = csv.writer(f)
writer.writerow(["UTM Policy Status on Fortigate Firewalls"])
writer.writerow(["-----","-----","-----","-----","-----","-----","-----","-----","-----","-----"])

def fmg_login():
    logging.debug("**** Start of the fmg_login function ****")
    # Logging into FMG and getting session id "sid"
    global sid
    global url_base
    client = requests.session()

    payload = {
        "id": 1,
        "method": "exec",
        "params": [
            {
                "data": {
                    "passwd": fmg_passwd,
                    "user": fmg_user,
                },
                "url": "/sys/login/user"
            }
        ]
    }
    r = client.post(url_base, json=payload, verify=False)
    # Retrieve session id. Add to HTTP header for future messages parsed_json = json.loads(r.text)
    parsed_json = json.loads(r.text)
    logging.debug("Response from FMG: " + str(parsed_json))
    try:
        sid = parsed_json['session']
        headers = {'session': sid}
    except:
        print("Error happened attempting to log in to FMG")
        logging.debug("Issue with logging in to FMG check IP/FQDN or user/password")
    return (sid)

def fmg_logout():
    logging.debug("**** Start of the fmg_logout function ****")
    # Logging out of FMG
    global sid
    global url_base
    client = requests.session()
    payload = {
        "id": 1,
        "method": "exec",
        "params": [
            {
                "url": "/sys/logout"
            }
        ],
        "session": sid
    }
    r = client.post(url_base, json=payload, verify=False)
    parsed_json = json.loads(r.text)
    logging.info("Logging out of FMG")
    logging.debug("Response from FMG: " + str(parsed_json))

def fmg_adom_list():
    logging.debug("**** Start of the fmg_adom_list function ****")
    # Getting FMG adom list
    global sid
    global adom_choice
    global adom_list
    global url_base
    adom_list_temp = []
    client = requests.session()
    payload = {
        "method": "get",
        "params": [
            {
                "fields": ["name", "desc"],
                "loadsub": 0,
                "url": "/dvmdb/adom"
            }
        ],
        "session": sid,
        "id": 1
    }
    r = client.post(url_base, json=payload, verify=False)
    parsed_json = json.loads(r.text)
    logging.debug(parsed_json)
    logging.debug("Getting list of ADOMs")
    logging.debug("Response from FMG: " + str(parsed_json))
    adom_ct = len(parsed_json["result"][0]["data"])
    logging.debug("Total number of ADOMs : " + str(adom_ct))
    count = 0
    while count < adom_ct:
        adom_name = parsed_json["result"][0]["data"][count]["name"]
        adom_list_temp.append(adom_name)
        count = count + 1
    logging.debug("Here is a list of ALL the FMG adom names: " + str(adom_list_temp))
    index = 1
    # Removing unwanted ADOMs from the list
    # ADOMs from list.
    for item in adom_list_temp:
        # print(item)
        if item in adom_exclude:
            pass
        else:
            adom_list.append(item)

def adom_policy_list(adom):
    global sid
    global adom_choice
    global policy_pkg
    global url_base
    client = requests.session()
    payload = {
        "method": "get",
        "params": [
            {
                "loadsub": 0,
                "url": "/pm/pkg/adom/" + adom
            }
        ],
        "session": sid,
        "id": 1
    }

    r = client.post(url_base, json=payload, verify=False)
    parsed_json = json.loads(r.text)
    logging.debug("Here is the parsed json from adom_policy_list : " + str(parsed_json['result'][0]['data']))
    count = len(parsed_json["result"][0]['data'])
    logging.debug("The number of policies packages in the adom are " + str(count))
    count_up = 0
    while count_up < count:
        policy_pkg = parsed_json["result"][0]["data"][count_up]["name"]
        print("Policy Package : " + policy_pkg)
        writer.writerow(["Policy Package : " + policy_pkg])
        policy_fields(policy_pkg)
        count_up = count_up + 1

def policy_fields(policy_pkg):
    global sid
    global adom_choice
    global url_base
    client = requests.session()

    payload = {
        "method": "get",
        "params": [
            {
                "fields": ["policyid",
                            "name",
                           "utm-status",
                           "profile-type",
                           "profile-protocol-options",
                           "av-profile",
                           "webfilter-profile",
                           "ips-sensor",
                           "dlp-sensor",
                           "application-list",
                           "voip-profile",
                           ],
                "loadsub": 0,
                "url": "/pm/config/adom/" + adom_choice + "/pkg/" + policy_pkg + "/firewall/policy"

            }
        ],
        "session": sid,
        "id": 1
    }

    r = client.post(url_base, json=payload, verify=False)
    parsed_json = json.loads(r.text)
    logging.debug("Here is the parsed json from policy_fields : " + str(parsed_json))

    count = len(parsed_json['result'][0]['data'])
    print("Number of policies in policy package : " + str(count))
    writer.writerow(["Number of policies in policy package : " + str(count)])

    count_up = 0
    writer.writerow(["Policy ID","Policy Name", "UTM Status", "AV Profile","Web Filter Profile", "IPS Sensor",
                     "DLP Sensor", "Application Control Profile", "VOIP Profile"])
    while count_up < count:
        policy_id = str(parsed_json['result'][0]['data'][count_up]['policyid'])
        try:
            policy_name = str(parsed_json['result'][0]['data'][count_up]['name'])
        except:
            policy_name = "NO NAME"
        utm_status = str(parsed_json['result'][0]['data'][count_up]['utm-status'])
        profile_type = str(parsed_json['result'][0]['data'][count_up]['profile-type'])
        profile_protocol_options = str(parsed_json['result'][0]['data'][count_up]['profile-protocol-options'])
        av_profile = str(parsed_json['result'][0]['data'][count_up]['av-profile'])
        if av_profile == "[]":
            av_profile = " "
        else:
            pass
        webfilter_profile = str(parsed_json['result'][0]['data'][count_up]['webfilter-profile'])
        if webfilter_profile == "[]":
            webfilter_profile = " "
        else:
            pass
        ips_sensor = str(parsed_json['result'][0]['data'][count_up]['ips-sensor'])
        if ips_sensor == "[]":
            ips_sensor = " "
        else:
            pass
        dlp_sensor = str(parsed_json['result'][0]['data'][count_up]['dlp-sensor'])
        if dlp_sensor == "[]":
            dlp_sensor = " "
        else:
            pass
        application_list = str(parsed_json['result'][0]['data'][count_up]['application-list'])
        if application_list == "[]":
            application_list = " "
        else:
            pass
        voip_profile = str(parsed_json['result'][0]['data'][count_up]['voip-profile'])
        if voip_profile == "[]":
            voip_profile = " "
        else:
            pass

        writer.writerow([policy_id,policy_name,utm_status,av_profile,webfilter_profile,
                        ips_sensor,dlp_sensor,application_list,voip_profile])

        print("Getting UTM features")
        count_up = count_up + 1

def main():
    global adom_choice
    global adom_list
    global writer
    global f
    fmg_login()
    fmg_adom_list()
    for item in adom_list:
        adom_choice = item
        print("Current ADOM : " + adom_choice)
        writer.writerow(["-----","-----","-----","-----","-----","-----","-----","-----","-----","-----"])
        writer.writerow(["Current ADOM : " + adom_choice])
        writer.writerow(["-----","-----","-----","-----","-----","-----","-----","-----","-----","-----"])
        adom_policy_list(item)
        writer.writerow(["END OF FILE"])
    f.close()
    fmg_logout()

if __name__ == "__main__":
    main()