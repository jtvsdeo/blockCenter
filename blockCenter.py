import meraki
import requests
import datetime
import ipaddress


def firewallRule(message):
    logs = m.appliance.getNetworkApplianceFirewallL3FirewallRules(networkId)
    srcIp = []
    for ip in message.split(): srcIp = ip; break

    if ipaddress.ip_address(srcIp).is_private:
        srcIp += "/32"
        for dicti in logs["rules"]:
            if dicti['srcCidr'] == srcIp:
                return
        fwRule = {'comment': "Security Automation", 'policy': 'deny', 'protocol': 'Any', 'srcPort': 'Any',
                  'srcCidr': '', 'destPort': 'Any', 'destCidr': 'Any', 'syslogEnabled': False}

        for key in fwRule:
            if key == "srcCidr":
                fwRule[key] = srcIp

        for curr in logs:
            logs[curr].pop()
            logs[curr].append(fwRule)
            m.appliance.updateNetworkApplianceFirewallL3FirewallRules(networkId, rules=logs[curr])  # Loop will only run once


def slackSend(message):
    fr = open("daily.log", "r")
    lines = fr.readlines()
    for line in lines:
        if message[27:] in line:
            return  # no slack alert needed, already happened before
    fa = open("daily.log", "a")
    fa.write(message + "\n")
    payload = '{"text": "3 malicious attempts today! %s. Private SRC added to Firewall Rules." }' % message[27:]
    slackSend = requests.post('', data=payload)  # Add Slack Webhook
    firewallRule(message[27:])
    print(slackSend.text)


def logExpiry():
    fr = open("daily.log", "r")
    lines = fr.readlines()
    count = 0
    for line in lines:
        formatLine = (str(line.split(" ", 2)[0])) + " " + (str(line.split(" ", 2)[1]))
        formatLine = datetime.datetime.strptime(formatLine, '%Y-%m-%d %H:%M:%S.%f')
        ''' Change below value to 1'''
        if (timeRn - formatLine).days > 1:
            del lines[count]
        else:
            break
        count += 1

    fw = open("daily.log", "w")
    for newLine in lines:
        fw.write(newLine)


if __name__ == '__main__':
    timeRn = (datetime.datetime.now())
    key = ""  # For API Key, Recommend Using environment vars for API keys!!!
    organizationId = ""
    networkId = ""
    m = meraki.DashboardAPI(api_key=key)
    logCount = {}
    log = ''
    while True:
        response = m.appliance.getNetworkApplianceSecurityEvents(networkId, timespan=86400)  # 86400 = 1 day
        logExpiry()  # clear out expired logs
        print(response)
        for i in response:
            logDate = datetime.datetime.strptime((i['ts']).replace('T', ' ').replace('Z', ''),'%Y-%m-%d %H:%M:%S.%f')  # Formatting the time from the logs, so it is in a comparable format
            src = i['srcIp']
            log = (str(src.split(":", 1)[0]) + " " + str(i['message']))

            if log not in logCount:
                logCount[log] = 1
            else:
                logCount[log] += 1

        for event in logCount:
            if logCount[event] >= 3:  # If there are more than 3 events in a day, Send a Slack message
                message = (str(timeRn) + " " + event)
                slackSend(str(message))