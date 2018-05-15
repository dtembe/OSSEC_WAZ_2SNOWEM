#!/usr/bin/python
import sys
import os
import time
import subprocess
import select
import json
from pprint import pprint
import base64
import urllib2

"""
***************
Author - Dan Tembe
Date - 05/15/2018
Compatibility - Wazuh 2.x & 3.x
***************

This is the final version of the script. It works in /bin/ossec2snowem.py
-F command ensures the tail restarts as needed. 
Change numeric value from 12 to something else, depending on the value of alerts you want to pass to ServiceNow event management.
***************
Auto start - 
Put this in /etc/init (Use /etc/systemd in Ubuntu 15.x)
ossec2snowemstartup.conf

start on runlevel [2345]
stop on runlevel [!2345]

exec /path/to/ossec2snowem.py
By placing this conf file there you hook into ubuntu's upstart service that runs services on startup.
manual starting/stopping is done with sudo service mystartupscript start and sudo service mystartupscript stop
****************
Actual Event from alerts.json after it has run through the script -
{
agent : {u'id': u'000', u'name': u'labsiem-waz01'}
manager : {u'name': u'labsiem-waz01'}
rule : {u'firedtimes': 11, u'description': u'System Audit event.', u'level': 3, u'pci_dss': [u'2.2.4'], u'cis': [u'7.2 Debian Linux'], u'groups': [u'ossec', u'rootcheck'], u'mail': False, u'id': u'516'}
decoder : {u'name': u'rootcheck'}
data : {u'file': u'/etc/fstab', u'title': u"CIS - Debian Linux - 7.2 - Removable partition /media without 'nosuid' set"}
id : 1525486328.381980
location : rootcheck
predecoder : {u'hostname': u'labsiem-waz01'}
full_log : System Audit: CIS - Debian Linux - 7.3 - User-mounted removable partition /media {CIS: 7.3 Debian Linux} {PCI_DSS: 2.2.4}. File: /etc/fstab. Reference: https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1.0.pdf .
timestamp : 2018-05-04T21:12:08-0500
}
***************

***************
Original Code 
f = subprocess.Popen(['tail','-f',"/file/to/tail"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)

while True:
    if p.poll(1):
        try:
            processIt(f.stdout.readline())
        except:
            pass
        time.sleep(1)
***************
"""


#global vars

snowemurl = "https://myinstance.service-now.com/api/now/table/em_event"
snowemuser = "UserName"
snowempassword = "Password"


def processit(l):
    try:
        j = json.loads( l )
        o_source = "Wazuh-API"
        o_node = (j.get('agent', {}).get('name'))
        o_metric_name = (j.get('location'))
        o_type = (j.get('rule', {}).get('pci_dss'))
        o_resource = (j.get('rule', {}).get('description'))
        o_severity = (j.get('rule', {}).get('level'))
        o_description = (j.get('full_log'))
        o_event_class = (j.get('rule', {}).get('level'))
        o_additional_info = j
        # print ("-" * 50)
        # print (o_source, o_node, o_metric_name, o_type, o_resource, o_severity, o_description, o_event_class, o_additional_info)
        # print ("-" * 50)
        data = {"source": o_source, "node": o_node, "metric_name": o_metric_name, "type": o_type,
                "resource": o_resource, "severity": o_severity, "event_class": o_event_class, "description": o_description,
                "additional_info": o_additional_info}
        return json.dumps(data)
    except:
        pass


def postjson(data):
        try:
            headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
            request = urllib2.Request(url=snowemurl, data=data, headers=headers)
            base64string = base64.urlsafe_b64encode('%s:%s' % (snowemuser, snowempassword))
            request.add_header("Authorization", "Basic %s" % base64string)
            f = urllib2.urlopen(request)
            f.read()
            f.close()
        except:
            pass


f = subprocess.Popen(['tail','-F',"/var/ossec/logs/alerts/alerts.json"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)



while True:
    if p.poll(1):
        try:
            data = processit(f.stdout.readline())
            #print("-" * 50)
            #print (data)
            #print("-" * 50)
            jdata = json.loads(data)
            if jdata['severity'] >= 10:
                #print ("-" * 50)
                #print (jdata['severity'])
                #print ("-" * 50)
                postjson(data)
        except:
            pass
    time.sleep(1)

