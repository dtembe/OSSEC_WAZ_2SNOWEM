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

#global vars

snowemurl = "https://myInstance.service-now.com/api/now/table/em_event"
snowemuser = "UserName"
snowempassword = "Password"


def processIt( l ):
    try:
        j = json.loads( l )
        o_source = "Wazuh-API"
        o_node = (j.get('agent', {}).get('name'))
        o_metric_name = (j.get('location'))
        o_type = (j.get('rule', {}).get('pci_dss'))
        o_resource = (j.get('rule', {}).get('description'))
        o_severity = (j.get('rule', {}).get('level'))
        o_description = (j.get('full_log'))
        o_event_class = (j.get('rule', {}).get('id'))
        o_additional_info = j
        # print ("-" * 50)
        # print (o_source, o_node, o_metric_name, o_type, o_resource, o_severity, o_description, o_event_class, o_additional_info)
        # print ("-" * 50)
        data = {"source": o_source, "node": o_node, "metric_name": o_metric_name, "type": o_type,
                "resource": o_resource, "severity": o_severity, "description": o_description,
                "additional_info": o_additional_info}
        data = json.dumps(data)

        headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
        request = urllib2.Request(url=snowemurl, data=data, headers=headers)
        base64string = base64.urlsafe_b64encode('%s:%s' % (snowemuser, snowempassword))
        request.add_header("Authorization", "Basic %s" % base64string)
        f = urllib2.urlopen(request)
        f.read()
        f.close()

    except:
        pass


f = subprocess.Popen(['tail','-f',"/var/ossec/logs/alerts/alerts.json"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p = select.poll()
p.register(f.stdout)

while True:
    if p.poll(1):
        try:
            processIt(f.stdout.readline())
        except:
            pass
        time.sleep(1)
