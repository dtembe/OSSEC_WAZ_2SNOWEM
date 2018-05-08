# OSSEC_WAZ_2SNOWEM
OSSEC or WAZUH Alerts to ServiceNOW Event Management Module 


Ossec/Wazuh to SNOW EM

This is a simple single shell script to connect OSSEC or WAZUH to SNOW EM. Using the existing slack integration.

Steps - log into OSSEC / WAZUH. Navigate to /var/ossec/integration/ cp -p slack slack.old vi slack dd all lines copy and paste all lines from waz2snowgtw.sh file change the post URL save the updated slack file

Next step - Initialize the integration naivgate to /var/ossec/etc/ vi ossec.conf add following lines

slack https://myInstance.service-now.com/api/now/table/em_event/

save the updated ossec.conf file

navigate to /var/ossec/bin directory ossec-control enable integration ossec-control restart

then cat the /var/ossec/logs/integrations.log file and grep for integration to see if there are any errors also cat the ossec.log file in the same directory to see if there are any errors in enabling the integration. Otherwise, you are good to go.

if credentials are correct, you should see all alerts from Wazuh / ossec in your ServiceNOW Event Management console.

Write Rules and map these to alerts, Create incidents and Dashboards. 

Thanks! 

Dan

Included is a Python script that can be run at statup which duplicates the alerts stream with data directly queried from the alerts.json file. This provides a lot more detail in the event and uses REST/JSON for push events. 

ossec2snowem.py

Thanks!
Dan


