# Splunk SysToXml Command

This app’s main function is to enable a custom Splunk search command to convert from syslog data to XML. XML logs are more understandable and readable and can be very helpful           for parsing and indexing data. By filtering Syslog events in Splunk and using this command, you can quickly convert them to XML format.                                                                                                      
# Note : your Splunk instance doesn’t require internet access.   

# Prerequisites
•	Install Splunk SDK for Python.
•	Filtering syslog window events and the common suffix “This event” in Splunk.
•	Load a txt file used as an xml database (under the “connection_to_xml_db” function).

# Installation
•	Unpack to $SPLUNK_HOME/etc/apps on your Splunk search head and restart the instance.

# Usage
The command is intended for syslog events that end in the common suffix “This event” , and can be used for any windows version.                                                                                                                     The command returns a new field called “xml_raw” that displays syslog events in xml format.  
Use as a search command like so:                                                                                                                 
index=syslog  “This  event”
| systoxml
| table xml_raw


https://github.com/barelk/SyslogToXml

Built By Bar Elkalai
