import re
import functools
import sys
from splunklib.searchcommands import dispatch, Configuration, StreamingCommand, Option, validators


@Configuration()
class SysToXml(StreamingCommand):
    """
    ## syntax
    
    <command>|systoxml

    ## Description

    Conversion from syslog data to xml.It can be used on any Windows version.
    The app will return the Splunk syslog events as xml events.
    Also, the application works on events that end with the common suffix "This event is generated..".
    
    ## Example
    
    index=syslog "This event"|systoxml

    """
    
    
    dict_xml = dict()   # A dictionary with the keys event id and version and the values are an xml log.
    dict_ext = dict()   # A dictionary with the keys event id and version and the values is the extraction pattern.

    
    def get_key(self,x):
        """This function extracts the sub-keys and returns whether there was a match or not"""
        m = re.search(r'.*(?:\t|^)(.*):\t.*%.*', x)
        if m:
            return m.group(1)
        return ''

    def get_prime_key(self,x):
        """This function extracts the primekeys and returns whether there was a match or not"""
        m = re.search(r'^([^\t]*):(?:[^%]*)$', x)
        if m:
            return m.group(1)
        return ''

    def connection_to_xml_db(self):
        """Connecting to the xml file"""
        f1 = open(os.environ.get('SPLUNK_HOME'))
        #f1 = open(r"C:\Users\barel\Desktop\xmldb.txt")
        xml = f1.read()
        f1.close()
        return xml
          
    def temmplate_xml_extraction(self):
        """This function creates a template for extracting value from syslog events"""
        xml = self.connection_to_xml_db()
        xml_output = xml.split('Id          :')
        for log in xml_output:
            if log != None and log !='\n\n':
                log = "Id          :" + log
                dict = {}
                id_ext = re.search(r'(?<=Id          :)(.*?)(?=\nVersion)',log)
                version_ext = re.search(r'(?<=Version     :)(.*?)(?=\nLogLink)',log)
                version = int(version_ext.group(1).strip())
                if id_ext:
                    eventcode_key = int(id_ext.group(1).strip())
                    self.dict_xml[(eventcode_key,version)] = log



                m = re.search( r'(?:.|\n)*Description : .*\n(?:[^A-Z])*((.|\n)*)This event(?:(.|\n)*)', log)
                subkeys_string = list(map(lambda x: x.strip(),list(filter(lambda x: x!='', list(map(lambda x: self.get_key(x), m.group(1).split("\n")))))))
                primekeys_strings = list(map(lambda x: x.strip(),list(filter(lambda x: x!='', list(map(lambda x: self.get_prime_key(x), m.group(1).split("\n")))))))
                subkeys_string_without_metachar = list(map(lambda x: re.escape(x), subkeys_string))   # Duplicate the keys list without special characters for regular expressions below.
                primekeys_strings_without_metachar = list(map(lambda x: re.escape(x), primekeys_strings))



                for i in primekeys_strings_without_metachar:   # A helper dictionary in which the keyes are prime keys and the values are sub-keys.
                    dict[i] = list()


                if primekeys_strings_without_metachar:
                    ext_prime_re = functools.reduce(lambda a,b: a+b+"((?:.|\n)*)", primekeys_strings_without_metachar, ".*")   # Extraction pattern between primary keys
                    m2 = re.search(ext_prime_re, m.group(1))
                    j = 0   
                    i = 0
                    while i < len(subkeys_string):
                        if m2.group(j+1).find(subkeys_string[i]) != -1 and subkeys_string_without_metachar[i] not in dict[primekeys_strings_without_metachar[j]]:
                            dict[primekeys_strings_without_metachar[j]].append(subkeys_string_without_metachar[i])
                            i += 1
                        else:
                            j += 1
                            if j > (len(m2.groups()) - 1):
                                break


                ext_value_re_arr = list(map(lambda x: functools.reduce(lambda a,b: a+b+": ((?:.|\n)*)", x, ""), list(dict.values())))  # Extraction pattern between sub-keys for each primary key
                ext_all_values_re ="^(?:.|\n)*"
                for i in range(len(primekeys_strings_without_metachar)):
                    ext_all_values_re += primekeys_strings_without_metachar[i]+":   " +ext_value_re_arr[i]    # Final template - primekey: subkey: value
                self.dict_ext[(eventcode_key,version)] = ext_all_values_re
                
    def convert_sys_to_xml(self,eventcode,version,syslogStr):
        """This function receives a key for an extrction template(eventcode,version) and accordingly returns a syslog event in xml format"""
        if self.dict_ext.get((eventcode,version)):
            if self.dict_ext[(eventcode,version)]:
                new_rec = re.search(r'((.|\n)*)This event', syslogStr)
                f_rec=list(new_rec.groups())[:-1]
                m3 = re.search(self.dict_ext[(eventcode,version)], str(f_rec[0]))
                if m3:
                    sys_to_xml=self.dict_xml[(eventcode,version)]
                    for i in m3.groups():
                        sys_to_xml= re.sub(r'%\d+', i, sys_to_xml,1)
                    return sys_to_xml
            
   
    def stream(self, records):
        self.temmplate_xml_extraction()
        for record in records:
            id_sys_ext = re.search(r'EventID\=(.*?)\\tEventIDCode', record['_raw'])
            if id_sys_ext:
                eventcode_sys_key = id_sys_ext.group(1).strip()
                eventcode_sys_key=eventcode_sys_key.replace("\\","")
                eventcode_sys_key=int(eventcode_sys_key)
                if self.convert_sys_to_xml(eventcode_sys_key,0,record['_raw']):
                    record['xml_raw'] = self.convert_sys_to_xml(eventcode_sys_key,0,record['_raw'])
                if self.convert_sys_to_xml(eventcode_sys_key,1,record['_raw']):
                    record['xml_raw'] = self.convert_sys_to_xml(eventcode_sys_key,1,record['_raw'])
                if self.convert_sys_to_xml(eventcode_sys_key,2,record['_raw']):
                    record['xml_raw'] = self.convert_sys_to_xml(eventcode_sys_key,2,record['_raw'])
                yield record


            
if __name__ == "__main__":
    dispatch(SysToXml, sys.argv, sys.stdin, sys.stdout, __name__)


