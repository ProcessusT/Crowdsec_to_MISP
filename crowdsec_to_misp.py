#!/usr/bin/env python3

from datetime import date
import time
import os, sys
import sqlite3
import re
from pymisp import PyMISP


try:
        # Check if crowdsec db exists
        if os.path.isfile("/var/lib/crowdsec/data/crowdsec.db"):
                try:
                        con = sqlite3.connect("/var/lib/crowdsec/data/crowdsec.db")
                        curs = con.cursor()
                        # get all ips (value) from the community decisions table
                        curs.execute("select value from decisions")
                        consoles = curs.fetchall()
                        con.close()
                        crowdsec_ips = []
                        for console in consoles:
                                try:
                                        # For each ip, append in global array
                                        crowdsec_ips.append(str(console[0]))
                                except Exception as err:
                                        print(err)
                                        pass
                        con.close()
                except Exception as err:
                        print(err)
                        sys.exit(1)

                # CROWDSEC-IPS event id
                event_id=<YOUR MISP EVENT ID HERE>

                # MISP config keys
                misp_url='https://<YOUR MISP DNS NAME HERE>:8085/'
                misp_key='<YOU MISP API KEY HERE>'
                misp_verifycert=True

                try:
                        pymisp=PyMISP(misp_url, misp_key, misp_verifycert)
                        for ip in crowdsec_ips:
                                result=pymisp.add_attribute(event_id, {'type': 'ip-dst', 'value': str(ip), 'comment': 'From Crowdsec community decisions'}, pythonify=True)
                except Exception as err:
                        print(err)
                        sys.exit(1)

                print("It seems that everything works fine. For the moment.")
        else:
                print("Database does not exist.\n")
                sys.exit(1)
except Exception as err:
        print(err)
        sys.exit(1)