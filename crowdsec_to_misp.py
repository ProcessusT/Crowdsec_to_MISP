#!/usr/bin/env python3

from datetime import date
import time
import os, sys
import sqlite3
import re
from pymisp import PyMISP, MISPEvent


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

                

                # MISP config keys
                misp_url='https://<MISP URL>'
                misp_key='<MISP API KEY>'
                misp_verifycert=True

                try:

                        pymisp=PyMISP(misp_url, misp_key, misp_verifycert)

                        oldevent = pymisp.search(eventinfo='CROWDSEC DB', metadata=True)
                        oldevent_id = oldevent[0]['Event']['id']

                        
                        event = MISPEvent()
                        event.distribution = 1
                        event.threat_level_id = 1
                        event.analysis = 0
                        event.info = "CROWDSEC DB"
                        event = pymisp.add_event(event, pythonify=True)

                        # CROWDSEC-IPS event id
                        event_id=event.id

                        for ip in crowdsec_ips:
                                result=pymisp.add_attribute(event_id, {'type': 'ip-dst', 'value': str(ip), 'comment': 'From Crowdsec community decisions'}, pythonify=True)

                        # on delete l'ancien event
                        pymisp.delete_event(oldevent_id)
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