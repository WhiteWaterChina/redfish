#!/usr/bin/env python
# -*- coding:cp936 -*-
import Tkinter
import requests
import os
import json
import tkMessageBox
import ttk
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_session_num_sub(bmc_ip, auth_token):
    try:
        url_sessioon = "https://%s/redfish/v1/SessionService/Sessions/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        data_session = []
        response_get_session_num = requests.get(url_sessioon, headers=headers, verify=False)
        statuscode_get_session_num = response_get_session_num.status_code
        num_session = response_get_session_num.json()['Members@odata.count']
        title_session = 'ID'.ljust(15) + 'UseName'.ljust(15)
        for count in range(1,num_session):
            url_sessioon_sub = "https://%s/redfish/v1/SessionService/Sessions/%s" % (bmc_ip, count)
            response_get_session_sub = requests.get(url_sessioon_sub, headers=headers, verify=False).json()
            line_get_session = str(response_get_session_sub['Id']).ljust(15) + str(response_get_session_sub['UserName']).ljust(15)
            data_session.append(line_get_session + os.linesep)
        return statuscode_get_session_num, title_session, data_session
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')