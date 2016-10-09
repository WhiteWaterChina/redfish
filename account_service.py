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


def display_account_sub(bmc_ip, auth_token):
    try:
        url_display_account = "https://%s/redfish/v1/AccountService/Accounts" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        qq = requests.get(url_display_account, headers=headers, verify=False)
        test = qq.json()["Members"]
        account_num = []
        url_account = []
        info_account_display = []
        for line in test:
            account_num.append(str(line["@odata.id"]).split('/')[-1])
        for number_account in account_num:
            url_account.append("https://%s/redfish/v1/AccountService/Accounts/%s" % (bmc_ip, number_account))
        title_display = "ID".ljust(10) + "UserName".ljust(20) + "RoleId".ljust(15) + "Locked".ljust(10) + "Enabled".ljust(10)
        for url_account_display in url_account:
            response_display_account_1 = requests.get(url_account_display, headers=headers, verify=False)
            response_display_account = response_display_account_1.json()
            id_display = response_display_account['Id']
            username_display = response_display_account['UserName']
            roleid_display = response_display_account['RoleId']
            locked_display = response_display_account['Locked']
            enabled_display = response_display_account['Enabled']
            content_display = str(id_display).ljust(10) + str(username_display).ljust(20) + str(roleid_display).ljust(15) + str(locked_display).ljust(10) + str(enabled_display).ljust(10)
            statuscode_display_account = response_display_account_1.status_code
            info_account_display.append(content_display)
            if statuscode_display_account != 200:
                tkMessageBox.showerror('错误'.decode('gbk'), '请检查Auth是否已经过期'.decode('gbk'))
        return title_display, info_account_display
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')
