#!/usr/bin/env python
# -*- coding:cp936 -*-
import Tkinter
import requests
import os
import json
import tkMessageBox
import ttk


def get_system_info_sub(bmc_ip, auth_token):
    try:
        url_chassis = "https://%s/redfish/v1/Systems/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_system_info = requests.get(url_chassis, headers=headers, verify=False)
        statuscode_get_system_info = response_get_system_info.status_code
        data_display = response_get_system_info.json()
        return statuscode_get_system_info, data_display
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_processor1_info(bmc_ip, auth_token):
    try:
        url_cpu1_info = "https://%s/redfish/v1/Systems/1/Processors/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_cpu1 = requests.get(url_cpu1_info, headers=headers, verify=False)
        data_cpu1 = json.dumps(response_cpu1.json(), indent=4)
        statuscode_cpu1_info = response_cpu1.status_code
        return statuscode_cpu1_info, data_cpu1
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_processor2_info(bmc_ip, auth_token):
    try:
        url_cpu2_info = "https://%s/redfish/v1/Systems/1/Processors/2" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_cpu2 = requests.get(url_cpu2_info, headers=headers, verify=False)
        data_cpu2 = json.dumps(response_cpu2.json(), indent=4)
        statuscode_cpu2_info = response_cpu2.status_code
        return statuscode_cpu2_info, data_cpu2
    except BaseException:
            tkMessageBox.showerror('ERROR', 'ERROR')


def get_simplestorage_sub(bmc_ip, auth_token):
    try:
        url_simplestorage = "https://%s/redfish/v1/Systems/1/SimpleStorage/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_simplestorage = requests.get(url_simplestorage, headers=headers, verify=False)
        data_simplestorage = json.dumps(response_simplestorage.json(), indent=4)
        statuscode_simplestorage = response_simplestorage.status_code
        return statuscode_simplestorage, data_simplestorage
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


