#!/usr/bin/env python
# -*- coding:cp936 -*-
import Tkinter
import requests
import os
import json
import tkMessageBox
import ttk


def get_manager_info_sub(bmc_ip, auth_token):
    try:
        url_manager = "https://%s/redfish/v1/Managers/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager = requests.get(url_manager, headers=headers, verify=False)
        statuscode_get_mangager = response_get_manager.status_code
        data_get_manager = response_get_manager.json()
        return statuscode_get_mangager, data_get_manager
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_network_protocal_sub(bmc_ip, auth_token):
    try:
        url_manager = "https://%s/redfish/v1/Managers/1/NetworkProtocol" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager_protocal = requests.get(url_manager, headers=headers, verify=False)
        statuscode_get_mangager_protocal = response_get_manager_protocal.status_code
        data_get_manager_protocal = response_get_manager_protocal.json()
        return statuscode_get_mangager_protocal, data_get_manager_protocal
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_ethernet_interface_sub(bmc_ip, auth_token):
    try:
        url_manager = "https://%s/redfish/v1/Managers/1/EthernetInterfaces/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager_interface = requests.get(url_manager, headers=headers, verify=False)
        statuscode_get_mangager_interface = response_get_manager_interface.status_code
        data_get_manager_interface = response_get_manager_interface.json()
        return statuscode_get_mangager_interface, data_get_manager_interface
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_serial_interface_sub(bmc_ip, auth_token):
    try:
        url_manager = "https://%s/redfish/v1/Managers/1/SerialInterfaces/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager_serial_interface = requests.get(url_manager, headers=headers, verify=False)
        statuscode_get_mangager_serial_interface = response_get_manager_serial_interface.status_code
        data_get_manager_serial_interface = response_get_manager_serial_interface.json()
        return statuscode_get_mangager_serial_interface, data_get_manager_serial_interface
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_current_mousemode_sub(bmc_ip, auth_token):
    try:
        url_manager_mousemode = "https://%s/redfish/v1/Managers/1/MouseMode" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager_mousemode = requests.get(url_manager_mousemode, headers=headers, verify=False)
        statuscode_get_mangager_mousemode = response_get_manager_mousemode.status_code
        data_get_manager_mousemode = response_get_manager_mousemode.json()['Mode']
        return statuscode_get_mangager_mousemode, data_get_manager_mousemode
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_logservices_sub(bmc_ip, auth_token):
    try:
        url_manager_logservices = "https://%s/redfish/v1/Managers/1/LogServices/Log1/Entries" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager_logservice = requests.get(url_manager_logservices, headers=headers, verify=False)
        statuscode_get_number_log = response_get_manager_logservice.status_code
        number_log_entries = response_get_manager_logservice.json()['Members@odata.count']
        data_log_sum = []
        for count in range(1,number_log_entries+1):
            url_get_log = "https://%s/redfish/v1/Managers/1/LogServices/Log1/Entries/%s" % (bmc_ip,count)
            response_get_log = requests.get(url_get_log, headers=headers, verify=False)
            data_log = json.dumps(response_get_log.json(), indent=4)
            data_log_sum.append(data_log + os.linesep)
        return statuscode_get_number_log, number_log_entries, data_log_sum
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_ntp_info_sub(bmc_ip, auth_token):
    try:
        url_manager_ntp = "https://%s/redfish/v1/Managers/1/NTP" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_manager_ntp = requests.get(url_manager_ntp, headers=headers, verify=False)
        statuscode_get_ntp = response_get_manager_ntp.status_code
        return statuscode_get_ntp, json.dumps(response_get_manager_ntp.json(), indent=4)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def clear_sel_log_sub(bmc_ip, auth_token):
    try:
        url_manager_clearsel = "https://%s/redfish/v1/Managers/1/LogServices/Log1/Actions/LogService.Reset" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload =  "{\"Actions\": {\"ClearLog\"}"
        response_clear_sel = requests.post(url_manager_clearsel, headers=headers, data=payload,  verify=False)
        statuscode_clear_sel = response_clear_sel.status_code
        return statuscode_clear_sel
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def reset_bmc_sub(bmc_ip, auth_token):
    try:
        url_reset_bmc = "https://%s/redfish/v1/Managers/1/Actions/Manager.Reset" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"Actions\": {\"Reset\"}"
        response_reset_bmc = requests.post(url_reset_bmc, headers=headers, data=payload, verify=False)
        statuscode_reset_bmc = response_reset_bmc.status_code
        return statuscode_reset_bmc
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def bmc_restore_factory(bmc_ip, auth_token):
    try:
        url_restor_factory = "https://%s/redfish/v1/Managers/1/Actions/Oem/ManagerConfig.Reset" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"Actions\": {\"Reset\"}"
        response_restort_factory = requests.post(url_restor_factory, headers=headers, data=payload, verify=False)
        statuscode_restort_factory = response_restort_factory.status_code
        return statuscode_restort_factory
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')
