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