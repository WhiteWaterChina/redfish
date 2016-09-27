#!/usr/bin/env python
# -*- coding:cp936 -*-
import Tkinter
import requests
import os
import json
import tkMessageBox
import ttk


def uid_current_status(bmc_ip,auth_token):
    try:
        url_uid = "https://%s/redfish/v1/Systems/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        uid_status_response = requests.get(url_uid, headers=headers, verify=False)
        statuscode_uid_status = uid_status_response.status_code
        uid_status = uid_status_response.json()['IndicatorLED']
        return uid_status, statuscode_uid_status
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_off(bmc_ip,auth_token):
    try:
        url_uid = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"IndicatorLED\": \"Off\"}"
        uid_off = requests.patch(url_uid, headers=headers, data=payload, verify=False)
        statuscode_uid_off = uid_off.status_code
        return statuscode_uid_off
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_blinking(bmc_ip,auth_token):
    try:
        url_uid = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"IndicatorLED\": \"Blinking\"}"
        uid_on = requests.request('PATCH', url_uid, headers=headers, data=payload, verify=False)
        statuscode_uid_on = uid_on.status_code
        return statuscode_uid_on
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_info(bmc_ip, auth_token):
    try:
        url_chassis = "https://%s/redfish/v1/Chassis/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_chassis_info = requests.get(url_chassis, headers=headers, verify=False)
        statuscode_get_chassis_info = response_get_chassis_info.status_code
        data_display = response_get_chassis_info.json()
        return statuscode_get_chassis_info, data_display
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_power_info(bmc_ip, auth_token):
    try:
        url_chassis_power = "https://%s/redfish/v1/Chassis/1/Power" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_chassis_power_info = requests.get(url_chassis_power, headers=headers, verify=False)
        statuscode_get_chassis_info = response_get_chassis_power_info.status_code
        tilte_power = "SensorName".ljust(15) + "SensorNumber".ljust(15) + "ReadingVolts".ljust(
            20) + "UpperThresholdNonCritical".ljust(30) + "UpperThresholdCritical".ljust(
            30) + "UpperThresholdFatal".ljust(
            30) + "LowerThresholdNonCritical".ljust(30) + "LowerThresholdCritical".ljust(
            30) + "LowerThresholdFatal".ljust(30)
        data_to_filter_power = response_get_chassis_power_info.json()['Voltages']
        data_to_display = []
        for item in data_to_filter_power:
            sensorname = item['Name']
            sensornumber = item['SensorNumber']
            ReadingVolts = item['ReadingVolts']
            UpperThresholdNonCritical = item['UpperThresholdNonCritical']
            UpperThresholdCritical = item['UpperThresholdCritical']
            UpperThresholdFatal = item['UpperThresholdFatal']
            LowerThresholdNonCritical = item['LowerThresholdNonCritical']
            LowerThresholdCritical = item['LowerThresholdCritical']
            LowerThresholdFatal = item['LowerThresholdFatal']
            line_to_add = str(sensorname).ljust(15) + str(sensornumber).ljust(15) + str(ReadingVolts).ljust(20) + str(UpperThresholdNonCritical).ljust(
                          30) + str(UpperThresholdCritical).ljust(30) + str(UpperThresholdFatal).ljust(30) + str(LowerThresholdNonCritical).ljust(
                          30) + str(LowerThresholdCritical).ljust(30) + str(LowerThresholdFatal).ljust(30)
            data_to_display.append(line_to_add)
        return statuscode_get_chassis_info, tilte_power, data_to_display
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_thermal_info(bmc_ip, auth_token):
    try:
        url_chassis_thermal = "https://%s/redfish/v1/Chassis/1/Thermal" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_chassis_thermal_info = requests.get(url_chassis_thermal, headers=headers, verify=False)
        statuscode_get_chassis_thermal_info = response_get_chassis_thermal_info.status_code
        data_to_filter_thermal = response_get_chassis_thermal_info.json()['Temperatures']
        title_thermal = 'Name'.ljust(20) + 'State'.ljust(15) + 'ReadingCelsius'.ljust(15) + 'SensorNumber'.ljust(15) + 'UpperThresholdNonCritical'.ljust(
                        30) + 'UpperThresholdCritical'.ljust(30) + 'UpperThresholdFatal'.ljust(30) + 'LowerThresholdNonCritical'.ljust(
                        30) + 'LowerThresholdCritical'.ljust(30) + 'LowerThresholdFatal'.ljust(30)
        data_display_thermal = []
        for item in data_to_filter_thermal:
            Name = item['Name']
            SensorNumber = item['SensorNumber']
            ReadingCelsius = item['ReadingCelsius']
            State = item['Status']['State']
            UpperThresholdNonCritical = item['UpperThresholdNonCritical']
            UpperThresholdCritical = item['UpperThresholdCritical']
            UpperThresholdFatal = item['UpperThresholdFatal']
            LowerThresholdNonCritical = item['LowerThresholdNonCritical']
            LowerThresholdCritical =  item['LowerThresholdCritical']
            LowerThresholdFatal = item['LowerThresholdFatal']

            line_to_add_thermal = str(Name).ljust(20) + str(State).ljust(15) + str(ReadingCelsius).ljust(15) + str(SensorNumber).ljust(15) + str(UpperThresholdNonCritical).ljust(30) + str(UpperThresholdCritical).ljust(30) + str(UpperThresholdFatal).ljust(30
                                  ) + str(LowerThresholdNonCritical).ljust(30) + str(LowerThresholdCritical).ljust(30) + str(LowerThresholdFatal).ljust(30)
            data_display_thermal.append(line_to_add_thermal)
        return statuscode_get_chassis_thermal_info, title_thermal, data_display_thermal
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_fanmode(bmc_ip, auth_token):
    try:
        url_chassis = "https://%s/redfish/v1/Chassis/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_get_chassis_fanmode = requests.get(url_chassis, headers=headers, verify=False)
        statuscode_get_chassis_fanmode = response_get_chassis_fanmode.status_code
        data_display = response_get_chassis_fanmode.json()['Oem']['OemFan']['FanMode']
        return statuscode_get_chassis_fanmode, data_display
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')

