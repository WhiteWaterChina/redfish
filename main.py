#!/usr/bin/env python
# -*- coding:cp936 -*-
import Tkinter
import requests
import os
import json
import tkMessageBox
import ttk
import add_account
auth_token = 0
root = Tkinter.Tk()
root.title("Redfish测试工具".decode('gbk'))
root.geometry('800x600')
#        self.root.iconbitmap('inspur.ico')
root.resizable(width=True, height=True)
var_char_entry_username_add = Tkinter.StringVar()
var_char_entry_password_add = Tkinter.StringVar()
var_char_entry_id_add = Tkinter.StringVar()
var_char_enabled_or_not = Tkinter.StringVar()
var_char_locked_or_not = Tkinter.StringVar()
var_char_roleid = Tkinter.StringVar()



def get_x_auth_token():
    global auth_token
    global bmc_ip
    try:
        bmc_ip = var_char_entry_bmcip.get()
        username = var_char_entry_username.get()
        password = var_char_entry_password.get()
        url_auth_session = "https://%s/redfish/v1/SessionService/Sessions/" % bmc_ip
        payload = "{\"UserName\":\"%s\",\"Password\":\"%s\"}" % (username, password)
        headers = {
            'cache-control': "no-cache",
        }
        response_to_get_auth = requests.post(url_auth_session, data=payload, headers=headers, verify=False)
        auth_token = response_to_get_auth.headers.get('X-Auth-Token ')
        text_show.delete(0.0, Tkinter.END)
        text_show.insert('1.0', 'Below is the authorized key:' + os.linesep + auth_token)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'Invalid IP/Username/Password')


def get_processor1_info():
    try:
        url_cpu1_info = "https://%s/redfish/v1/Systems/1/Processors/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_cpu1 = requests.get(url_cpu1_info, headers=headers, verify=False)
        response_cpu1_info = json.dumps(response_cpu1.json(), indent=4)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the infomation of CPU1' + os.linesep)
        text_show.insert(Tkinter.END, response_cpu1_info)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_processor2_info():
    try:
        url_cpu2_info = "https://%s/redfish/v1/Systems/1/Processors/2" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_cpu2 = requests.get(url_cpu2_info, headers=headers, verify=False)
        response_cpu2_info = json.dumps(response_cpu2.json(), indent=4)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the infomation of CPU2' + os.linesep)
        text_show.insert(Tkinter.END, response_cpu2_info)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def forcerestart_computer():
    try:
        url_computerreset = "https://%s/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"ResetType\":\"ForceRestart\"}"
        computer_forcereset = requests.post(url_computerreset, headers=headers, data=payload, verify=False)
        statuscode_forcerestart_computer = computer_forcereset.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of ForceRestart' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_forcerestart_computer)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def forceoff_computer():
    try:
        url_computerreset = "https://%s/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"ResetType\":\"ForceOff\"}"
        computer_off = requests.post(url_computerreset, headers=headers, data=payload, verify=False)
        statuscode_forceoff_computer = computer_off.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of ForceOff' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_forceoff_computer)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def forceon_computer():
    try:
        url_computerreset = "https://%s/redfish/v1/Systems/1/Actions/ComputerSystem.Reset" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"ResetType\":\"On\"}"
        computer_on = requests.post(url_computerreset, headers=headers, data=payload, verify=False)
        statuscode_forceon_computer = computer_on.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of ForceOn' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_forceon_computer)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_blinking():
    try:
        url_uid = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"IndicatorLED\": \"Blinking\"}"
        uid_on = requests.request('PATCH', url_uid, headers=headers, data=payload, verify=False)
        statuscode_uid_on = uid_on.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of uid blinking' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_uid_on)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_off():
    try:
        url_uid = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"IndicatorLED\": \"Off\"}"
        uid_off = requests.patch(url_uid, headers=headers, data=payload, verify=False)
        statuscode_uid_off = uid_off.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of uid off' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_uid_off)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_current_status():
    try:
        url_uid = "https://%s/redfish/v1/Systems/1" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        uid_status_response = requests.get(url_uid, headers=headers, verify=False).json()
        uid_status = uid_status_response['IndicatorLED']
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Current Status of UID is:' + os.linesep)
        text_show.insert(Tkinter.END, uid_status)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def boot_to_bios():
    try:
        url_bootdevice = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        payload = "{\"Boot\": {\"BootSourceOverrideEnabled\": \"Once\",\"BootSourceOverrideTarget\": \"BiosSetup\"}}"
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        boot_to_bios_response = requests.patch(url_bootdevice, headers=headers, data=payload, verify=False)
        statuscode_boot_to_bios = boot_to_bios_response.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of Boot to Bios:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_boot_to_bios)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def boot_to_hdd():
    try:
        url_bootdevice = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        payload = "{\"Boot\": {\"BootSourceOverrideEnabled\": \"Once\",\"BootSourceOverrideTarget\": \"Hdd\"}}"
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        boot_to_hdd_response = requests.patch(url_bootdevice, headers=headers, data=payload, verify=False)
        statuscode_boot_to_hdd = boot_to_hdd_response.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of Boot to Hdd:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_boot_to_hdd)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def boot_to_pxe():
    try:
        url_bootdevice = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        payload = "{\"Boot\": {\"BootSourceOverrideEnabled\": \"Once\",\"BootSourceOverrideTarget\": \"Pxe\"}}"
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        boot_to_pxe_response = requests.patch(url_bootdevice, headers=headers, data=payload, verify=False)
        statuscode_boot_to_pxe = boot_to_pxe_response.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of Boot to Pxe:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_boot_to_pxe)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def showhelp():
    try:
        helpdetail = ''' 这里是测试使用说明!
            请先在窗口中分别输入要测试的BMC的IP/用户名/密码。
            然后点击GET_AUTH获取x-auth-token。再进行后面的测试。
            Token的有效期是30分钟，如果测试中出现unauthorized的错误时，请重新点击GET_AUTH来获取x-auth-token'''.decode('gbk')
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, helpdetail + os.linesep)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')

def addaccount():

    new_window = Tkinter.Toplevel()
    new_window.title("增加新用户".decode('gbk'))
    new_window.geometry('600x300')
    frame_sec_top = Tkinter.Frame(new_window, height=6)
    frame_sec_top.pack(side=Tkinter.TOP)
    Tkinter.Label(frame_sec_top, text='请在如下输入需要增加的用户名/密码/ID等信息'.decode('gbk'), bg='Yellow').pack()

    frame_sec_middle = Tkinter.Frame(new_window, height=6)
    frame_sec_middle.pack(fill=Tkinter.X)
    frame_middle_username = Tkinter.Frame(frame_sec_middle)
    frame_middle_username.pack(side=Tkinter.LEFT)

    frame_middle_password = Tkinter.Frame(frame_sec_middle)
    frame_middle_password.pack(side=Tkinter.LEFT)

    frame_middle_id = Tkinter.Frame(frame_sec_middle)
    frame_middle_id.pack(side=Tkinter.LEFT)

    frame_middle_roleid = Tkinter.Frame(frame_sec_middle)
    frame_middle_roleid.pack(side=Tkinter.LEFT)

    frame_middle_enabled = Tkinter.Frame(frame_sec_middle)
    frame_middle_enabled.pack(side=Tkinter.LEFT)

    frame_middle_locked = Tkinter.Frame(frame_sec_middle)
    frame_middle_locked.pack(side=Tkinter.LEFT)

    Tkinter.Label(frame_middle_username, text='用户名'.decode("gbk"), width=10).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_password, text='密码'.decode('gbk'), width=10).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_enabled, text='是否生效'.decode('gbk'), width=10).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_id, text="用户ID号".decode('gbk'), width=10).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_roleid, text='用户权限'.decode('gbk'), width=10).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_locked, text='是否锁定'.decode('gbk'), width=10).pack(side=Tkinter.TOP)

#    global var_char_entry_username_add
#    var_char_entry_username_add = Tkinter.StringVar()
    Tkinter.Entry(frame_middle_username, textvariable=var_char_entry_username_add, width=10).pack(
            side=Tkinter.BOTTOM)

#    global var_char_entry_password_add
#    var_char_entry_password_add = Tkinter.StringVar()
    Tkinter.Entry(frame_middle_password, textvariable=var_char_entry_password_add, width=10).pack(
            side=Tkinter.BOTTOM)

#    global var_char_enabled_or_not
#    var_char_enabled_or_not = Tkinter.StringVar()
    enabled_box = ttk.Combobox(frame_middle_enabled, textvariable=var_char_enabled_or_not,
                                   values=['true', 'false'], width=10)
    enabled_box.pack(side=Tkinter.BOTTOM)

#    global var_char_locked_or_not
#    var_char_locked_or_not = Tkinter.StringVar()
    locked_box = ttk.Combobox(frame_middle_locked, textvariable=var_char_locked_or_not,
                                  values=['True', 'False'], width=10)
    locked_box.pack(side=Tkinter.BOTTOM)

#    global var_char_roleid
#    var_char_roleid = Tkinter.StringVar()
    roleid_box = ttk.Combobox(frame_middle_roleid, textvariable=var_char_roleid, values=['Admin', 'Operator', 'ReadOnlyUser'], width=10)
    roleid_box.pack(side=Tkinter.BOTTOM)

#    global var_char_entry_id_add
#    var_char_entry_id_add = Tkinter.StringVar()
    Tkinter.Entry(frame_middle_id, textvariable=var_char_entry_id_add, width=10).pack(
            side=Tkinter.BOTTOM)

    frame_sec_bottom = Tkinter.Frame(new_window)
    frame_sec_bottom.pack()
    Tkinter.Button(frame_sec_bottom, text='确定'.decode('gbk'), width=30, command=play_add_account).pack(side=Tkinter.LEFT)
    Tkinter.Button(frame_sec_bottom, text='退出'.decode('gbk'), width=30, command=new_window.quit()).pack(side=Tkinter.RIGHT)

def play_add_account():
        try:
            username_add_account = var_char_entry_username_add.get()
            password_add_account = var_char_entry_password_add.get()
            id_add_account = var_char_entry_id_add.get()
            enabled_str_account = var_char_enabled_or_not.get()
            locked_str_account = var_char_locked_or_not.get()
            roleid_str_account = var_char_roleid.get()
            url_account = "https://%s/redfish/v1/AccountService/Accounts/" % bmc_ip
            headers = {
                'x-auth-token': "%s" % auth_token,
                'cache-control': "no-cache",
            }
            payload = '{\"UserName\":\"%s\", \"Password\":\"%s\", \"Locked\":\"%s\", \"RoleId\":\"%s\", \"Enabled\":%s}' % (username_add_account, password_add_account, locked_str_account, roleid_str_account, enabled_str_account)
            add_account_response = requests.post(url_account, headers=headers, data=payload, verify=False)
            statuscode_add_account = add_account_response.status_code
            text_show.delete(0.0, Tkinter.END)
            text_show.insert(1.0, 'Statuscode of add account:' + os.linesep)
            text_show.insert(Tkinter.END, statuscode_add_account)

        except BaseException:
            tkMessageBox.showerror('ERROR', 'ERROR')

#global new_window
# top
menubar = Tkinter.Menu(root)
helpmenu = Tkinter.Menu(menubar, tearoff=0)
helpmenu.add_command(label="使用说明".decode('gbk'), command=showhelp)
menubar.add_cascade(label="Usage", menu=helpmenu)
root.config(menu=menubar)

# top_frame
frame_top = Tkinter.Frame(root, height=6)
frame_top.pack(side=Tkinter.TOP)

frame_top_left = Tkinter.Frame(frame_top)
frame_top_left.pack(side=Tkinter.LEFT)

frame_top_middle = Tkinter.Frame(frame_top)
frame_top_middle.pack(side=Tkinter.LEFT)

frame_top_right = Tkinter.Frame(frame_top)
frame_top_right.pack(side=Tkinter.RIGHT)

Tkinter.Label(frame_top_left, text='BMC_IP', bg='Red', width=30).pack(side=Tkinter.TOP)
Tkinter.Label(frame_top_middle, text='用户名'.decode('gbk'), bg='Green', width=30).pack(side=Tkinter.TOP)
Tkinter.Label(frame_top_right, text='密码'.decode('gbk'), bg='Yellow', width=30).pack(side=Tkinter.TOP)

var_char_entry_bmcip = Tkinter.StringVar()
Tkinter.Entry(frame_top_left, textvariable=var_char_entry_bmcip, width=30).pack(side=Tkinter.BOTTOM)
#        self.var_char_entry_bmcip.set('None')

var_char_entry_username = Tkinter.StringVar()
Tkinter.Entry(frame_top_middle, textvariable=var_char_entry_username, width=30).pack(
        side=Tkinter.BOTTOM)
#        self.var_char_entry_username.set('None')

var_char_entry_password = Tkinter.StringVar()
Tkinter.Entry(frame_top_right, textvariable=var_char_entry_password, width=30).pack(
        side=Tkinter.BOTTOM)
#        self.var_char_entry_password.set('None')

# right_text_show
frame_right = Tkinter.Frame(root)
frame_right.pack(side=Tkinter.RIGHT)
text_show = Tkinter.Text(frame_right)
text_show.pack(fill=Tkinter.BOTH)
text_show.insert('1.0', 'hello!')

# left_button
frame_left = Tkinter.Frame(root)
frame_left.pack(side=Tkinter.LEFT, fill=Tkinter.BOTH)

Tkinter.Button(frame_left, text='GET_AUTH', command=get_x_auth_token, width=30).pack()

menubar_system = Tkinter.Menubutton(frame_left, text='Get_processor_info', width=30)
menubar_system.pack()
menu_system_processor = Tkinter.Menu(menubar_system)
menu_system_processor.add_command(label='Processor_1', command=get_processor1_info)
menu_system_processor.add_command(label='Processor_2', command=get_processor2_info)
menubar_system['menu'] = menu_system_processor
#       power control
menubar_power_control = Tkinter.Menubutton(frame_left, text='Power_control', width=30)
menubar_power_control.pack()
menu_power_control = Tkinter.Menu(menubar_power_control)
menu_power_control.add_command(label='ForceRestart', command=forcerestart_computer)
menu_power_control.add_command(label='ForceOff', command=forceoff_computer)
menu_power_control.add_command(label='ForceOn', command=forceon_computer)
menubar_power_control['menu'] = menu_power_control
#       UID灯控制
menubar_uid_control = Tkinter.Menubutton(frame_left, text='UID_Control', width=30)
menubar_uid_control.pack()
menu_uid_control = Tkinter.Menu(menubar_uid_control)
menu_uid_control.add_command(label='Get_Status', command=uid_current_status)
menu_uid_control.add_command(label='Blinking', command=uid_blinking)
menu_uid_control.add_command(label='Off', command=uid_off)
menubar_uid_control['menu'] = menu_uid_control

menubar_bootdevice = Tkinter.Menubutton(frame_left, text='Bootdevice', width=30)
menubar_bootdevice.pack()
menu_bootdevice = Tkinter.Menu(menubar_bootdevice)
menu_bootdevice.add_command(label='PXE', command=boot_to_pxe)
menu_bootdevice.add_command(label='BIOS', command=boot_to_bios)
menu_bootdevice.add_command(label='HDD', command=boot_to_hdd)
#        self.menu_bootdevice.add_command(label='FloppyRemovableMedia', command=self.boot_to_floppyremovablemedia)
#        self.menu_bootdevice.add_command(label='UsbKey',command=self.boot_to_usbkey)
#        self.menu_bootdevice.add_command(label='UsbHdd', command=self.boot_to_usbhdd)
#        self.menu_bootdevice.add_command(label='UsbFloppy', command=self.boot_to_usbfloppy)
#        self.menu_bootdevice.add_command(label='UsbCd', command=self.boot_to_usbcd)
#        self.menu_bootdevice.add_command(label='UefiUsbKey', commmand=self.boot_to_uefiusbkey)
#        self.menu_bootdevice.add_command(label='UefiCd', command=self.boot_to_ueficd)
#        self.menu_bootdevice.add_command(label='UefiHdd', command=self.boot_to_uefihdd)
#        self.menu_bootdevice.add_command(label='UefiUsbHdd',command=self.boot_to_uefiusbhdd)
#        self.menu_bootdevice.add_command(label='UefiUsbCd'.command=self.boot_to_uefiusbcd)
menubar_bootdevice['menu'] = menu_bootdevice

menubar_account = Tkinter.Menubutton(frame_left, text='Account', width=30)
menubar_account.pack()
menu_account = Tkinter.Menu(menubar_account)
menu_account.add_command(label='ADD', command=addaccount)
#Tkinter.Button(frame_left, text='Add_account', command=addaccount, width=30).pack()
menubar_account['menu'] = menu_account

Tkinter.mainloop()
