#!/usr/bin/env python
# -*- coding:cp936 -*-
import Tkinter
import requests
import os
import json
import tkMessageBox
import ttk
import account_service
import chassis
import system
import manager

auth_token = 0
bmc_ip = 0
root = Tkinter.Tk()
root.title("Redfish���Թ���".decode('gbk'))
root.geometry('800x600')
#        self.root.iconbitmap('inspur.ico')
root.resizable(width=True, height=True)
var_char_entry_username_add = Tkinter.StringVar()
var_char_entry_password_add = Tkinter.StringVar()
var_char_entry_id_add = Tkinter.StringVar()
var_char_enabled_or_not = Tkinter.StringVar()
var_char_locked_or_not = Tkinter.StringVar()
var_char_roleid = Tkinter.StringVar()
var_char_id_del = Tkinter.StringVar()
var_char_entry_id_change_roleid = Tkinter.StringVar()
var_char_roleid_change = Tkinter.StringVar()
var_char_entry_id_change_password = Tkinter.StringVar()
var_char_entry_new_passwd = Tkinter.StringVar()
var_char_fanmode = Tkinter.StringVar()
var_char_combox_bootdevice = Tkinter.StringVar()
var_char_combox_mousemode = Tkinter.StringVar()


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
        tkMessageBox.showerror('����'.decode('gbk'), '����IP/�û���/�����Ƿ���ȷ�������Ƿ�ͨ��'.decode('gbk'))


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


def set_bootdevice():
    try:
        new_window_bootdevice = Tkinter.Toplevel()
        new_window_bootdevice.title("�����´������豸".decode('gbk'))
        new_window_bootdevice.geometry('600x300')
        frame_sec_top = Tkinter.Frame(new_window_bootdevice, height=6)
        frame_sec_top.pack(side=Tkinter.TOP)
        Tkinter.Label(frame_sec_top, text='��������ѡ���´��������豸'.decode('gbk'), bg='Yellow').pack()

        frame_sec_middle = Tkinter.Frame(new_window_bootdevice, height=10)
        frame_sec_middle.pack(fill=Tkinter.X)

        frame_middle_bootdevice = Tkinter.Frame(frame_sec_middle)
        frame_middle_bootdevice.pack()

        Tkinter.Label(frame_middle_bootdevice, text='ѡ�������豸'.decode("gbk"), width=30, height=3).pack(side=Tkinter.TOP)
        box_set_bootdevice = ttk.Combobox(frame_middle_bootdevice, textvariable=var_char_combox_bootdevice,
                              values=['Pxe', 'Hdd', 'BiosSetup'], width=20)
        box_set_bootdevice.pack(side=Tkinter.BOTTOM)

        frame_sec_bottom = Tkinter.Frame(new_window_bootdevice)
        frame_sec_bottom.pack()
        Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, height=2, command=play_set_bootdevice).pack(
            side=Tkinter.LEFT)
        Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30, height=2, command=new_window_bootdevice.destroy
                       ).pack(side=Tkinter.RIGHT)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def play_set_bootdevice():
    try:
        bootdevice = var_char_combox_bootdevice.get()
        url_set_bootdevice = "https://%s/redfish/v1/Systems/1/" % bmc_ip
        payload = "{\"Boot\": {\"BootSourceOverrideEnabled\": \"Once\",\"BootSourceOverrideTarget\": \"%s\"}}" % bootdevice
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        response_set_bootdevice = requests.patch(url_set_bootdevice, headers=headers, data=payload, verify=False)
        statuscode_set_bootdevice = response_set_bootdevice.status_code
        print  statuscode_set_bootdevice
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of Boot to %s:' % bootdevice + os.linesep)
        text_show.insert(Tkinter.END, statuscode_set_bootdevice)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def showhelp():
    try:
        helpdetail = ''' �����ǲ���ʹ��˵��!
            �����ڴ����зֱ�����Ҫ���Ե�BMC��IP/�û���/���롣
            Ȼ����GET_AUTH��ȡx-auth-token���ٽ��к���Ĳ��ԡ�
            Token����Ч����30���ӣ���������г���unauthorized�Ĵ���ʱ��
            �����µ��GET_AUTH����ȡx-auth-token'''.decode('gbk')
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, helpdetail + os.linesep)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def display_account():
    try:
        title_display, info_account_display = account_service.display_account_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(0.0, title_display + os.linesep)
        for item_user_account in info_account_display:
            text_show.insert(Tkinter.END, item_user_account + os.linesep)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def add_account_init():
    new_window = Tkinter.Toplevel()
    new_window.title("�������û�".decode('gbk'))
    new_window.geometry('600x300')
    frame_sec_top = Tkinter.Frame(new_window, height=6)
    frame_sec_top.pack(side=Tkinter.TOP)
    Tkinter.Label(frame_sec_top, text='��������������Ҫ���ӵ��û���/����/ID����Ϣ'.decode('gbk'), bg='Yellow').pack()

    frame_sec_middle = Tkinter.Frame(new_window, height=10)
    frame_sec_middle.pack(fill=Tkinter.X)

    frame_middle_username = Tkinter.Frame(frame_sec_middle)
    frame_middle_username.pack(side=Tkinter.LEFT)

    frame_middle_password = Tkinter.Frame(frame_sec_middle)
    frame_middle_password.pack(side=Tkinter.LEFT)

    frame_middle_roleid = Tkinter.Frame(frame_sec_middle)
    frame_middle_roleid.pack(side=Tkinter.LEFT)

    frame_middle_enabled = Tkinter.Frame(frame_sec_middle)
    frame_middle_enabled.pack(side=Tkinter.LEFT)

    frame_middle_locked = Tkinter.Frame(frame_sec_middle)
    frame_middle_locked.pack(side=Tkinter.LEFT)

    Tkinter.Label(frame_middle_username, text='�û���'.decode("gbk"), width=10, height=3).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_password, text='����'.decode('gbk'), width=10, height=3).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_enabled, text='�Ƿ���Ч'.decode('gbk'), width=10, height=3).pack(side=Tkinter.TOP)
    #    Tkinter.Label(frame_middle_id, text="�û�ID��".decode('gbk'), width=10).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_roleid, text='�û�Ȩ��'.decode('gbk'), width=10, height=3).pack(side=Tkinter.TOP)
    Tkinter.Label(frame_middle_locked, text='�Ƿ�����'.decode('gbk'), width=10, height=3).pack(side=Tkinter.TOP)

    #    global var_char_entry_username_add
    #    var_char_entry_username_add = Tkinter.StringVar()
    Tkinter.Entry(frame_middle_username, textvariable=var_char_entry_username_add, width=10,
                  font=('Helvetica', '10')).pack(
        side=Tkinter.BOTTOM)

    #    global var_char_entry_password_add
    #    var_char_entry_password_add = Tkinter.StringVar()
    Tkinter.Entry(frame_middle_password, textvariable=var_char_entry_password_add, width=10,
                  font=('Helvetica', '10')).pack(
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
    roleid_box = ttk.Combobox(frame_middle_roleid, textvariable=var_char_roleid,
                              values=['Admin', 'Operator', 'ReadOnlyUser'], width=10)
    roleid_box.pack(side=Tkinter.BOTTOM)

    #    global var_char_entry_id_add
    #    var_char_entry_id_add = Tkinter.StringVar()
    #    Tkinter.Entry(frame_middle_id, textvariable=var_char_entry_id_add, width=10).pack(side=Tkinter.BOTTOM)

    frame_sec_bottom = Tkinter.Frame(new_window)
    frame_sec_bottom.pack()
    Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, height=2, command=play_add_account).pack(
        side=Tkinter.LEFT)
    Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30, height=2, command=new_window.destroy).pack(
        side=Tkinter.RIGHT)


def play_add_account():
    try:
        username_add_account = var_char_entry_username_add.get()
        password_add_account = var_char_entry_password_add.get()
        id_add_account = var_char_entry_id_add.get()
        enabled_str_account = var_char_enabled_or_not.get()
        locked_str_account = var_char_locked_or_not.get()
        roleid_str_account = var_char_roleid.get()

        url_add_account = "https://%s/redfish/v1/AccountService/Accounts/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = '{\"UserName\":\"%s\", \"Password\":\"%s\", \"Locked\":\"%s\", \"RoleId\":\"%s\", \"Enabled\":%s}' % (
            username_add_account, password_add_account, locked_str_account, roleid_str_account, enabled_str_account)
        add_account_response = requests.post(url_add_account, headers=headers, data=payload, verify=False)
        statuscode_add_account = add_account_response.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Statuscode of add account:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_add_account)
        #        var_char_entry_username_add.set(None)
        #        var_char_entry_password_add.set(None)
        #        var_char_enabled_or_not.set(None)
        #        var_char_locked_or_not.set(None)
        #        var_char_roleid.set(None)
        if statuscode_add_account == 201:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '�û������ɹ������ֶ��ر��û���������'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '�û�����ʧ�ܣ�����������Ŀ'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def del_account():
    new_window_del = Tkinter.Toplevel()
    new_window_del.title("ɾ���û�".decode('gbk'))
    new_window_del.geometry('600x300')
    frame_sec_top = Tkinter.Frame(new_window_del, height=6)
    frame_sec_top.pack(side=Tkinter.TOP)
    Tkinter.Label(frame_sec_top, text='��������������Ҫɾ�����û�ID'.decode('gbk'), bg='Yellow').pack()

    frame_sec_middle = Tkinter.Frame(new_window_del, height=6)
    frame_sec_middle.pack(fill=Tkinter.X)

    Tkinter.Label(frame_sec_middle, text='�û�ID'.decode("gbk"), width=30, height=3).pack(side=Tkinter.TOP)

    Tkinter.Entry(frame_sec_middle, textvariable=var_char_id_del, width=30, font=('Helvetica', '10')).pack(
        side=Tkinter.BOTTOM)

    frame_sec_bottom = Tkinter.Frame(new_window_del)
    frame_sec_bottom.pack()
    Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, command=play_delete_account).pack(
        side=Tkinter.LEFT)
    Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30, command=new_window_del.destroy).pack(
        side=Tkinter.RIGHT)


def play_delete_account():
    try:
        id_del = var_char_id_del.get()
        url_account_del = "https://%s/redfish/v1/AccountService/Accounts/%s" % (bmc_ip, id_del)
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = '{\"Id\":\"%s\"}' % id_del
        add_account_response = requests.delete(url_account_del, headers=headers, data=payload, verify=False)
        statuscode_add_account = add_account_response.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Statuscode of add account:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_add_account)
        var_char_id_del.set(None)
        if statuscode_add_account == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '�û�ɾ���ɹ������ֶ��ر��û���������'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '�û�ɾ��ʧ�ܣ�����������Ŀ'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def change_account_roleid():
    try:
        new_window_change_roleid = Tkinter.Toplevel()
        new_window_change_roleid.title("�޸��û���RoleId".decode('gbk'))
        new_window_change_roleid.geometry('600x300')
        frame_sec_top = Tkinter.Frame(new_window_change_roleid, height=6)
        frame_sec_top.pack(side=Tkinter.TOP)
        Tkinter.Label(frame_sec_top, text='��������������Ҫ���õ�RoleId'.decode('gbk'), bg='Yellow').pack()

        frame_sec_middle = Tkinter.Frame(new_window_change_roleid, height=6)
        frame_sec_middle.pack(fill=Tkinter.X)

        frame_middle_id = Tkinter.Frame(frame_sec_middle)
        frame_middle_id.pack(side=Tkinter.LEFT)

        frame_middle_roleid = Tkinter.Frame(frame_sec_middle)
        frame_middle_roleid.pack(side=Tkinter.LEFT)

        Tkinter.Label(frame_middle_id, text='�û�ID'.decode("gbk"), width=20, height=3).pack(side=Tkinter.TOP)
        Tkinter.Label(frame_middle_roleid, text='��ѡ���û���RoleId'.decode('gbk'), width=20, height=3).pack(side=Tkinter.TOP)

        Tkinter.Entry(frame_middle_id, textvariable=var_char_entry_id_change_roleid, width=10,
                      font=('Helvetica', '10')).pack(
            side=Tkinter.BOTTOM)

        box_change_roleid = ttk.Combobox(frame_middle_roleid, textvariable=var_char_roleid_change,
                                         values=['Admin', 'Operator', 'ReadOnlyUser'], width=10)
        box_change_roleid.pack(side=Tkinter.BOTTOM)

        frame_sec_bottom = Tkinter.Frame(new_window_change_roleid)
        frame_sec_bottom.pack()
        Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, height=2, command=play_change_roleid).pack(
            side=Tkinter.LEFT)
        Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30, height=2,
                       command=new_window_change_roleid.destroy).pack(side=Tkinter.RIGHT)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def play_change_roleid():
    try:
        id_change_roleid = var_char_entry_id_change_roleid.get()
        roleid_account_change = var_char_roleid_change.get()
        url_account_change_roleid = "https://%s/redfish/v1/AccountService/Accounts/%s/" % (bmc_ip, id_change_roleid)
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"RoleId\":\"%s\"}" % roleid_account_change
        response_change_roleid = requests.patch(url_account_change_roleid, headers=headers, data=payload, verify=False)
        statuscode_change_roleid = response_change_roleid.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Statuscode of add account:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_change_roleid)
        if statuscode_change_roleid == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '�û��޸�RoleId�ɹ������ֶ��ر��û���������'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '�û��޸�RoleIdʧ�ܣ�����������Ŀ'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def change_account_passwd():
    try:
        new_window_change_passwd = Tkinter.Toplevel()
        new_window_change_passwd.title('�޸��û�������'.decode('gbk'))
        new_window_change_passwd.geometry('600x300')
        frame_sec_top = Tkinter.Frame(new_window_change_passwd, height=6)
        frame_sec_top.pack(side=Tkinter.TOP)
        Tkinter.Label(frame_sec_top, text='��������������Ҫ�޸�������û���ID���µ�����'.decode('gbk'), bg='Yellow').pack()

        frame_sec_middle = Tkinter.Frame(new_window_change_passwd, height=6)
        frame_sec_middle.pack()

        frame_middle_id = Tkinter.Frame(frame_sec_middle)
        frame_middle_id.pack(side=Tkinter.LEFT)

        frame_middle_passwd = Tkinter.Frame(frame_sec_middle)
        frame_middle_passwd.pack(side=Tkinter.LEFT)

        Tkinter.Label(frame_middle_id, text='�û�ID'.decode("gbk"), width=20, height=3).pack(side=Tkinter.TOP)
        Tkinter.Label(frame_middle_passwd, text='�µ�����'.decode('gbk'), width=20, height=3).pack(side=Tkinter.TOP)
        Tkinter.Entry(frame_middle_id, textvariable=var_char_entry_id_change_password, width=20,
                      font=('Helvetica', '10')).pack(side=Tkinter.BOTTOM)
        Tkinter.Entry(frame_middle_passwd, textvariable=var_char_entry_new_passwd, width=20,
                      font=('Helvetica', '10')).pack(side=Tkinter.BOTTOM)

        frame_sec_bottom = Tkinter.Frame(new_window_change_passwd)
        frame_sec_bottom.pack()
        Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, height=2, command=play_change_passwd).pack(
            side=Tkinter.LEFT)
        Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30, height=2,
                       command=new_window_change_passwd.destroy).pack(side=Tkinter.RIGHT)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def play_change_passwd():
    try:
        id_change_passwd = var_char_entry_id_change_password.get()
        new_passwd = var_char_entry_new_passwd.get()
        url_account_change_passwd = "https://%s/redfish/v1/AccountService/Accounts/%s/" % (bmc_ip, id_change_passwd)
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"Password\":\"%s\"}" % new_passwd
        response_change_roleid = requests.patch(url_account_change_passwd, headers=headers, data=payload, verify=False)
        statuscode_change_roleid = response_change_roleid.status_code
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Statuscode of add account:' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_change_roleid)
        if statuscode_change_roleid == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '�û��޸�����ɹ������ֶ��ر��û���������'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '�û��޸�����ʧ�ܣ�����������Ŀ'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_info():
    try:
        statuscode_get_chassis_info, data_display = chassis.get_chassis_info(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Chassis info:' + os.linesep)
        text_show.insert(Tkinter.END, json.dumps(data_display, indent=4))
        if statuscode_get_chassis_info == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ��Ϣ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡ��Ϣʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_thermal():
    try:
        statuscode_get_chassis_thermal, title_display, data_display = chassis.get_chassis_thermal_info(bmc_ip,
                                                                                                       auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, title_display + os.linesep)
        for line in data_display:
            text_show.insert(Tkinter.END, line + os.linesep)
        if statuscode_get_chassis_thermal == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ��Ϣ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡ��Ϣʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_chassis_power():
    try:
        statuscode_get_chassis_power_info, title_display, data_display = chassis.get_chassis_power_info(bmc_ip,
                                                                                                        auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, title_display + os.linesep)
        for line in data_display:
            text_show.insert(Tkinter.END, line + os.linesep)
        if statuscode_get_chassis_power_info == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ��Ϣ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡ��Ϣʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_fanmode():
    try:
        statuscode_display, data_display = chassis.get_chassis_fanmode(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Current FAN Mode:' + os.linesep)
        text_show.insert(Tkinter.END, data_display)
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ��Ϣ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡ��Ϣʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def set_fanmode():
    try:
        new_window_set_fanmode = Tkinter.Toplevel()
        new_window_set_fanmode.title("���÷���ģʽ".decode('gbk'))
        new_window_set_fanmode.geometry('600x300')
        frame_sec_top = Tkinter.Frame(new_window_set_fanmode, height=6)
        frame_sec_top.pack(side=Tkinter.TOP)
        Tkinter.Label(frame_sec_top, text='��������ѡ����Ҫ���õķ���ģʽ'.decode('gbk'), bg='Yellow').pack()

        frame_sec_middle = Tkinter.Frame(new_window_set_fanmode, height=6)
        frame_sec_middle.pack(fill=Tkinter.X)

        Tkinter.Label(frame_sec_middle, text='����ģʽ'.decode("gbk"), width=30, height=3).pack(side=Tkinter.TOP)
        fanmode_box = ttk.Combobox(frame_sec_middle, textvariable=var_char_fanmode,
                                   values=['Standard', 'FullSpeed', 'PUE2', 'HeavyIO'], width=10)
        fanmode_box.pack(side=Tkinter.BOTTOM)

        frame_sec_bottom = Tkinter.Frame(new_window_set_fanmode)
        frame_sec_bottom.pack()
        Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, command=play_set_fanmode).pack(
            side=Tkinter.LEFT)
        Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30,
                       command=new_window_set_fanmode.destroy).pack(
            side=Tkinter.RIGHT)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def play_set_fanmode():
    try:
        fanmode = var_char_fanmode.get()
        url_chassis = "https://%s/redfish/v1/Chassis/1/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"Oem\":{\"OemFan\":{\"FanMode\":\"%s\"}}}" % fanmode
        response_set_fanmode = requests.patch(url_chassis, headers=headers, data=payload, verify=False)
        statuscode_set_fanmode = response_set_fanmode.status_code
        if statuscode_set_fanmode == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_blinking():
    try:
        statuscode_uid_on = chassis.uid_blinking(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of uid blinking' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_uid_on)
        if statuscode_uid_on == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_off():
    try:
        statuscode_uid_off = chassis.uid_off(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Below is the Status Code of uid off' + os.linesep)
        text_show.insert(Tkinter.END, statuscode_uid_off)
        if statuscode_uid_off == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def uid_current_status():
    try:
        uid_status, statuscode_uid_status = chassis.uid_current_status(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(1.0, 'Current Status of UID is:' + os.linesep)
        text_show.insert(Tkinter.END, uid_status)
        if statuscode_uid_status == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_system_info():
    try:
        statuscode_display, data_display = system.get_system_info_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, json.dumps(data_display, indent=4))
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_processor1_info():
    try:
        statuscode_display, data_display = system.get_processor1_info(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, data_display)
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_processor2_info():
    try:
        statuscode_display, data_display = system.get_processor2_info(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, data_display)
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_simplestorage():
    try:
        statuscode_display, data_display = system.get_simplestorage_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, data_display)
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '��ȡ�ɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '��ȡʧ�ܣ�����'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_info():
    try:
        statuscode_display, data_display = manager.get_manager_info_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, json.dumps(data_display, indent=4))
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_network_protocal():
    try:
        statuscode_display, data_display = manager.get_manager_network_protocal_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, json.dumps(data_display, indent=4))
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_ethernet_interface():
    try:
        statuscode_display, data_display = manager.get_manager_ethernet_interface_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, json.dumps(data_display, indent=4))
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_serial_interface():
    try:
        statuscode_display, data_display = manager.get_manager_serial_interface_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, json.dumps(data_display, indent=4))
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_logservices():
    try:
        pass
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def get_manager_current_mousemode():
    try:
        statuscode_display, data_display = manager.get_manager_current_mousemode_sub(bmc_ip, auth_token)
        text_show.delete(0.0, Tkinter.END)
        text_show.insert(Tkinter.END, '�����ǵ�ǰ��Mouse Mode:'.decode('gbk') + os.linesep)
        text_show.insert(Tkinter.END, data_display)
        if statuscode_display == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def set_manager_mousemode():
    try:
        new_window_set_mouse = Tkinter.Toplevel()
        new_window_set_mouse.title("�޸��û���RoleId".decode('gbk'))
        new_window_set_mouse.geometry('600x300')
        frame_sec_top = Tkinter.Frame(new_window_set_mouse, height=6)
        frame_sec_top.pack(side=Tkinter.TOP)
        Tkinter.Label(frame_sec_top, text='��������Ҫ���õ�Mouse Mode'.decode('gbk'), bg='Yellow').pack()

        frame_sec_middle = Tkinter.Frame(new_window_set_mouse, height=6)
        frame_sec_middle.pack(fill=Tkinter.X)

        frame_middle_mousemode = Tkinter.Frame(frame_sec_middle)
        frame_middle_mousemode.pack(side=Tkinter.LEFT)

        Tkinter.Label(frame_middle_mousemode, text='Mode'.decode("gbk"), width=20, height=3).pack(side=Tkinter.TOP)

        box_set_mousemode = ttk.Combobox(frame_middle_mousemode, textvariable=var_char_combox_mousemode,
                                         values=['Absolute', 'Relative', 'Single'], width=10)
        box_set_mousemode.pack(side=Tkinter.BOTTOM)

        frame_sec_bottom = Tkinter.Frame(new_window_set_mouse)
        frame_sec_bottom.pack()
        Tkinter.Button(frame_sec_bottom, text='ȷ��'.decode('gbk'), width=30, height=2, command=play_set_mousemode).pack(
            side=Tkinter.LEFT)
        Tkinter.Button(frame_sec_bottom, text='�˳�'.decode('gbk'), width=30, height=2,
                       command=new_window_set_mouse.destroy).pack(side=Tkinter.RIGHT)
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')


def play_set_mousemode():
    try:
        mousemode = var_char_combox_mousemode.get()
        url_mousemode = "https://%s/redfish/v1/Managers/1/MouseMode/" % bmc_ip
        headers = {
            'x-auth-token': "%s" % auth_token,
            'cache-control': "no-cache",
        }
        payload = "{\"Mode\": \"%s\"}" % mousemode
        response_set_mousemode = requests.patch(url_mousemode, headers=headers, data=payload, verify=False)
        statuscode_set_mousemode = response_set_mousemode.status_code
        if statuscode_set_mousemode == 200:
            tkMessageBox.showinfo('�ɹ�'.decode('gbk'), '���óɹ�'.decode('gbk'))
        else:
            tkMessageBox.showerror('����'.decode('gbk'), '����ʧ�ܣ���������ѡ��'.decode('gbk'))
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')

def get_manager_smtp():
    try:
        pass
    except BaseException:
        tkMessageBox.showerror('ERROR', 'ERROR')





# top
menubar = Tkinter.Menu(root)
helpmenu = Tkinter.Menu(menubar, tearoff=0)
helpmenu.add_command(label="ʹ��˵��".decode('gbk'), command=showhelp)
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
Tkinter.Label(frame_top_middle, text='�û���'.decode('gbk'), bg='Green', width=30).pack(side=Tkinter.TOP)
Tkinter.Label(frame_top_right, text='����'.decode('gbk'), bg='Yellow', width=30).pack(side=Tkinter.TOP)

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
# ���������
scroll_text_right = Tkinter.Scrollbar(frame_right, orient=Tkinter.VERTICAL)
# ���������
scroll_text_bottom = Tkinter.Scrollbar(frame_right, orient=Tkinter.HORIZONTAL)
text_show = Tkinter.Text(frame_right, yscrollcommand=scroll_text_right.set, xscrollcommand=scroll_text_bottom.set,
                         wrap='none')
scroll_text_right.config(command=text_show.yview)
scroll_text_bottom.config(command=text_show.xview)
scroll_text_right.pack(fill="y", expand=0, side=Tkinter.RIGHT, anchor=Tkinter.N)
scroll_text_bottom.pack(fill="x", expand=0, side=Tkinter.BOTTOM, anchor=Tkinter.N)
text_show.pack(fill=Tkinter.BOTH)
text_show.insert('1.0', 'hello!')

# left_button
frame_left = Tkinter.Frame(root)
frame_left.pack(side=Tkinter.LEFT, fill=Tkinter.BOTH)

Tkinter.Button(frame_left, text='GET_AUTH', command=get_x_auth_token, width=30).pack()

menubar_system = Tkinter.Menubutton(frame_left, text='System', width=30)
menubar_system.pack()
menu_system = Tkinter.Menu(menubar_system)
menu_system_processor = Tkinter.Menu(menu_system)
menu_system_power_control = Tkinter.Menu(menu_system)
menu_system.add_cascade(label='CPU��Ϣ'.decode('gbk'), menu=menu_system_processor)
menu_system_processor.add_command(label='CPU1', command=get_processor1_info)
menu_system_processor.add_command(label='CPU2', command=get_processor2_info)
menu_system.add_command(label='SimpleStorage', command=get_simplestorage)
menu_system.add_command(label='���������豸'.decode('gbk'), command=set_bootdevice)
menu_system.add_cascade(label='Power control', menu=menu_system_power_control)
menu_system_power_control.add_command(label='ForceRestart', command=forcerestart_computer)
menu_system_power_control.add_command(label='ForceOff', command=forceoff_computer)
menu_system_power_control.add_command(label='ForceOn', command=forceon_computer)

menubar_system['menu'] = menu_system


menubar_account = Tkinter.Menubutton(frame_left, text='�û�����'.decode('gbk'), width=30)
menubar_account.pack()
menu_account = Tkinter.Menu(menubar_account)
menu_account.add_command(label='�鿴���ڵ��û�'.decode('gbk'), command=display_account)
menu_account.add_command(label='�����û�'.decode('gbk'), command=add_account_init)
menu_account.add_command(label='ɾ���û�'.decode('gbk'), command=del_account)
menu_account.add_command(label='�޸��û���RoleId'.decode('gbk'), command=change_account_roleid)
menu_account.add_command(label='�޸��û�����'.decode('gbk'), command=change_account_passwd)
menubar_account['menu'] = menu_account

menubar_chassis = Tkinter.Menubutton(frame_left, text='Chassis', width=30)
menubar_chassis.pack()
menu_chassis = Tkinter.Menu(menubar_chassis)
menu_chassis_uid = Tkinter.Menu(menu_chassis)
menu_chassis_fanmode = Tkinter.Menu(menu_chassis)
menu_chassis.add_command(label='�鿴Chassis info'.decode('gbk'), command=get_chassis_info)
menu_chassis.add_command(label='�鿴Thermal info'.decode('gbk'), command=get_chassis_thermal)
menu_chassis.add_command(label='�鿴Power info'.decode('gbk'), command=get_chassis_power)

menu_chassis.add_cascade(label='����ת��'.decode('gbk'), menu=menu_chassis_fanmode)
menu_chassis_fanmode.add_command(label='��ǰ״̬'.decode('gbk'), command=get_fanmode)
menu_chassis_fanmode.add_command(label='���÷���״̬'.decode('gbk'), command=set_fanmode)
menu_chassis.add_cascade(label='UID����'.decode('gbk'), menu=menu_chassis_uid)
menu_chassis_uid.add_command(label='��ǰ״̬'.decode('gbk'), command=uid_current_status)
menu_chassis_uid.add_command(label='Blinking'.decode('gbk'), command=uid_blinking)
menu_chassis_uid.add_command(label='�ر�'.decode('gbk'), command=uid_off)
menubar_chassis['menu'] = menu_chassis

menubar_manager = Tkinter.Menubutton(frame_left, text='Manager', width=30)
menubar_manager.pack()
menu_manager = Tkinter.Menu(menubar_manager)
menu_manager_mousemode = Tkinter.Menu(menu_manager)
menu_manager.add_command(label='��ȡManager��Ϣ'.decode('gbk'), command=get_manager_info)
menu_manager.add_command(label='��ȡNetworkProtocol��Ϣ'.decode('gbk'), command=get_manager_network_protocal)
menu_manager.add_command(label='��ȡEthernetInterfaces��Ϣ'.decode('gbk'), command=get_manager_ethernet_interface)
menu_manager.add_command(label='��ȡSerialInterfaces��Ϣ'.decode('gbk'), command=get_manager_serial_interface)
menu_manager.add_command(label='��ȡLogServices��Ϣ'.decode('gbk'), command=get_manager_logservices)
menu_manager.add_cascade(label='MouseMode', menu=menu_manager_mousemode)
menu_manager_mousemode.add_command(label='��ȡ��ǰ״̬'.decode('gbk'), command=get_manager_current_mousemode)
menu_manager_mousemode.add_command(label='MouseMode'.decode('gbk'), command=set_manager_mousemode)
menu_manager.add_command(label='��ȡSMTP��Ϣ'.decode('gbk'), command=get_manager_smtp)
menubar_manager['menu'] = menu_manager

Tkinter.mainloop()
