
import getpass
import threading
import time
import traceback
from tabulate import tabulate
from waitress import serve
from aciapilib import aciDB
from aciconfigs import aciConfig
from acitables import aciTable
from flask import Flask, render_template, session, redirect, url_for
from flask import flash, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_admin import BaseView, AdminIndexView, expose, Admin
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from itsdangerous import URLSafeTimedSerializer




def get_data():
    c = [('ab:ac:ac:ac:ad:ad', '1.1.1.1', 'tenant', 'app', 'epg', 'interface', '0000-00-00 00:00:03', '0000-00-00 00:00:44'),
         ('bb:ac:ac:ac:ad:ad', '1.1.1.1', 'tenant', 'app', 'epg', 'interface', '0000-00-00 00:00:03',
          '0000-00-00 00:00:44')]
    data = ''
    for (mac, ip, tenant, app, epg, interface, timestart, timestop) in c:
        if timestop is None:
            timestop = '0000-00-00 00:00:00'
        data = data + '<tr> <td>' + mac + '</td> '
        data = data + '<td>' + ip + '</td> '
        data = data + '<td>' + tenant + '</td> '
        data = data + '<td>' + app + '</td> '
        data = data + '<td>' + epg + '</td> '
        data = data + '<td>' + interface + '</td> '
        data = data + '<td>' + str(timestart) + '</td> '
        data = data + '<td>' + str(timestop) + '</td> '
        data = data + '</tr>'
    return data

def get_data2(result):
    data = ''
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            print key.split(', ')[1] + ': ' + result[key]
    for key in sorted(result.keys()):
        if isinstance(result[key], list):
            if result[key] != []:
                if len(result.keys()) == 1:
                    #data = data + '<tr>'
                    #for row_item in key.split(','):
                    #   data = data + '<td>' + str(row_item) + '</td> '
                    #data = data + '</tr>'
                    for row in result[key]:
                        data = data + '<tr>'
                        for row_item in row:
                            data = data + '<td>' + str(row_item) + '</td> '
                        data = data + '</tr>'
                else:
                    print len(result.keys()) , ' keys'
    return data


def get_data3(result, grep_list=None):
    data = {}
    data['header'] = []
    data['row'] = []
    data['rows'] = ''
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            result[key] = [[result[key]]]
        if isinstance(result[key], list):
            if grep: result[key] = grep(result[key], grep_list)
            if result[key] != []:
                if len(result.keys()) == 1:
                    data['header'] = key.split(',')
                    data['row'] = [result[key]]
                else:
                    headers = ''
                    rows = ''
                    data['header'] = None
                    headers = headers + '<tr bgcolor="#ceceff">'
                    for header in key.split(',')[1:]:
                        headers = headers + '<td style="white-space: pre-line"><b>'+ str(header) +'</b></td>'
                    headers = headers + '</tr>'
                    data['rows'] = data['rows'] + headers

                    rows = rows + '<tr>'
                    for rowkeys in result[key]:
                        for row in rowkeys:
                            rows = rows + '<td style="white-space: pre-line">' + str(row) + '</td>'
                        rows = rows + '</tr>'
                    data['rows'] = data['rows'] + rows

    return data

def get_data4(result, grep_list=None):
    data = {}
    data['header'] = []
    data['row'] = []
    data['rows'] = ''
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            print key.split(', ')[1] + ': ' + result[key]
    for key in sorted(result.keys()):
        if not isinstance(result[key], list):
            data['row'].append([[key.split(', ')[1] + ': ' + result[key]]])
        if isinstance(result[key], list):
            if grep: result[key] = grep(result[key], grep_list)
            if result[key] != []:
                if len(result.keys()) == 1:
                    data['header'] = key.split(',')
                    data['row'] = result[key]
                else:
                    headers = ''
                    rows = ''
                    data['header'] = None
                    headers = headers + '<tr bgcolor="#ceceff">'
                    for header in key.split(',')[1:]:
                        headers = headers + '<td style="white-space: pre-line"><b>'+ str(header) +'</b></td>'
                    headers = headers + '</tr>'
                    data['rows'] = data['rows'] + headers

                    rows = rows + '<tr>'
                    for rowkeys in result[key]:
                        for row in rowkeys:
                            rows = rows + '<td style="white-space: pre-line">' + str(row) + '</td>'
                        rows = rows + '</tr>'
                    data['rows'] = data['rows'] + rows

    return data


def grep(resultin, grep_list):
    resultout = resultin
    if grep_list:
        resultout = [line for line in resultin if str(grep_list).lower().strip() in str(line).lower()]
    return resultout

def generate_auth_token(login, password, url, apic):

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps({'login': login, 'password': password, 'url': url, 'apic': apic})

def verify_auth_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(str(token), max_age=12600)
        if data is None:
            data= {}
    except SignatureExpired:
        return {}
    except BadSignature:
        return {}
    return data

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'Dnit7qz7hjkffhFDgf67Ghl8vLFvk0snhwP'
app.config['CSRF_ENABLED'] = True
CSRFProtect(app)
userlog =[]

#url = 'https://sandboxapicdc.cisco.com'

apic_dict = {'sandboxapicdc.cisco.com1': ['box1', 'sandboxapicdc', 'sandboxapicdc.cisco.com', 'sandboxapicdc.cisco.com'],
             'sandboxapicdc.cisco.com2': ['box2', 'sandboxapicdc2', 'sandboxapicdc.cisco.com', 'sandboxapicdc.cisco.com']
                 }
apic_list = sorted(apic_dict.keys())
apic_list.insert(0, 'Choose APIC')

class aciapp(BaseView):
    @expose('/')
    def index(self):
        variable = request.args.get('variable')
        token = request.args.get('token')
        if userlog:
            folder = ''
            with open(folder + 'user.log', 'a') as printfile:
                printfile.write('\n'.join(userlog))
                printfile.write('\n')
                del userlog[:]
        if variable:
            return redirect(url_for('aciapp.show_tenant', token=token, grep=''))
        if token:
            token_data = verify_auth_token(token)
            if token_data:
                login = token_data.get('login')
                password = token_data.get('password')
                url = token_data.get('url')
                apic = token_data.get('apic')
                if login == None: login = ''
                if password == None: password = ''
                else: password = 'tokenpassword'
            else:
                login = ''
                password = ''
                url = ''
                apic = 'No Apic'
                token = ''
            formaction = "/aciapp/credential"
            formname = 'token'
            return render_template('index.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   apic_list=apic_list, username=login, password=password, url=url)
        else:
            login = ''
            password = ''
            url = ''
            apic = 'No Apic'
            token = ''
            if login == None: login = ''
            if password == None: password = ''
            formaction = "/aciapp/credential"
            formname = ''
            return render_template('index.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   apic_list=apic_list, username=login, password=password, url=url)

    @expose('/credential', methods=['GET', 'POST'] )
    def credentials(self):
        aci = aciDB()
        login = str(request.form['username'])
        password = str(request.form['password'])
        selectapic = str(request.form['selectapic'])
        apic = apic_dict[selectapic][2]
        url = "https://" + apic
        if password == 'tokenpassword':
            token = str(request.form['token'])
            token_data = verify_auth_token(token)
            password = token_data.get('password')
        login_apic = aci.login(login, password, url)
        token = generate_auth_token(login, password, url, selectapic)
        return redirect(url_for('aciapp.index', variable=login_apic, token=token))

    @expose('/tenanttable')
    def show_tenant(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_tenant_table(tenant_name)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                          ', tenanttable ' + str(grep_list))
            formaction = "/aciapp/tenanttable"
            formname = 'Display Tenant list '
            row_url = ['href=tenanttable?token=' + token + '&grep=''&tenant_name=', '', '', '',
                       'href=bdtable?token=' + token + '&grep=''&tenant_name=', '',
                       'href=epgtable?token=' + token + '&grep=''&tenant_name=',
                       'href=contracttable?token=' + token + '&grep=''&tenant_name=', '']
            return render_template('main5.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'],
                                   row_url=row_url)
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/bdtable')
    def show_bd(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            bd_name = request.args.get('bd_name')
            if bd_name:
                bd_name = bd_name.split('/')[-1]
                if bd_name.startswith('*'):
                    bd_name = bd_name.replace('*', '', 1)
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_bd_table(tenant_name, bd_name)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', bdtable ' + str(grep_list))
            formaction= "/aciapp/bdtable"
            formname = 'Display BridgeDomain list '
            if bd_name:
                return render_template('main6.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, tableheader=data['header'], tablerows=data['rows'])
            else:
                row_url = ['href=bdtable?token='+ token + '&grep=''&bd_name=','','','','','','','href=epgtable?token='+
                           token + '&grep=''&epg_bd=','','']
                return render_template('main5.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, tableheader=data['header'], tablerows=data['row'],
                                       row_url=row_url)
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/epgtable')
    def show_epg(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            epg_name = request.args.get('epg_name')
            epg_bd = request.args.get('epg_bd')
            grep_list = request.args.get('grep')
            if epg_bd:
                grep_list = epg_bd.split('/')[-1]
            if grep_list is not None:
                result = acitable.get_epg_table(tenant_name, epg_name)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', epgtable ' + str(grep_list))
            formaction= "/aciapp/epgtable"
            formname = 'Display EPG list '
            if epg_name:
                return render_template('main6.html', formaction=formaction, formname=formname, apic=apic, token=token, 
                                       username=login, url=url, tableheader=data['header'], tablerows=data['rows'])
            else:
                row_url = ['href=tenanttable?token='+ token + '&grep=''&tenant_name=','','href=epgtable?token='+ token +
                           '&grep=''&epg_name=','','','href=bdtable?token='+ token + '&grep=','',
                           'href=vlantable?token='+ token + '&grep=','','','']
                return render_template('main4.html', formaction=formaction, formname=formname, apic=apic, token=token, 
                                       username=login, url=url, tableheader=data['header'], tablerows=data['row'],
                                       row_url=row_url)
        except:
            return redirect(url_for('aciapp.index', token=token))
            
    @expose('/endpointtable')
    def show_endpoint(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            endpoint = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_endpoint_table(endpoint)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', endpointtable ' + str(grep_list))
            formaction= "/aciapp/endpointtable"
            formname = 'Display Endpoint list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))


    @expose('/contracttable')
    def show_contract(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            tenant_name = request.args.get('tenant_name')
            contract_name = request.args.get('contract_name')
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_contract_table(tenant_name, contract_name)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', contracttable ' + str(grep_list))
            formaction= "/aciapp/contracttable"
            formname = 'Display Contract list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/hosttable')
    def show_host(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_host_table()
                result_list = result[result.keys()[0]]
                if grep_list: result_list = grep(result_list, grep_list)
                result[result.keys()[0]] = [line[0:8] for line in result_list]
                data = get_data3(result)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', hosttable ' + str(grep_list))
            formaction = "/aciapp/hosttable"
            formname = 'Display Host list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/porttable')
    def show_port(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            node = request.args.get('node')
            port = request.args.get('port')
            port_name = request.args.get('port_name')
            if port_name:
                if '-' in port_name:
                    node = port_name.split('-')[0]
                    port = port_name.split('-')[1]
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_port_table(node, port)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', porttable ' + str(grep_list))
            formaction= "/aciapp/porttable"
            formname = 'Display Port list '
            if port:
                return render_template('main6.html', formaction=formaction, formname=formname, apic=apic, token=token, 
                                       username=login, url=url, tableheader=data['header'], tablerows=data['rows'])
            else:
                row_url = ['href=porttable?token='+ token + '&grep=''&port_name=', '', '', '', '', '', '', '', '', '']
                return render_template('main4.html', formaction=formaction, formname=formname, apic=apic, token=token, 
                                       username=login, url=url, tableheader=data['header'], tablerows=data['row'], row_url=row_url)
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/portstattable')
    def show_port_stat(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)    
            node = None
            port = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_port_stat_table(node, port)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', portstattable ' + str(grep_list))
            formaction= "/aciapp/portstattable"
            formname = 'Display Port Stat list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/ipgtable')
    def show_ipg(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            ipg_type = None
            ipg_name = None
            node = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_ipg_table(node, ipg_type, ipg_name)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', ipgtable ' + str(grep_list))
            formaction= "/aciapp/ipgtable"
            formname = 'Display IPG list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/fextable')
    def show_fex(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)    
            ipg_name = None
            node = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_fex_table(node, ipg_name)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', fextable ' + str(grep_list))
            formaction= "/aciapp/fextable"
            formname = 'Display Fex list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))


    @expose('/vlantable')
    def show_vlan(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            vlan = request.args.get('vlan')
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_vlan_table(vlan)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', vlantable ' + str(grep_list))
            formaction= "/aciapp/vlantable"
            formname = 'Display Vlan list '
            if vlan:
                row_url = ['href=vlantable?token='+ token + '&grep=''&vlan=', 'href=vlantable?token='+ token + '&grep=',
                           '', 'href=porttable?token='+ token + '&grep=', '', 'href=bdtable?token='+ token + '&grep=',
                           'href=tenanttable?token='+ token + '&grep=', 'href=epgtable?token='+ token + '&grep=', '']
            else:
                row_url = ['href=vlantable?token='+ token + '&grep=''&vlan=', 'href=vlantable?token='+ token + '&grep=',
                           '', 'href=bdtable?token='+ token + '&grep=', 'href=tenanttable?token='+ token + '&grep=',
                           'href=epgtable?token='+ token + '&grep=', '', '', '']
            return render_template('main4.html', formaction=formaction, formname=formname, apic=apic, token=token, 
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'], row_url=row_url)
        except:
            return redirect(url_for('aciapp.index', token=token))


    @expose('/vlandomaintable')
    def show_vlan_domain(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            domain = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_vlan_per_domain_table(domain)
                data = get_data3(result)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', vlandomaintable ' + str(grep_list))
            formaction= "/aciapp/vlandomaintable"
            formname = 'Display Vlan Per Domain list '
            return render_template('main6.html', formaction=formaction, formname=formname, apic=apic, token=token, 
                                   username=login, url=url, tableheader=data['header'], tablerows=data['rows'])
        except:
            return redirect(url_for('aciapp.index', token=token))


    @expose('/lldptable')
    def show_lldp(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            node = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_lldp_table(node)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', lldptable ' + str(grep_list))
            formaction= "/aciapp/lldptable"
            formname = 'Display LLDP Neighbor list '
            return render_template('main3.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))


    @expose('/nodetable')
    def show_node(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            role = None
            node = None
            grep_list = request.args.get('grep')
            if grep_list is not None:
                result = acitable.get_switch_table(role, node)
                data = get_data3(result, grep_list)
            else:
                data = {'header': '', 'row': '', 'rows': ''}
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', nodetable ' + str(grep_list))
            formaction= "/aciapp/nodetable"
            formname = 'Display Node list '
            return render_template('main6.html', formaction=formaction, formname=formname, apic=apic, token=token, tableheader=data['header'],
                                   tablerows=data['rows'])
        except:
            return redirect(url_for('aciapp.index', token=token))


    @expose('/snapshottable')
    def show_snapshot(self):
        try:
            token = request.args.get('token')
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            aci = aciDB()
            acitable = aciTable(aci)
            login_apic = aci.login(login, password, url)
            grep_list = request.args.get('grep')
            result = acitable.get_snapshot_table()
            data = get_data3(result, grep_list)
            aci.logout()
            userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) + \
                           ', snapshottable ' + str(grep_list))
            formaction= "/aciapp/snapshottable"
            formname = 'Display Snapshot list '
            return render_template('snapshottable.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                   username=login, url=url, tableheader=data['header'], tablerows=data['row'])
        except:
            return redirect(url_for('aciapp.index', token=token))

    @expose('/createsnapshot')
    def createsnapshot(self):
        token = request.args.get('token')
        return redirect(url_for('aciapp.snapshot', function='create_snapshot', token=token))

    def commitcheck(self, cmd, token):
        try:
            result_resp = ''
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            aci = aciDB()
            aciconfig = aciConfig(aci)
            login_apic = aci.login(login, password, url)
            commands = self.cmdtodict(cmd.split('\n'))
            if commands:
                results, post_url, post_resp, warnings = aciconfig.functions(commands, 'yes', 'no')
                result_resp = result_resp + '\n' + aci.get_xml_from_json(results) + '\n'.join(warnings)
            aci.logout()
            return result_resp

        except:
            return result_resp
            
    def commitnocheck(self, cmd, token):
        try:
            result_resp = ''
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            aci = aciDB()
            aciconfig = aciConfig(aci)
            login_apic = aci.login(login, password, url)
            commands = self.cmdtodict(cmd.split('\n'))
            if commands:
                results, post_url, post_resp, warnings = aciconfig.functions(commands, 'no', 'no')
                result_resp = result_resp + '\n' + aci.get_xml_from_json(results) + '\n'.join(warnings)
            aci.logout()
            return result_resp
        except:
            return result_resp

    def commitsend(self, cmd, token):
        try:
            result_resp = ''
            localtime = time.asctime(time.localtime(time.time()))
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            aci = aciDB()
            aciconfig = aciConfig(aci)
            login_apic = aci.login(login, password, url)
            commands = self.cmdtodict(cmd.split('\n'))
            if commands:
                folder = ''
                results, post_url, post_resp, warnings = aciconfig.functions(commands, 'yes', 'yes')
                with open(folder + 'output.log', 'a') as printfile:
                    if results:
                        printfile.write('=======================================================\n')
                        printfile.write(
                            '%s - config generated by %s for %s %s - commit send\n' % (localtime, login, url, apic))
                        printfile.write('\n')
                        printfile.write(''.join([line for line in cmd.split('\n')]))
                        printfile.write('\n')
                        for i, result in enumerate(results):
                            if post_url[i]:
                                printfile.write('\n')
                                printfile.write(aci.get_xml_from_json([result]))
                                printfile.write('post: %s\n' % (post_url[i]))
                                printfile.write('%s\n' % (post_resp[i]))
                                printfile.write('%s\n' % (post_resp[i].text))
                                result_resp = result_resp + '\n' + aci.get_xml_from_json([result]) + '\n' + \
                                'post: %s\n' % (post_url[i]) + '%s\n' % (post_resp[i]) + '%s\n' % (post_resp[i].text)
                        result_resp = result_resp + '\n' + '\n'.join(warnings)

                        result_resp = result_resp + '\n' + 'config sent to apic has been saved in output.log \n'
                    else:
                        result_resp = '\n'.join(warnings) + '\n' + 'config NOT sent to apic \n'
                aci.logout()
            return result_resp
        except:
            return result_resp

    @expose('/portmanager', methods=['GET', 'POST'])
    def portmanager(self):
        commandlist = ''
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        data= {"row": [], "header": None}
        if request.files:
            imported= request.files['import_file']
            for i, line in enumerate(imported):
                linecsv = line.split(',')
                if len(linecsv) >= 9:
                    if '.csv' in imported.filename:
                        linecsv = line.split(',')
                    elif '.txt' in imported.filename:
                        linecsv = line.split()
                    else:
                        linecsv = ''
                        line = ''
                    if i == 0:
                        data['header'] = linecsv
                    else:
                        data['row'].append(linecsv)
                        commandlist = commandlist + line

        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if 'Submit-Cmd' in request.form.keys():
                commandlist=request.form['commandlist']
                cmdlist1, cmdlist2, cmdlist3, cmdlist4, cmdlist5, cmdlist6, warnings = self.pm_csv1(commandlist, token)
                cmdbuffer = '\n'.join(cmdlist1) + '\n' + '\n'.join(cmdlist2) + '\n' + '\n'.join(cmdlist3) + '\n' + \
                            '\n'.join(cmdlist4) + '\n' + '\n'.join(cmdlist5) + '\n' + '\n'.join(warnings)
                formaction = "/aciapp/portmanager"
                formname = 'Edit '
                return render_template('pmcmdcliform.html', formaction=formaction, formname=formname, apic=apic, 
                                       token=token, username=login, url=url, 
                                       commandlist=commandlist, cmdbuffer=cmdbuffer, cmdlist1='\n'.join(cmdlist1),
                                       cmdlist2='\n'.join(cmdlist2), cmdlist3='\n'.join(cmdlist3),
                                       cmdlist4='\n'.join(cmdlist4), cmdlist5='\n'.join(cmdlist5),
                                       cmdlist6=' '.join(cmdlist6))
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.portmanager', token=token))
            elif 'Submit-NoCheck' in request.form.keys():
                commandlist = request.form['commandlist']
                cmdlist = [request.form['cmdlist1'],request.form['cmdlist2'],request.form['cmdlist3'],
                           request.form['cmdlist4'],request.form['cmdlist5']]
                cmdbuffer = self.pmcommitnocheck(cmdlist, token)
                formaction = "/aciapp/portmanager"
                formname = 'Commit No Check Output '
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, 
                                       token=token, username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)
            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['commandlist']
                portdata = ''
                portlist = request.form['cmdlist6']
                preportdata = self.pmportreport(portlist.split(' '), token)
                for portdataline in preportdata['row']:
                    portdata = portdata + str('@#$%^&*()_+{}[]'.join(portdataline) + '\n')

                cmdlist = [request.form['cmdlist1'], request.form['cmdlist2'], request.form['cmdlist3'],
                           request.form['cmdlist4'], request.form['cmdlist5']]
                cmdbuffer = self.pmcommitsend(cmdlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend portmanager')
                formaction = "/aciapp/portmanager"
                formname = 'Commit Send Output '
                return render_template('pmcommitform.html', formaction=formaction, formname=formname, apic=apic, 
                                       token=token, username=login, url=url, commandlist=portlist, cmdbuffer=cmdbuffer,
                                       portdata=portdata)
            elif 'Submit-Return' in request.form.keys():
                portlist = request.form['commandlist']
                portdata = request.form['portdata']
                data = self.pmportreport(portlist.split(' '), token)
                data['row'].append(['Previous State'])
                for portdataline in portdata.split('\n'):
                    data['row'].append(portdataline.split('@#$%^&*()_+{}[]'))
            else:
                if 'cmdbuffer' in request.form.keys():
                    commandlist = request.form['commandlist']
        formaction = "/aciapp/portmanager"
        formname =  'Portmanager '
        return render_template('pmform.html', formaction=formaction, formname=formname, apic=apic, token=token,         
                                username=login, url=url, tableheader=data['header'], tablerows=[data['row']], commandlist=commandlist)

    @expose('/pmcsvtocmd', methods=['GET', 'POST'])
    def pmcsvtocmd(self):
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            commandlist=request.form['commandlist']
            cmdlist1, cmdlist2, cmdlist3, cmdlist4, cmdlist5, cmdlist6, warnings = self.pm_csv1(commandlist, token)
            cmdbuffer = '\n'.join(cmdlist1) + '\n' + '\n'.join(cmdlist2) + '\n' + '\n'.join(cmdlist3) + '\n' + \
                        '\n'.join(cmdlist4) + '\n' + '\n'.join(cmdlist5) + '\n' + '\n'.join(warnings)
            formaction = "/aciapp/portmanager"
            formname = 'Edit '
            return render_template('pmcmdcliform.html', formaction=formaction, formname=formname, apic=apic, 
                                   token=token, username=login, url=url, 
                                   commandlist=commandlist, cmdbuffer=cmdbuffer, cmdlist1='\n'.join(cmdlist1),
                                   cmdlist2='\n'.join(cmdlist2), cmdlist3='\n'.join(cmdlist3),
                                   cmdlist4='\n'.join(cmdlist4), cmdlist5='\n'.join(cmdlist5),
                                   cmdlist6=' '.join(cmdlist6))

    def pmcommitnocheck(self, cmdlist, token):
        try:
            result_resp = ''
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            aci = aciDB()
            aciconfig = aciConfig(aci)
            login_apic = aci.login(login, password, url)
            cmdset = ['Delete Static Binding', 'Delete Port', 'Create Port', 'Create Static Binding',
                      'Disable/Enable Port']
            for n, cmd in enumerate(cmdlist):
                commands = self.cmdtodict(cmd.split('\n'))
                if commands:
                    result_resp = result_resp + '\n' + str(cmdset[n]) + ' Configuration and Responses:\n'
                    results, post_url, post_resp, warnings = aciconfig.functions(commands, 'no', 'no')
                    result_resp = result_resp + '\n' + aci.get_xml_from_json(results) + '\n'
            aci.logout()
            return result_resp

        except:
            return result_resp

    def pmcommitsend(self, cmdlist, token):
        result_resp = ''
        localtime = time.asctime(time.localtime(time.time()))
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        aci = aciDB()
        aciconfig = aciConfig(aci)
        login_apic = aci.login(login, password, url)
        if login_apic:
            cmdset = ['Delete Static Binding', 'Delete Port', 'Create Port', 'Create Static Binding',
                      'Disable/Enable Port']
            for n, cmd in enumerate(cmdlist):
                commands = self.cmdtodict(cmd.split('\n'))
                if commands:
                    result_resp = result_resp + '\n' + str(cmdset[n]) + ' Configuration and Responses:\n'
                    folder = ''
                    results, post_url, post_resp, warnings = aciconfig.functions(commands, 'yes', 'yes')
                    with open(folder + 'output.log', 'a') as printfile:
                        if results:
                            printfile.write('=======================================================\n')
                            printfile.write(
                                '%s - config generated by %s for %s %s - commit send\n' % (localtime, login, url, apic))
                            printfile.write('\n')
                            printfile.write(''.join([line for line in cmd.split('\n')]))
                            printfile.write('\n')
                            for i, result in enumerate(results):
                                if post_url[i]:
                                    printfile.write('\n')
                                    printfile.write(aci.get_xml_from_json([result]))
                                    printfile.write('post: %s\n' % (post_url[i]))
                                    printfile.write('%s\n' % (post_resp[i]))
                                    printfile.write('%s\n' % (post_resp[i].text))
                                    result_resp = result_resp + '\n' + aci.get_xml_from_json([result]) + '\n' + \
                                                  'post: %s\n' % (post_url[i]) + '%s\n' % (post_resp[i]) + \
                                                  '%s\n' % (post_resp[i].text)
                            result_resp = result_resp + '\n' + 'config sent to apic has been saved in output.log \n'
                        result_resp = result_resp + '\n' + '\n'.join(warnings) + '\n'
                        for resp in post_resp:
                            if str(resp) != '<Response [200]>':
                                print 'commit send Halted due to config failed response from apic'
                                break
        aci.logout()
        return result_resp

    def pmportreport(self, portlist, token):
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        aci = aciDB()
        acitable = aciTable(aci)
        login_apic = aci.login(login, password, url)
        if login_apic:
            result = acitable.get_pm_port_report(portlist)
            data = get_data4(result)
        aci.logout()
        return data

    @expose('/snapshot', methods=['GET', 'POST'])
    def snapshot(self):
        commandlist = ''
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if 'Submit-More' in request.form.keys():
                commandlist = request.form['cmdbuffer']
            elif 'Submit-Cmd' in request.form.keys():
                commandlist = request.form['commandlist']
                formaction = "/aciapp/snapshot"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.snapshot',token=token))
            elif 'Submit-Check' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitcheck(commandlist, token)
                formaction = "/aciapp/snapshot"
                formname = 'Commit Check Result'
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)
            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitsend(commandlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend snapshot')
                formaction = "/aciapp/snapshot"
                formname = 'Commit Send Result'
                return render_template('snapcommitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist='', cmdbuffer=cmdbuffer)
            elif 'Submit-Snap' in request.form.keys():
                time.sleep(8)
                return redirect(url_for('aciapp.show_snapshot', token=token))
            else:
                commandlist = str(request.form.get('commandlist'))
                function = str(request.form.get('function'))
                if function == 'create_snapshot':
                    commandlist, target, descr = self.create_snapshot(request.form)
                    target_list = [('fabric', '')]
                    target_list.extend(self.obj_completers('tenant', {}, token))
                    if target == None:
                        function_list = ['create_snapshot', 'delete_snapshot']
                        formaction = "/aciapp/snapshot"
                        formname = 'Configure Snapshot'
                        return render_template('snapshotform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               target='', descr='', target_list=target_list)
                if function == 'delete_snapshot':
                    commandlist, filename = self.delete_snapshot(request.form)
                    filename_list = self.obj_completers('snapshot', {}, token)
                    if filename == None:
                        function_list = ['delete_snapshot', 'create_snapshot']
                        formaction = "/aciapp/snapshot"
                        formname = 'Configure Snapshot'
                        return render_template('snapshotform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               filename='', filename_list=filename_list)
                if function == 'choose':
                    commandlist = request.form.get('commandlist')
                if commandlist != '':
                    formaction = "/aciapp/snapshot"
                    formname = 'CMD CLI'
                    return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                           username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
        function = 'create_snapshot'
        target_list = [('fabric', '')]
        target_list.extend(self.obj_completers('tenant', {}, token))
        function_list = ['create_snapshot', 'delete_snapshot']
        formaction = "/aciapp/snapshot"
        formname = 'Configure Snapshot'
        return render_template('snapshotform.html', formaction=formaction, formname=formname, apic=apic,
                               token=token, username=login, url=url,
                               commandlist=commandlist, function=function, function_list=function_list,
                               filename='', target='', filename_list=[], target_list=target_list)

    @expose('/create', methods=['GET', 'POST'])
    def create(self):
        commandlist = ''
        function = ''
        function_list = ['choose', 'create_app', 'create_bd_layer2', 'create_bd_layer3', 'create_context',
                         'create_dhcprelay_label', 'create_epg',
                         'create_port', 'create_fex', 'create_ipg', 'create_network_layer2', 'create_network_layer3',
                         'create_static_direct', 'create_static_pc', 'create_static_vpc',
                         'create_switch', 'create_tenant', 'create_vlanid']
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if apic == None:
                return redirect(url_for('aciapp.index', token=token))
            elif 'Submit-More' in request.form.keys():
                commandlist = request.form['cmdbuffer']
            elif 'Submit-Cmd' in request.form.keys():
                commandlist = request.form['commandlist']
                formaction = "/aciapp/create"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.create', token=token))
            elif 'Submit-Check' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitcheck(commandlist, token)
                formaction = "/aciapp/create"
                formname = 'Commit Check Result'
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)

            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitsend(commandlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend create')
                formaction = "/aciapp/create"
                formname = 'Commit Send Result'
                return render_template('configcommitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist='', cmdbuffer=cmdbuffer)
            elif 'Submit-Return' in request.form.keys():
                return redirect(url_for('aciapp.create', token=token))
            else:
                commandlist = str(request.form.get('commandlist'))
                function = str(request.form.get('function'))
                if function == 'create_tenant':
                    commandlist, tenant, descr = self.create_tenant(request.form)
                    tenant_list = self.obj_completers('tenant', {}, token)
                    if tenant == None:
                        function_list = ['create_tenant']
                        formaction = "/aciapp/create"
                        formname = 'Configure Tenant'
                        return render_template('tenantform.html', formaction=formaction, formname=formname, apic=apic,  
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant='', descr='', tenant_list=tenant_list)
                if function == 'create_context':
                    commandlist, tenant, ctx, descr = self.create_context(request.form)
                    if tenant == None or ctx == None or tenant == '' or ctx == '':
                        tenant_list = self.obj_completers('tenant', {}, token)
                        function_list = ['create_context']
                        formaction = "/aciapp/create"
                        formname = 'Configure Context'
                        return render_template('contextform.html', formaction=formaction, formname=formname, apic=apic,         
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant,  ctx='', descr='', tenant_list=tenant_list)
                if function == 'create_bd_layer2' or function == 'create_bd_layer3':
                    commandlist, tenant, ctx, bd, subnet, scope, l3out, descr = self.create_bd(request.form)
                    if tenant == None or ctx == None or bd == None or tenant == '' or ctx == '' or bd == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list=[]
                        if not ctx and tenant: ctx_list = self.obj_completers('ctx', {}, token, tenant)
                        else: ctx_list=[]
                        if not l3out and tenant: l3out_list = self.obj_completers('l3out', {}, token, tenant)
                        else: l3out_list = []
                        function_list = [function]
                        formaction = "/aciapp/create"
                        formname = 'Configure Bridge Domain'
                        return render_template('bdform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, ctx=ctx, bd='', descr='',
                                               tenant_list=tenant_list, ctx_list=ctx_list, l3out_list=l3out_list)
                if function == 'create_dhcprelay_label':
                    commandlist, tenant, bd, dhcprelay = self.create_dhcprelay_label(request.form)
                    if tenant == None or bd == None or dhcprelay == None or tenant == '' or bd == '' or dhcprelay == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list=[]
                        if not bd and tenant: bd_list = self.obj_completers('bd', {}, token, tenant)
                        else: bd_list=[]
                        if not dhcprelay and tenant: dhcp_list = self.obj_completers('dhcprelay', {}, token)
                        else: dhcp_list=[]
                        function_list = ['create_dhcprelay_label']
                        formaction = "/aciapp/create"
                        formname = 'Configure Dhcprelay'
                        return render_template('dhcplabelform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, dhcprelay=dhcprelay, bd=bd, tenant_list=tenant_list,
                                               bd_list=bd_list, dhcp_list=dhcp_list)
                if function == 'create_app':
                    commandlist, tenant, app = self.create_app(request.form)
                    if tenant == None or app == None or tenant == '' or app == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list=[]
                        function_list = ['create_app']
                        formaction = "/aciapp/create"
                        formname = 'Configure App Profile'
                        return render_template('appform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant,  app='', descr='', tenant_list=tenant_list)

                if function == 'create_epg':
                    commandlist, tenant, bd, app, epg, domain, descr= self.create_epg(request.form)
                    if tenant == None or bd == None or app == None or epg == None or tenant == '' or bd == '' \
                        or app == '' or epg == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list=[]
                        if not app and tenant: app_list = self.obj_completers('app', {}, token, tenant)
                        else: app_list=[]
                        if not domain and tenant: domain_list = self.obj_completers('domain', {}, token)
                        else: domain_list=[]
                        if not bd and tenant: bd_list = self.obj_completers('bd', {}, token)
                        else: bd_list=[]
                        function_list = ['create_epg']
                        formaction = "/aciapp/create"
                        formname = 'Configure EndPoint Group'
                        return render_template('epgform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, app=app, bd=bd, epg='', descr='', domain='',
                                               tenant_list=tenant_list,
                                               bd_list=bd_list, app_list=app_list, domain_list=domain_list)
                if function == 'create_static_direct' or function == 'create_static_vpc' or \
                            function == 'create_static_pc':
                    commandlist, tenant, app, epg, node, port, encap, mode, ipg = self.create_static(request.form)
                    if tenant == None or app == None or epg == None or node == None or port == None or \
                            encap == None or mode == None or tenant == '' or app == '' or epg == '' or node == '' or \
                            port == '' or encap == '' or mode == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list = []
                        if not app and tenant: app_list = self.obj_completers('app', {}, token, tenant)
                        else:app_list = []
                        if not epg and tenant: epg_list = self.obj_completers('epg', {}, token, tenant)
                        else: epg_list = []
                        if not node and tenant: node_list = self.obj_completers('node', {}, token)
                        else: node_list = []
                        if not port and node: port_list = self.port_completers({}, {}, node, token)
                        else: port_list = []
                        if not ipg and node: ipg_list = self.obj_completers('ipg', {}, token)
                        else: ipg_list = []
                        function_list = [function]
                        formaction = "/aciapp/create"
                        formname = 'Configure Static Port Binding to EPG'
                        return render_template('staticbindform.html', formaction=formaction, formname=formname,
                                               apic=apic, token=token, username=login, url=url,
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, app=app, epg=epg, node=node, port=port,
                                               tenant_list=tenant_list, app_list=app_list, epg_list=epg_list,
                                               ipg_list=ipg_list, node_list=node_list, port_list=port_list)
                if function == 'create_network_layer2' or function == 'create_network_layer3':
                    commandlist, tenant, ctx, app, grpnum, domain, encap, subnet, scope, l3out, descr = \
                            self.create_network(request.form)
                    if tenant == None or ctx == None or domain == None or app == None or grpnum == None or \
                            tenant == '' or ctx == '' or domain == '' or app == '' or grpnum == ''  or encap == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list=[]
                        if not app and tenant: app_list = self.obj_completers('app', {}, token, tenant)
                        else: app_list = []
                        if not domain and tenant and grpnum: domain_list = self.obj_completers('domain', {}, token)
                        else: domain_list = []
                        if not ctx and tenant: ctx_list = self.obj_completers('ctx', {}, token, 'common')
                        else: ctx_list=[]
                        if not l3out and tenant and grpnum: l3out_list = self.obj_completers('l3out', {}, token, 'common')
                        else: l3out_list = []
                        grpnum_list = ['01','02','03','04','05','06','07','08','09','10','11','12']
                        if grpnum is not None and grpnum != 'None' and grpnum != '':
                            if domain == None or domain == 'None':
                                domain = 'PDOM_' + str(grpnum)
                        function_list = [function]
                        formaction = "/aciapp/create"
                        formname = 'Configure EndPoint Group'
                        return render_template('networkform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, app=app, ctx=ctx, grpnum=grpnum, descr='', domain=domain,
                                               tenant_list=tenant_list, ctx_list=ctx_list, l3out_list=l3out_list,
                                               grpnum_list=grpnum_list, app_list=app_list, domain_list=domain_list)
                if function == 'create_port':
                    commandlist, node, port, ipg, descr = self.create_port(request.form)
                    if not node: node_list= self.obj_completers('node', {}, token)
                    else: node_list=[]
                    if not port and node: port_list= self.port_completers({}, {}, node, token)
                    else: port_list=[]
                    ipg_list= self.obj_completers('ipg', {}, token)
                    if node == None or port == None or node == '' or port == '':
                        function_list = ['create_port']
                        formaction = "/aciapp/create"
                        formname = 'Create Port'
                        return render_template('portform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, port=port, ipg=ipg, descr='', node_list=node_list,
                                               ipg_list=ipg_list, port_list=port_list)
                if function == 'create_ipg':
                    commandlist, ipg, speed, aep, lacp, lldp, cdp, mcp, l2int, descr = self.create_ipg(request.form)
                    if ipg == None or speed == None or aep == None or ipg == '' or speed == '' or aep == '':
                        aep_list = self.obj_completers('aep', {}, token)
                        function_list = [function]
                        formaction = "/aciapp/create"
                        formname = 'Configure IPG'
                        return render_template('ipgform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               ipg='', speed='1G_ON', aep='', lacp='None', lldp='lldp_enabled',
                                               cdp='cdp_enabled', mcp='mdp_enabled', l2int='global_vlan_scope',
                                               descr='None', aep_list=aep_list)
                if function == 'create_fex':
                    commandlist, node, fromport, toport, fex, cab = self.create_fex(request.form)
                    if node == None or fromport == None or toport == None or fex == None or \
                            node == '' or fromport == '' or toport == '' or fex == '':
                        if not node:
                            node_list = self.obj_completers('node', {}, token)
                        else:
                            node_list = []
                        if not fromport or not toport:
                            if node:
                                port_list = self.port_completers({}, {}, node, token)
                            else:
                                port_list = []
                        fex_list = ['101', '102', '103', '104', '105', '106', '107', '108', '109', '110', '111', '112']
                        function_list = [function]
                        formaction = "/aciapp/create"
                        formname = 'Create Fex'
                        return render_template('fexform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url,
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, fromport=fromport, toport=toport, fex=fex, cab='',
                                               node_list=node_list, fex_list=fex_list, port_list=port_list)
                if function == 'create_switch':
                    commandlist, node1, node2, vpc_id = self.create_switch(request.form)
                    if node1 == None or node2 == None or vpc_id == None or node1 == '' or node2 == '' or vpc_id == '':
                        node_list = self.obj_completers('node', {}, token)
                        function_list = [function]
                        formaction = "/aciapp/create"
                        formname = 'Create Switch'
                        return render_template('switchform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url,
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node1=node1, node2=node2, vpc_id='', node_list=node_list)
                if function == 'create_vlanid':
                    commandlist = self.create_vlanid(request.form)
                if function == 'choose':
                    commandlist = request.form.get('commandlist')
                if commandlist != '':
                    formaction = "/aciapp/create"
                    formname = 'CMD CLI'
                    return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                           username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)

        formaction = "/aciapp/create"
        formname = 'Create Objects '
        return render_template('configureform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                               username=login, url=url, function_list=function_list, commandlist=commandlist, function=function) 


    @expose('/modify', methods=['GET', 'POST'])
    def modify(self):
        commandlist = ''
        function = ''
        tenant = ''
        ctx = ''
        bd = ''
        bd_type = ''
        subnet = ''
        scope = ''
        l3out = ''
        app = ''
        epg = ''
        node =''
        port =''
        ipg =''
        descr = ''
        function_list = ['choose', 'modify_bd_arpflood', 'modify_bd_context', 'modify_bd_description',
                       'modify_bd_mac', 'modify_bd_routing', 'modify_bd_unicast', 'modify_epg_bd',
                       'modify_epg_prefgrp', 'modify_epg_intraepg', 'modify_epg_description', 'modify_ipg_speed',
                       'modify_ipg_aep', 'modify_ipg_cdp', 'modify_ipg_description', 'modify_ipg_lacp',
                       'modify_ipg_lldp', 'modify_ipg_mcp', 'modify_ipg_vlanscope',
                       'modify_port_description', 'modify_port_ipg', 'modify_static_binding']
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if apic == None:
                return redirect(url_for('aciapp.index', token=token))
            elif 'Submit-More' in request.form.keys():
                commandlist = request.form['cmdbuffer']
            elif 'Submit-Cmd' in request.form.keys():
                commandlist = request.form['commandlist']
                formaction = "/aciapp/modify"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.modify', token=token))
            elif 'Submit-Check' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitcheck(commandlist, token)
                formaction = "/aciapp/modify"
                formname = 'Commit Check Result'
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)

            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitsend(commandlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend modify')
                formaction = "/aciapp/modify"
                formname = 'Commit Send Result'
                return render_template('configcommitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist='', cmdbuffer=cmdbuffer)
            elif 'Submit-Return' in request.form.keys():
                return redirect(url_for('aciapp.modify', token=token))
            else:
                commandlist = str(request.form.get('commandlist'))
                function = str(request.form.get('function'))
                if function == 'modify_port_ipg':
                    commandlist, node, port, ipg = self.modify_port_ipg(request.form)
                    if not node: node_list= self.obj_completers('node', {}, token)
                    else: node_list=[]
                    if not port and node: port_list= self.port_completers({}, {}, node, token)
                    else: port_list=[]
                    if not ipg and node: ipg_list= self.obj_completers('ipg', {}, token)
                    else: ipg_list=[]
                    if node == None or port == None or node == '' or port == '' or ipg == '':
                        function_list = ['modify_port_ipg']
                        formaction = "/aciapp/modify"
                        formname = 'Modify Port'
                        return render_template('portform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, port=port, ipg=ipg, descr='', node_list=node_list,
                                               ipg_list=ipg_list, port_list=port_list)
                if function == 'modify_port_description':
                    commandlist, node, port, descr = self.modify_port_description(request.form)
                    if not node: node_list= self.obj_completers('node', {}, token)
                    else: node_list=[]
                    if not port and node: port_list= self.port_completers({}, {}, node, token)
                    else: port_list=[]
                    if node == None or port == None or node == '' or port == '' or descr == '':
                        function_list = ['modify_port_description']
                        formaction = "/aciapp/modify"
                        formname = 'Modify Port'
                        return render_template('portform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, port=port, ipg='', descr='', node_list=node_list,
                                               ipg_list='', port_list=port_list)
                if function == 'choose':
                    commandlist = request.form.get('commandlist')
                if commandlist != '':
                    formaction = "/aciapp/modify"
                    formname = 'CMD CLI'
                    return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                           username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
        formaction = "/aciapp/modify"
        formname = 'Modify Objects '
        return render_template('configureform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                               username=login, url=url, function_list=function_list, commandlist=commandlist, function=function)

    @expose('/delete', methods=['GET', 'POST'])
    def delete(self):
        commandlist = ''
        function = ''
        tenant = ''
        ctx = ''
        bd = ''
        bd_type = ''
        subnet = ''
        scope = ''
        l3out = ''
        app = ''
        epg = ''
        node =''
        port =''
        ipg =''
        descr = ''
        function_list = ['choose', 'delete_app', 'delete_bd', 'delete_context', 'delete_dhcprelay', 'delete_epg',
                       'delete_port', 'delete_fex', 'delete_ipg', 'delete_snapshot', 'delete_static_direct',
                       'delete_static_pc', 'delete_static_vpc', 'delete_switch', 'delete_tenant']
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if apic == None:
                return redirect(url_for('aciapp.index', token=token))
            elif 'Submit-More' in request.form.keys():
                commandlist = request.form['cmdbuffer']
            elif 'Submit-Cmd' in request.form.keys():
                commandlist = request.form['commandlist']
                formaction = "/aciapp/delete"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.delete', token=token))
            elif 'Submit-Check' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitcheck(commandlist, token)
                formaction = "/aciapp/delete"
                formname = 'Commit Check Result'
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)

            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitsend(commandlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend delete')
                formaction = "/aciapp/delete"
                formname = 'Commit Send Result'
                return render_template('configcommitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist='', cmdbuffer=cmdbuffer)
            elif 'Submit-Return' in request.form.keys():
                return redirect(url_for('aciapp.delete', token=token))
            else:
                commandlist = str(request.form.get('commandlist'))
                function = str(request.form.get('function'))
                if function == 'delete_tenant':
                    commandlist, tenant = self.delete_tenant(request.form)
                    tenant_list = self.obj_completers('tenant', {}, token)
                    if tenant == None:
                        function_list = ['delete_tenant']
                        formaction = "/aciapp/delete"
                        formname = 'Delete Tenant'
                        return render_template('tenantform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, descr='', tenant_list=tenant_list)
                if function == 'delete_context':
                    commandlist, tenant, ctx = self.delete_context(request.form)
                    if tenant == None or ctx == None or tenant == '' or ctx == '':
                        tenant_list = self.obj_completers('tenant', {}, token)
                        ctx_list = self.obj_completers('ctx', {}, token, tenant)
                        function_list = ['delete_context']
                        formaction = "/aciapp/delete"
                        formname = 'Delete Context'
                        return render_template('contextform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant,  ctx=ctx, descr='', tenant_list=tenant_list, ctx_list=ctx_list)
                if function == 'delete_bd':
                    commandlist, tenant, bd = self.delete_bd(request.form)
                    if tenant == None or bd == None or tenant == '' or bd == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list=[]
                        if not bd and tenant: bd_list = self.obj_completers('bd', {}, token, tenant)
                        else: bd_list=[]
                        function_list = ['delete_bd']
                        formaction = "/aciapp/delete"
                        formname = 'Delete Bridge Domain'
                        return render_template('bdform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, ctx='', bd=bd, descr='', tenant_list=tenant_list,
                                               bd_list=bd_list)
                if function == 'delete_dhcprelay':
                    commandlist, tenant, bd, dhcprelay = self.delete_dhcprelay_label(request.form)
                    if tenant == None or bd == None or dhcprelay == None or tenant == '' or bd == '' or dhcprelay == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list = []
                        if not bd and tenant: bd_list = self.obj_completers('bd', {}, token, tenant)
                        else: bd_list = []
                        if not dhcprelay and tenant: dhcp_list = self.obj_completers('dhcprelay', {}, token)
                        else: dhcp_list = []
                        function_list = [function]
                        formaction = "/aciapp/delete"
                        formname = 'Delete Dhcprelay'
                        return render_template('dhcplabelform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, dhcprelay=dhcprelay, bd=bd, tenant_list=tenant_list,
                                               bd_list=bd_list, dhcp_list=dhcp_list)
                if function == 'delete_app':
                    commandlist, tenant, app = self.delete_app(request.form)
                    if tenant == None or app == None or tenant == '' or app == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list = []
                        if not app and tenant: app_list = self.obj_completers('app', {}, token, tenant)
                        else: app_list = []
                        function_list = ['delete_app']
                        formaction = "/aciapp/delete"
                        formname = 'Delete App Profile'
                        return render_template('appform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, app=app, descr='', tenant_list=tenant_list,
                                               app_list=app_list)
                if function == 'delete_epg':
                    commandlist, tenant, app, epg = self.delete_epg(request.form)
                    if tenant == None or app == None or epg == None or tenant == '' or app == '' or epg == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list = []
                        if not app and tenant: app_list = self.obj_completers('app', {}, token, tenant)
                        else: app_list = []
                        if not epg and tenant: epg_list = self.obj_completers('epg', {}, token, tenant)
                        else: epg_list = []
                        function_list = ['delete_epg']
                        formaction = "/aciapp/delete"
                        formname = 'Delete EndPoint Group'
                        return render_template('epgform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, app=app, epg=epg, tenant_list=tenant_list,
                                               app_list=app_list, epg_list=epg_list)
                if function == 'delete_static_direct' or function == 'delete_static_vpc' or \
                            function == 'delete_static_pc':
                    commandlist, tenant, app, epg, node, port, ipg = self.delete_static(request.form)
                    if tenant == None or app == None or epg == None or node == None or port == None or \
                            tenant == '' or app == '' or epg == '' or node == '' or port == '':
                        if not tenant: tenant_list = self.obj_completers('tenant', {}, token)
                        else: tenant_list = []
                        if not app and tenant: app_list = self.obj_completers('app', {}, token, tenant)
                        else:app_list = []
                        if not epg and tenant: epg_list = self.obj_completers('epg', {}, token, tenant)
                        else: epg_list = []
                        if not node and tenant: node_list = self.obj_completers('node', {}, token)
                        else: node_list = []
                        if not port and node: port_list = self.port_completers({}, {}, node, token)
                        else: port_list = []
                        if not ipg and node: ipg_list = self.obj_completers('ipg', {}, token)
                        else: ipg_list = []
                        function_list = [function]
                        formaction = "/aciapp/delete"
                        formname = 'Delete Static Port Binding to EPG'
                        return render_template('staticbindform.html', formaction=formaction, formname=formname,
                                               apic=apic, token=token, username=login, url=url,
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               tenant=tenant, app=app, epg=epg, node=node, port=port,
                                               tenant_list=tenant_list, app_list=app_list, epg_list=epg_list,
                                               ipg_list=ipg_list, node_list=node_list, port_list=port_list)
                if function == 'delete_port':
                    commandlist, node, port = self.delete_port(request.form)
                    if not node: node_list= self.obj_completers('node', {}, token)
                    else: node_list=[]
                    if not port and node: port_list= self.port_completers({}, {}, node, token)
                    else: port_list=[]
                    if node == None or port == None or node == '' or port == '':
                        function_list = ['delete_port']
                        formaction = "/aciapp/delete"
                        formname = 'Delete Port'
                        return render_template('portform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, port=port, ipg='', descr='', node_list=node_list,
                                               ipg_list='', port_list=port_list)
                if function == 'delete_ipg':
                    commandlist = self.delete_ipg(request.form)
                if function == 'delete_fex':
                    commandlist, node, fex = self.delete_fex(request.form)
                    if node == None or fex == None or node == '' or fex == '':
                        node_list = self.obj_completers('node', {}, token)
                        fex_list = ['101', '102', '103', '104', '105', '106', '107', '108', '109', '110', '111', '112']
                        function_list = [function]
                        formaction = "/aciapp/delete"
                        formname = 'Delete Fex'
                        return render_template('fexform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url,
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, fex=fex, node_list=node_list, fex_list=fex_list)
                if function == 'delete_switch':
                    commandlist, node1, node2 = self.delete_switch(request.form)
                    if node1 == None or node2 == None or node1 == '' or node2 == '':
                        node_list = self.obj_completers('node', {}, token)
                        function_list = [function]
                        formaction = "/aciapp/delete"
                        formname = 'Delete Switch'
                        return render_template('switchform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url,
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node1=node1, node2=node2, node_list=node_list)
                if function == 'choose':
                    commandlist = request.form.get('commandlist')
                if commandlist != '':
                    formaction = "/aciapp/delete"
                    formname = 'CMD CLI'
                    return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                           username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)

        formaction = "/aciapp/delete"
        formname = 'Delete Objects '
        return render_template('configureform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                               function_list=function_list, commandlist=commandlist, function=function)  
     
    @expose('/enable', methods=['GET', 'POST'])
    def enable(self):
        commandlist = ''
        function = ''
        node = ''
        port = ''
        function_list = ['choose', 'enable_port', 'disable_port']
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if apic == None:
                return redirect(url_for('aciapp.index', token=token))
            elif 'Submit-More' in request.form.keys():
                commandlist = request.form['cmdbuffer']
            elif 'Submit-Cmd' in request.form.keys():
                commandlist = request.form['commandlist']
                formaction = "/aciapp/enable"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.enable', token=token))
            elif 'Submit-Check' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitcheck(commandlist, token)
                formaction = "/aciapp/enable"
                formname = 'Commit Check Result'
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)
            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitsend(commandlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend enable/disable')
                formaction = "/aciapp/enable"
                formname = 'Commit Send Result'
                return render_template('configcommitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist='', cmdbuffer=cmdbuffer)
            elif 'Submit-Return' in request.form.keys():
                return redirect(url_for('aciapp.enable', token=token))
            else:
                function = str(request.form.get('function'))
                if function == 'enable_port':
                    commandlist, node, port = self.enable_port(request.form)
                    if not node: node_list= self.obj_completers('node', {}, token)
                    else: node_list=[]
                    if not port and node: port_list= self.port_completers({}, {}, node, token)
                    else: port_list=[]
                    if node == None or port == None or node == '' or port == '':
                        function_list = ['enable_port']
                        formaction = "/aciapp/enable"
                        formname = 'Enable Port'
                        return render_template('portform.html', formaction=formaction, formname=formname, apic=apic,
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, port=port, ipg='', descr='', node_list=node_list,
                                               ipg_list='', port_list=port_list)
                if function == 'disable_port':
                    commandlist, node, port = self.enable_port(request.form)
                    if not node: node_list= self.obj_completers('node', {}, token)
                    else: node_list=[]
                    if not port and node: port_list= self.port_completers({}, {}, node, token)
                    else: port_list=[]
                    if node == None or port == None or node == '' or port == '':
                        function_list = ['disable_port']
                        formaction = "/aciapp/enable"
                        formname = 'Disable Port'
                        return render_template('portform.html', formaction=formaction, formname=formname, apic=apic, 
                                               token=token, username=login, url=url, 
                                               commandlist=commandlist, function=function, function_list=function_list,
                                               node=node, port=port, ipg='', descr='', node_list=node_list,
                                               ipg_list='', port_list=port_list)
                if function == 'choose':
                    commandlist = request.form.get('commandlist')
                if commandlist != '':
                    formaction = "/aciapp/enable"
                    formname = 'CMD CLI'
                    return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                           username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
        formaction = "/aciapp/enable"
        formname = 'Enable/Disable Port'
        return render_template('configureform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                               username=login, url=url, commandlist=commandlist, function=function, function_list=function_list,
                               node=node, port=port)
     
    @expose('/configure', methods=['GET', 'POST'])
    def configure(self):
        commandlist = ''
        function = ''
        data = {"row": [], "header": None}
        token = request.args.get('token')
        token_data = verify_auth_token(token)
        login = token_data.get('login')
        password = token_data.get('password')
        url = token_data.get('url')
        apic = token_data.get('apic')
        token = generate_auth_token(login, password, url, apic)
        if request.form:
            token = request.form['token']
            apic = request.form['apic']
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            apic = token_data.get('apic')
            token = generate_auth_token(login, password, url, apic)
            if apic == None:
                return redirect(url_for('aciapp.index', token=token))
            elif 'Submit-Cli' in request.form.keys():
                commandlist = request.form['commandlist']
                cmdbuffer= commandlist + '\n' +request.form['cmdbuffer']
                formaction = "/aciapp/configure"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)
            elif 'Submit-More' in request.form.keys():
                commandlist = request.form['cmdbuffer']
            elif 'Submit-Cmd' in request.form.keys():
                commandlist = request.form['commandlist']
                formaction = "/aciapp/configure"
                formname = 'CMD CLI'
                return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
            elif 'Submit-Cancel' in request.form.keys():
                return redirect(url_for('aciapp.configure', token=token))
            elif 'Submit-Check' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitcheck(commandlist, token)
                formaction = "/aciapp/configure"
                formname = 'Commit Check Result'
                return render_template('commitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist=commandlist, cmdbuffer=cmdbuffer)

            elif 'Submit-Send' in request.form.keys():
                commandlist = request.form['cmdbuffer']
                cmdbuffer = self.commitsend(commandlist, token)
                userlog.append(time.ctime() + ', ' + str(request.remote_addr) + ', ' + str(login) + ', ' + str(apic) +
                               ', commitsend cli')
                formaction = "/aciapp/configure"
                formname = 'Commit Send Result'
                return render_template('configcommitform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                       username=login, url=url, commandlist='', cmdbuffer=cmdbuffer)
            elif 'Submit-Return' in request.form.keys():
                return redirect(url_for('aciapp.configure', token=token))
            else:
                commandlist = str(request.form.get('commandlist'))
                if commandlist != '':
                    formaction = "/aciapp/configure"
                    formname = 'CMD CLI'
                    return render_template('cmdcliform.html', formaction=formaction, formname=formname, apic=apic, token=token,
                                           username=login, url=url, commandlist=commandlist, cmdbuffer=commandlist)
        if request.files:
            imported = request.files['import_file']
            for i, line in enumerate(imported):
                if '.csv' in imported.filename:
                    linecsv = line.split(',')
                elif '.txt' in imported.filename:
                    linecsv = line.split()
                else:
                    linecsv = ''
                    line = ''
                if i == 0:
                    data['header'] = linecsv
                    data['row'].append(linecsv)
                else:
                    data['row'].append(linecsv)
                    commandlist = commandlist + line.replace(',', ' ')
        formaction = "/aciapp/configure"
        formname = 'import/CLI '
        return render_template('configureform2.html', formaction=formaction, formname=formname, apic=apic, 
                               token=token, username=login, url=url, 
                               commandlist=commandlist, function=function, tableheader=data['header'], tablerows=[data['row']])

    def create_tenant(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create tenant'
            tenant = str(form_dict.get('tenant'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if descr == '': descr = 'None'
            if tenant == '': tenant = 'None'
            if tenant != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + descr
        return commandlist, form_dict.get('tenant'), form_dict.get('descr')

    def delete_tenant(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete tenant'
            tenant = str(form_dict.get('tenant'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if tenant != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant
        return commandlist, form_dict.get('tenant')

    def create_context(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create context'
            tenant = str(form_dict.get('tenant'))
            ctx = str(form_dict.get('ctx'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if descr == '': descr = 'None'
            if tenant == '': tenant = 'None'
            if ctx == '': ctx = 'None'
            if tenant != 'None' and ctx != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + ctx + ' ' + descr
        return commandlist, form_dict.get('tenant'), form_dict.get('ctx'), form_dict.get('descr')

    def delete_context(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete context'
            tenant = str(form_dict.get('tenant'))
            ctx = str(form_dict.get('ctx'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if ctx == '': ctx = 'None'
            if tenant != 'None' and ctx != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + ctx
        return commandlist, form_dict.get('tenant'), form_dict.get('ctx')

    def create_app(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create app profile'
            tenant = str(form_dict.get('tenant'))
            app = str(form_dict.get('app'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if app == '': app = 'None'
            if tenant != 'None' and app != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + app
        return commandlist, form_dict.get('tenant'), form_dict.get('app')

    def delete_app(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete app profile'
            tenant = str(form_dict.get('tenant'))
            app = str(form_dict.get('app'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if app == '': app = 'None'
            if tenant != 'None' and app != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + app
        return commandlist, form_dict.get('tenant'), form_dict.get('app')

    def create_bd(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create bd'
            if str(form_dict.get('function')) == 'create_bd_layer2':
                bd_type = 'l2'
            else:
                bd_type = 'l3'
            tenant = str(form_dict.get('tenant'))
            ctx = str(form_dict.get('ctx'))
            bd = str(form_dict.get('bd'))
            subnet = str(form_dict.get('subnet'))
            scope = str(form_dict.get('scope'))
            l3out = str(form_dict.get('l3out'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if ctx == '': ctx = 'None'
            if bd == '': bd = 'None'
            if subnet == '': subnet = 'None'
            if scope == '': scope = 'None'
            if l3out == '': l3out = 'None'
            if descr == '': descr = 'None'
            if tenant != 'None' and ctx != 'None' and bd != 'None' :
                commandlist = commandlist + '\n' + function + ' ' + bd_type + ' ' + tenant + ' ' + ctx + ' ' + \
                              bd + ' ' + subnet + ' ' + scope + ' ' + l3out + ' ' + descr
        return commandlist, form_dict.get('tenant'), form_dict.get('ctx'), form_dict.get('bd'), \
               form_dict.get('subnet'), form_dict.get('scope'), form_dict.get('l3out'), form_dict.get('descr')

    def delete_bd(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete bd'
            tenant = str(form_dict.get('tenant'))
            bd = str(form_dict.get('bd'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if bd == '': bd = 'None'
            if tenant != 'None' and bd != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + bd
        return commandlist, form_dict.get('tenant'), form_dict.get('bd')

    def create_dhcprelay_label(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create dhcprelay label'
            tenant = str(form_dict.get('tenant'))
            bd = str(form_dict.get('bd'))
            dhcprelay = str(form_dict.get('dhcprelay'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if bd == '': bd = 'None'
            if dhcprelay == '': dhcprelay = 'None'
            if tenant != 'None' and bd != 'None' and dhcprelay != 'None':
                commandlist = commandlist + '\n' + function + ' ' +tenant + ' ' + bd + ' ' + dhcprelay
        return commandlist, form_dict.get('tenant'), form_dict.get('bd'), form_dict.get('dhcprelay')

    def delete_dhcprelay_label(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete dhcprelay label'
            tenant = str(form_dict.get('tenant'))
            bd = str(form_dict.get('bd'))
            dhcprelay = str(form_dict.get('dhcprelay'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if bd == '': bd = 'None'
            if dhcprelay == '': dhcprelay = 'None'
            if tenant != 'None' and bd != 'None' and dhcprelay != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + bd + ' ' + dhcprelay
        return commandlist, form_dict.get('tenant'), form_dict.get('bd'), form_dict.get('dhcprelay')

    def create_epg(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create epg'
            tenant = str(form_dict.get('tenant'))
            bd = str(form_dict.get('bd'))
            app = str(form_dict.get('app'))
            epg = str(form_dict.get('epg'))
            domain = str(form_dict.get('domain'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if bd == '': bd = 'None'
            if app == '': app = 'None'
            if epg == '': epg = 'None'
            if domain == '': domain = 'None'
            if descr == '': descr = 'None'
            if tenant != 'None' and bd != 'None' and app != 'None' and epg != 'None' and domain != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + bd + ' ' + \
                              app + ' ' + epg + ' ' + domain + ' ' + descr
        return commandlist, form_dict.get('tenant'), form_dict.get('bd'), form_dict.get('app'), \
               form_dict.get('epg'), form_dict.get('domain'), form_dict.get('descr')

    def delete_epg(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete epg'
            tenant = str(form_dict.get('tenant'))
            app = str(form_dict.get('app'))
            epg = str(form_dict.get('epg'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if app == '': app = 'None'
            if epg == '': epg = 'None'
            if tenant != 'None' and app != 'None' and epg != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + app + ' ' + epg
        return commandlist, form_dict.get('tenant'), form_dict.get('app'), form_dict.get('epg')

    def create_ipg(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create ipg'
            ipg = str(form_dict.get('ipg'))
            speed = str(form_dict.get('speed'))
            aep = str(form_dict.get('aep'))
            lacp = str(form_dict.get('lacp'))
            lldp = str(form_dict.get('lldp'))
            cdp = str(form_dict.get('cdp'))
            mcp = str(form_dict.get('mcp'))
            l2int = str(form_dict.get('l2int'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if ipg == '': ipg = 'None'
            if speed == '': speed = 'None'
            if aep == '': aep = 'None'
            if lacp == '': lacp = 'None'
            if lldp == '': lldp = 'None'
            if cdp == '': cdp = 'None'
            if mcp == '': mcp = 'None'
            if l2int == '': l2int = 'None'
            if descr == '': descr = 'None'
            if ipg != 'None' and speed != 'None' and speed != 'aep':
                commandlist = commandlist + '\n' + function + ' ' + ipg + ' ' + speed + ' ' + aep + ' ' + \
                              lacp + ' ' + lldp + ' ' + cdp + ' ' + mcp + ' ' + l2int + ' ' + descr
        return commandlist, form_dict.get('ipg'), form_dict.get('speed'), form_dict.get('aep'), \
               form_dict.get('lacp'), form_dict.get('lldp'), form_dict.get('cdp'), form_dict.get('mcp'), \
               form_dict.get('l2int'), form_dict.get('descr')

    def delete_ipg(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete ipg'
            ipg = str(form_dict.get('ipg'))
            commandlist = str(form_dict.get('commandlist'))
            if ipg == '': ipg = 'None'
            if ipg != 'None':
                commandlist = commandlist + '\n' + function + ' ' + ipg
        return commandlist, form_dict.get('ipg')

    def create_port(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'create port'
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            ipg = str(form_dict.get('ipg'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if port == '': port = 'None'
            if ipg == '': ipg = 'None'
            if descr == '': descr = 'None'
            if node != 'None' and port != 'None' and ipg != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + port + ' ' + ipg + ' ' + descr
        return commandlist, form_dict.get('node'), form_dict.get('port'), form_dict.get('ipg'), form_dict.get('descr')

    def delete_port(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete port'
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if port == '': port = 'None'
            if node != 'None' and port != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + port
        return commandlist, form_dict.get('node'), form_dict.get('port')

    def create_static(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create static binding'
            if str(form_dict.get('function')) == 'create_static_vpc':
                ipg_type = 'vpc'
            elif str(form_dict.get('function')) == 'create_static_pc':
                ipg_type = 'pc'
            else:
                ipg_type = 'direct'
            tenant = str(form_dict.get('tenant'))
            app = str(form_dict.get('app'))
            epg = str(form_dict.get('epg'))
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            encap = str(form_dict.get('encap'))
            mode = str(form_dict.get('mode'))
            ipg = str(form_dict.get('ipg'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if app == '': app = 'None'
            if epg == '': epg = 'None'
            if node == '': node = 'None'
            if port == '': port = 'None'
            if encap == '': encap = 'None'
            if mode == '': mode = 'None'
            if ipg == '': ipg = 'None'
            if tenant != 'None' and app != 'None' and epg != 'None' and node != 'None' and port != 'None' and \
                encap != 'None' and mode != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + app + ' ' + epg + ' ' + \
                              node + ' ' + port + ' ' + encap + ' ' + mode + ' ' + ipg + ' ' + ipg_type
        return commandlist, form_dict.get('tenant'), form_dict.get('app'), form_dict.get('epg'), \
               form_dict.get('node'), form_dict.get('port'), form_dict.get('encap'), form_dict.get('mode'), \
               form_dict.get('ipg')

    def delete_static(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete static binding'
            if str(form_dict.get('function')) == 'delete_static_vpc':
                ipg_type = 'vpc'
            elif str(form_dict.get('function')) == 'delete_static_pc':
                ipg_type = 'pc'
            else:
                ipg_type = 'direct'
            tenant = str(form_dict.get('tenant'))
            app = str(form_dict.get('app'))
            epg = str(form_dict.get('epg'))
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            ipg = str(form_dict.get('ipg'))
            commandlist = str(form_dict.get('commandlist'))
            if tenant == '': tenant = 'None'
            if app == '': app = 'None'
            if epg == '': epg = 'None'
            if node == '': node = 'None'
            if port == '': port = 'None'
            if ipg == '': ipg = 'None'
            if tenant != 'None' and app != 'None' and epg != 'None' and node != 'None' and port != 'None':
                commandlist = commandlist + '\n' + function + ' ' + tenant + ' ' + app + ' ' + epg + ' ' + \
                              node + ' ' + port + ' ' + ipg + ' ' + ipg_type
        return commandlist, form_dict.get('tenant'), form_dict.get('app'), form_dict.get('epg'), \
               form_dict.get('node'), form_dict.get('port'), form_dict.get('ipg')

    def enable_port(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'enable port'
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if port == '': port = 'None'
            if node != 'None' and port != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + port
        return commandlist, form_dict.get('node'), form_dict.get('port')
        
    def disable_port(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'disable port'
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if port == '': port = 'None'
            if node != 'None' and port != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + port
        return commandlist, form_dict.get('node'), form_dict.get('port')
     
    def modify_port_ipg(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'modify port ipg'
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            ipg = str(form_dict.get('ipg'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if port == '': port = 'None'
            if ipg == '': ipg = 'None'
            if node != 'None' and port != 'None' and ipg != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + port + ' ' + ipg
        return commandlist, form_dict.get('node'), form_dict.get('port'), form_dict.get('ipg')
    
    def modify_port_description(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'modify port description'
            node = str(form_dict.get('node'))
            port = str(form_dict.get('port'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if port == '': port = 'None'
            if descr == '': descr = 'None'
            if node != 'None' and port != 'None' and descr != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + port + ' ' + descr
        return commandlist, form_dict.get('node'), form_dict.get('port'), form_dict.get('descr')

    def create_snapshot(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create snapshot'
            target = str(form_dict.get('target'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if target == '': target = 'None'
            if descr == '': descr = 'None'
            if target != 'None':
                commandlist = commandlist + '\n' + function + ' ' + target + ' ' + descr
        return commandlist, form_dict.get('target'), form_dict.get('descr')

    def delete_snapshot(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete snapshot'
            filename = str(form_dict.get('filename'))
            commandlist = str(form_dict.get('commandlist'))
            if filename == '': filename = 'None'
            if filename != 'None':
                commandlist = commandlist + '\n' + function + ' ' + filename
        return commandlist, form_dict.get('filename')

    def create_switch(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'create switch'
            node1 = str(form_dict.get('node1'))
            node2 = str(form_dict.get('node2'))
            vpc_id = str(form_dict.get('vpc_id'))
            commandlist = str(form_dict.get('commandlist'))
            if node1 == '': node1 = 'None'
            if node2 == '': node2 = 'None'
            if vpc_id == '': vpc_id = 'None'
            if node1 != 'None' and node2 != 'None' and vpc_id != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node1 + ' ' + node2 + ' ' + vpc_id
        return commandlist, form_dict.get('node1'), form_dict.get('node2'), form_dict.get('vpc_id')

    def delete_switch(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete switch'
            node1 = str(form_dict.get('node1'))
            node2 = str(form_dict.get('node2'))
            commandlist = str(form_dict.get('commandlist'))
            if node1 == '': node1 = 'None'
            if node2 == '': node2 = 'None'
            if node1 != 'None' and node2 != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node1 + ' ' + node2
        return commandlist, form_dict.get('node1'), form_dict.get('node2')

    def create_fex(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'create fex'
            node = str(form_dict.get('node'))
            fromport = str(form_dict.get('fromport'))
            toport = str(form_dict.get('toport'))
            fex = str(form_dict.get('fex'))
            cab = str(form_dict.get('cab'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if fromport == '': fromport = 'None'
            if toport == '': toport = 'None'
            if fex == '': fex = 'None'
            if cab == '': cab = 'None'
            if node != 'None' and fromport != 'None' and toport != 'None' and fex != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + fromport + ' ' + toport + ' ' + \
                              fex + ' ' + cab
        return commandlist, form_dict.get('node'), form_dict.get('fromport'), form_dict.get('toport'), \
               form_dict.get('fex'), form_dict.get('cab')

    def delete_fex(self , form_dict):
        commandlist = ''
        if form_dict:
            function = 'delete fex'
            node = str(form_dict.get('node'))
            fex = str(form_dict.get('fex'))
            commandlist = str(form_dict.get('commandlist'))
            if node == '': node = 'None'
            if fex == '': fex = 'None'
            if node != 'None'and fex != 'None':
                commandlist = commandlist + '\n' + function + ' ' + node + ' ' + fex
        return commandlist, form_dict.get('node'), form_dict.get('fex')

    def create_network(self, form_dict):
        commandlist = ''
        if form_dict:
            function = 'create network'
            if str(form_dict.get('function')) == 'create_network_layer2':
                bd_type = 'l2'
            else:
                bd_type = 'l3'
            tenant = str(form_dict.get('tenant'))
            ctx = str(form_dict.get('ctx'))
            app = str(form_dict.get('app'))
            grpnum = str(form_dict.get('grpnum'))
            domain = str(form_dict.get('domain'))
            encap = str(form_dict.get('encap'))
            subnet = str(form_dict.get('subnet'))
            scope = str(form_dict.get('scope'))
            l3out = str(form_dict.get('l3out'))
            descr = str(form_dict.get('descr'))
            commandlist = str(form_dict.get('commandlist'))
            if bd_type == '': bd_type = 'None'
            if tenant == '': tenant = 'None'
            if ctx == '': ctx = 'None'
            if app == '': app = 'None'
            if grpnum == '': grpnum = 'None'
            if domain == '': domain = 'None'
            if encap == '': encap = 'None'
            if subnet == '': subnet = 'None'
            if scope == '': scope = 'None'
            if l3out == '': l3out = 'None'
            if descr == '': descr = 'None'
            if bd_type != 'None' and tenant != 'None' and ctx != 'None' and app != 'None'  and domain != 'None':
                commandlist = commandlist + '\n' + function + ' ' + bd_type + ' ' + tenant + ' ' + ctx + ' ' + \
                              app + ' ' + grpnum + ' ' + domain + ' ' + encap + ' ' + \
                              subnet + ' ' + scope + ' ' + l3out + ' ' + descr
        return commandlist, form_dict.get('tenant'), form_dict.get('ctx'), form_dict.get('app'), \
                form_dict.get('grpnum'), form_dict.get('domain'), form_dict.get('encap'), \
                form_dict.get('subnet'), form_dict.get('scope'), form_dict.get('l3out'), form_dict.get('descr')

    def pm_csv1(self, pmcmdlist, token):

            obj_list = []
            obj_descr = {}
            commandlist1 = []
            commandlist2 = []
            commandlist3 = []
            commandlist4 = []
            commandlist5 = []
            commandlist6 = []
            warnings = []
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB()
            login_apic = aci.login(login, password, url)
            if login_apic:
                port_dict = aci.get_port_dict()
                ipg_dict = aci.get_ipg_dict()
                switch_dict = aci.get_switch_dict()
                epg_dict = aci.get_epg_dict()
                for action in pmcmdlist.split('\n'):
                    action = action.split(',')
                    if len(action) >= 9:
                        pm_speed = action[1].strip().lower()
                        pm_vlan = action[2].strip()
                        pm_epg = action[3].strip()
                        pm_action = action[4].strip().lower()
                        pm_node = action[5].strip()
                        pm_port = 'eth' + action[6].strip() + '/' + action[7].strip()
                        pm_descr = action[8].strip()
                        pm_tenant = ''
                        pm_app = ''
                        pm_epg_dn = ''
                        pm_mode = 'native'
                        pm_ipg = pm_speed
                        pm_ipg_type = 'direct'
                        pm_vlanscope = '_G_'

                        for epg_dn in epg_dict.keys():
                            if pm_epg == epg_dict[epg_dn]['name']:
                                pm_tenant = epg_dict[epg_dn]['tenant']
                                pm_app = epg_dict[epg_dn]['app']
                                pm_epg_dn = epg_dn
                                break

                        for epg_dn in epg_dict.keys():
                            if epg_dn != pm_epg_dn:
                                if 'vlan-' + pm_vlan in epg_dict[epg_dn]['vlan'] or 'vlan-' + pm_vlan in \
                                        epg_dict[epg_dn]['encap']:
                                    for port_name in sorted(port_dict.keys()):
                                        if epg_dn in port_dict[port_name]['epg']:
                                            if port_dict[port_name]['switch'] == pm_node or \
                                                            port_dict[port_name]['node'] == pm_node:
                                                pm_vlanscope = '_PL_'
                                                break
                        if pm_epg_dn:
                            for domain in epg_dict[pm_epg_dn]['domain']:
                                if 'PDOM' in domain:
                                    grpnum = domain[-2:]
                                    if grpnum.isdigit():
                                        if pm_speed == '100':
                                            pm_ipg = 'IPG_AC_100M_ON' + pm_vlanscope + grpnum
                                        elif pm_speed == '1000':
                                            pm_ipg = 'IPG_AC_1G_ON' + pm_vlanscope + grpnum
                                        elif pm_speed == '10000':
                                            pm_ipg = 'IPG_AC_10G_ON' + pm_vlanscope + grpnum
                                        elif pm_speed == '100m':
                                            pm_ipg = 'IPG_AC_100M_ON' + pm_vlanscope + grpnum
                                        elif pm_speed == '1g':
                                            pm_ipg = 'IPG_AC_1G_ON' + pm_vlanscope + grpnum
                                        elif pm_speed == '10g':
                                            pm_ipg = 'IPG_AC_10G_ON' + pm_vlanscope + grpnum
                                        elif pm_speed == 'auto':
                                            pm_ipg = 'IPG_AC_AUTO_ON' + pm_vlanscope + grpnum
                                        break

                        if pm_node.lower() in switch_dict.keys():
                            pm_node = str(switch_dict[pm_node.lower()]['id'])
                        if pm_node.upper() in switch_dict.keys():
                            pm_node = str(switch_dict[pm_node.upper()]['id'])
                        if pm_node + '-' + pm_port in port_dict.keys():
                            pm_port_name = pm_node + '-' + pm_port
                            if switch_dict[pm_node]['role'] != 'leaf':
                                warnings.append(pm_port_name + ' is not a leaf port')
                                continue
                            if port_dict[pm_port_name]['type'] == 'fexbundle':
                                warnings.append(pm_port_name + ' is a fex uplink')
                                continue
                            if 'fabric' in port_dict[pm_port_name]['usage']:
                                warnings.append(pm_port_name + ' is a leaf uplink')
                                continue
                            if 'controller' in port_dict[pm_port_name]['usage']:
                                warnings.append(pm_port_name + ' is a controller uplink')
                                continue
                            if 'infra' in port_dict[pm_port_name]['usage']:
                                warnings.append(pm_port_name + ' is an infra uplink')
                                continue
                            if port_dict[pm_port_name]['type'] != 'accportgrp' and \
                                            port_dict[pm_port_name]['type'] != '':
                                warnings.append(pm_port_name + ' is not a direct port')
                                continue
                            if pm_ipg not in ipg_dict.keys() and pm_action != 'cease':
                                if pm_ipg.replace('_ON', '_OFF') not in ipg_dict.keys():
                                    warnings.append(pm_port_name + ' ipg: ' + pm_ipg + ' or epg: ' + pm_epg +
                                                    ' does not exist or PDOM domain not in epg ' + pm_epg_dn)
                                    continue
                                else:
                                    pm_ipg = pm_ipg.replace('_ON', '_OFF')
                            if pm_action != 'cease' and pm_action != 'provide' and pm_action != 'amend':
                                warnings.append(pm_port_name + ' action must be provide, amend or cease')
                                continue
                            if 'vlan-' + pm_vlan not in epg_dict[pm_epg_dn]['vlan'] and epg_dict[pm_epg_dn][
                                'vlan'] != [] and \
                                            pm_epg_dn not in port_dict[pm_port_name]['epg'] and pm_action != 'cease':
                                warnings.append(pm_port_name + ' vlan ' + pm_vlan +
                                                ' is not match existing vlans on the epg ' + pm_epg)
                                continue
                            if 'down' in port_dict[pm_port_name]['operst']:
                                if port_dict[pm_port_name]['selector'] != '' and \
                                                port_dict[pm_port_name]['leaf_profile'] != '':
                                    selector = port_dict[pm_port_name]['selector']
                                    leaf_profile = port_dict[pm_port_name]['leaf_profile']
                                    if len(port_dict[pm_port_name]['blockport']) > 1:
                                        warnings.append('blockname: ' + port_dict[pm_port_name]['blockname'] +
                                                        ' is used by multiple ports: ' +
                                                        ','.join(port_dict[pm_port_name]['blockport']))
                                        continue
                                    port_with_same_selector = [port for port in port_dict.keys() if
                                                               port_dict[port]['selector'] == selector and
                                                               port_dict[port]['leaf_profile'] == leaf_profile]
                                    if len(port_with_same_selector) > 1:
                                        warnings.append(
                                            'Interface Selector: ' + port_dict[pm_port_name]['selector'] +
                                            ' is used by multiple ports: ' + ','.join(port_with_same_selector))
                                        continue
                                    commandlist2.append('delete port ' + pm_node + ' ' + pm_port)

                                for port_epg_dn in port_dict[pm_port_name]['epg']:
                                    port_tenant = port_epg_dn.split('uni/tn-')[1].split('/')[0]
                                    port_app = port_epg_dn.split('/ap-')[1].split('/')[0]
                                    port_epg = port_epg_dn.split('/epg-')[1]
                                    port_ipg = port_dict[pm_port_name]['ipg']
                                    port_ipg_type = port_dict[pm_port_name]['type']
                                    commandlist1.append('delete static binding ' + port_tenant + ' ' + port_app + ' ' +
                                                        port_epg + ' ' + pm_node + ' ' + pm_port + ' None direct')
                                    action = ['delete', 'static', 'binding', port_tenant, port_app,
                                          ]
                                if pm_action == 'provide' or pm_action == 'amend':
                                    commandlist3.append('create port ' + pm_node + ' ' + pm_port + ' ' +
                                                        pm_ipg + ' ' + pm_descr)

                                    commandlist4.append('create static binding ' + pm_tenant + ' ' + pm_app + ' ' +
                                                        pm_epg + ' ' + pm_node + ' ' + pm_port + ' ' + pm_vlan + ' ' +
                                                        pm_mode + ' None direct')
                                    commandlist5.append('enable port ' + pm_node + ' ' + pm_port)

                                    commandlist6.append(pm_node + '-' + pm_port)

                                if pm_action == 'cease':
                                    commandlist5.append('disable port ' + pm_node + ' ' + pm_port)

                                    commandlist6.append(pm_node + '-' + pm_port)
                            else:
                                warnings.append(pm_port_name + ' is not down')
                                continue


                return commandlist1, commandlist2, commandlist3, commandlist4, commandlist5, commandlist6, warnings


    def obj_completers(self, obj, obj_dict, token, tenant=None):
        try:
            obj_list = []
            obj_descr = {}
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB()
            login_apic = aci.login(login, password, url)
            if login_apic:
                if obj == 'node':
                    if obj_dict == {}:
                        obj_dict = aci.get_switch_dict()
                if obj == 'ipg':
                    if obj_dict == {}:
                        obj_dict = aci.get_ipg_dict('basic')
                if obj == 'tenant':
                    if obj_dict == {}:
                        obj_dict = aci.get_tenant_name_dict()
                if obj == 'bd':
                    if obj_dict == {}:
                        obj_dict = aci.get_bd_name_dict()
                if obj == 'ctx':
                    if obj_dict == {}:
                        obj_dict = aci.get_ctx_name_dict()
                if obj == 'app':
                    if obj_dict == {}:
                        obj_dict = aci.get_app_name_dict()
                if obj == 'epg':
                    if obj_dict == {}:
                        obj_dict = aci.get_epg_name_dict()
                if obj == 'contract':
                    if obj_dict == {}:
                        obj_dict = aci.get_contract_name_dict()
                if obj == 'l3out':
                    if obj_dict == {}:
                        obj_dict = aci.get_l3out_name_dict()
                if obj == 'aep':
                    if obj_dict == {}:
                        obj_dict = aci.get_aep_dict()
                if obj == 'domain':
                    if obj_dict == {}:
                        obj_dict = aci.get_domain_dict()
                if obj == 'snapshot':
                    if obj_dict == {}:
                        obj_dict = aci.get_snapshot_dict()
                if obj == 'dhcprelay':
                    if obj_dict == {}:
                        obj_dict = aci.get_dhcprelay_name_dict()
                if obj == 'vlanpool':
                    if obj_dict == {}:
                        obj_dict = aci.get_vlanpool_name_dict()
                for obj_name in obj_dict.keys():
                    if obj == 'node':
                        if obj_dict[obj_name]['role'] == 'leaf' or obj_dict[obj_name]['role'] == 'spine':
                            obj_list.append((unicode(obj_name), obj_dict[obj_name]['role']))
                    elif obj == 'snapshot':
                        obj_list.append((obj_dict[obj_name]['name'], obj_name, obj_dict[obj_name]['descr']))
                    elif 'descr' in obj_dict[obj_name]:
                        if 'tenant' in obj_dict[obj_name] and tenant != None:
                            if obj_dict[obj_name]['tenant'] == tenant:
                                obj_list.append((obj_dict[obj_name]['name'], obj_dict[obj_name]['descr']))
                        else:
                            obj_list.append((unicode(obj_dict[obj_name]['name']), unicode(obj_dict[obj_name]['descr'])))
                    elif 'type' in obj_dict[obj_name]:
                        obj_list.append((unicode(obj_dict[obj_name]['name']), unicode(obj_dict[obj_name]['type'])))
                    else:
                        obj_list.append((unicode(obj_dict[obj_name]['name']), ''))
            return sorted(obj_list)
        except:
            return ['','', '']
            
    def port_completers(self, port_dict, switch_dict, node, token):
        try:
            port_list = []
            token_data = verify_auth_token(token)
            login = token_data.get('login')
            password = token_data.get('password')
            url = token_data.get('url')
            aci = aciDB()
            login_apic = aci.login(login, password, url)
            if login_apic:
                if switch_dict == {}:
                    switch_dict = aci.get_switch_dict()
                if node in switch_dict.keys():
                    node = switch_dict[node]['id']
                    if port_dict == {}:
                        port_dict = aci.get_port_name_dict()
                    port_list = []
                    port_list_unsorted = []
                    port_descr = {}
                    for port_name in port_dict.keys():
                        if port_dict[port_name]['node'] == node:
                            portnum = []
                            for pnum in port_dict[port_name]['id'].split('eth')[1].split('/'):
                                if len(pnum) < 2:
                                    pnum = '0' + str(pnum)
                                portnum.append(pnum)
                            portnum = int(('').join(portnum))

                            port_list_unsorted.append([portnum, unicode(port_dict[port_name]['id']),
                                                      unicode(port_dict[port_name]['descr'])])
                            port_descr[unicode(port_dict[port_name]['id'])] = unicode(port_dict[port_name]['descr'])
                    for port_name in sorted(port_list_unsorted):
                        port_list.append((port_name[1],port_name[2]))
            return port_list
        except:
            return port_list                      

    def cmdtodict(self, cmdlist):
        commands = []
        for cmdline in cmdlist:
            if ',' in cmdline:
                action = cmdline.strip().replace(', ', ',').replace(' ,', ',').split(',')
            else:
                action = cmdline.strip().replace('  ', ' ').replace('  ', ' ').replace('  ', ' ').split()
            if '' == cmdline.strip():
                continue
            if 'create' == action[0] and 'tenant' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    command['descr'] = (' '.join(action[3:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'tenant' == action[1]:
                command = {}
                if len(action) >= 3:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    commands.append(command)
            if 'create' == action[0] and 'port' == action[1]:
                command = {}
                if len(action) >= 6:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node'] = action[2]
                    command['port'] = action[3]
                    command['ipg'] = action[4]
                    command['descr'] = (' '.join(action[5:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'port' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node'] = action[2]
                    command['port'] = action[3]
                    commands.append(command)
            if 'create' == action[0] and 'static' == action[1]:
                command = {}
                if len(action) >= 12:
                    command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                    command['tenant'] = action[3]
                    command['app'] = action[4]
                    command['epg'] = action[5]
                    command['node'] = action[6]
                    command['port'] = action[7]
                    command['encap'] = action[8]
                    command['mode'] = action[9]
                    command['ipg'] = action[10]
                    command['ipg_type'] = action[11]
                    commands.append(command)
            if 'delete' == action[0] and 'static' == action[1]:
                command = {}
                if len(action) >= 10:
                    command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                    command['tenant'] = action[3]
                    command['app'] = action[4]
                    command['epg'] = action[5]
                    command['node'] = action[6]
                    command['port'] = action[7]
                    command['ipg'] = action[8]
                    command['ipg_type'] = action[9]
                    commands.append(command)
            if 'create' == action[0] and 'snapshot' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['target'] = action[2]
                    command['descr'] = (' '.join(action[3:])).strip('"').strip("'").strip()
                    for i, cmd in enumerate(commands):
                        if cmd['function'] == 'create snapshot':
                            del commands[i]
                    commands.append(command)
            if 'delete' == action[0] and 'snapshot' == action[1]:
                command = {}
                if len(action) >= 3:
                    command['function'] = action[0] + ' ' + action[1]
                    command['filename'] = action[2]
                    commands.append(command)
            if 'create' == action[0] and 'ipg' == action[1]:
                command = {}
                if len(action) >= 10:
                    command['function'] = action[0] + ' ' + action[1]
                    command['ipg'] = action[2]
                    command['speed'] = action[3]
                    command['aep'] = action[4]
                    command['lacp'] = action[5]
                    command['lldp'] = action[6]
                    command['cdp'] = action[7]
                    command['mcp'] = action[8]
                    command['l2int'] = action[9]
                    command['descr'] = (' '.join(action[10:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'ipg' == action[1]:
                command = {}
                if len(action) >= 3:
                    command['function'] = action[0] + ' ' + action[1]
                    command['ipg'] = action[2]
                    commands.append(command)
            if 'create' == action[0] and 'fex' == action[1]:
                command = {}
                if len(action) >= 7:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node'] = action[2]
                    command['fromport'] = action[3]
                    command['toport'] = action[4]
                    command['fex'] = action[5]
                    command['cab'] = (' '.join(action[6:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'fex' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node'] = action[2]
                    command['fex'] = action[3]
                    commands.append(command)
            if 'create' == action[0] and 'switch' == action[1]:
                command = {}
                if len(action) >= 5:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node1'] = action[2]
                    command['node2'] = action[3]
                    command['vpc_id'] = action[4]
                    commands.append(command)
            if 'delete' == action[0] and 'switch' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node1'] = action[2]
                    command['node2'] = action[3]
                    commands.append(command)
            if 'create' == action[0] and 'network' == action[1]:
                command = {}
                if len(action) >= 13:
                    command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                    command['tenant'] = action[3]
                    command['ctx'] = action[4]
                    command['app'] = action[5]
                    command['grpnum'] = action[6]
                    command['domain'] = action[7]
                    command['encap'] = action[8]
                    command['subnet'] = action[9]
                    command['scope'] = action[10]
                    command['l3out'] = action[11]
                    command['descr'] = (' '.join(action[12:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'create' == action[0] and 'context' == action[1]:
                command = {}
                if len(action) >= 5:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    command['ctx'] = action[3]
                    command['descr'] = (' '.join(action[4:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'context' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    command['ctx'] = action[3]
                    commands.append(command)
            if 'create' == action[0] and 'bd' == action[1]:
                command = {}
                if len(action) >= 10:
                    command['function'] = action[0] + ' ' + action[1]
                    command['bd_type'] = action[2]
                    command['tenant'] = action[3]
                    command['ctx'] = action[4]
                    command['bd'] = action[5]
                    command['subnet'] = action[6]
                    command['scope'] = action[7]
                    command['l3out'] = action[8]
                    command['descr'] = (' '.join(action[9:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'bd' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    command['bd'] = action[3]
                    commands.append(command)
            if 'create' == action[0] and 'app' == action[1]:
                command = {}
                if len(action) >= 5:
                    command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                    command['tenant'] = action[3]
                    command['app'] = action[4]
                    commands.append(command)
            if 'delete' == action[0] and 'app' == action[1]:
                command = {}
                if len(action) >= 5:
                    command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                    command['tenant'] = action[3]
                    command['app'] = action[4]
                    commands.append(command)
            if 'create' == action[0] and 'epg' == action[1]:
                command = {}
                if len(action) >= 8:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    command['bd'] = action[3]
                    command['app'] = action[4]
                    command['epg'] = action[5]
                    command['domain'] = action[6]
                    command['descr'] = (' '.join(action[7:])).strip('"').strip("'").strip()
                    commands.append(command)
            if 'delete' == action[0] and 'epg' == action[1]:
                command = {}
                if len(action) >= 5:
                    command['function'] = action[0] + ' ' + action[1]
                    command['tenant'] = action[2]
                    command['app'] = action[3]
                    command['epg'] = action[4]
                    commands.append(command)
            if 'create' == action[0] and 'dhcprelay' == action[1]:
                command = {}
                if len(action) >= 6:
                    if action[2] == 'label':
                        command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                        command['bd_tenant'] = action[3]
                        command['bd'] = action[4]
                        command['dhcprelay'] = action[5]
                        commands.append(command)
            if 'delete' == action[0] and 'dhcprelay' == action[1]:
                command = {}
                if len(action) >= 6:
                    if action[2] == 'label':
                        command['function'] = action[0] + ' ' + action[1] + ' ' + action[2]
                        command['bd_tenant'] = action[3]
                        command['bd'] = action[4]
                        command['dhcprelay'] = action[5]
                        commands.append(command)
            if 'create' == action[0] and 'vlanid' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['vlanpool'] = action[2]
                    command['encap'] = action[3]
                    commands.append(command)
            if 'enable' == action[0] and 'port' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node'] = action[2]
                    command['port'] = action[3]
                    commands.append(command)
            if 'disable' == action[0] and 'port' == action[1]:
                command = {}
                if len(action) >= 4:
                    command['function'] = action[0] + ' ' + action[1]
                    command['node'] = action[2]
                    command['port'] = action[3]
                    commands.append(command)
            if 'modify' == action[0] and 'port' == action[1]:
                command = {}
                if len(action) >= 6:
                    command['function'] = 'modify port'
                    command['ipg'] = 'None'
                    command['descr'] = 'None'
                    command['node'] = action[3]
                    command['port'] = action[4]
                    for cmd in commands:
                        if cmd['function'] == 'modify port':
                            if cmd['node'] == command['node'] and cmd['port'] == command['port']:
                                command = cmd
                    if 'ipg' == action[2]:
                        command['ipg'] = action[5]
                    if 'description' == action[2]:
                        command['descr'] = (' '.join(action[5:])).strip('"').strip("'").strip()
                    if command not in commands:
                        commands.append(command)
            if 'modify' == action[0] and 'ipg' == action[1]:
                command = {}
                if len(action) >= 5:
                    command['function'] = 'modify ipg'
                    command['speed'] = 'None'
                    command['aep'] = 'None'
                    command['lacp'] = 'None'
                    command['lldp'] = 'None'
                    command['cdp'] = 'None'
                    command['mcp'] = 'None'
                    command['l2int'] = 'None'
                    command['descr'] = 'None'
                    command['ipg'] = action[3]
                    for cmd in commands:
                        if cmd['function'] == 'modify ipg':
                            if cmd['ipg'] == command['ipg'].strip():
                                command = cmd
                    if 'speed' == action[2]:
                        command['speed'] = action[4]
                    if 'aep' == action[2]:
                        command['aep'] = action[4]
                    if 'lacp' == action[2]:
                        command['lacp'] = action[4]
                    if 'lldp' == action[2]:
                        command['lldp'] = action[4]
                    if 'cdp' == action[2]:
                        command['cdp'] = action[4]
                    if 'mcp' == action[2]:
                        command['mcp'] = action[4]
                    if 'vlanscope' == action[2]:
                        command['intl2'] = action[4]
                    if 'description' == action[2]:
                        command['descr'] = (' '.join(action[4:])).strip('"').strip("'").strip()
                    if command not in commands:
                        commands.append(command)
            if 'modify' == action[0] and 'bd' == action[1]:
                command = {}
                if len(action) >= 6:
                    command['function'] = 'modify bd'
                    command['ctx'] = 'None'
                    command['routing'] = 'None'
                    command['arp'] = 'None'
                    command['unicast'] = 'None'
                    command['multicast'] = 'None'
                    command['mac'] = 'None'
                    command['descr'] = 'None'
                    command['tenant'] = action[3]
                    command['bd'] = action[4]
                    command['epg'] = action[5]
                    for cmd in commands:
                        if cmd['function'] == 'modify bd':
                            if cmd['tenant'] == command['tenant'] and cmd['bd'] == command['bd']:
                                command = cmd
                    if 'context' == action[2]:
                        command['ctx'] = action[5]
                    if 'routing' == action[2]:
                        command['routing'] = action[5]
                    if 'arpflood' == action[2]:
                        command['arp'] = action[5]
                    if 'unicast' == action[2]:
                        command['unicast'] = action[5]
                    if 'mac' == action[2]:
                        command['mac'] = action[5]
                    if 'description' == action[2]:
                        command['descr'] = (' '.join(action[5:])).strip('"').strip("'").strip()
                    if command not in commands:
                        commands.append(command)
            if 'modify' == action[0] and 'epg' == action[1]:
                command = {}
                if len(action) >= 7:
                    command['function'] = 'modify epg'
                    command['bd'] = 'None'
                    command['prefgrp'] = 'None'
                    command['intraepg'] = 'None'
                    command['descr'] = 'None'
                    command['tenant'] = action[3]
                    command['app'] = action[4]
                    command['epg'] = action[5]
                    for cmd in commands:
                        if cmd['function'] == 'modify epg':
                            if cmd['tenant'] == command['tenant'] and \
                                            cmd['app'] == command['app'] and cmd['epg'] == command['epg']:
                                command = cmd
                    if 'bd' == action[2]:
                        command['bd'] = action[6]
                    if 'prefgrp' == action[2]:
                        command['prefgrp'] = action[6]
                    if 'intraepg' == action[2]:
                        command['intraepg'] = action[6]
                    if 'description' == action[2]:
                        command['descr'] = (' '.join(action[6:])).strip('"').strip("'").strip()
                    if command not in commands:
                        commands.append(command)
            if 'modify' == action[0] and 'static' == action[1]:
                command = {}
                if len(action) >= 12:
                    command['function'] = 'modify static binding'
                    command['tenant'] = action[3]
                    command['app'] = action[4]
                    command['epg'] = action[5]
                    command['node'] = action[6]
                    command['port'] = action[7]
                    command['encap'] = action[8]
                    command['mode'] = action[9]
                    command['ipg'] = action[10]
                    command['ipg_type'] = action[11]
                    if command not in commands:
                        commands.append(command)
        return commands

admin = Admin(app, url='/', base_template='index-static.html',)

admin.add_view(aciapp(name='aciapp'))

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port='8080', url_scheme='http')
