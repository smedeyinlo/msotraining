# title           :aciapilib.py
# description     :aci library module
# author          :segun medeyinlo
# date            :08102018
# version         :0.23
# usage           :
# notes           :updated 29042019
# python_version  :2.7.10
# ==============================================================================


import json

import requests
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning

"""
aciDB library
this library is used for .....
the main methods are ...
logout
    this is used to logout of the apic
login
    this is used to login
"""


class aciDB:
    """
    main class
    """

    def __init__(self):
        """
        input: nothing
        return: nothing
        self.mysession holds the current session for the connection to the apic
        """
        self.mysession = None
        self.apic = ''

    def login(self, uid, pwd, apic):
        """
        uid: this is the username to logout
        pwd: this is the unencrypted password
        apic: this it the full apic url eg https://x.x.x.x
        return: None if failed, retruns an str of seconds if successfull
        """
        self.apic = str(apic)
        login_url = self.apic + '/api/aaaLogin.json'
        data = {'aaaUser': {'attributes': {'name': uid,
                                           'pwd': pwd}}}

        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
        self.mysession = requests.Session()

        try:
            post_resp = self.mysession.post(login_url, data=json.dumps(data, sort_keys=True), verify=False)
            post_resp_data = json.loads(post_resp.text)['imdata'][0]
            if post_resp.ok:
                # print 'Successfull login to APIC: ', self.apic
                timeout = post_resp_data['aaaLogin']['attributes']['refreshTimeoutSeconds']
                return timeout
            else:
                print 'Could not login to APIC: ', self.apic
                return None
                # raise
        except:
            print 'Could not connect to APIC: ', self.apic
            return None
            # raise

    def refresh(self):
        refresh_url = self.apic + '/api/aaaRefresh.json'
        self.mysession.get(refresh_url)

    def logout(self):
        self.mysession.close()
        self.mysession = None

    def send_to_apic(self, result_json):
        post_urls = []
        post_resps = []
        if result_json != []:
            for object_dict in result_json:
                post_url = ''
                post_resp = ''
                if len(object_dict.keys()) == 1:
                    key = object_dict.keys()[0]
                    try:
                        object_dn = object_dict[key]['attributes']['dn']
                        post_url = self.apic + '/api/mo/' + object_dn + '.json'
                        post_resp = self.mysession.post(post_url, data=json.dumps(object_dict, sort_keys=True),
                                                       verify=False)
                    except:
                        print 'exception: an object not sent to apic, check object dn for', key
                        pass
                post_urls.append(post_url)
                post_resps.append(post_resp)
        else:
            print 'no config to send to apic'
        return post_urls, post_resps

    def do_tenant(self, tenant, status, attr=None):
        tenant = {'fvTenant': {'attributes': {'name': tenant, 'dn': 'uni/tn-' + tenant}, 'children': []}}
        if attr:
            if 'descr' in attr.keys():  tenant['fvTenant']['attributes']['descr'] = attr['descr']
        tenant['fvTenant']['attributes']['status'] = status
        return tenant

    def do_context(self, context, status, attr=None):
        context = {'fvCtx': {'attributes': {'name': context}, 'children': []}}
        if attr:
            if 'intractx' in attr.keys(): context['fvCtx']['attributes']['pcEnfPref'] = attr['intractx']
        context['fvCtx']['attributes']['status'] = status
        return context

    def do_app(self, app, status, attr=None):
        app = {'fvAp': {'attributes': {'name': app}, 'children': []}}
        if attr:
            if 'descr' in attr.keys(): app['fvAp']['attributes']['descr'] = attr['descr']
        app['fvAp']['attributes']['status'] = status
        return app

    def do_bd(self, bd, status, context=None, l3out=None, attr=None):
        bd = {'fvBD': {'attributes': {'name': bd}, 'children': []}}
        if attr:
            if 'descr' in attr.keys(): bd['fvBD']['attributes']['descr'] = attr['descr']
            if 'unicastRoute' in attr.keys(): bd['fvBD']['attributes']['unicastRoute'] = attr['unicastRoute']
            if 'iplearning' in attr.keys(): bd['fvBD']['attributes']['ipLearning'] = attr['iplearning']
            if 'limitiplearn' in attr.keys(): bd['fvBD']['attributes']['limitIpLearnToSubnets'] = attr['limitiplearn']
            if 'arpflood' in attr.keys(): bd['fvBD']['attributes']['arpFlood'] = attr['arpflood']
            if 'unkunicast' in attr.keys(): bd['fvBD']['attributes']['unkMacUcastAct'] = attr['unkunicast']
            if 'mcastAllow' in attr.keys(): bd['fvBD']['attributes']['mcastAllow'] = attr['mcastAllow']
            if 'mac' in attr.keys(): bd['fvBD']['attributes']['mac'] = attr['mac']
            if 'encapflood' in attr.keys(): bd['fvBD']['attributes']['multiDstPktAct'] = attr['encapflood']
        if context:
            context = {'fvRsCtx': {'attributes': {'tnFvCtxName': context}}}
            bd['fvBD']['children'].append(context)
        if l3out:
            l3out = {'fvRsBDToOut': {'attributes': {'tnL3extOutName': l3out}}}
            bd['fvBD']['children'].append(l3out)
        bd['fvBD']['attributes']['status'] = status
        return bd

    def do_subnet_to_bd(self, subnet, bd, status, attr=None):
        subnet = {'fvSubnet': {'attributes': {'ip': subnet}, 'children': []}}
        if attr:
            if 'scope' in attr.keys(): subnet['fvSubnet']['attributes']['scope'] = attr['scope']
            # scope is "scope":"private", "scope":"public", or "scope":"private,shared"
        subnet['fvSubnet']['attributes']['status'] = status
        bd['fvBD']['children'].append(subnet)
        return bd

    def do_epg(self, epg, status, bd=None, attr=None):
        epg = {'fvAEPg': {'attributes': {'name': epg}, 'children': []}}
        if attr:
            if 'descr' in attr.keys(): epg['fvAEPg']['attributes']['descr'] = attr['descr']
            if 'prefgrp' in attr.keys(): epg['fvAEPg']['attributes']['prefGrMemb'] = attr['prefgrp']
            if 'intraepg' in attr.keys(): epg['fvAEPg']['attributes']['pcEnfPref'] = attr['intraepg']
            if 'uepg' in attr.keys(): epg['fvAEPg']['attributes']['isAttrBasedEPg'] = attr['uepg']
            if 'encapflood' in attr.keys(): epg['fvAEPg']['attributes']['floodOnEncap'] = attr['encapflood']
        if bd:
            bd = {'fvRsBd': {'attributes': {'tnFvBDName': bd}}}
            epg['fvAEPg']['children'].append(bd)
        epg['fvAEPg']['attributes']['status'] = status
        return epg

    def do_domain_to_epg(self, domain, type, epg, status, attr=None):
        if type == 'physDomP':
            domain = {'fvRsDomAtt': {'attributes': {'tDn': 'uni/phys-' + domain}, 'children': []}}
            if attr:
                if 'imedcy' in attr.keys():  domain['fvRsPathAtt']['attributes']['instrImedcy'] = attr['imedcy']
            domain['fvRsDomAtt']['attributes']['status'] = status
            epg['fvAEPg']['children'].append(domain)
        elif type == 'vmmDomP':
            domain = {'fvRsDomAtt': {'attributes': {'tDn': 'uni/vmmp-VMware/dom-' + domain}, 'children': []}}
            if attr:
                if 'imedcy' in attr.keys():  domain['fvRsPathAtt']['attributes']['instrImedcy'] = attr['imedcy']
            domain['fvRsDomAtt']['attributes']['status'] = status
            epg['fvAEPg']['children'].append(domain)
        return epg

    def do_static_port(self, path, status, attr=None):
        path = {'fvRsPathAtt': {'attributes': {'tDn': path}, 'children': []}}
        if attr:
            if 'imedcy' in attr.keys():  path['fvRsPathAtt']['attributes']['instrImedcy'] = attr['imedcy']
            if 'mode' in attr.keys(): path['fvRsPathAtt']['attributes']['mode'] = attr['mode']
            if 'encap' in attr.keys(): path['fvRsPathAtt']['attributes']['encap'] = attr['encap']
        path['fvRsPathAtt']['attributes']['status'] = status
        return path

    def do_dhcprelay_policy(self, ipaddr, l3ext_dn, status, attr=None):
        dhcprelay_policy = {'dhcpRelayP': {'attributes': {'mode': 'visible', 'name': 'DHCP_Relay_' + str(ipaddr),
                                                          'owner': 'tenant'},
                                    'children': [{'dhcpRsProv': {'attributes': {'addr': ipaddr, 'tDn': l3ext_dn}}}]}}
        dhcprelay_policy['dhcpRelayP']['attributes']['status'] = status
        return dhcprelay_policy

    def do_dhcprelay_label(self, dhcprelay, status, attr=None):
        dhcprelay_label = {'dhcpLbl': {'attributes': {'name': dhcprelay, 'owner': 'tenant'}}}
        dhcprelay_label['dhcpLbl']['attributes']['status'] = status
        return dhcprelay_label

    def do_vlanpool(self, vlanpool, type, status, attr=None):
        vlanpool = {'fvnsVlanInstP': {'attributes': {'name': vlanpool, 'allocMode': type}, 'children': []}}
        if attr:
            if 'descr' in attr.keys(): vlanpool['fvnsVlanInstP']['attributes']['descr'] = attr['descr']
        vlanpool['fvnsVlanInstP']['attributes']['status'] = status
        return vlanpool

    def do_vlanpool_encap(self, fromencap, toencap, status, attr=None):
        vlanpool_encap = {'fvnsEncapBlk': {'attributes': {'from': fromencap, 'to': toencap}, 'children': []}}
        vlanpool_encap['fvnsEncapBlk']['attributes']['status'] = status
        return vlanpool_encap

    def do_switch_vpcprotgrp(self, node1, node2, status, vpc_id=None):
        switch_vpc = {
            "fabricExplicitGEp": {"attributes": {"name": 'vPC-' + str(node1) + '-' + str(node2), "status": status},
                                  "children": [{"fabricRsVpcInstPol": {"attributes": {"tnVpcInstPolName": 'default'}}},
                                               {"fabricNodePEp": {"attributes": {"id": str(node1)}}},
                                               {"fabricNodePEp": {"attributes": {"id": str(node2)}}}]}}
        if vpc_id:
            switch_vpc["fabricExplicitGEp"]["attributes"]["id"] = vpc_id
        return switch_vpc

    def do_switch_profile(self, node, status, int_profile=None):
        switch_profile = {"infraNodeP": {"attributes": {"name": 'LEAF_' + str(node), "status": status},
                                         "children": [
                        {"infraLeafS": {"attributes": {"type": "range","name": 'LEAF_' + str( node)},
                                        "children": [
                        {"infraNodeBlk": {"attributes": {"from_": node, "name": 'LEAF_' + str(node), "to_": node},
                                          "children": []}}]}}]}}
        if int_profile:
            int_profile = {"infraRsAccPortP": {"attributes": {"tDn": 'uni/infra/accportprof-IP_LEAF_' + str(node)}}}
            switch_profile['infraNodeP']['children'].append(int_profile)
        return switch_profile

    def do_int_profile(self, node, status, attr=None):
        int_profile = {
            "infraAccPortP": {"attributes": {"name": 'IP_LEAF_' + str(node), "status": status}, "children": []}}
        if attr:
            if 'leaf_profile' in attr.keys(): int_profile['infraAccPortP']['attributes']['name'] = attr['leaf_profile']
        return int_profile

    def do_fex_int_profile(self, node, fex, status, attr=None):
        int_profile = {
            "infraFexP": {"attributes": {"name": 'IP_LEAF_' + str(node) + '_fex' + str(fex), "status": status},
                          "children": []}}
        if attr:
            if 'leaf_profile' in attr.keys(): int_profile['infraFexP']['attributes']['name'] = attr['leaf_profile']
        return int_profile

    def do_interface_selector(self, port, module, status, ipg_name=None, ipg_type=None, attr=None):
        portblk = {"infraPortBlk": {
            "attributes": {"name": port, "fromPort": port, "fromCard": module, "toPort": port, "toCard": module},
            "children": []}}
        hport = {"infraHPortS": {"attributes": {"type": "range", "name": 'IS_Intf-' + str(port), "status": status},
                                 "children": [portblk]}}
        if status == 'deleted':
            hport = {"infraHPortS": {"attributes": {"type": "range", "name": 'IS_Intf-' + str(port), "status": status},
                                     "children": []}}
        if attr:
            if 'descr' in attr.keys(): portblk['infraPortBlk']['attributes']['descr'] = attr['descr']
            if 'blockname' in attr.keys(): portblk['infraPortBlk']['attributes']['name'] = attr['blockname']
            if 'selector' in attr.keys(): hport['infraHPortS']['attributes']['name'] = attr['selector']
        if ipg_name and ipg_type:
            if ipg_type == 'accportgrp':
                ipg_name = {"infraRsAccBaseGrp": {"attributes": {"tDn": 'uni/infra/funcprof/accportgrp-' + ipg_name}}}
                hport['infraHPortS']['children'].append(ipg_name)
            elif ipg_type == 'accbundle-node' or ipg_type == 'accbundle-link':
                ipg_name = {"infraRsAccBaseGrp": {"attributes": {"tDn": 'uni/infra/funcprof/accbundle-' + ipg_name}}}
                hport['infraHPortS']['children'].append(ipg_name)
        return hport

    def do_fex_interface_selector(self, fromport, toport, fromcard, tocard, fex, status, ipg_name=None, attr=None):
        portblk = {"infraPortBlk": {
            "attributes": {"name": fromport + toport, "fromPort": fromport, "fromCard": fromcard, "toPort": toport,
                           "toCard": tocard}, "children": []}}
        hport = {"infraHPortS": {"attributes": {"type": "range", "name": 'fex' + str(fex), "status": status},
                                 "children": [portblk]}}
        if status == 'deleted':
            hport = {"infraHPortS": {"attributes": {"type": "range", "name": 'fex' + str(fex), "status": status},
                                     "children": []}}
        if attr:
            if 'descr' in attr.keys(): portblk['infraPortBlk']['attributes']['descr'] = attr['descr']
            if 'blockname' in attr.keys(): portblk['infraPortBlk']['attributes']['name'] = attr['blockname']
            if 'selector' in attr.keys(): hport['infraHPortS']['attributes']['name'] = attr['selector']
        if ipg_name:
            ipg_name = {"infraRsAccBaseGrp": {
                "attributes": {'fexId': str(fex), "tDn": 'uni/infra/fexprof-' + ipg_name + '/fexbundle-' + ipg_name}}}
            hport['infraHPortS']['children'].append(ipg_name)
        return hport

    def do_ipg(self, ipg_name, ipg_type, status, attr=None):
        ipg = {}
        ipg_children = []

        if ipg_type == 'accbundle-node':
            ipg = {"infraAccBndlGrp": {"attributes": {"lagT": "node", "name": ipg_name, "status": status},
                                       "children": ipg_children}}
            if attr:
                if 'descr' in attr.keys(): ipg['infraAccBndlGrp']['attributes']['descr'] = attr['descr']
        if ipg_type == 'accbundle-link':
            ipg = {"infraAccBndlGrp": {"attributes": {"lagT": "link", "name": ipg_name, "status": status},
                                       "children": ipg_children}}
            if attr:
                if 'descr' in attr.keys(): ipg['infraAccBndlGrp']['attributes']['descr'] = attr['descr']
        if ipg_type == 'accportgrp':
            ipg = {"infraAccPortGrp": {"attributes": {"name": ipg_name, "status": status}, "children": ipg_children}}
            if attr:
                if 'descr' in attr.keys(): ipg['infraAccPortGrp']['attributes']['descr'] = attr['descr']
        if ipg_type == 'fexbundle':
            ipg = {"infraFexBndlGrp": {"attributes": {"name": ipg_name, "status": status}, "children": []}}
            if attr:
                if 'descr' in attr.keys(): ipg['infraFexBndlGrp']['attributes']['descr'] = attr['descr']
            return ipg
        if attr:
            if 'aep' in attr.keys(): ipg_children.append(
                {"infraRsAttEntP": {"attributes": {"tDn": "uni/infra/attentp-" + attr['aep']}}})
            if 'speed' in attr.keys(): ipg_children.append(
                {"infraRsHIfPol": {"attributes": {"tnFabricHIfPolName": attr['speed']}}})
            if 'lldp' in attr.keys(): ipg_children.append(
                {"infraRsLldpIfPol": {"attributes": {"tnLldpIfPolName": attr['lldp']}}})
            if 'cdp' in attr.keys(): ipg_children.append(
                {"infraRsCdpIfPol": {"attributes": {"tnCdpIfPolName": attr['cdp']}}})
            if 'mcp' in attr.keys(): ipg_children.append(
                {"infraRsMcpIfPol": {"attributes": {"tnMcpIfPolName": attr['mcp']}}})
            if 'l2int' in attr.keys(): ipg_children.append(
                {"infraRsL2IfPol": {"attributes": {"tnL2IfPolName": attr['l2int']}}})
            if 'lacp' in attr.keys(): ipg_children.append(
                {"infraRsLacpPol": {"attributes": {"tnLacpLagPolName": attr['lacp']}}})
        return ipg

    def do_oospath(self, path, status):

        path = {'fabricRsOosPath': {'attributes': {'tDn': path, "lc": "blacklist", "status": status}, 'children': []}}
        return path

    def do_snapshot(self, snapshot, export_policy, status, attr=None):
        if status == 'deleted':
            snapshot_dn = "uni/backupst/snapshots-[uni/fabric/configexp-" + export_policy + "]/snapshot-" + snapshot
            snapshot = {'configSnapshot': {'attributes': {"name": snapshot, "dn": snapshot_dn, "retire": "true"},
                                           'children': []}}
            return snapshot
        else:
            export_policy = {'configExportP': {
                'attributes': {'name': export_policy, "dn": "uni/fabric/configexp-" + export_policy,
                               "adminSt": "triggered", "snapshot": "yes", "status": "created,modified"},
                'children': []}}
            if attr:
                if 'descr' in attr.keys():
                    export_policy['configExportP']['attributes']['descr'] = attr['descr']
                if 'targetdn' in attr.keys():
                    export_policy['configExportP']['attributes']['targetDn'] = attr['targetdn']
            return export_policy

    def get_fabric_config(self):
        get_url = self.apic + '/api/node/mo/uni.json?query-target=subtree&rsp-prop-include=config-only'
        resp = self.mysession.get(get_url, verify=False)

        result = json.loads(resp.text)['imdata']
        return result

    def get_tenant_deep(self, tenant_name):
        get_url = self.apic + '/api/node/mo/uni/tn-' + tenant_name + \
            '.json?query-target=self&rsp-subtree=full&rsp-prop-include=naming-only'
        resp = self.mysession.get(get_url, verify=False)
        tenant_naming = json.loads(resp.text)['imdata'][0]
        get_url = self.apic + '/api/node/mo/uni/tn-' + 'common' + \
            '.json?query-target=self&rsp-subtree=full&rsp-prop-include=naming-only'
        resp = self.mysession.get(get_url, verify=False)
        common_naming = json.loads(resp.text)['imdata'][0]
        return common_naming, tenant_naming

    def get_tenant_json(self, tenant_name, limit='naming-only'):
        get_url = self.apic + '/api/node/mo/uni/tn-' + tenant_name + \
                  '.json?query-target=self&rsp-subtree=full&rsp-prop-include=' + limit
        resp = self.mysession.get(get_url, verify=False)
        tenant_json = json.loads(resp.text)['imdata'][0]
        return tenant_json

    def get_tenants(self):
        tenants_list = []
        get_url = self.apic + '/api/class/fvTenant.json'

        resp = self.mysession.get(get_url, verify=False)

        tenants = json.loads(resp.text)['imdata']

        for tenant in tenants:
            tenants_list.append(str(tenant['fvTenant']['attributes']['name']))
        return tenants_list

    def get_obj_dict(self, obj, parent, parent_dict, obj_name, obj_filter='name'):
        result = {}
        try:
            objs_dict = [child[obj] for child in parent_dict[parent]['children'] if obj in child]
            result = {
                obj: [obj_dict for obj_dict in objs_dict if str(obj_dict['attributes'][obj_filter]) == obj_name][0]}
        except:
            pass
        return result

    def get_tenant_name_dict(self):
        tenant_name_dict = {}
        get_url = self.apic + '/api/class/fvTenant.json'

        resp = self.mysession.get(get_url, verify=False)

        tenants = json.loads(resp.text)['imdata']

        for tenant in tenants:
            tenant_name = str(tenant['fvTenant']['attributes']['name'])
            tenant_name_dict[tenant_name] = {}
            tenant_name_dict[tenant_name]['name'] = tenant_name
            tenant_name_dict[tenant_name]['descr'] = str(tenant['fvTenant']['attributes']['descr'])
            tenant_name_dict[tenant_name]['alias'] = str(tenant['fvTenant']['attributes']['nameAlias'])
        return tenant_name_dict

    def get_tenant_dict(self):
        tenant_dict = {}
        get_url = self.apic + '/api/class/fvTenant.json'

        resp = self.mysession.get(get_url, verify=False)

        tenants = json.loads(resp.text)['imdata']

        for tenant in tenants:
            tenant_name = str(tenant['fvTenant']['attributes']['name'])
            tenant_dict[tenant_name] = {}
            tenant_dict[tenant_name]['name'] = tenant_name
            tenant_dict[tenant_name]['descr'] = str(tenant['fvTenant']['attributes']['descr'])
            tenant_dict[tenant_name]['dn'] = str(tenant['fvTenant']['attributes']['dn'])
            tenant_dict[tenant_name]['alias'] = str(tenant['fvTenant']['attributes']['nameAlias'])
            tenant_dict[tenant_name]['annotation'] = ''
            if 'annotation' in tenant['fvTenant']['attributes']:
                tenant_dict[tenant_name]['annotation'] = str(tenant['fvTenant']['attributes']['annotation'])
            tenant_dict[tenant_name]['ctx'] = []
            tenant_dict[tenant_name]['bd'] = []
            tenant_dict[tenant_name]['app'] = []
            tenant_dict[tenant_name]['epg'] = []
            tenant_dict[tenant_name]['contract'] = []
            tenant_dict[tenant_name]['l3out'] = []

        ctx_dict = self.get_ctx_name_dict()
        for ctx_dn in ctx_dict.keys():
            tenant_dict[ctx_dict[ctx_dn]['tenant']]['ctx'].append(ctx_dn)
        bd_dict = self.get_bd_name_dict()
        for bd_dn in bd_dict.keys():
            tenant_dict[bd_dict[bd_dn]['tenant']]['bd'].append(bd_dn)
        app_dict = self.get_app_name_dict()
        for app_dn in app_dict.keys():
            tenant_dict[app_dict[app_dn]['tenant']]['app'].append(app_dn)
        epg_dict = self.get_epg_name_dict()
        for epg_dn in epg_dict.keys():
            tenant_dict[epg_dict[epg_dn]['tenant']]['epg'].append(epg_dn)
        contract_dict = self.get_contract_name_dict()
        for contract_dn in contract_dict.keys():
            tenant_dict[contract_dict[contract_dn]['tenant']]['contract'].append(contract_dn)
        l3out_dict = self.get_l3out_name_dict()
        for l3out_dn in l3out_dict.keys():
            tenant_dict[l3out_dict[l3out_dn]['tenant']]['l3out'].append(l3out_dn)

        return tenant_dict

    def get_switch_dict(self):
        switch_dict = {}

        get_url = self.apic + '/api/node/class/fabricNode.json?'

        resp = self.mysession.get(get_url, verify=False)

        nodes = json.loads(resp.text)['imdata']
        for node in nodes:
            node_id = str(node['fabricNode']['attributes']['id'])
            switch = str(node['fabricNode']['attributes']['name'])
            switch_dict[node_id] = node['fabricNode']['attributes']
            switch_dict[node_id]['pod'] = str(
                node['fabricNode']['attributes']['dn'].split('/pod-')[1].split('/')[0])
            switch_dict[switch] = node['fabricNode']['attributes']
            switch_dict[switch]['pod'] = str(node['fabricNode']['attributes']['dn'].split('/pod-')[1].split('/')[0])
            if 'controller' == str(node['fabricNode']['attributes']['role']):
                switch_dict[switch]['fabricSt'] = 'N/A'
        return switch_dict

    def get_rsbd_dict(self):
        rsbd_dict = {}
        get_url = self.apic + '/api/class/fvRsBd.json'

        resp = self.mysession.get(get_url, verify=False)

        rsbds = json.loads(resp.text)['imdata']

        for rsbd in rsbds:
            if 'fvRsBd' in rsbd:
                rsbd_dn = str(rsbd['fvRsBd']['attributes']['dn'].split('/rsbd')[0])
                rsbd_tdn = str(rsbd['fvRsBd']['attributes']['tDn'])
                rsbd_name = str(rsbd['fvRsBd']['attributes']['tnFvBDName'])
                if rsbd_tdn:
                    rsbd_dict[rsbd_dn] = {}
                    rsbd_dict[rsbd_dn]['bd_tenant'] = str(rsbd_tdn.split('uni/tn-')[1].split('/')[0])
                    rsbd_dict[rsbd_dn]['name'] = rsbd_name
                    rsbd_dict[rsbd_dn]['dn'] = rsbd_dn
                    rsbd_dict[rsbd_dn]['tdn'] = rsbd_tdn
                    if rsbd_dict[rsbd_dn]['bd_tenant'] == 'common': rsbd_dict[rsbd_dn]['name'] = '*' + rsbd_name

        return rsbd_dict

    def get_bd_name_dict(self):
        bd_name_dict = {}
        get_url = self.apic + '/api/class/fvBD.json?'

        resp = self.mysession.get(get_url, verify=False)

        bds = json.loads(resp.text)['imdata']
        for bd in bds:
            if 'fvBD' in bd:
                bd_dn = str(bd['fvBD']['attributes']['dn'])
                bd_name_dict[bd_dn] = {}
                bd_name_dict[bd_dn]['name'] = str(bd['fvBD']['attributes']['name'])
                bd_name_dict[bd_dn]['descr'] = str(bd['fvBD']['attributes']['descr'])
                bd_name_dict[bd_dn]['tenant'] = str(bd_dn.split('uni/tn-')[1].split('/')[0])
        return bd_name_dict

    def get_bd_dict(self):
        bd_dict = {}
        get_url = self.apic + '/api/class/fvBD.json?' \
                              'rsp-subtree=full&rsp-subtree-class=fvRsCtx,fvRtBd,fvSubnet,dhcpLbl,fvRsBDToOut'

        resp = self.mysession.get(get_url, verify=False)

        bds = json.loads(resp.text)['imdata']
        for bd in bds:
            if 'fvBD' in bd:
                bd_dn = str(bd['fvBD']['attributes']['dn'])
                bd_dict[bd_dn] = {}
                bd_dict[bd_dn]['name'] = str(bd['fvBD']['attributes']['name'])
                bd_dict[bd_dn]['descr'] = str(bd['fvBD']['attributes']['descr'])
                bd_dict[bd_dn]['tenant'] = str(bd_dn.split('uni/tn-')[1].split('/')[0])
                bd_dict[bd_dn]['unicastRoute'] = str(bd['fvBD']['attributes']['unicastRoute'])
                bd_dict[bd_dn]['iplearning'] = str(bd['fvBD']['attributes']['ipLearning'])
                bd_dict[bd_dn]['limitiplearn'] = str(bd['fvBD']['attributes']['limitIpLearnToSubnets'])
                bd_dict[bd_dn]['arpflood'] = str(bd['fvBD']['attributes']['arpFlood'])
                bd_dict[bd_dn]['unkunicast'] = str(bd['fvBD']['attributes']['unkMacUcastAct'])
                bd_dict[bd_dn]['encapflood'] = str(bd['fvBD']['attributes']['multiDstPktAct'])
                bd_dict[bd_dn]['mac'] = str(bd['fvBD']['attributes']['mac'])
                bd_dict[bd_dn]['ctx_tenant'] = ''
                bd_dict[bd_dn]['ctx'] = ''
                bd_dict[bd_dn]['context_dn'] = ''
                bd_dict[bd_dn]['epg'] = []
                bd_dict[bd_dn]['subnet'] = []
                bd_dict[bd_dn]['dhcp'] = []
                bd_dict[bd_dn]['l3out'] = []
                bd_children = bd['fvBD']['children']
                for bd_child in bd_children:
                    if 'fvRsCtx' in bd_child:
                        bd_context_dn = str(bd_child['fvRsCtx']['attributes']['tDn'])
                        if bd_context_dn:
                            bd_dict[bd_dn]['ctx_tenant'] = str(bd_context_dn.split('uni/tn-')[1].split('/')[0])
                            bd_dict[bd_dn]['ctx'] = str(bd_context_dn.split('/ctx-')[1].split('/')[0])
                            bd_dict[bd_dn]['context_dn'] = str(bd_context_dn)
                    if 'fvRtBd' in bd_child:
                        bd_epg_dn = str(bd_child['fvRtBd']['attributes']['tDn'])
                        bd_dict[bd_dn]['epg'].append(str(bd_epg_dn))
                    if 'fvSubnet' in bd_child:
                        bd_subnet_ip = str(bd_child['fvSubnet']['attributes']['ip'])
                        bd_dict[bd_dn]['subnet'].append(str(bd_subnet_ip))
                    if 'dhcpLbl' in bd_child:
                        bd_dhcp = str(bd_child['dhcpLbl']['attributes']['name'])
                        bd_dict[bd_dn]['dhcp'].append(str(bd_dhcp))
                    if 'fvRsBDToOut' in bd_child:
                        bd_l3out = str(bd_child['fvRsBDToOut']['attributes']['tnL3extOutName'])
                        bd_dict[bd_dn]['l3out'].append(str(bd_l3out))

        return bd_dict

    def get_ctx_name_dict(self):
        ctx_name_dict = {}
        get_url = self.apic + '/api/class/fvCtx.json'

        resp = self.mysession.get(get_url, verify=False)

        ctxs = json.loads(resp.text)['imdata']

        for ctx in ctxs:
            if 'fvCtx' in ctx:
                ctx_dn = str(ctx['fvCtx']['attributes']['dn'])
                ctx_name_dict[ctx_dn] = {}
                ctx_name_dict[ctx_dn]['name'] = str(ctx['fvCtx']['attributes']['name'])
                ctx_name_dict[ctx_dn]['descr'] = str(ctx['fvCtx']['attributes']['descr'])
                ctx_name_dict[ctx_dn]['tenant'] = str(ctx_dn.split('uni/tn-')[1].split('/')[0])
                ctx_name_dict[ctx_dn]['intractx'] = str(ctx['fvCtx']['attributes']['pcEnfPref'])

        return ctx_name_dict

    def get_app_name_dict(self):
        app_name_dict = {}
        get_url = self.apic + '/api/class/fvAp.json'

        resp = self.mysession.get(get_url, verify=False)

        apps = json.loads(resp.text)['imdata']

        for app in apps:
            if 'fvAp' in app:
                app_dn = str(app['fvAp']['attributes']['dn'])
                app_name_dict[app_dn] = {}
                app_name_dict[app_dn]['name'] = str(app['fvAp']['attributes']['name'])
                app_name_dict[app_dn]['descr'] = str(app['fvAp']['attributes']['descr'])
                app_name_dict[app_dn]['tenant'] = str(app_dn.split('uni/tn-')[1].split('/')[0])

        return app_name_dict

    def get_epg_name_dict(self):
        epg_name_dict = {}

        get_url = self.apic + '/api/class/fvAEPg.json?'

        resp = self.mysession.get(get_url, verify=False)

        epgs = json.loads(resp.text)['imdata']
        # print epgs
        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                epg_name_dict[epg_dn] = {}
                epg_name_dict[epg_dn]['tenant'] = str(epg_dn.split('uni/tn-')[1].split('/')[0])
                epg_name_dict[epg_dn]['app'] = str(epg_dn.split('/ap-')[1].split('/')[0])
                epg_name_dict[epg_dn]['name'] = str(epg['fvAEPg']['attributes']['name'])
                epg_name_dict[epg_dn]['descr'] = str(epg['fvAEPg']['attributes']['descr'])
        return epg_name_dict

    def get_epg_dict(self):
        epg_dict = {}
        bd_dict = self.get_bd_dict()
        get_url = self.apic + '/api/class/fvAEPg.json?' \
                              'rsp-subtree=full&rsp-subtree-class=fvRsDomAtt,fvRsPathAtt,fvRsCustQosPol&' \
                              'rsp-prop-include=config-only'
        resp = self.mysession.get(get_url, verify=False)
        epgs = json.loads(resp.text)['imdata']
        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                epg_dict[epg_dn] = {}
                epg_dict[epg_dn]['tenant'] = str(epg_dn.split('uni/tn-')[1].split('/')[0])
                epg_dict[epg_dn]['app'] = str(epg_dn.split('/ap-')[1].split('/')[0])
                epg_dict[epg_dn]['name'] = str(epg['fvAEPg']['attributes']['name'])
                epg_dict[epg_dn]['alias'] = str(epg['fvAEPg']['attributes']['nameAlias'])
                epg_dict[epg_dn]['prefgrp'] = str(epg['fvAEPg']['attributes']['prefGrMemb'])
                epg_dict[epg_dn]['intraepg'] = str(epg['fvAEPg']['attributes']['pcEnfPref'])
                epg_dict[epg_dn]['useg'] = str(epg['fvAEPg']['attributes']['isAttrBasedEPg'])
                if 'encapflood' in epg['fvAEPg']['attributes']:
                    epg_dict[epg_dn]['encapflood'] = str(epg['fvAEPg']['attributes']['floodOnEncap'])
                epg_dict[epg_dn]['descr'] = str(epg['fvAEPg']['attributes']['descr'])
                epg_dict[epg_dn]['context'] = ''
                epg_dict[epg_dn]['bd'] = ''
                epg_dict[epg_dn]['bd_subnet'] = []
                epg_dict[epg_dn]['bd_tenant'] = ''
                epg_dict[epg_dn]['ctx'] = ''
                epg_dict[epg_dn]['ctx_tenant'] = ''
                epg_dict[epg_dn]['vlan'] = []
                epg_dict[epg_dn]['encap'] = []
                epg_dict[epg_dn]['path'] = []
                epg_dict[epg_dn]['domain'] = []
                if 'children' in epg['fvAEPg']:
                    epg_children = epg['fvAEPg']['children']
                    for child in epg_children:
                        if 'fvRsPathAtt' in child:
                            epg_dict[epg_dn]['path'].append(str(child['fvRsPathAtt']['attributes']['tDn']))
                            encap = str(child['fvRsPathAtt']['attributes']['encap'])
                            if encap not in epg_dict[epg_dn]['vlan']: epg_dict[epg_dn]['vlan'].append(encap)
                        if 'fvRsDomAtt' in child:
                            epg_dict[epg_dn]['domain'].append(str(child['fvRsDomAtt']['attributes']['tDn']))

        get_url = self.apic + '/api/class/fvAEPg.json?' \
                              'rsp-subtree=children&rsp-subtree-class=fvCEp,fvRsBd'
        resp = self.mysession.get(get_url, verify=False)
        epgs = json.loads(resp.text)['imdata']
        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                if 'children' in epg['fvAEPg']:
                    epg_children = epg['fvAEPg']['children']
                    for child in epg_children:
                        if 'fvRsBd' in child:
                            bd_dn = str(child['fvRsBd']['attributes']['tDn'])
                            if bd_dn in bd_dict.keys():
                                # if bd_dn:
                                epg_dict[epg_dn]['bd'] = str(child['fvRsBd']['attributes']['tnFvBDName'])
                                epg_dict[epg_dn]['bd_subnet'] = bd_dict[bd_dn]['subnet']
                                epg_dict[epg_dn]['bd_tenant'] = str(bd_dn.split('uni/tn-')[1].split('/')[0])
                                context_dn = str(bd_dict[bd_dn]['context_dn'])
                                if '/ctx-' in context_dn:
                                    epg_dict[epg_dn]['ctx'] = str(context_dn.split('/ctx-')[1])
                                    epg_dict[epg_dn]['ctx_tenant'] = str(context_dn.split('uni/tn-')[1].split('/')[0])
                        if 'fvCEp' in child:
                            encap = str(child['fvCEp']['attributes']['encap'])
                            if encap not in epg_dict[epg_dn]['encap']: epg_dict[epg_dn]['encap'].append(encap)

        return epg_dict

    def get_contract_name_dict(self):
        contract_name_dict = {}

        get_url = self.apic + '/api/class/vzBrCP.json'

        resp = self.mysession.get(get_url, verify=False)

        contracts = json.loads(resp.text)['imdata']

        # print contracts

        for contract in contracts:
            if 'vzBrCP' in contract:
                contract_dn = str(contract['vzBrCP']['attributes']['dn'])
                contract_name_dict[contract_dn] = {}
                contract_name_dict[contract_dn]['name'] = str(contract['vzBrCP']['attributes']['name'])
                contract_name_dict[contract_dn]['tenant'] = str(contract_dn.split('uni/tn-')[1].split('/')[0])
                contract_name_dict[contract_dn]['scope'] = str(contract['vzBrCP']['attributes']['scope'])
        return contract_name_dict

    def get_contract_dict(self):
        contract_dict = {}
        cpif_dict = {}

        get_url = self.apic + '/api/class/vzBrCP.json?rsp-subtree=full&rsp-subtree-class=vzSubj,vzRsSubjFiltAtt,' \
                              'vzOutTerm,vzInTerm,vzRsSubjGraphAtt'

        resp = self.mysession.get(get_url, verify=False)

        contracts = json.loads(resp.text)['imdata']

        # print contracts

        for contract in contracts:
            if 'vzBrCP' in contract:
                contract_dn = str(contract['vzBrCP']['attributes']['dn'])
                contract_dict[contract_dn] = {}
                contract_dict[contract_dn]['name'] = str(contract['vzBrCP']['attributes']['name'])
                contract_dict[contract_dn]['tenant'] = str(contract_dn.split('uni/tn-')[1].split('/')[0])
                contract_dict[contract_dn]['scope'] = str(contract['vzBrCP']['attributes']['scope'])
                contract_dict[contract_dn]['filter'] = []
                contract_dict[contract_dn]['ports'] = []
                contract_dict[contract_dn]['pepg'] = []
                contract_dict[contract_dn]['cepg'] = []
                contract_dict[contract_dn]['dir'] = []
                contract_dict[contract_dn]['servicegraph'] = ''
                contract_dict[contract_dn]['sg'] = ''

                if 'children' in contract['vzBrCP']:
                    contract_subjects = contract['vzBrCP']['children']
                    for contract_subject in contract_subjects:
                        revFltPorts = str(contract_subject['vzSubj']['attributes']['revFltPorts'])
                        if 'children' in contract_subject['vzSubj']:
                            filters = contract_subject['vzSubj']['children']
                            for filter in filters:
                                if 'vzRsSubjFiltAtt' in filter:
                                    filter_tdn = str(filter['vzRsSubjFiltAtt']['attributes']['tDn'])
                                    contract_dict[contract_dn]['filter'].append(filter_tdn)
                                    filter_name = str(filter['vzRsSubjFiltAtt']['attributes']['tnVzFilterName'])
                                    if revFltPorts == 'yes': filter_dir = 'bidir_reverse_port'
                                    else: filter_dir = 'bidir_same_port'
                                    contract_dict[contract_dn]['ports'].append(filter_name)
                                    contract_dict[contract_dn]['dir'].append(filter_dir)
                                if 'vzOutTerm' in filter:
                                    if 'children' in filter['vzOutTerm']:
                                        outfilters = filter['vzOutTerm']['children']
                                        for filter in outfilters:
                                            filter_tdn = str(filter['vzRsFiltAtt']['attributes']['tDn'])
                                            contract_dict[contract_dn]['filter'].append(filter_tdn)
                                            filter_name = str(filter['vzRsFiltAtt']['attributes']['tnVzFilterName'])
                                            filter_dir = 'unidir_out'
                                            contract_dict[contract_dn]['ports'].append(filter_name)
                                            contract_dict[contract_dn]['dir'].append(filter_dir)
                                if 'vzInTerm' in filter:
                                    if 'children' in filter['vzInTerm']:
                                        infilters = filter['vzInTerm']['children']
                                        for filter in infilters:
                                            filter_tdn = str(filter['vzRsFiltAtt']['attributes']['tDn'])
                                            contract_dict[contract_dn]['filter'].append(filter_tdn)
                                            filter_name = str(filter['vzRsFiltAtt']['attributes']['tnVzFilterName'])
                                            filter_dir = 'unidir_in'
                                            contract_dict[contract_dn]['ports'].append(filter_name)
                                            contract_dict[contract_dn]['dir'].append(filter_dir)
                                if 'vzRsSubjGraphAtt' in filter:
                                    contract_dict[contract_dn]['servicegraph'] = \
                                        str(filter['vzRsSubjGraphAtt']['attributes']['tDn'])
                                    contract_dict[contract_dn]['sg'] = \
                                        str(filter['vzRsSubjGraphAtt']['attributes']['tnVnsAbsGraphName'])

        # print contract_dict
        get_url = self.apic + '/api/class/vzCPIf.json?rsp-subtree=full&rsp-subtree-class=vzRsIf'

        resp = self.mysession.get(get_url, verify=False)

        cpifs = json.loads(resp.text)['imdata']
        #print cpifs
        for cpif in cpifs:
            if 'vzCPIf' in cpif:
                cpif_dn = str(cpif['vzCPIf']['attributes']['dn'])
                cpif_dict[cpif_dn] = ''
                if 'children' in cpif['vzCPIf']:
                    cpif_children = cpif['vzCPIf']['children']
                    for child in cpif_children:
                        if 'vzRsIf' in child:
                            contract_dn = str(child['vzRsIf']['attributes']['tDn'])
                            if str(child['vzRsIf']['attributes']['state']) == 'formed':
                                if contract_dn: cpif_dict[cpif_dn] = contract_dn

        # print cpif_dict
        get_url = self.apic + '/api/class/vzAny.json?rsp-subtree=full&rsp-subtree-class=vzRsAnyToProv,vzRsAnyToCons,' \
                              'vzRsAnyToConsIf'

        resp = self.mysession.get(get_url, verify=False)

        vzanys = json.loads(resp.text)['imdata']

        #print vzanys
        for vzany in vzanys:
            if 'vzAny' in vzany:
                vzany_dn = str(vzany['vzAny']['attributes']['dn'])
                if 'children' in vzany['vzAny']:
                    vzany_children = vzany['vzAny']['children']
                    for child in vzany_children:
                        if 'vzRsAnyToProv' in child:
                            contract_dn = str(child['vzRsAnyToProv']['attributes']['tDn'])
                            if contract_dn: contract_dict[contract_dn]['pepg'].append(vzany_dn)
                        if 'vzRsAnyToCons' in child:
                            contract_dn = str(child['vzRsAnyToCons']['attributes']['tDn'])
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(vzany_dn)
                        if 'vzRsAnyToConsIf' in child:
                            contract_dn = str(child['vzRsAnyToConsIf']['attributes']['tDn'])
                            contract_dn = str(cpif_dict[contract_dn])
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(vzany_dn)
        #print cpif_dict
        get_url = self.apic + '/api/class/fvAEPg.json?rsp-subtree=full&rsp-subtree-class=fvRsProv,fvRsCons'

        resp = self.mysession.get(get_url, verify=False)

        epgs = json.loads(resp.text)['imdata']
        # print epgs

        for epg in epgs:
            if 'fvAEPg' in epg:
                epg_dn = str(epg['fvAEPg']['attributes']['dn'])
                if 'children' in epg['fvAEPg']:
                    epg_children = epg['fvAEPg']['children']
                    for child in epg_children:
                        if 'fvRsProv' in child:
                            contract_dn = child['fvRsProv']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['pepg'].append(epg_dn)
                        if 'fvRsCons' in child:
                            contract_dn = child['fvRsCons']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(epg_dn)

        get_url = self.apic + '/api/class/l3extInstP.json?rsp-subtree=full&rsp-subtree-class=fvRsProv,fvRsCons'

        resp = self.mysession.get(get_url, verify=False)

        l3exts = json.loads(resp.text)['imdata']

        # print l3exts
        for l3ext in l3exts:
            if 'l3extInstP' in l3ext:
                l3ext_dn = l3ext['l3extInstP']['attributes']['dn']
                l3ext_tenant = l3ext_dn.split('uni/tn-')[1].split('/')[0]
                l3ext_name = l3ext['l3extInstP']['attributes']['name']
                if 'children' in l3ext['l3extInstP']:
                    l3ext_children = l3ext['l3extInstP']['children']
                    for child in l3ext_children:
                        if 'fvRsProv' in child:
                            contract_dn = child['fvRsProv']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['pepg'].append(l3ext_dn)
                        if 'fvRsCons' in child:
                            contract_dn = child['fvRsCons']['attributes']['tDn']
                            if contract_dn: contract_dict[contract_dn]['cepg'].append(l3ext_dn)

        return contract_dict

    def get_filter_dict(self):
        filter_dict = {}
        get_url = self.apic + '/api/class/vzFilter.json?rsp-subtree=full&rsp-subtree-class=vzEntry'

        resp = self.mysession.get(get_url, verify=False)

        filters = json.loads(resp.text)['imdata']

        # print filters

        for filter in filters:
            if 'vzFilter' in filter:
                filter_dn = str(filter['vzFilter']['attributes']['dn'])
                filter_dict[filter_dn] = {}
                filter_dict[filter_dn]['name'] = str(filter['vzFilter']['attributes']['name'])
                if 'children' in filter['vzFilter']:
                    filter_dict[filter_dn]['entries'] = filter['vzFilter']['children']
                else:
                    filter_dict[filter_dn]['entries'] = []
        return filter_dict

    def get_interface_dict(self):
        intf_dict = {}
        node_dict = {}
        fex_dict = {}
        switch_dict = self.get_switch_dict()

        # get nodes
        get_url = self.apic + '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraNodeP'

        resp = self.mysession.get(get_url, verify=False)

        infra = json.loads(resp.text)['imdata'][0]

        # print infra

        if 'children' in infra['infraInfra']:
            nodeps = infra['infraInfra']['children']
            for nodep in nodeps:
                if 'infraNodeP' in nodep:
                    node_name = str(nodep['infraNodeP']['attributes']['name'])
                    nodes = []
                    if 'children' in nodep['infraNodeP']:
                        nodep_children = nodep['infraNodeP']['children']
                        for leafs in nodep_children:
                            if 'infraLeafS' in leafs:
                                if 'children' in leafs['infraLeafS']:
                                    leafs_children = leafs['infraLeafS']['children']
                                    for nodeblk in leafs_children:
                                        if 'infraNodeBlk' in nodeblk:
                                            node1 = str(nodeblk['infraNodeBlk']['attributes']['from_'])
                                            node2 = str(nodeblk['infraNodeBlk']['attributes']['to_'])
                                            for node in range(int(node1), int(node2) + 1, 1):
                                                nodes.append(str(node))
                        for accportp in nodep_children:
                            if 'infraRsAccPortP' in accportp:
                                accportp_rn = str(accportp['infraRsAccPortP']['attributes']['tDn'].split('/')[2])
                                node_dict[accportp_rn] = nodes

        # get interfaces
        get_url = self.apic + '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraAccPortP'

        resp = self.mysession.get(get_url, verify=False)

        infra = json.loads(resp.text)['imdata'][0]

        # print infra

        if 'children' in infra['infraInfra']:
            accportps = infra['infraInfra']['children']
            for accportp in accportps:
                if 'infraAccPortP' in accportp:
                    accportp_rn = str(accportp['infraAccPortP']['attributes']['rn'])
                    accportp_name = str(accportp['infraAccPortP']['attributes']['name'])
                    if accportp_rn in node_dict.keys():
                        intf_nodes = node_dict[accportp_rn]
                    else:
                        continue
                    if 'children' in accportp['infraAccPortP']:
                        accportp_children = accportp['infraAccPortP']['children']
                        for hports in accportp_children:
                            if 'infraHPortS' in hports:
                                ipg_name = ''
                                ipg_type = ''
                                fex_id = ''
                                hport_name = hports['infraHPortS']['attributes']['name']
                                if 'children' in hports['infraHPortS']:
                                    hports_children = hports['infraHPortS']['children']
                                    for accbasegrp in hports_children:
                                        if 'infraRsAccBaseGrp' in accbasegrp:
                                            if str(accbasegrp['infraRsAccBaseGrp']['attributes']['state']) == 'formed':
                                                accbasegrp_dn = str(
                                                    accbasegrp['infraRsAccBaseGrp']['attributes']['tDn'])
                                                accbasegrp_rn = str(
                                                    accbasegrp['infraRsAccBaseGrp']['attributes']['tDn'].split('/')[2])
                                                accport_tcl = str(accbasegrp['infraRsAccBaseGrp']['attributes']['tCl'])
                                                if accport_tcl == 'infraAccBndlGrp':
                                                    ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accbundle-')[1]
                                                    ipg_type = 'accbundle'
                                                elif accport_tcl == 'infraAccPortGrp':
                                                    ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accportgrp-')[1]
                                                    ipg_type = 'accportgrp'
                                                elif accport_tcl == 'infraFexBndlGrp':
                                                    fex_id = str(accbasegrp['infraRsAccBaseGrp']['attributes']['fexId'])
                                                    fex_dict[accbasegrp_rn] = fex_id
                                                    node_dict[accbasegrp_rn] = intf_nodes
                                                    ipg_name = str(
                                                        accbasegrp_dn.split('/fexprof-')[1].split('/')[0]) + '/' + str(
                                                        accbasegrp_dn.split('/fexbundle-')[1])
                                                    ipg_type = 'fexbundle'
                                    for portblk in hports_children:
                                        if 'infraPortBlk' in portblk:
                                            port1 = str(portblk['infraPortBlk']['attributes']['fromPort'])
                                            port2 = str(portblk['infraPortBlk']['attributes']['toPort'])
                                            mod = str(portblk['infraPortBlk']['attributes']['fromCard'])
                                            descr = str(portblk['infraPortBlk']['attributes']['descr'])
                                            portblk_name = str(portblk['infraPortBlk']['attributes']['name'])
                                            portblk_port = [str(port) for port in range(int(port1), int(port2) + 1, 1)]
                                            for port in portblk_port:
                                                for node in intf_nodes:
                                                    if node in switch_dict.keys():
                                                        switch_name = switch_dict[node]['name']
                                                    else:
                                                        switch_name = ''
                                                    intf_name = node + '-eth' + mod + '/' + str(port)
                                                    intf_dict[intf_name] = {}
                                                    intf_dict[intf_name]['name'] = intf_name
                                                    intf_dict[intf_name]['descr'] = descr
                                                    intf_dict[intf_name]['switch'] = switch_name
                                                    intf_dict[intf_name]['node'] = node
                                                    intf_dict[intf_name]['fexid'] = fex_id
                                                    intf_dict[intf_name]['ipg'] = ipg_name
                                                    intf_dict[intf_name]['leaf_profile'] = accportp_name
                                                    intf_dict[intf_name]['selector'] = hport_name
                                                    intf_dict[intf_name]['blockname'] = portblk_name
                                                    intf_dict[intf_name]['blockport'] = portblk_port
                                                    intf_dict[intf_name]['type'] = ipg_type
                                                    intf_dict[intf_name]['aep'] = ''
                                                    intf_dict[intf_name]['domain'] = []
                                                    intf_dict[intf_name]['poolname'] = []
                                                    intf_dict[intf_name]['domain_type'] = []
                                                    intf_dict[intf_name]['poolvlan'] = []
                                                    intf_dict[intf_name]['mode'] = []
                                                    intf_dict[intf_name]['encap'] = []
                                                    intf_dict[intf_name]['epg'] = []
                                                    intf_dict[intf_name]['bd'] = []
        # get fex interfaces
        get_url = self.apic + '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraFexP'
        resp = self.mysession.get(get_url, verify=False)
        infra = json.loads(resp.text)['imdata'][0]

        # print infra
        if 'children' in infra['infraInfra']:
            accportps = infra['infraInfra']['children']
            for accportp in accportps:
                if 'infraFexP' in accportp:
                    accportp_rn = str(accportp['infraFexP']['attributes']['rn'])
                    accportp_name = str(accportp['infraFexP']['attributes']['name'])
                    # accportp_dn = 'uni/infra/' + accportp_rn
                    if accportp_rn in node_dict.keys():
                        intf_nodes = node_dict[accportp_rn]
                    else:
                        continue
                    if 'children' in accportp['infraFexP']:
                        accportp_children = accportp['infraFexP']['children']
                        for hports in accportp_children:
                            if 'infraHPortS' in hports:
                                hport_name = hports['infraHPortS']['attributes']['name']
                                if 'children' in hports['infraHPortS']:
                                    hports_children = hports['infraHPortS']['children']
                                    ipg_name = ''
                                    fex_id = ''
                                    for accbasegrp in hports_children:
                                        if 'infraRsAccBaseGrp' in accbasegrp:
                                            accbasegrp_dn = str(accbasegrp['infraRsAccBaseGrp']['attributes']['tDn'])
                                            accport_tcl = str(accbasegrp['infraRsAccBaseGrp']['attributes']['tCl'])
                                            fex_id = str(accbasegrp['infraRsAccBaseGrp']['attributes']['fexId'])
                                            if accport_tcl == 'infraAccBndlGrp':
                                                ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accbundle-')[1]
                                            elif accport_tcl == 'infraAccPortGrp':
                                                ipg_name = accbasegrp_dn.split('uni/infra/funcprof/accportgrp-')[1]
                                    for portblk in hports_children:
                                        if 'infraPortBlk' in portblk:
                                            port1 = str(portblk['infraPortBlk']['attributes']['fromPort'])
                                            port2 = str(portblk['infraPortBlk']['attributes']['toPort'])
                                            mod = str(portblk['infraPortBlk']['attributes']['fromCard'])
                                            descr = str(portblk['infraPortBlk']['attributes']['descr'])
                                            portblk_name = str(portblk['infraPortBlk']['attributes']['name'])
                                            portblk_port = [str(port) for port in range(int(port1), int(port2) + 1, 1)]
                                            if accportp_rn in node_dict.keys():
                                                fex = fex_dict[accportp_rn]
                                                for port in portblk_port:
                                                    for node in intf_nodes:
                                                        if node in switch_dict.keys():
                                                            switch_name = switch_dict[node]['name']
                                                        else:
                                                            switch_name = ''
                                                        intf_name = node + '-eth' + fex + '/' + mod + '/' + str(port)
                                                        intf_dict[intf_name] = {}
                                                        intf_dict[intf_name]['name'] = intf_name
                                                        intf_dict[intf_name]['descr'] = descr
                                                        intf_dict[intf_name]['switch'] = switch_name
                                                        intf_dict[intf_name]['node'] = node
                                                        intf_dict[intf_name]['fexid'] = fex_id
                                                        intf_dict[intf_name]['ipg'] = ipg_name
                                                        intf_dict[intf_name]['leaf_profile'] = accportp_name
                                                        intf_dict[intf_name]['selector'] = hport_name
                                                        intf_dict[intf_name]['blockname'] = portblk_name
                                                        intf_dict[intf_name]['blockport'] = portblk_port
                                                        intf_dict[intf_name]['type'] = ''
                                                        intf_dict[intf_name]['aep'] = ''
                                                        intf_dict[intf_name]['domain'] = []
                                                        intf_dict[intf_name]['poolname'] = []
                                                        intf_dict[intf_name]['domain_type'] = []
                                                        intf_dict[intf_name]['poolvlan'] = []
                                                        intf_dict[intf_name]['mode'] = []
                                                        intf_dict[intf_name]['encap'] = []
                                                        intf_dict[intf_name]['epg'] = []
                                                        intf_dict[intf_name]['bd'] = []
        return intf_dict

    def get_intf_dict(self):
        intf_dict = self.get_interface_dict()
        path_dict = self.get_path_dict()
        ipg_dict = self.get_ipg_dict('basic')
        intf_list = []
        for intf_name in intf_dict.keys():
            nodenum = int(intf_dict[intf_name]['name'].split('-')[0])
            portnum = []
            for pnum in intf_dict[intf_name]['name'].split('eth')[1].split('/'):
                if len(pnum) < 2:
                    pnum = '0' + str(pnum)
                portnum.append(pnum)
            portnum = int(''.join(portnum))
            intf_list.append([nodenum, portnum, intf_dict[intf_name]['name']])

        for intf_names in sorted(intf_list):
            intf_name = intf_names[2]
            ipg_name = intf_dict[intf_name]['ipg']
            if ipg_name in ipg_dict.keys():
                intf_dict[intf_name]['type'] = ipg_dict[ipg_name]['type']
                intf_dict[intf_name]['aep'] = ipg_dict[ipg_name]['aep']
                intf_dict[intf_name]['domain'] = ipg_dict[ipg_name]['domain']
                intf_dict[intf_name]['poolname'] = ipg_dict[ipg_name]['poolname']
                intf_dict[intf_name]['domain_type'] = ipg_dict[ipg_name]['domain_type']
                intf_dict[intf_name]['poolvlan'] = ipg_dict[ipg_name]['poolvlan']

            if intf_name in path_dict.keys() or ipg_name in path_dict.keys():

                if intf_name in path_dict.keys():
                    intf_dict[intf_name]['mode'] = path_dict[intf_name]['mode']
                    intf_dict[intf_name]['encap'] = path_dict[intf_name]['encap']
                    intf_dict[intf_name]['epg'] = path_dict[intf_name]['epg']
                    intf_dict[intf_name]['epg_descr'] = path_dict[intf_name]['epg_descr']
                    intf_dict[intf_name]['bd'] = path_dict[intf_name]['bd']

                elif ipg_name in path_dict.keys():
                    intf_dict[intf_name]['mode'] = path_dict[ipg_name]['mode']
                    intf_dict[intf_name]['encap'] = path_dict[ipg_name]['encap']
                    intf_dict[intf_name]['epg'] = path_dict[ipg_name]['epg']
                    intf_dict[intf_name]['epg_descr'] = path_dict[ipg_name]['epg_descr']
                    intf_dict[intf_name]['bd'] = path_dict[ipg_name]['bd']
        return intf_dict

    def get_ipg_name_dict(self):
        ipg_name_dict = {}

        get_url = self.apic + '/api/node/class/infraFuncP.json?rsp-subtree=children&' \
                              'rsp-subtree-class=infraAccPortGrp,infraAccBndlGrp'
        resp = self.mysession.get(get_url, verify=False)
        funcp = json.loads(resp.text)['imdata'][0]
        if 'children' in funcp['infraFuncP']:
            ipgs = funcp['infraFuncP']['children']
            for ipg in ipgs:
                if 'infraAccPortGrp' in ipg or "infraAccBndlGrp" in ipg:
                    ipg_name = str(ipg[ipg.keys()[0]]['attributes']['name'])
                    ipg_rn = str(ipg[ipg.keys()[0]]['attributes']['rn'])
                    ipg_name_dict[ipg_name] = {}
                    ipg_name_dict[ipg_name]['name'] = str(ipg[ipg.keys()[0]]['attributes']['name'])
                    ipg_name_dict[ipg_name]['descr'] = str(ipg[ipg.keys()[0]]['attributes']['descr'])
                    ipg_type = str(ipg_rn.split('-')[0])
                    if 'lagT' in ipg[ipg.keys()[0]]['attributes']:
                        ipg_name_dict[ipg_name]['type'] = ipg_type + '-' + str(ipg[ipg.keys()[0]]['attributes']['lagT'])
                    else:
                        ipg_name_dict[ipg_name]['type'] = ipg_type
        return ipg_name_dict

    def get_ipg_dict(self, limit=None):
        ipg_dict = {}

        # get ipgs
        get_url = self.apic + '/api/node/class/infraFuncP.json?query-target=self&rsp-subtree=full&' \
                              'rsp-subtree-class=infraRsAttEntP,infraRsCdpIfPol,infraRsHIfPol,infraRsLldpIfPol,infraRsLacpPol,infraRsMcpIfPol,infraRsL2IfPol'

        resp = self.mysession.get(get_url, verify=False)

        funcp = json.loads(resp.text)['imdata'][0]

        # print funcp

        if 'children' in funcp['infraFuncP']:
            ipgs = funcp['infraFuncP']['children']
            for ipg in ipgs:
                ipg_lacp = 'N/A'
                ipg_aep = ''
                ipg_speed = ''
                ipg_cdp = ''
                ipg_lldp = ''
                ipg_mcp = ''
                ipg_l2int = ''

                if 'infraAccPortGrp' in ipg or "infraAccBndlGrp" in ipg:
                    ipg_name = str(ipg[ipg.keys()[0]]['attributes']['name'])
                    ipg_descr = str(ipg[ipg.keys()[0]]['attributes']['descr'])
                    ipg_dict[ipg_name] = {}
                    ipg_rn = str(ipg[ipg.keys()[0]]['attributes']['rn'])
                    ipg_type = str(ipg_rn.split('-')[0])
                    if 'lagT' in ipg[ipg.keys()[0]]['attributes']: ipg_type = ipg_type + '-' + str(
                        ipg[ipg.keys()[0]]['attributes']['lagT'])

                    if 'children' in ipg[ipg.keys()[0]]:
                        ipg_children = ipg[ipg.keys()[0]]['children']
                        for child in ipg_children:
                            child_dn = child[child.keys()[0]]['attributes']['tDn']
                            if 'uni/infra/lacplagp-' in child_dn: ipg_lacp = str(
                                child_dn.split('uni/infra/lacplagp-')[1])
                            if 'uni/infra/attentp-' in child_dn: ipg_aep = str(child_dn.split('uni/infra/attentp-')[1])
                            if 'uni/infra/hintfpol-' in child_dn: ipg_speed = str(
                                child_dn.split('uni/infra/hintfpol-')[1])
                            if 'uni/infra/cdpIfP-' in child_dn: ipg_cdp = str(child_dn.split('uni/infra/cdpIfP-')[1])
                            if 'uni/infra/lldpIfP-' in child_dn: ipg_lldp = str(child_dn.split('uni/infra/lldpIfP-')[1])
                            if 'uni/infra/mcpIfP-' in child_dn: ipg_mcp = str(child_dn.split('uni/infra/mcpIfP-')[1])
                            if 'uni/infra/l2IfP-' in child_dn: ipg_l2int = str(child_dn.split('uni/infra/l2IfP-')[1])
                        ipg_dict[ipg_name]['name'] = ipg_name
                        ipg_dict[ipg_name]['descr'] = ipg_descr
                        ipg_dict[ipg_name]['lacp'] = ipg_lacp
                        ipg_dict[ipg_name]['aep'] = ipg_aep
                        ipg_dict[ipg_name]['speed'] = ipg_speed
                        ipg_dict[ipg_name]['cdp'] = ipg_cdp
                        ipg_dict[ipg_name]['lldp'] = ipg_lldp
                        ipg_dict[ipg_name]['type'] = ipg_type
                        ipg_dict[ipg_name]['mcp'] = ipg_mcp
                        ipg_dict[ipg_name]['l2int'] = ipg_l2int
                        ipg_dict[ipg_name]['rn'] = ipg_rn
                        ipg_dict[ipg_name]['interfaces'] = []
                        ipg_dict[ipg_name]['intf_descr'] = []
                        ipg_dict[ipg_name]['nodes'] = []
                        ipg_dict[ipg_name]['switches'] = []
                        ipg_dict[ipg_name]['ipg_nodes'] = []
                        ipg_dict[ipg_name]['ipg_switches'] = []
                        ipg_dict[ipg_name]['domain'] = []
                        ipg_dict[ipg_name]['poolname'] = []
                        ipg_dict[ipg_name]['domain_type'] = []
                        ipg_dict[ipg_name]['poolvlan'] = []

        # add domain information to ipg_dict

        aep_dict = self.get_aep_dict()
        for aep_name in aep_dict.keys():
            ipg_names = aep_dict[aep_name]['ipg']
            for ipg_name in ipg_names:
                if ipg_name in ipg_dict.keys():
                    ipg_dict[ipg_name]['domain'] = aep_dict[aep_name]['domain']
                    ipg_dict[ipg_name]['poolname'] = aep_dict[aep_name]['poolname']
                    ipg_dict[ipg_name]['domain_type'] = aep_dict[aep_name]['domain_type']
                    ipg_dict[ipg_name]['poolvlan'] = aep_dict[aep_name]['poolvlan']

        # add interfaces to ipg_dict
        if limit is None:
            intf_dict = self.get_interface_dict()
            for intf in intf_dict.keys():
                ipg_name = intf_dict[intf]['ipg']
                if ipg_name in ipg_dict.keys():
                    ipg_dict[ipg_name]['interfaces'].append(intf_dict[intf]['name'])
                    ipg_dict[ipg_name]['intf_descr'].append(intf_dict[intf]['descr'])
                    ipg_dict[ipg_name]['nodes'].append(intf_dict[intf]['node'])
                    ipg_dict[ipg_name]['switches'].append(intf_dict[intf]['switch'])
                    if intf_dict[intf]['node'] not in ipg_dict[ipg_name]['ipg_nodes']:
                        ipg_dict[ipg_name]['ipg_nodes'].append(intf_dict[intf]['node'])
                    if intf_dict[intf]['switch'] not in ipg_dict[ipg_name]['ipg_switches']:
                        ipg_dict[ipg_name]['ipg_switches'].append(intf_dict[intf]['switch'])

        return ipg_dict

    def get_fex_dict(self):
        fex_dict = {}
        intf_dict = self.get_interface_dict()
        # get ipgs
        get_url = self.apic + '/api/node/class/infraFexP.json?query-target=self&rsp-subtree=full&' \
                              'rsp-subtree-class=infraFexBndlGrp'

        resp = self.mysession.get(get_url, verify=False)

        fexps = json.loads(resp.text)['imdata']

        for fexp in fexps:
            fexp_name = str(fexp['infraFexP']['attributes']['name'])
            if 'children' in fexp['infraFexP']:
                fexs = fexp['infraFexP']['children']
                for fex in fexs:
                    if 'infraFexBndlGrp' in fex:
                        fex_name = fexp_name + '/' + str(fex['infraFexBndlGrp']['attributes']['name'])
                        fex_descr = str(fex['infraFexBndlGrp']['attributes']['descr'])
                        fex_dict[fex_name] = {}
                        fex_dict[fex_name]['name'] = fexp_name
                        fex_dict[fex_name]['ipg'] = str(fex['infraFexBndlGrp']['attributes']['name'])
                        fex_dict[fex_name]['descr'] = fex_descr
                        fex_dict[fex_name]['type'] = 'fexbundle'
                        fex_dict[fex_name]['interfaces'] = []
                        fex_dict[fex_name]['intf_descr'] = []
                        fex_dict[fex_name]['fexid'] = []
                        fex_dict[fex_name]['nodes'] = []
                        fex_dict[fex_name]['switches'] = []

        for intf in intf_dict.keys():
            fex_name = intf_dict[intf]['ipg']
            if fex_name in fex_dict.keys():
                fex_dict[fex_name]['interfaces'].append(intf_dict[intf]['name'])
                fex_dict[fex_name]['intf_descr'].append(intf_dict[intf]['descr'])
                if intf_dict[intf]['fexid'] not in fex_dict[fex_name]['fexid']:
                    fex_dict[fex_name]['fexid'].append(intf_dict[intf]['fexid'])
                if intf_dict[intf]['node'] not in fex_dict[fex_name]['nodes']:
                    fex_dict[fex_name]['nodes'].append(intf_dict[intf]['node'])
                if intf_dict[intf]['switch'] not in fex_dict[fex_name]['switches']:
                    fex_dict[fex_name]['switches'].append(intf_dict[intf]['switch'])

        return fex_dict

    def get_path_dict(self):
        path_dict = {}
        rsbd_dict = self.get_rsbd_dict()
        epg_name_dict = self.get_epg_name_dict()

        get_url = self.apic + '/api/class/fvIfConn.json'

        resp = self.mysession.get(get_url, verify=False)

        paths = json.loads(resp.text)['imdata']
        # print paths
        for path in paths:
            if "fvIfConn" in path:
                path_name = ''
                path_dn = str(path['fvIfConn']['attributes']['dn'])
                path_mode = str(path['fvIfConn']['attributes']['mode'])
                path_encap = str(path['fvIfConn']['attributes']['encap'])
                path_imedcy = str(path['fvIfConn']['attributes']['resImedcy'])
                path_node = str(path_dn.split('/node-')[1].split('/')[0])
                if '/stpathatt-' in path_dn:
                    path_name = str(path_dn.split('/stpathatt-[')[1].split(']')[0])
                    if len(path_name.split('/')) > 1:
                        path_name = path_node + '-' + 'eth' + str(path_dn.split('/stpathatt-[eth')[1].split(']')[0])
                elif '/extstpathatt-' in path_dn:
                    path_name = str(path_dn.split('/extstpathatt-[')[1].split(']')[0])
                    if len(path_name.split('/')) > 1:
                        path_fex = 'eth' + str(path_dn.split(']-extchid-')[1].split('/')[0]) + '/'
                        path_name = path_node + '-' + path_fex + str(
                            path_dn.split('/extstpathatt-[eth')[1].split(']')[0])
                elif '/dyatt-' in path_dn:
                    path_name = str(path_dn.split('/pathep-[')[1].split(']')[0])
                    if len(path_name.split('/')) > 1:
                        path_name = path_node + '-' + 'eth' + str(path_dn.split('/pathep-[eth')[1].split(']')[0])
                if path_name not in path_dict.keys():
                    path_dict[path_name] = {}
                    path_dict[path_name]['name'] = path_name
                    path_dict[path_name]['descr'] = ''
                    path_dict[path_name]['dn'] = []
                    path_dict[path_name]['mode'] = []
                    path_dict[path_name]['encap'] = []
                    path_dict[path_name]['epg'] = []
                    path_dict[path_name]['epg_descr'] = []
                    path_dict[path_name]['bd'] = []
                if 'unknown' == path_encap: path_encap = 'N/A'
                path_dict[path_name]['dn'].append(path_dn)

                if 'uni/epp/fv-' in path_dn and '/ap-' in path_dn and '/epg-' in path_dn:
                    path_locale = str(path_dn.split('uni/epp/fv-[')[1].split(']')[0])
                    path_dict[path_name]['mode'].append(path_mode)
                    path_dict[path_name]['encap'].append(path_encap)
                    path_dict[path_name]['epg'].append(path_locale)
                    if path_locale in epg_name_dict.keys():
                        path_dict[path_name]['epg_descr'].append(epg_name_dict[path_locale]['descr'])
                    else:
                        path_dict[path_name]['epg_descr'].append('')
                    if path_locale in rsbd_dict.keys():
                        path_dict[path_name]['bd'].append(rsbd_dict[path_locale]['name'])
                    else:
                        path_dict[path_name]['bd'].append('')
                if 'uni/epp/fv-' in path_dn and '/lDevVip-' in path_dn and ']-ctx-[' in path_dn and ']-bd-[' in path_dn and '/BD-' in path_dn:
                    path_locale = str(path_dn.split('uni/epp/fv-[')[1])
                    path_dict[path_name]['mode'].append(path_mode)
                    path_dict[path_name]['encap'].append(path_encap)
                    path_dict[path_name]['epg'].append(path_locale.split('uni/ldev-[')[1].split(']')[0])
                    path_dict[path_name]['epg_descr'].append('L4_L7_Device')
                    path_bd = path_locale.split(']-bd-[')[1].split('/BD-')[1].split(']')[0]
                    path_bd_tenant = path_locale.split(']-bd-[')[1].split('/tn-')[1].split('/')[0]
                    if path_bd_tenant == 'common': path_bd = '*' + path_bd
                    path_dict[path_name]['bd'].append(path_bd)
                if 'uni/epp/rtd-' in path_dn and '/out-' in path_dn and '/instP-' in path_dn:
                    path_locale = str(path_dn.split('uni/epp/rtd-[')[1].split(']')[0])
                    path_dict[path_name]['mode'].append(path_mode)
                    path_dict[path_name]['encap'].append(path_encap)
                    path_dict[path_name]['epg'].append(path_locale)
                    path_dict[path_name]['epg_descr'].append('External_EPG')
                    path_dict[path_name]['bd'].append('N/A')
        return path_dict

    def get_vlan_dict(self):
        vlan_dict = {}
        intf_dict = self.get_intf_dict()
        ipg_dict = self.get_ipg_dict('basic')

        for intf_name in intf_dict.keys():
            for n, path_encap in enumerate(intf_dict[intf_name]['encap']):
                if path_encap not in vlan_dict.keys():
                    vlan_dict[path_encap] = {}
                    vlan_dict[path_encap]['name'] = path_encap
                    vlan_dict[path_encap]['id'] = '0'
                    vlan_dict[path_encap]['intf_descr'] = []
                    vlan_dict[path_encap]['interfaces'] = []
                    vlan_dict[path_encap]['dn'] = []
                    vlan_dict[path_encap]['mode'] = []
                    vlan_dict[path_encap]['epg'] = []
                    vlan_dict[path_encap]['epg_descr'] = []
                    vlan_dict[path_encap]['bd'] = []
                    vlan_dict[path_encap]['switch'] = []
                    vlan_dict[path_encap]['node'] = []
                    vlan_dict[path_encap]['ipg'] = []
                    vlan_dict[path_encap]['type'] = []
                    vlan_dict[path_encap]['aep'] = []
                    vlan_dict[path_encap]['domain'] = []
                    vlan_dict[path_encap]['poolname'] = []
                    vlan_dict[path_encap]['domain_type'] = []
                    vlan_dict[path_encap]['poolvlan'] = []

                if 'unknown' in path_encap: vlan_dict[path_encap]['name'] = ''
                if 'vlan-' in path_encap: vlan_dict[path_encap]['id'] = path_encap.split('vlan-')[1]
                vlan_dict[path_encap]['interfaces'].append(intf_dict[intf_name]['name'])
                vlan_dict[path_encap]['intf_descr'].append(intf_dict[intf_name]['descr'])
                vlan_dict[path_encap]['mode'].append(intf_dict[intf_name]['mode'][n])
                vlan_dict[path_encap]['epg'].append(intf_dict[intf_name]['epg'][n])
                vlan_dict[path_encap]['epg_descr'].append(intf_dict[intf_name]['epg_descr'][n])
                vlan_dict[path_encap]['bd'].append(intf_dict[intf_name]['bd'][n])
                vlan_dict[path_encap]['switch'].append(intf_dict[intf_name]['switch'])
                vlan_dict[path_encap]['node'].append(intf_dict[intf_name]['node'])
                vlan_dict[path_encap]['ipg'].append(intf_dict[intf_name]['ipg'])

                # add domain information from ipg_dict
                ipg_name = intf_dict[intf_name]['ipg']
                if ipg_name in ipg_dict.keys():
                    vlan_dict[path_encap]['aep'].append(ipg_dict[ipg_name]['aep'])
                    vlan_dict[path_encap]['domain'].extend(ipg_dict[ipg_name]['domain'])
                    vlan_dict[path_encap]['poolname'].extend(ipg_dict[ipg_name]['poolname'])
                    vlan_dict[path_encap]['domain_type'].extend(ipg_dict[ipg_name]['domain_type'])
                    vlan_dict[path_encap]['poolvlan'].extend(ipg_dict[ipg_name]['poolvlan'])
        return vlan_dict

    def get_vlanpool_name_dict(self):
        vlanpool_name_dict = {}
        get_url = self.apic + '/api/class/fvnsVlanInstP.json'
        resp = self.mysession.get(get_url, verify=False)
        vlanpools = json.loads(resp.text)['imdata']
        for pool in vlanpools:
            if "fvnsVlanInstP" in pool:
                pool_dn = str(pool['fvnsVlanInstP']['attributes']['dn'])
                vlanpool_name_dict[pool_dn] = {}
                vlanpool_name_dict[pool_dn]['name'] = str(pool['fvnsVlanInstP']['attributes']['name'])
                vlanpool_name_dict[pool_dn]['descr'] = str(pool['fvnsVlanInstP']['attributes']['descr'])
                vlanpool_name_dict[pool_dn]['type'] = str(pool['fvnsVlanInstP']['attributes']['allocMode'])
        return vlanpool_name_dict

    def get_vlanpool_dict(self):
        vlanpool_dict = {}
        get_url = self.apic + '/api/class/fvnsVlanInstP.json?rsp-subtree=full&' \
                              'rsp-subtree-class=fvnsEncapBlk,fvnsRtVlanNs'
        resp = self.mysession.get(get_url, verify=False)
        vlanpools = json.loads(resp.text)['imdata']
        for pool in vlanpools:
            if "fvnsVlanInstP" in pool:
                pool_dn = str(pool['fvnsVlanInstP']['attributes']['dn'])
                vlanpool_dict[pool_dn] = {}
                vlanpool_dict[pool_dn]['name'] = str(pool['fvnsVlanInstP']['attributes']['name'])
                vlanpool_dict[pool_dn]['descr'] = str(pool['fvnsVlanInstP']['attributes']['descr'])
                vlanpool_dict[pool_dn]['type'] = str(pool['fvnsVlanInstP']['attributes']['allocMode'])
                vlanpool_dict[pool_dn]['domain'] = []
                vlanpool_dict[pool_dn]['domain_type'] = []
                vlanpool_dict[pool_dn]['domain_dn'] = []
                vlanpool_dict[pool_dn]['vlan'] = []
                vlanpool_dict[pool_dn]['poolvlan'] = []
                vlanid_list = []
                if 'children' in pool['fvnsVlanInstP']:
                    pool_children = pool['fvnsVlanInstP']['children']
                    for child in pool_children:
                        if 'fvnsRtVlanNs' in child:
                            if str(child['fvnsRtVlanNs']['attributes']['tDn']):
                                dom_dn = str(child['fvnsRtVlanNs']['attributes']['tDn'])
                                dom_type = str(child['fvnsRtVlanNs']['attributes']['tCl'])
                                vlanpool_dict[pool_dn]['domain_dn'].append(dom_dn)
                                vlanpool_dict[pool_dn]['domain_type'].append(dom_type)
                                if 'uni/phys-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/phys-')[1])
                                elif 'uni/l2dom-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/l2dom-')[1])
                                elif 'uni/l3dom-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/l3dom-')[1])
                                elif 'uni/vmmp-VMware/dom-' in dom_dn:
                                    dom_name = str(dom_dn.split('uni/vmmp-VMware/dom-')[1])
                                else:
                                    dom_name = dom_dn
                                vlanpool_dict[pool_dn]['domain'].append(dom_name)
                        if 'fvnsEncapBlk' in child:
                            vlanid_from = int(str(child['fvnsEncapBlk']['attributes']['from']).split('vlan-')[1])
                            vlanid_to = int(str(child['fvnsEncapBlk']['attributes']['to']).split('vlan-')[1])
                            for vlanid in range(vlanid_from, vlanid_to + 1, 1):
                                    vlanid_list.append(vlanid)
                vlanpool_dict[pool_dn]['vlan'] = sorted(vlanid_list)

                #compress the vlanid_list
                vlanid_from_list = []
                vlanid_to_list = []

                vlanid_list = sorted(vlanid_list)
                for n in range(0, len(vlanid_list), 1):
                    if n == 0:
                        vlanid_from_list.append(vlanid_list[n])

                    if n != len(vlanid_list) - 1:
                        if vlanid_list[n] + 1 == vlanid_list[n + 1]:
                            continue
                        else:
                            vlanid_from_list.append(vlanid_list[n + 1])
                            vlanid_to_list.append(vlanid_list[n])
                    if n == len(vlanid_list) - 1:
                        vlanid_to_list.append(vlanid_list[n])

                vlanid_range_list = []
                for n in range(0, len(vlanid_from_list), 1):
                    if vlanid_from_list[n] == vlanid_to_list[n]:
                        vlanid_range_list.append(str(vlanid_from_list[n]))
                    else:
                        vlanid_range_list.append(
                            str(vlanid_from_list[n]) + '-' + str(vlanid_to_list[n]))
                vlanpool_dict[pool_dn]['poolvlan'] = vlanid_range_list
        return vlanpool_dict

    def get_domain_name_dict(self):
        domain_name_dict = {}
        get_url = self.apic + '/api/class/physDomP.json'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "physDomP" in domain:
                domain_dn = str(domain['physDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['physDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'physDomP'

        get_url = self.apic + '/api/class/vmmDomP.json'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "vmmDomP" in domain:
                domain_dn = str(domain['vmmDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['vmmDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'vmmDomP'

        get_url = self.apic + '/api/class/l3extDomP.json'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "l3extDomP" in domain:
                domain_dn = str(domain['l3extDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['l3extDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'l3extDomP'

        get_url = self.apic + '/api/class/l2extDomP.json'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "l2extDomP" in domain:
                domain_dn = str(domain['l2extDomP']['attributes']['dn'])
                domain_name_dict[domain_dn] = {}
                domain_name_dict[domain_dn]['name'] = str(domain['l2extDomP']['attributes']['name'])
                domain_name_dict[domain_dn]['type'] = 'l2extDomP'
        return domain_name_dict

    def get_domain_dict(self):
        domain_dict = {}
        vlanpool_dict = self.get_vlanpool_dict()
        get_url = self.apic + '/api/class/physDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "physDomP" in domain:
                domain_dn = str(domain['physDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['physDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'physDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['physDomP']:
                    domain_children = domain['physDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                        if 'infraRtDomP' in child:
                            if str(child['infraRtDomP']['attributes']['tDn']):
                                aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])

        get_url = self.apic + '/api/class/vmmDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "vmmDomP" in domain:
                domain_dn = str(domain['vmmDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['vmmDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'vmmDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['vmmDomP']:
                    domain_children = domain['vmmDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                            if 'infraRtDomP' in child:
                                if str(child['infraRtDomP']['attributes']['tDn']):
                                    aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                    domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])

        get_url = self.apic + '/api/class/l3extDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "l3extDomP" in domain:
                domain_dn = str(domain['l3extDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['l3extDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'l3extDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['l3extDomP']:
                    domain_children = domain['l3extDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                        if 'infraRtDomP' in child:
                            if str(child['infraRtDomP']['attributes']['tDn']):
                                aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])

        get_url = self.apic + '/api/class/l2extDomP.json?rsp-subtree=full&rsp-subtree-class=infraRtDomP,infraRsVlanNs'
        resp = self.mysession.get(get_url, verify=False)
        domains = json.loads(resp.text)['imdata']
        for domain in domains:
            if "l2extDomP" in domain:
                domain_dn = str(domain['l2extDomP']['attributes']['dn'])
                domain_dict[domain_dn] = {}
                domain_dict[domain_dn]['name'] = str(domain['l2extDomP']['attributes']['name'])
                domain_dict[domain_dn]['type'] = 'l2extDomP'
                domain_dict[domain_dn]['aep'] = []
                domain_dict[domain_dn]['poolname'] = ''
                domain_dict[domain_dn]['poolvlan'] = []
                domain_dict[domain_dn]['vlan'] = []
                if 'children' in domain['l2extDomP']:
                    domain_children = domain['l2extDomP']['children']
                    for child in domain_children:
                        if 'infraRsVlanNs' in child:
                            if str(child['infraRsVlanNs']['attributes']['tDn']):
                                vlanpool_dn = str(child['infraRsVlanNs']['attributes']['tDn'])
                                if vlanpool_dn in vlanpool_dict.keys():
                                    domain_dict[domain_dn]['poolname'] = vlanpool_dict[vlanpool_dn]['name']
                                    domain_dict[domain_dn]['poolvlan'] = vlanpool_dict[vlanpool_dn]['poolvlan']
                                    domain_dict[domain_dn]['vlan'] = vlanpool_dict[vlanpool_dn]['vlan']
                        if 'infraRtDomP' in child:
                            if str(child['infraRtDomP']['attributes']['tDn']):
                                aep_dn = str(child['infraRtDomP']['attributes']['tDn'])
                                domain_dict[domain_dn]['aep'].append(aep_dn.split('uni/infra/attentp-')[1])
        return domain_dict

    def get_aep_name_dict(self):
        aep_name_dict = {}
        get_url = self.apic + '/api/class/infraAttEntityP.json'
        resp = self.mysession.get(get_url, verify=False)
        aeps = json.loads(resp.text)['imdata']
        for aep in aeps:
            if "infraAttEntityP" in aep:
                aep_dn = str(aep['infraAttEntityP']['attributes']['dn'])
                aep_name_dict[aep_dn] = {}
                aep_name_dict[aep_dn]['name'] = str(aep['infraAttEntityP']['attributes']['name'])
                aep_name_dict[aep_dn]['descr'] = str(aep['infraAttEntityP']['attributes']['descr'])
        return aep_name_dict

    def get_aep_dict(self):
        aep_dict = {}
        domain_dict = self.get_domain_dict()
        get_url = self.apic + '/api/class/infraAttEntityP.json?rsp-subtree=full&' \
                              'rsp-subtree-class=infraRsDomP,infraRtAttEntP'
        resp = self.mysession.get(get_url, verify=False)
        aeps = json.loads(resp.text)['imdata']
        for aep in aeps:
            if "infraAttEntityP" in aep:
                aep_name = str(aep['infraAttEntityP']['attributes']['name'])
                aep_dict[aep_name] = {}
                aep_dict[aep_name]['name'] = str(aep['infraAttEntityP']['attributes']['name'])
                aep_dict[aep_name]['descr'] = str(aep['infraAttEntityP']['attributes']['descr'])
                aep_dict[aep_name]['domain'] = []
                aep_dict[aep_name]['domain_type'] = []
                aep_dict[aep_name]['ipg'] = []
                aep_dict[aep_name]['poolname'] = []
                aep_dict[aep_name]['poolvlan'] = []
                if 'children' in aep['infraAttEntityP']:
                    domain_children = aep['infraAttEntityP']['children']
                    for child in domain_children:
                        if 'infraRtAttEntP' in child:
                            if str(child['infraRtAttEntP']['attributes']['tDn']):
                                ipg_dn = str(child['infraRtAttEntP']['attributes']['tDn'])
                                ipg_name = ''
                                if 'uni/infra/funcprof/accbundle-' in ipg_dn: ipg_name = str(
                                    ipg_dn.split('uni/infra/funcprof/accbundle-')[1])
                                if 'uni/infra/funcprof/accportgrp-' in ipg_dn: ipg_name = str(
                                    ipg_dn.split('uni/infra/funcprof/accportgrp-')[1])
                                if aep_name in aep_dict.keys(): aep_dict[aep_name]['ipg'].append(ipg_name)
                        if 'infraRsDomP' in child:
                            if str(child['infraRsDomP']['attributes']['tDn']):
                                domain_dn = str(child['infraRsDomP']['attributes']['tDn'])
                                if domain_dn in domain_dict.keys():
                                    aep_dict[aep_name]['domain'].append(domain_dict[domain_dn]['name'])
                                    aep_dict[aep_name]['domain_type'].append(domain_dict[domain_dn]['type'])
                                    aep_dict[aep_name]['poolname'].append(domain_dict[domain_dn]['poolname'])
                                    aep_dict[aep_name]['poolvlan'].extend(domain_dict[domain_dn]['poolvlan'])
        return aep_dict

    def get_physif_dict(self):
        physif_dict = {}

        get_url = self.apic + '/api/class/l1PhysIf.json'

        resp = self.mysession.get(get_url, verify=False)
        PhysIfs = json.loads(resp.text)['imdata']
        # print PhysIfs
        for PhysIf in PhysIfs:
            if 'l1PhysIf' in PhysIf:
                port_dn = str(PhysIf['l1PhysIf']['attributes']['dn'])
                port_node = str(port_dn.split('/node-')[1].split('/')[0])
                port_name = port_node + '-' + str(PhysIf['l1PhysIf']['attributes']['id'])
                physif_dict[port_name] = {}
                physif_dict[port_name]['name'] = port_name
                physif_dict[port_name]['node'] = port_node
                physif_dict[port_name]['id'] = str(PhysIf['l1PhysIf']['attributes']['id'])
                physif_dict[port_name]['descr'] = str(PhysIf['l1PhysIf']['attributes']['descr'])
                physif_dict[port_name]['usage'] = str(PhysIf['l1PhysIf']['attributes']['usage'])
                physif_dict[port_name]['speed'] = str(PhysIf['l1PhysIf']['attributes']['speed'])
                physif_dict[port_name]['adminst'] = str(PhysIf['l1PhysIf']['attributes']['adminSt'])
        return physif_dict

    def get_port_stat_dict(self):
        port_stat_dict = {}

        get_url = self.apic + '/api/node/class/eqptIngrTotalHist5min.json'
        resp = self.mysession.get(get_url, verify=False)
        ingrs = json.loads(resp.text)['imdata']
        for ingr in ingrs:
            port = ''
            node = ''
            port_dn = ingr['eqptIngrTotalHist5min']['attributes']['dn']
            if '/node-' in port_dn: node = port_dn.split('/node-')[1].split('/')[0]
            if '/phys-[' in port_dn: port = port_dn.split('/phys-[')[1].split(']')[0]
            port_name = node + '-' + port
            if node != '' and port != '':
                if port_name not in port_stat_dict.keys():
                    port_stat_dict[port_name] = {}
                    port_stat_dict[port_name]['bytesratein'] = '0'
                    port_stat_dict[port_name]['bytesrateout'] = '0'
                    port_stat_dict[port_name]['packetin'] = '0'
                    port_stat_dict[port_name]['packetout'] = '0'
                    port_stat_dict[port_name]['portevent'] = []
                    port_stat_dict[port_name]['eventtime'] = []
                port_stat_dict[port_name]['bytesratein'] = \
                    str(int(float(ingr['eqptIngrTotalHist5min']['attributes']['bytesRateMin']) * 8))
                port_stat_dict[port_name]['packetin'] = \
                    ingr['eqptIngrTotalHist5min']['attributes']['pktsMin']

        get_url = self.apic + '/api/node/class/eqptEgrTotalHist5min.json'
        resp = self.mysession.get(get_url, verify=False)
        egrs = json.loads(resp.text)['imdata']
        for egr in egrs:
            port = ''
            node = ''
            port_dn = egr['eqptEgrTotalHist5min']['attributes']['dn']
            if '/node-' in port_dn: node = port_dn.split('/node-')[1].split('/')[0]
            if '/phys-[' in port_dn: port = port_dn.split('/phys-[')[1].split(']')[0]
            port_name = node + '-' + port
            if node != '' and port != '':
                if port_name not in port_stat_dict.keys():
                    port_stat_dict[port_name] = {}
                    port_stat_dict[port_name]['bytesratein'] = '0'
                    port_stat_dict[port_name]['bytesrateout'] = '0'
                    port_stat_dict[port_name]['packetin'] = '0'
                    port_stat_dict[port_name]['packetout'] = '0'
                    port_stat_dict[port_name]['portevent'] = []
                    port_stat_dict[port_name]['eventtime'] = []
                port_stat_dict[port_name]['bytesrateout'] = \
                    str(int(float(egr['eqptEgrTotalHist5min']['attributes']['bytesRateMin']) * 8))
                port_stat_dict[port_name]['packetout'] = \
                    egr['eqptEgrTotalHist5min']['attributes']['pktsMin']

        get_url = self.apic + '/api/node/class/eventRecord.json?query-target-filter=or(' \
                              'eq(eventRecord.cause,"port-up"),eq(eventRecord.cause,"port-down"))' \
                              '&order-by=eventRecord.created|desc&page=0&page-size=5000'
        resp = self.mysession.get(get_url, verify=False)
        eventrecords = json.loads(resp.text)['imdata']
        if eventrecords:
            for eventrecord in eventrecords:
                port = ''
                node = ''
                port_dn = eventrecord['eventRecord']['attributes']['affected']
                if '/node-' in port_dn: node = port_dn.split('/node-')[1].split('/')[0]
                if '/phys-[' in port_dn: port = port_dn.split('/phys-[')[1].split(']')[0]
                port_name = node + '-' + port
                if node != '' and port != '':
                    if port_name not in port_stat_dict.keys():
                        port_stat_dict[port_name] = {}
                        port_stat_dict[port_name]['bytesratein'] = '0'
                        port_stat_dict[port_name]['bytesrateout'] = '0'
                        port_stat_dict[port_name]['packetin'] = '0'
                        port_stat_dict[port_name]['packetout'] = '0'
                        port_stat_dict[port_name]['portevent'] = []
                        port_stat_dict[port_name]['eventtime'] = []
                    port_stat_dict[port_name]['portevent'].append(
                        eventrecord['eventRecord']['attributes']['cause'])
                    port_stat_dict[port_name]['eventtime'].append(
                        eventrecord['eventRecord']['attributes']['created'].split('.')[0])
        return port_stat_dict

    def get_port_name_dict(self):
        port_name_dict = {}

        # get port operational status
        get_url = self.apic + '/api/class/l1PhysIf.json'
        resp = self.mysession.get(get_url, verify=False)
        PhysIfs = json.loads(resp.text)['imdata']
        # print PhysIfs
        for PhysIf in PhysIfs:
            if 'l1PhysIf' in PhysIf:
                intf_dn = str(PhysIf['l1PhysIf']['attributes']['dn'])
                if '/node-' in intf_dn:
                    node = str(intf_dn.split('/node-')[1].split('/')[0])
                    intf_name = node + '-' + str(PhysIf['l1PhysIf']['attributes']['id'])
                    port_name_dict[intf_name] = {}
                    port_name_dict[intf_name]['name'] = intf_name
                    port_name_dict[intf_name]['node'] = node
                    port_name_dict[intf_name]['id'] = str(PhysIf['l1PhysIf']['attributes']['id'])
                    port_name_dict[intf_name]['descr'] = str(PhysIf['l1PhysIf']['attributes']['descr'])
                    port_name_dict[intf_name]['usage'] = str(PhysIf['l1PhysIf']['attributes']['usage'])
                    port_name_dict[intf_name]['speed'] = str(PhysIf['l1PhysIf']['attributes']['speed'])
                    port_name_dict[intf_name]['adminst'] = str(PhysIf['l1PhysIf']['attributes']['adminSt'])
        return port_name_dict

    def get_port_dict(self, limit=None):
        port_dict = {}
        if limit:
            intf_dict = self.get_interface_dict()
        else:
            intf_dict = self.get_intf_dict()
        switch_dict = self.get_switch_dict()

        # get port operational status
        get_url = self.apic + '/api/class/l1PhysIf.json'
        resp = self.mysession.get(get_url, verify=False)
        PhysIfs = json.loads(resp.text)['imdata']
        # print PhysIfs
        for PhysIf in PhysIfs:
            if 'l1PhysIf' in PhysIf:
                intf_dn = str(PhysIf['l1PhysIf']['attributes']['dn'])
                if '/node-' in intf_dn:
                    node = str(intf_dn.split('/node-')[1].split('/')[0])
                    intf_name = node + '-' + str(PhysIf['l1PhysIf']['attributes']['id'])
                    if node in switch_dict.keys():
                        switch_name = switch_dict[node]['name']
                    else:
                        switch_name = ''
                    port_dict[intf_name] = {}
                    port_dict[intf_name]['id'] = str(PhysIf['l1PhysIf']['attributes']['id'])
                    port_dict[intf_name]['descr'] = str(PhysIf['l1PhysIf']['attributes']['descr'])
                    port_dict[intf_name]['usage'] = str(PhysIf['l1PhysIf']['attributes']['usage'])
                    port_dict[intf_name]['speed'] = str(PhysIf['l1PhysIf']['attributes']['speed'])
                    port_dict[intf_name]['adminst'] = str(PhysIf['l1PhysIf']['attributes']['adminSt'])
                    port_dict[intf_name]['dn'] = str(PhysIf['l1PhysIf']['attributes']['dn'])
                    port_dict[intf_name]['operst'] = ''
                    port_dict[intf_name]['bundleindex'] = ''
                    port_dict[intf_name]['opersterr'] = ''
                    port_dict[intf_name]['name'] = intf_name
                    port_dict[intf_name]['switch'] = switch_name
                    port_dict[intf_name]['node'] = node
                    port_dict[intf_name]['fexid'] = ''
                    port_dict[intf_name]['ipg'] = ''
                    port_dict[intf_name]['type'] = ''
                    port_dict[intf_name]['aep'] = ''
                    port_dict[intf_name]['domain'] = []
                    port_dict[intf_name]['poolname'] = []
                    port_dict[intf_name]['domain_type'] = []
                    port_dict[intf_name]['poolvlan'] = []
                    port_dict[intf_name]['mode'] = []
                    port_dict[intf_name]['encap'] = []
                    port_dict[intf_name]['epg'] = []
                    port_dict[intf_name]['bd'] = []
                    port_dict[intf_name]['leaf_profile'] = ''
                    port_dict[intf_name]['selector'] = ''
                    port_dict[intf_name]['blockname'] = ''
                    port_dict[intf_name]['blockport'] = ''
                    port_dict[intf_name]['bytesratein'] = '0'
                    port_dict[intf_name]['bytesrateout'] = '0'
                    port_dict[intf_name]['packetin'] = '0'
                    port_dict[intf_name]['packetout'] = '0'
                    port_dict[intf_name]['portevent'] = '0'
                    port_dict[intf_name]['lastevent'] = ''
                    port_dict[intf_name]['firstevent'] = ''
                    try:
                        if intf_name in intf_dict.keys():
                            port_dict[intf_name]['descr'] = intf_dict[intf_name]['descr']
                            port_dict[intf_name]['name'] = intf_dict[intf_name]['name']
                            port_dict[intf_name]['switch'] = intf_dict[intf_name]['switch']
                            port_dict[intf_name]['node'] = intf_dict[intf_name]['node']
                            port_dict[intf_name]['fexid'] = intf_dict[intf_name]['fexid']
                            port_dict[intf_name]['ipg'] = intf_dict[intf_name]['ipg']
                            port_dict[intf_name]['leaf_profile'] = intf_dict[intf_name]['leaf_profile']
                            port_dict[intf_name]['selector'] = intf_dict[intf_name]['selector']
                            port_dict[intf_name]['blockname'] = intf_dict[intf_name]['blockname']
                            port_dict[intf_name]['blockport'] = intf_dict[intf_name]['blockport']
                            port_dict[intf_name]['aep'] = intf_dict[intf_name]['aep']
                            port_dict[intf_name]['type'] = intf_dict[intf_name]['type']
                            port_dict[intf_name]['domain'] = intf_dict[intf_name]['domain']
                            port_dict[intf_name]['poolname'] = intf_dict[intf_name]['poolname']
                            port_dict[intf_name]['domain_type'] = intf_dict[intf_name]['domain_type']
                            port_dict[intf_name]['poolvlan'] = intf_dict[intf_name]['poolvlan']
                            port_dict[intf_name]['mode'] = intf_dict[intf_name]['mode']
                            port_dict[intf_name]['encap'] = intf_dict[intf_name]['encap']
                            port_dict[intf_name]['epg'] = intf_dict[intf_name]['epg']
                            port_dict[intf_name]['bd'] = intf_dict[intf_name]['bd']

                    except:
                        pass

        get_url = self.apic + '/api/class/ethpmPhysIf.json'
        resp = self.mysession.get(get_url, verify=False)
        ethpmPhysIfs = json.loads(resp.text)['imdata']
        # print ethpmPhysIfs
        for ethpmPhysIf in ethpmPhysIfs:
            if 'ethpmPhysIf' in ethpmPhysIf:
                intf_dn = str(ethpmPhysIf['ethpmPhysIf']['attributes']['dn'])
                if '/node-' in intf_dn:
                    node = str(intf_dn.split('/node-')[1].split('/')[0])
                    intf_name = node + '-' + str(
                        ethpmPhysIf['ethpmPhysIf']['attributes']['dn'].split('/phys-[')[1].split(']')[0])
                    port_dict[intf_name]['bundleindex'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['bundleIndex'])
                    if str(ethpmPhysIf['ethpmPhysIf']['attributes']['operStQual']) != 'sfp-missing':
                        port_dict[intf_name]['speed'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['operSpeed'])
                    port_dict[intf_name]['operst'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['operSt'])
                    port_dict[intf_name]['opersterr'] = str(ethpmPhysIf['ethpmPhysIf']['attributes']['operStQual'])
                    if port_dict[intf_name]['bundleindex'] == 'unspecified': port_dict[intf_name]['bundleindex'] = ''

        if limit is 'full':
            port_stat_dict = self.get_port_stat_dict()
            for intf_name in port_stat_dict.keys():
                try:
                    port_dict[intf_name]['bytesratein'] = port_stat_dict[intf_name]['bytesratein']
                    port_dict[intf_name]['bytesrateout'] = port_stat_dict[intf_name]['bytesrateout']
                    port_dict[intf_name]['packetin'] = port_stat_dict[intf_name]['packetin']
                    port_dict[intf_name]['packetout'] = port_stat_dict[intf_name]['packetout']
                    port_dict[intf_name]['portevent'] = len(port_stat_dict[intf_name]['portevent'])
                    if port_stat_dict[intf_name]['eventtime']:
                        port_dict[intf_name]['lastevent'] = port_stat_dict[intf_name]['eventtime'][0]
                        port_dict[intf_name]['firstevent'] = port_stat_dict[intf_name]['eventtime'][-1]
                except:
                    pass

        return port_dict

    def get_endpoint_dict(self):
        endpoint_dict = {}
        ipg_dict = self.get_ipg_dict()

        get_url = self.apic + '/api/class/fvCEp.json?rsp-subtree=children&rsp-subtree-class=fvIp'

        resp = self.mysession.get(get_url, verify=False)

        ceps = json.loads(resp.text)['imdata']
        endpoints = {}
        for cep in ceps:
            if "fvCEp" in cep:
                cep_dn = str(cep['fvCEp']['attributes']['dn'])
                endpoints[cep_dn] = {}
                endpoints[cep_dn]['mac'] = str(cep['fvCEp']['attributes']['mac'])
                endpoints[cep_dn]['ip'] = []
                endpoints[cep_dn]['encap'] = str(cep['fvCEp']['attributes']['encap'])
                endpoints[cep_dn]['epg'] = cep_dn.split('/cep-')[0]
                endpoints[cep_dn]['interfaces'] = []
                endpoints[cep_dn]['type'] = ''
                if 'children' in cep['fvCEp']:
                    cep_children = cep['fvCEp']['children']
                    for cep_child in cep_children:
                        endpoints[cep_dn]['ip'].append(str(cep_child['fvIp']['attributes']['addr']))
                else:
                    endpoints[cep_dn]['ip'].append(str(cep['fvCEp']['attributes']['ip']))

        get_url = self.apic + '/api/class/fvRsCEpToPathEp.json'

        resp = self.mysession.get(get_url, verify=False)

        paths = json.loads(resp.text)['imdata']
        # print paths
        for path in paths:
            if "fvRsCEpToPathEp" in path:
                path_names = []
                path_type = ''
                path_dn = str(path['fvRsCEpToPathEp']['attributes']['dn'])
                cep_dn = str(path_dn.split('/rscEpToPathEp-')[0])
                if '/rscEpToPathEp-' in path_dn:
                    path_name = str(path_dn.split('/rscEpToPathEp-[')[1].split(']')[0])
                    if '/pathep-[eth' in path_name:
                        path_type = 'accportgrp'
                        path_node = str(path_name.split('/paths-')[1].split('/')[0])
                        if '/extpaths-' in path_name:
                            path_fex = 'eth' + str(path_name.split('/extpaths-')[1].split('/')[0]) + '/'
                            path_names = [path_node + '-' + path_fex + path_name.split('eth')[1].split(']')[0]]
                        else:
                            path_names = [path_node + '-' + path_name.split('/pathep-[')[1].split(']')[0]]
                    else:
                        path_name = path_name.split('/pathep-[')[1].split(']')[0]
                        if path_name in ipg_dict.keys():
                            path_names = ipg_dict[path_name]['interfaces']
                            path_type = ipg_dict[path_name]['type']

                    if cep_dn in endpoints.keys():
                        endpoints[cep_dn]['interfaces'] = path_names
                        endpoints[cep_dn]['type'] = path_type

        for endpoint in endpoints.keys():
            endpoint_mac = endpoints[endpoint]['mac']
            if endpoint_mac not in endpoint_dict.keys():
                endpoint_dict[endpoint_mac] = {}
                endpoint_dict[endpoint_mac]['name'] = endpoint_mac
                endpoint_dict[endpoint_mac]['mac'] = [endpoints[endpoint]['mac']]
                endpoint_dict[endpoint_mac]['ip'] = [endpoints[endpoint]['ip']]
                endpoint_dict[endpoint_mac]['encap'] = [endpoints[endpoint]['encap']]
                endpoint_dict[endpoint_mac]['epg'] = [endpoints[endpoint]['epg']]
                endpoint_dict[endpoint_mac]['interfaces'] = [endpoints[endpoint]['interfaces']]
                endpoint_dict[endpoint_mac]['type'] = [endpoints[endpoint]['type']]
            else:
                endpoint_dict[endpoint_mac]['mac'].append(endpoints[endpoint]['mac'])
                endpoint_dict[endpoint_mac]['ip'].append(endpoints[endpoint]['ip'])
                endpoint_dict[endpoint_mac]['encap'].append(endpoints[endpoint]['encap'])
                endpoint_dict[endpoint_mac]['epg'].append(endpoints[endpoint]['epg'])
                endpoint_dict[endpoint_mac]['interfaces'].append(endpoints[endpoint]['interfaces'])
                endpoint_dict[endpoint_mac]['type'].append(endpoints[endpoint]['type'])

        return endpoint_dict

    def get_switch_profile_dict(self):
        node_id_dict = {}
        # get nodes
        get_url = self.apic + '/api/node/mo/uni/infra/.json?rsp-subtree=full&rsp-subtree-class=infraNodeP'

        resp = self.mysession.get(get_url, verify=False)

        infra = json.loads(resp.text)['imdata'][0]

        # print infra

        if 'children' in infra['infraInfra']:
            nodeps = infra['infraInfra']['children']
            for nodep in nodeps:
                if 'infraNodeP' in nodep:
                    node_name = str(nodep['infraNodeP']['attributes']['name'])
                    nodes = []
                    if 'children' in nodep['infraNodeP']:
                        nodep_children = nodep['infraNodeP']['children']
                        for leafs in nodep_children:
                            if 'infraLeafS' in leafs:
                                if 'children' in leafs['infraLeafS']:
                                    leafs_children = leafs['infraLeafS']['children']
                                    for nodeblk in leafs_children:
                                        if 'infraNodeBlk' in nodeblk:
                                            node1 = str(nodeblk['infraNodeBlk']['attributes']['from_'])
                                            node2 = str(nodeblk['infraNodeBlk']['attributes']['to_'])
                                            for node in range(int(node1), int(node2) + 1, 1):
                                                nodes.append(str(node))
                                                if str(node) not in node_id_dict.keys():
                                                    node_id_dict[str(node)] = {}
                                                    node_id_dict[str(node)]['int_profile'] = []
                                                    node_id_dict[str(node)]['sw_profile'] = []
                        for accportp in nodep_children:
                            if 'infraRsAccPortP' in accportp:

                                accportp_rn = str(
                                    accportp['infraRsAccPortP']['attributes']['tDn'].split('/accportprof-')[1])
                                if str(accportp['infraRsAccPortP']['attributes']['state']) == 'formed':
                                    for node in nodes:
                                        node_id_dict[node]['int_profile'].append(accportp_rn)
                                        node_id_dict[node]['sw_profile'].append(node_name)

        return node_id_dict

    def get_switch_maint_dict(self):
        node_id_dict = {}
        # get nodes

        get_url = self.apic + '/api/node/class/fabricNodeBlk.json?'
        resp = self.mysession.get(get_url, verify=False)
        fnodeblks = json.loads(resp.text)['imdata']
        for fnodeblk in fnodeblks:
            fnodeblk_dn = str(fnodeblk['fabricNodeBlk']['attributes']['dn'])
            node1 = str(fnodeblk['fabricNodeBlk']['attributes']['from_'])
            node2 = str(fnodeblk['fabricNodeBlk']['attributes']['to_'])
            for node in range(int(node1), int(node2) + 1, 1):
                if str(node) not in node_id_dict.keys():
                    node_id_dict[str(node)] = {}
                    node_id_dict[str(node)]['fwgrp'] = ''
                    node_id_dict[str(node)]['maintgrp'] = ''
                if '/fwgrp-' in fnodeblk_dn:
                    node_id_dict[str(node)]['fwgrp'] = fnodeblk_dn.split('/fwgrp-')[1].split('/')[0]
                elif '/maintgrp-' in fnodeblk_dn:
                    node_id_dict[str(node)]['maintgrp'] = fnodeblk_dn.split('/maintgrp-')[1].split('/')[0]
        return node_id_dict

    def get_switch_health_dict(self):
        node_id_dict = {}
        # get nodes

        get_url = self.apic + '/api/node/class/healthInst.json?'
        resp = self.mysession.get(get_url, verify=False)
        nodehealths = json.loads(resp.text)['imdata']
        for nodehealth in nodehealths:
            if '/sys/health' in str(nodehealth['healthInst']['attributes']['dn']):
                node = str(nodehealth['healthInst']['attributes']['dn'].split('/node-')[1].split('/')[0])
                node_id_dict[node] = {}
                node_id_dict[node]['healthscore'] = str(nodehealth['healthInst']['attributes']['cur'])

        return node_id_dict

    def get_switch_oob_dict(self):
        node_id_dict = {}
        # get nodes
        get_url = self.apic + '/api/class/mgmtRsOoBStNode.json'

        resp = self.mysession.get(get_url, verify=False)

        oobmgmts = json.loads(resp.text)['imdata']

        # print oobmgmts

        for oobmgmt in oobmgmts:
            node = str(oobmgmt['mgmtRsOoBStNode']['attributes']['dn'].split('/node-')[1].split(']')[0])
            node_id_dict[node] = {}
            node_id_dict[node]['addr'] = str(oobmgmt['mgmtRsOoBStNode']['attributes']['addr'])
            node_id_dict[node]['gw'] = str(oobmgmt['mgmtRsOoBStNode']['attributes']['gw'])

        return node_id_dict

    def get_switch_vpcpair_dict(self):
        node_id_dict = {}
        # get nodes
        get_url = self.apic + '/api/class/fabricExplicitGEp.json?rsp-subtree=full&rsp-subtree-class=fabricNodePEp'

        resp = self.mysession.get(get_url, verify=False)

        vpcpairs = json.loads(resp.text)['imdata']

        # print vpcpairs
        for vpcpair in vpcpairs:
            if 'children' in vpcpair['fabricExplicitGEp']:
                vpcpair_nodes = vpcpair['fabricExplicitGEp']['children']
                node_list = []
                for vpcpair_node in vpcpair_nodes:
                    node = str(vpcpair_node['fabricNodePEp']['attributes']['id'])
                    node_list.append(node)
                for vpcpair_node in vpcpair_nodes:
                    node = str(vpcpair_node['fabricNodePEp']['attributes']['id'])
                    node_id_dict[node] = {}
                    node_id_dict[node]['name'] = str(vpcpair['fabricExplicitGEp']['attributes']['name'])
                    node_id_dict[node]['id'] = str(vpcpair['fabricExplicitGEp']['attributes']['id'])
                    node_id_dict[node]['ip'] = str(vpcpair['fabricExplicitGEp']['attributes']['virtualIp'])
                    node_id_dict[node]['nodes'] = sorted(node_list)
        return node_id_dict

    def get_vpcpair_dict(self):
        vpcpair_dict = {}
        # get nodes
        get_url = self.apic + '/api/class/fabricExplicitGEp.json?rsp-subtree=full&rsp-subtree-class=fabricNodePEp'

        resp = self.mysession.get(get_url, verify=False)

        vpcpairs = json.loads(resp.text)['imdata']

        # print vpcpairs
        for vpcpair in vpcpairs:
            vpcid = str(vpcpair['fabricExplicitGEp']['attributes']['id'])
            vpcpair_dict[vpcid] = {}
            vpcpair_dict[vpcid]['name'] = str(vpcpair['fabricExplicitGEp']['attributes']['name'])
            vpcpair_dict[vpcid]['id'] = vpcid
            vpcpair_dict[vpcid]['ip'] = str(vpcpair['fabricExplicitGEp']['attributes']['virtualIp'])
            vpcpair_dict[vpcid]['nodes'] = []
            if 'children' in vpcpair['fabricExplicitGEp']:
                vpcpair_nodes = vpcpair['fabricExplicitGEp']['children']
                for vpcpair_node in sorted(vpcpair_nodes):
                    node = str(vpcpair_node['fabricNodePEp']['attributes']['id'])
                    vpcpair_dict[vpcid]['nodes'].append(node)

        return vpcpair_dict

    def get_lldp_dict(self):
        lldp_dict = {}

        get_url = self.apic + '/api/class/lldpAdjEp.json'
        resp = self.mysession.get(get_url, verify=False)
        lldps = json.loads(resp.text)['imdata']

        for lldp in lldps:
            if "lldpAdjEp" in lldp:
                lldp_dn = str(lldp['lldpAdjEp']['attributes']['dn'])
                lldp_node = lldp_dn.split('/node-')[1].split('/')[0]
                lldp_port = lldp_dn.split('/if-[')[1].split(']')[0]
                lldp_name = lldp_node + '-' + lldp_port
                lldp_dict[lldp_name] = {}
                lldp_dict[lldp_name]['name'] = lldp_name
                lldp_dict[lldp_name]['local_name'] = lldp_node
                lldp_dict[lldp_name]['local_port'] = lldp_port
                lldp_dict[lldp_name]['remote_name'] = str(lldp['lldpAdjEp']['attributes']['sysName'])
                lldp_dict[lldp_name]['remote_port'] = str(lldp['lldpAdjEp']['attributes']['portIdV'])
                lldp_dict[lldp_name]['remote_portdesc'] = str(lldp['lldpAdjEp']['attributes']['portDesc'])
                lldp_dict[lldp_name]['remote_sysdesc'] = str(lldp['lldpAdjEp']['attributes']['sysDesc'])
                lldp_dict[lldp_name]['remote_mgmtip'] = str(lldp['lldpAdjEp']['attributes']['mgmtIp'])
                lldp_dict[lldp_name]['remote_mac'] = str(lldp['lldpAdjEp']['attributes']['chassisIdV'])

        return lldp_dict

    def get_l3out_name_dict(self):
        l3out_name_dict = {}

        get_url = self.apic + '/api/class/l3extOut.json'
        resp = self.mysession.get(get_url, verify=False)
        l3outs = json.loads(resp.text)['imdata']

        for l3out in l3outs:
            if "l3extOut" in l3out:
                l3out_dn = str(l3out['l3extOut']['attributes']['dn'])
                l3out_name_dict[l3out_dn] = {}
                l3out_name_dict[l3out_dn]['name'] = str(l3out['l3extOut']['attributes']['name'])
                l3out_name_dict[l3out_dn]['descr'] = str(l3out['l3extOut']['attributes']['descr'])
                l3out_name_dict[l3out_dn]['tenant'] = str(l3out_dn.split('uni/tn-')[1].split('/')[0])
        return l3out_name_dict

    def get_l3ext_name_dict(self):
        l3ext_name_dict = {}

        get_url = self.apic + '/api/class/l3extInstP.json'
        resp = self.mysession.get(get_url, verify=False)
        l3exts = json.loads(resp.text)['imdata']

        for l3ext in l3exts:
            if "l3extInstP" in l3ext:
                l3ext_dn = str(l3ext['l3extInstP']['attributes']['dn'])
                l3ext_name_dict[l3ext_dn] = {}
                l3ext_name_dict[l3ext_dn]['name'] = str(l3ext['l3extInstP']['attributes']['name'])
                l3ext_name_dict[l3ext_dn]['descr'] = str(l3ext['l3extInstP']['attributes']['descr'])
                l3ext_name_dict[l3ext_dn]['tenant'] = str(l3ext_dn.split('uni/tn-')[1].split('/')[0])
                l3ext_name_dict[l3ext_dn]['l3out'] = str(l3ext_dn.split('/out-')[1].split('/')[0])
        return l3ext_name_dict

    def get_dhcprelay_name_dict(self):
        dhcprelay_name_dict = {}

        get_url = self.apic + '/api/class/dhcpRelayP.json'
        resp = self.mysession.get(get_url, verify=False)
        dhcprelays = json.loads(resp.text)['imdata']

        for dhcprelay in dhcprelays:
            if "dhcpRelayP" in dhcprelay:
                dhcprelay_name = str(dhcprelay['dhcpRelayP']['attributes']['name'])
                dhcprelay_name_dict[dhcprelay_name] = {}
                dhcprelay_name_dict[dhcprelay_name]['name'] = str(dhcprelay['dhcpRelayP']['attributes']['name'])
                dhcprelay_name_dict[dhcprelay_name]['descr'] = str(dhcprelay['dhcpRelayP']['attributes']['descr'])
        return dhcprelay_name_dict

    def get_export_policy_dict(self):
        export_policy_dict = {}

        get_url = self.apic + '/api/class/configExportP.json?rsp-subtree=full'
        resp = self.mysession.get(get_url, verify=False)
        export_policys = json.loads(resp.text)['imdata']

        for export_policy in export_policys:
            name = str(export_policy['configExportP']['attributes']['name'])
            target = str(export_policy['configExportP']['attributes']['targetDn'])
            snapshot = str(export_policy['configExportP']['attributes']['snapshot'])
            remotelocation = ''
            if 'children' in export_policy['configExportP']:
                export_policy_children = export_policy['configExportP']['children']
                for export_policy_child in export_policy_children:
                    if 'configRsRemotePath' in export_policy_child:
                        remotelocation = \
                            str(export_policy_child['configRsRemotePath']['attributes']['tnFileRemotePathName'])
            export_policy_dict[name] = {}
            export_policy_dict[name]['name'] = name
            export_policy_dict[name]['target'] = target
            export_policy_dict[name]['snapshot'] = snapshot
            export_policy_dict[name]['remotelocation'] = remotelocation

        return export_policy_dict

    def get_snapshot_dict(self):
        snapshot_dict = {}
        get_url = self.apic + '/api/class/configSnapshot.json?rsp-subtree=full'
        resp = self.mysession.get(get_url, verify=False)
        snapshots = json.loads(resp.text)['imdata']
        for snapshot in snapshots:
            filename = str(snapshot['configSnapshot']['attributes']['fileName'])
            if '_tn-' in filename:
                target = '-'.join(filename.split('_tn-')[1].split('-')[:-5])
            else:
                target = 'Fabric'
            snapshot_dict[filename] = {}
            snapshot_dict[filename]['name'] = str(snapshot['configSnapshot']['attributes']['name'])
            snapshot_dict[filename]['dn'] = str(snapshot['configSnapshot']['attributes']['dn'])
            snapshot_dict[filename]['filename'] = str(snapshot['configSnapshot']['attributes']['fileName'])
            snapshot_dict[filename]['descr'] = str(snapshot['configSnapshot']['attributes']['descr'])
            snapshot_dict[filename]['target'] = target

        return snapshot_dict


    def get_xml_from_json(self, result_json):

        child1 = None
        child2 = None
        child3 = None
        child4 = None
        children1 = []
        children2 = []
        children3 = []
        children4 = []
        children5 = []
        result = []

        for json_file in result_json:
            data = json.dumps(json_file, sort_keys=True)
            data = json.loads(data)
            for parent in data.keys():
                if 'attributes' in data[parent]:
                    result.append('  ' + '<' + str(parent))
                    for attribute in sorted(data[parent]['attributes'].keys()):
                        result.append(' ' + attribute + '="' + data[parent]['attributes'][attribute] + '"')
                if 'children' in data[parent]:
                    children1 = data[parent]['children']
                else:
                    children1 = []
                if children1 == []:
                    result.append('/>\n')
                else:
                    result.append('>\n')
                for data1 in children1:
                    for child1 in data1.keys():
                        if 'attributes' in data1[child1]:
                            result.append('    ' + '<' + str(child1))
                            for attribute in sorted(data1[child1]['attributes'].keys()):
                                result.append(' ' + attribute + '="' + data1[child1]['attributes'][attribute] + '"')
                        if 'children' in data1[child1]:
                            children2 = data1[child1]['children']
                        else:
                            children2 = []
                        if children2 == []:
                            result.append('/>\n')
                        else:
                            result.append('>\n')
                        for data2 in children2:
                            for child2 in data2.keys():
                                if 'attributes' in data2[child2]:
                                    result.append('      ' + '<' + str(child2))
                                    for attribute in sorted(data2[child2]['attributes'].keys()):
                                        result.append(
                                            ' ' + attribute + '="' + data2[child2]['attributes'][attribute] + '"')
                                if 'children' in data2[child2]:
                                    children3 = data2[child2]['children']
                                else:
                                    children3 = []
                                if children3 == []:
                                    result.append('/>\n')
                                else:
                                    result.append('>\n')
                                for data3 in children3:
                                    for child3 in data3.keys():
                                        if 'attributes' in data3[child3]:
                                            result.append('        ' + '<' + str(child3))
                                            for attribute in sorted(data3[child3]['attributes'].keys()):
                                                result.append(' ' + attribute + '="' + data3[child3]['attributes'][
                                                    attribute] + '"')
                                        if 'children' in data3[child3]:
                                            children4 = data3[child3]['children']
                                        else:
                                            children4 = []
                                        if children4 == []:
                                            result.append('/>\n')
                                        else:
                                            result.append('>\n')
                                        for data4 in children4:
                                            for child4 in data4.keys():
                                                if 'attributes' in data4[child4]:
                                                    result.append('          ' + '<' + str(child4))
                                                    for attribute in sorted(data4[child4]['attributes'].keys()):
                                                        result.append(
                                                            ' ' + attribute + '="' + data4[child4]['attributes'][
                                                                attribute] + '"')
                                                if 'children' in data4[child4]:
                                                    children5 = data4[child4]['children']
                                                else:
                                                    children5 = []
                                                if children5 == []:
                                                    result.append('/>\n')
                                                else:
                                                    result.append('>\n')
                                                print children5, 'not converted'
                                            if children5 != []: result.append(
                                                '          ' + '</' + str(child4) + '>' + '\n')
                                    if children4 != []: result.append('        ' + '</' + str(child3) + '>' + '\n')
                            if children3 != []: result.append('      ' + '</' + str(child2) + '>' + '\n')
                    if children2 != []: result.append('    ' + '</' + str(child1) + '>' + '\n')
            if children1 != []: result.append('  ' + '</' + str(parent) + '>' + '\n')
            result.append('\n')

        result = ''.join(result)
        return result
