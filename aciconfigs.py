
#title           :aciconfigs.py
#description     :aci configs
#author          :segun medeyinlo
#date            :08102018
#version         :0.23
#usage           :
#notes           :updated 29042019
#python_version  :2.7.10
#==============================================================================
import json
import netaddr


class aciConfig():
    def __init__(self, session):
        self.session = session
        
    def functions(self, commands, validate='no', send_to_apic ='no'):
            post_url = ''
            post_resp = ''
            result_json = []
            required = []
            warnings = []
            infra_obj_dict = {}  
            infra_obj_dict['infraAccPortP'] = {}
            infra_obj_dict['infraFexP'] = {}
            infra_obj_dict['infraFuncP'] = {}
            infra_obj_dict['infraHPortS'] = {}
            infra_obj_dict['infraAccGrp'] = {}
            infra_obj_dict['infraFexGrp'] = {}
            infra_obj_dict['infraNodeP'] = {}
            infra_obj_dict['fvnsVlanInstP'] = {}
            infra_obj_dict['fvnsEncapBlk'] = {}
            fabric_obj_dict = {}
            fabric_obj_dict['fabricOOServicePol'] = {}
            fabric_obj_dict['fabricProtPol'] = {}
            fabric_obj_dict['fabricRsOosPath'] = {}
            fabric_obj_dict['fabricExplicitGEp'] = {}
            fabric_obj_dict['configExportP'] = {}
            fabric_obj_dict['configSnapshotCont'] = {}
            fabric_obj_dict['configSnapshot'] = {}
            tenant_obj_dict = {}
            tenant_obj_dict['fvTenant'] = {}
            tenant_obj_dict['fvCtx'] = {}
            tenant_obj_dict['fvBD'] ={}
            tenant_obj_dict['fvAp'] = {}
            tenant_obj_dict['fvAEPg'] = {}
            tenant_obj_dict['fvRsPathAtt'] = {}
            tenant_obj_dict['dhcpRelayP'] = {}
            tenant_obj_dict['dhcpLbl'] = {}
            fex_list = []
            node_list = []
            port_dict = {}
            ipg_dict = {}
            fex_dict = {}
            aep_dict = {}
            dom_dict = {}
            switch_dict = {}
            tenants = {}
            tenant_dict = {}
            bd_dict = {}
            ctx_dict = {}
            epg_dict = {}
            app_name_dict = {}
            ctx_name_dict = {}
            bd_name_dict = {}
            epg_name_dict = {}
            ipg_name_dict = {}
            vpcpair_dict = {}
            switch_vpcpair_dict = {}
            dhcprelay_dict = {}
            vlanpool_dict = {}
            snapshot_dict = {}
            for command in commands:
                function = command['function']
                if function == 'create port':
                    try:
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                        ipg_name = str(command['ipg'])
                        descr = str(command['descr'])
                    except:
                        required.append('require node port ipg descr')
                        continue
                    if validate == 'no':
                        if node_name.isdigit():
                            node = node_name
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name in ipg_dict.keys():
                            ipg_type = ipg_dict[ipg_name]['type']
                        elif ipg_name.startswith('IPG_AC_'):
                            ipg_type = 'accportgrp'
                        elif ipg_name.startswith('IPG_vPC_'):
                            ipg_type = 'accbundle-node'
                        elif ipg_name.startswith('IPG_PC_'):
                            ipg_type = 'accbundle-link'
                        else:
                            required.append('Cannot determine ipg_type from ipg_name, ' + ipg_name +
                                            'kindly use the standard naming convention, IPG_AC_ or IPG_vPC_ or IPG_PC_')
                            continue
                        required.append('manually check node,port,ipg are valid')
                        required.append(
                            'manually check ipg_type is correct and port is not already assigned to another ipg')
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name in ipg_dict.keys():
                            ipg_type = ipg_dict[ipg_name]['type']
                        elif ipg_name.startswith('IPG_AC_'):
                            ipg_type = 'accportgrp'
                        elif ipg_name.startswith('IPG_vPC_'):
                            ipg_type = 'accbundle-node'
                        elif ipg_name.startswith('IPG_PC_'):
                            ipg_type = 'accbundle-link'
                        else:
                            ipg_type = 'unknown'
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + '  is not valid')
                            continue
                        if ipg_name in ipg_dict.keys():
                            ipg_type = ipg_dict[ipg_name]['type']
                        else:
                            if ipg_type + '/' + ipg_name not in infra_obj_dict['infraAccGrp'].keys():
                                required.append('provided ipg ' + ipg_name + ' is not valid')
                                continue
                        if port_dict[node + '-' + port_name]['selector'] != '':
                            required.append(
                                'provided port ' + node + '-' + port_name +
                                ' is currently assigned to selector ' + port_dict[node + '-' + port_name]['selector'])
                            continue
                        if port_dict[node + '-' + port_name]['ipg'] != '':
                            required.append(
                                'provided port ' + node + '-' + port_name +
                                ' is currently assigned to ipg ' + port_dict[node + '-' + port_name]['ipg'])
                            continue
                        if switch_dict[node_name]['role'] != 'leaf':
                            required.append('provided port ' + node + '-' + port_name + ' is not a leaf port')
                            continue
                        if port_dict[node + '-' + port_name]['type'] == 'fexbundle':
                            required.append('provided port ' + node + '-' + port_name + ' is a fex uplink')
                            continue
                        if 'fabric' in port_dict[node + '-' + port_name]['usage']:
                            required.append('provided port ' + node + '-' + port_name + ' is a leaf uplink')
                            continue
                        if 'controller' in port_dict[node + '-' + port_name]['usage']:
                            required.append('provided port ' + node + '-' + port_name + ' is a controller uplink')
                            continue
                        if 'infra' in port_dict[node + '-' + port_name]['usage']:
                            required.append('provided port ' + node + '-' + port_name + ' is an infra uplink')
                            continue
                    host = str(port_name.split('eth')[1])
                    if len(host.split('/')) == 3:
                        fex = host.split('/')[0]
                        module = host.split('/')[1]
                        port = host.split('/')[2]
                        int_profile_name = node + '-' + fex
                        if int_profile_name not in infra_obj_dict['infraFexP'].keys():
                            infra_obj_dict['infraFexP'][int_profile_name] = \
                                self.session.do_fex_int_profile(node, fex, 'modified')
                    elif len(host.split('/')) == 2:
                        module = host.split('/')[0]
                        port = host.split('/')[1]
                        int_profile_name = node
                        if int_profile_name not in infra_obj_dict['infraAccPortP'].keys():
                            infra_obj_dict['infraAccPortP'][int_profile_name] = \
                                self.session.do_int_profile(node, 'modified')
                    int_selector_name = int_profile_name + '/' + port
                    if descr != 'None':
                        hport_attr = {'descr': descr}
                    else:
                        hport_attr = None
                    infra_obj_dict['infraHPortS'][int_selector_name] = \
                        self.session.do_interface_selector(port, module, 'created', ipg_name, ipg_type, hport_attr)

                if function == 'delete port':
                    try:
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                        leaf_profile = 'None'
                    except:
                        required.append('require node port')
                        continue
                    if validate == 'no':
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        required.append('manually check port is not already assigned to another epg')
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        if port_dict[node + '-' + port_name]['epg'] != []:
                            required.append(
                                'provided port ' + node + '-' + port_name +
                                ' is currently assigned to epg ' + ','.join(port_dict[node + '-' + port_name]['epg']))
                            continue
                    if port_dict[node + '-' + port_name]['leaf_profile'] != '':
                        leaf_profile = port_dict[node + '-' + port_name]['leaf_profile']
                    if port_dict[node + '-' + port_name]['selector'] != '':
                        selector = port_dict[node + '-' + port_name]['selector']
                    else:
                        required.append(
                            'provided port ' + node + '-' + port_name + ' interface selector has not been created')
                        continue
                    if port_dict[node + '-' + port_name]['blockname'] != '':
                        blockname = port_dict[node + '-' + port_name]['blockname']
                    else:
                        required.append(
                            'provided port ' + node + '-' + port_name + ' blockname has not been created')
                        continue
                    if len(port_dict[node + '-' + port_name]['blockport']) > 1:
                        required.append('blockname: '+ port_dict[node + '-' + port_name]['blockname'] +
                                        ' is used by multiple ports: ' +
                                        ','.join(port_dict[node + '-' + port_name]['blockport']))
                        continue
                    port_with_same_selector = [port for port in port_dict.keys() if
                                               port_dict[port]['selector'] == selector and
                                               port_dict[port]['leaf_profile'] == leaf_profile]
                    if len(port_with_same_selector) > 1:
                        required.append('Interface Selector: ' + port_dict[node + '-' + port_name]['selector'] +
                                        ' is used by multiple ports: ' +
                                        ','.join(port_with_same_selector))
                        continue
                    if switch_dict[node_name]['role'] != 'leaf':
                        required.append('provided port ' + node + '-' + port_name + ' is not a leaf port')
                        continue
                    if port_dict[node + '-' + port_name]['type'] == 'fexbundle':
                        required.append('provided port ' + node + '-' + port_name + ' is a fex uplink')
                        continue
                    if 'fabric' in port_dict[node + '-' + port_name]['usage']:
                        required.append('provided port ' + node + '-' + port_name + ' is a leaf uplink')
                        continue
                    if 'controller' in port_dict[node + '-' + port_name]['usage']:
                        required.append('provided port ' + node + '-' + port_name + ' is a controller uplink')
                        continue
                    if 'infra' in port_dict[node + '-' + port_name]['usage']:
                        required.append('provided port ' + node + '-' + port_name + ' is an infra uplink')
                        continue

                    host = str(port_name.split('eth')[1])
                    if len(host.split('/')) == 3:
                        fex = host.split('/')[0]
                        module = host.split('/')[1]
                        port = host.split('/')[2]
                        int_profile_name = node + '-' + fex
                        int_profile_attr = {}
                        if leaf_profile != 'None':
                            int_profile_attr['leaf_profile'] = leaf_profile
                            int_profile_name = leaf_profile
                        if int_profile_name not in infra_obj_dict['infraFexP'].keys():
                            infra_obj_dict['infraFexP'][int_profile_name] = \
                                self.session.do_fex_int_profile(node, fex, 'modified', int_profile_attr)
                    elif len(host.split('/')) == 2:
                        module = host.split('/')[0]
                        port = host.split('/')[1]
                        int_profile_name = node
                        int_profile_attr = {}
                        if leaf_profile != 'None':
                            int_profile_attr['leaf_profile'] = leaf_profile
                            int_profile_name = leaf_profile
                        if int_profile_name not in infra_obj_dict['infraAccPortP'].keys():
                            infra_obj_dict['infraAccPortP'][int_profile_name] = \
                                self.session.do_int_profile(node, 'modified', int_profile_attr)
                    int_selector_name = int_profile_name + '/' + port
                    hport_attr = {}
                    if selector != 'None':
                        hport_attr['selector'] = selector
                    if blockname != 'None':
                        hport_attr['blockname'] = blockname
                    infra_obj_dict['infraHPortS'][int_selector_name] = \
                        self.session.do_interface_selector(port, module, 'deleted', None, None, hport_attr)

                if function == 'modify port':

                    try:
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                        ipg_name = str(command['ipg'])
                        descr = str(command['descr'])
                        leaf_profile = 'None'
                    except:
                        required.append('require node port ipg descr')
                        continue
                    if validate == 'no':
                        required.append('modify port must be validated')
                    if port_dict == {}:
                        port_dict = self.session.get_port_dict()
                    if ipg_dict == {}:
                        ipg_dict = self.session.get_ipg_dict()
                    if switch_dict == {}:
                        switch_dict = self.session.get_switch_dict()
                    if node_name not in switch_dict.keys():
                        required.append('provided node' + node_name + ' is not valid')
                        continue
                    else:
                        node = str(switch_dict[node_name]['id'])
                    if node + '-' + port_name not in port_dict.keys():
                        required.append('provided port' + node + '-' + port_name + ' is not valid')
                        continue
                    if ipg_name != 'None':
                        if ipg_name in ipg_dict.keys():
                            ipg_type = ipg_dict[ipg_name]['type']
                        else:
                            required.append('provided ipg ' + ipg_name + ' is not valid')
                            continue
                        if ipg_type == 'accportgrp' or ipg_type == 'accbundle-link' or ipg_type == 'accbundle-node':
                            pass
                        else:
                            required.append('provided ipg ' + ipg_name +
                                            'with ipg type as ' + ipg_type + ' cannot be modified')
                    else:
                        ipg_name = None
                        ipg_type = None
                    if port_dict[node + '-' + port_name]['leaf_profile'] != '':
                        leaf_profile = port_dict[node + '-' + port_name]['leaf_profile']
                    if port_dict[node + '-' + port_name]['selector'] != '':
                        selector = port_dict[node + '-' + port_name]['selector']
                    else:
                        required.append(
                            'provided port ' + node + '-' + port_name + ' interface selector has not been created')
                        continue
                    if port_dict[node + '-' + port_name]['blockname'] != '':
                        blockname = port_dict[node + '-' + port_name]['blockname']
                    else:
                        required.append(
                            'provided port ' + node + '-' + port_name + ' blockname has not been created')
                        continue
                    if len(port_dict[node + '-' + port_name]['blockport']) > 1:
                        required.append('blockname: '+ port_dict[node + '-' + port_name]['blockname'] +
                                        ' is used by multiple ports: ' +
                                        ','.join(port_dict[node + '-' + port_name]['blockport']))
                        continue
                    port_with_same_selector = [port for port in port_dict.keys() if
                                               port_dict[port]['selector'] == selector and
                                               port_dict[port]['leaf_profile'] == leaf_profile]
                    if len(port_with_same_selector) > 1:
                        required.append('Interface Selector: ' + port_dict[node + '-' + port_name]['selector'] +
                                        ' is used by multiple ports: ' +
                                        ','.join(port_with_same_selector))
                        continue
                    if switch_dict[node_name]['role'] != 'leaf':
                        required.append('provided port ' + node + '-' + port_name + ' is not a leaf port')
                        continue
                    if port_dict[node + '-' + port_name]['type'] == 'fexbundle':
                        required.append('provided port ' + node + '-' + port_name + ' is a fex uplink')
                        continue
                    if 'fabric' in port_dict[node + '-' + port_name]['usage']:
                        required.append('provided port ' + node + '-' + port_name + ' is a leaf uplink')
                        continue
                    if 'controller' in port_dict[node + '-' + port_name]['usage']:
                        required.append('provided port ' + node + '-' + port_name + ' is a controller uplink')
                        continue
                    if 'infra' in port_dict[node + '-' + port_name]['usage']:
                        required.append('provided port ' + node + '-' + port_name + ' is an infra uplink')
                        continue

                    host = str(port_name.split('eth')[1])
                    if len(host.split('/')) == 3:
                        fex = host.split('/')[0]
                        module = host.split('/')[1]
                        port = host.split('/')[2]
                        int_profile_name = node + '-' + fex
                        int_profile_attr = {}
                        if leaf_profile != 'None':
                            int_profile_attr['leaf_profile'] = leaf_profile
                            int_profile_name = leaf_profile
                        if int_profile_name not in infra_obj_dict['infraFexP'].keys():
                            infra_obj_dict['infraFexP'][int_profile_name] = \
                                self.session.do_fex_int_profile(node, fex, 'modified', int_profile_attr)
                    elif len(host.split('/')) == 2:
                        module = host.split('/')[0]
                        port = host.split('/')[1]
                        int_profile_name = node
                        int_profile_attr = {}
                        if leaf_profile != 'None':
                            int_profile_attr['leaf_profile'] = leaf_profile
                            int_profile_name = leaf_profile
                        if int_profile_name not in infra_obj_dict['infraAccPortP'].keys():
                            infra_obj_dict['infraAccPortP'][int_profile_name] = \
                                self.session.do_int_profile(node, 'modified', int_profile_attr)
                    int_selector_name = int_profile_name + '/' + port
                    hport_attr = {}
                    if descr != 'None':
                        hport_attr['descr'] = descr
                    if selector != 'None':
                        hport_attr['selector'] = selector
                    if blockname != 'None':
                        hport_attr['blockname'] = blockname
                    infra_obj_dict['infraHPortS'][int_selector_name] = \
                        self.session.do_interface_selector(port, module, 'modified', ipg_name, ipg_type, hport_attr)

                if function == 'create ipg':
                    try:
                        ipg_name = str(command['ipg'])
                        speed_name = str(command['speed'])
                        aep_name = str(command['aep'])
                        lacp_name = str(command['lacp'])
                        lldp_name = str(command['lldp'])
                        cdp_name = str(command['cdp'])
                        mcp_name = str(command['mcp'])
                        l2int_name = str(command['l2int'])
                        descr = str(command['descr'])
                    except:
                        required.append('require ipg speed aep lacp lldp cdp mcp l2int descr')
                        continue

                    if validate == 'no':
                        if ipg_name.startswith('IPG_AC_'):
                            ipg_type = 'accportgrp'
                        elif ipg_name.startswith('IPG_vPC_'):
                            ipg_type = 'accbundle-node'
                        elif ipg_name.startswith('IPG_PC_'):
                            ipg_type = 'accbundle-link'
                        else:
                            required.append('Cannot determine ipg_type from ipg_name, ' + ipg_name +
                                            'kindly use the standard naming convention, IPG_AC_ or IPG_vPC_ or IPG_PC_')
                            continue
                    else:
                        if aep_dict == {}:
                            aep_dict = self.session.get_aep_dict()
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name in ipg_dict.keys():
                            required.append('provided ipg ' + ipg_name + ' already exist ')
                            continue
                        if aep_name != 'None':
                            if aep_name not in aep_dict.keys():
                                required.append('provided aep ' + aep_name + ' does not exist ')
                                continue
                        if ipg_name.startswith('IPG_AC_'):
                            ipg_type = 'accportgrp'
                        elif ipg_name.startswith('IPG_vPC_'):
                            ipg_type = 'accbundle-node'
                        elif ipg_name.startswith('IPG_PC_'):
                            ipg_type = 'accbundle-link'
                        else:
                            required.append('Cannot determine ipg_type from ipg_name, ' + ipg_name +
                                            'kindly use the standard naming convention, IPG_AC_ or IPG_vPC_ or IPG_PC_')
                            continue
                    ipg_attr = {}
                    if speed_name != 'None':  ipg_attr['speed'] = speed_name
                    if aep_name != 'None':  ipg_attr['aep'] = aep_name
                    if lacp_name != 'None':  ipg_attr['lacp'] = lacp_name
                    if lldp_name != 'None':  ipg_attr['lldp'] = lldp_name
                    if cdp_name != 'None':  ipg_attr['cdp'] = cdp_name
                    if mcp_name != 'None':  ipg_attr['mcp'] = mcp_name
                    if l2int_name != 'None':  ipg_attr['l2int'] = l2int_name
                    if descr != 'None':  ipg_attr['descr'] = descr
                    if 'funcp' not in infra_obj_dict['infraFuncP'].keys():
                        infra_obj_dict['infraFuncP']['funcp'] = {"infraFuncP": {"attributes": {}, "children": []}}

                    infra_obj_dict['infraAccGrp'][ipg_type + '/' + ipg_name] = \
                        self.session.do_ipg(ipg_name, ipg_type, 'created', ipg_attr)

                if function == 'delete ipg':
                    try:
                        ipg_name = str(command['ipg'])
                    except:
                        required.append('require ipg')
                        continue

                    if validate == 'no':
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name in ipg_dict.keys():
                            ipg_type = ipg_dict[ipg_name]['type']
                        elif ipg_name.startswith('IPG_AC_'):
                            ipg_type = 'accportgrp'
                        elif ipg_name.startswith('IPG_vPC_'):
                            ipg_type = 'accbundle-node'
                        elif ipg_name.startswith('IPG_PC_'):
                            ipg_type = 'accbundle-link'
                        else:
                            required.append('Cannot determine ipg_type from ipg_name, ' + ipg_name +
                                            'kindly use the standard naming convention, IPG_AC_ or IPG_vPC_ or IPG_PC_')
                            continue
                    else:
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name not in ipg_dict.keys():
                            required.append('provided ipg ' + ipg_name + ' does not  exist ')
                            continue
                        else:
                            ipg_type = ipg_dict[ipg_name]['type']
                            if ipg_dict[ipg_name]['interfaces'] != []:
                                required.append('provided ipg ' + ipg_name + ' is assigned to an interface ')
                                continue
                    ipg_attr = None
                    if 'funcp' not in infra_obj_dict['infraFuncP'].keys():
                        infra_obj_dict['infraFuncP']['funcp'] = {"infraFuncP": {"attributes": {}, "children": []}}

                    infra_obj_dict['infraAccGrp'][ipg_type + '/' + ipg_name] = \
                        self.session.do_ipg(ipg_name, ipg_type, 'deleted', ipg_attr)

                if function == 'modify ipg':
                    try:
                        ipg_name = str(command['ipg'])
                        speed_name = str(command['speed'])
                        aep_name = str(command['aep'])
                        lacp_name = str(command['lacp'])
                        lldp_name = str(command['lldp'])
                        cdp_name = str(command['cdp'])
                        mcp_name = str(command['mcp'])
                        l2int_name = str(command['l2int'])
                        descr = str(command['descr'])
                    except:
                        required.append('require ipg speed aep lacp lldp cdp mcp l2int descr')
                        continue

                    if validate == 'no':
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name in ipg_dict.keys():
                            ipg_type = ipg_dict[ipg_name]['type']
                        elif ipg_name.startswith('IPG_AC_'):
                            ipg_type = 'accportgrp'
                        elif ipg_name.startswith('IPG_vPC_'):
                            ipg_type = 'accbundle-node'
                        elif ipg_name.startswith('IPG_PC_'):
                            ipg_type = 'accbundle-link'
                        else:
                            required.append('Cannot determine ipg_type from ipg_name, ' + ipg_name +
                                            'kindly use the standard naming convention, IPG_AC_ or IPG_vPC_ or IPG_PC_')
                            continue
                    else:
                        if aep_dict == {}:
                            aep_dict = self.session.get_aep_dict()
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if ipg_name not in ipg_dict.keys():
                            required.append('provided ipg ' + ipg_name + ' does not  exist ')
                            continue
                        else:
                            ipg_type = ipg_dict[ipg_name]['type']
                            if ipg_dict[ipg_name]['interfaces'] != [] and ipg_type == 'accportgrp':
                                required.append('provided ipg ' + ipg_name + ' is assigned to an interface ')
                                continue
                        if aep_name != 'None':
                            if aep_name not in aep_dict.keys():
                                required.append('provided aep ' + aep_name + ' does not exist ')
                                continue
                    ipg_attr = {}
                    if speed_name != 'None':  ipg_attr['speed'] = speed_name
                    if aep_name != 'None':  ipg_attr['aep'] = aep_name
                    if lacp_name != 'None':  ipg_attr['lacp'] = lacp_name
                    if lldp_name != 'None':  ipg_attr['lldp'] = lldp_name
                    if cdp_name != 'None':  ipg_attr['cdp'] = cdp_name
                    if mcp_name != 'None':  ipg_attr['mcp'] = mcp_name
                    if l2int_name != 'None':  ipg_attr['l2int'] = l2int_name
                    if descr != 'None':  ipg_attr['descr'] = descr
                    if 'funcp' not in infra_obj_dict['infraFuncP'].keys():
                        infra_obj_dict['infraFuncP']['funcp'] = {"infraFuncP": {"attributes": {}, "children": []}}

                    infra_obj_dict['infraAccGrp'][ipg_type + '/' + ipg_name] = \
                        self.session.do_ipg(ipg_name, ipg_type, 'modified', ipg_attr)

                if function == 'create fex':
                    try:
                        node_name = str(command['node'])
                        fromport_name = str(command['fromport'])
                        toport_name = str(command['toport'])
                        fex = str(command['fex'])
                        descr = 'FEX' + fex + '-' + str(command['cab'])
                    except:
                        required.append('require node fromport toport fex descr')
                        continue
                    if validate == 'no':
                        if node_name.isdigit():
                            node = node_name
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        if len(fromport_name.split('/')) > 2 or 'eth1/' not in fromport_name:
                            required.append('provided fromport ' + fromport_name + ' cannot be used as fex uplink')
                            continue
                        if len(toport_name.split('/')) > 2 or 'eth1/' not in toport_name:
                            required.append('provided toport ' + toport_name + ' cannot be used as fex uplink')
                            continue
                        if fex.isdigit():
                            pass
                        else:
                            required.append('provided fex ' + fex + ' must be a number')
                            continue
                        required.append('manually check node,port exist already')
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if fex_dict == {}:
                            fex_dict = self.session.get_fex_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + fromport_name not in port_dict.keys():
                            required.append('provided fromport ' + fromport_name + ' is not valid')
                            continue
                        if node + '-' + toport_name not in port_dict.keys():
                            required.append('provided toport ' + toport_name + ' is not valid')
                            continue
                        if len(fromport_name.split('/')) > 2 or 'eth1/' not in fromport_name:
                            required.append('provided fromport ' + fromport_name + ' cannot be used as fex uplink')
                            continue
                        if len(toport_name.split('/')) > 2 or 'eth1/' not in toport_name:
                            required.append('provided toport ' + toport_name + ' cannot be used as fex uplink')
                            continue
                        if fex.isdigit():
                            pass
                        else:
                            required.append('provided fex id ' + fex + '  must be a number')
                            continue
                        if fex in [','.join(sorted(fex_dict[fex_name]['fexid'])) for fex_name in fex_dict.keys()
                                   if node in fex_dict[fex_name]['nodes']]:
                            required.append('provided fex id ' + fex + ' is already in use on node ' + node_name)
                            continue
                        if 'IP_LEAF_' + node + '_fex' + fex + '/IP_LEAF_' + node + '_fex' + fex in fex_dict.keys():
                            required.append('provided fex id ' + fex + ' is already in use on fexname')
                            continue
                        ports = ['eth1/' + str(port_name) for port_name in
                                 range(int(fromport_name.split('/')[-1]), int(toport_name.split('/')[-1])+1)]
                        if ports == []:
                            required.append('at least one ports are required')
                            continue
                        port_ipg = []
                        for port_name in ports:
                            if port_dict[node + '-' + port_name]['ipg'] != '':
                                required.append(
                                    'provided port ' + node + '-' + port_name +
                                    ' is currently assigned to ' + port_dict[node + '-' + port_name]['ipg'])
                                port_ipg.append(port_name + ' : ' + port_dict[node + '-' + port_name]['ipg'])
                        if port_ipg != []:
                            continue
                        if int(fromport_name.split('/')[-1]) > int(toport_name.split('/')[-1]):
                            required.append(
                                'provided fromport ' + node + '-' + fromport_name +
                                ' is greater number than provided toport ' + node + '-' + toport_name)
                            continue
                    ipg_name = 'IP_LEAF_' + str(node) + '_fex' + str(fex)
                    ipg_type = 'fexbundle'
                    ports = [str(port_name.split('/')[-1]) for port_name in [fromport_name, toport_name]]
                    modules = [str(port_name.split('eth')[-1].split('/')[0]) for port_name in
                               [fromport_name, toport_name]]
                    int_profile_name = node
                    if int_profile_name not in infra_obj_dict['infraAccPortP'].keys():
                        infra_obj_dict['infraAccPortP'][int_profile_name] = \
                            self.session.do_int_profile(node, 'modified')
                    int_selector_name = int_profile_name + '/fex' + fex
                    if descr != 'None':
                        hport_attr = {'descr': descr}
                    else:
                        hport_attr = None
                    infra_obj_dict['infraHPortS'][int_selector_name] = \
                        self.session.do_fex_interface_selector(ports[0], ports[1], modules[0], modules[1], fex,
                                                               'created', ipg_name, hport_attr)
                    infra_obj_dict['infraFexP'][node + '-' + fex] = {
                        "infraFexP": {"attributes": {"name": ipg_name, "status": 'created'}, "children": []}}
                    infra_obj_dict['infraFexGrp'][node + '-' + fex] = self.session.do_ipg(ipg_name, ipg_type, 'created')

                if function == 'delete fex':
                    try:
                        node_name = str(command['node'])
                        fex = str(command['fex'])
                        selector = 'None'
                        leaf_profile = 'None'
                    except:
                        required.append('require node fromport toport fex')
                        continue
                    if validate == 'no':
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if fex_dict == {}:
                            fex_dict = self.session.get_fex_dict()
                        if node_name.isdigit():
                            node = node_name
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        if fex.isdigit():
                            pass
                        else:
                            required.append('provided fex ' + fex + ' must be a number')
                            continue
                        if fex not in [','.join(sorted(fex_dict[fex_name]['fexid'])) for fex_name in fex_dict.keys()
                                       if node in fex_dict[fex_name]['nodes']]:
                            required.append('provided fex id ' + fex + ' does not exit on node ' + node_name)
                            continue
                        ports = [sorted(fex_dict[fex_name]['interfaces']) for fex_name in fex_dict.keys()
                                 if node in fex_dict[fex_name]['nodes'] and fex_dict[fex_name]['fexid'] == [fex]][0]
                        port_selector = []
                        port_leaf_profile = []
                        for node_port_name in ports:
                            if port_dict[node_port_name]['selector'] not in port_selector:
                                port_selector.append(port_dict[node_port_name]['selector'])
                            if port_dict[node_port_name]['leaf_profile'] not in port_leaf_profile:
                                port_leaf_profile.append(port_dict[node_port_name]['leaf_profile'])
                        if len(port_selector) != 1:
                            required.append('Multiple Interface selector is used by fex: ' +
                                            ','.join(port_selector))
                            continue
                        else:
                            selector = port_selector[0]
                        if len(port_leaf_profile) != 1:
                            required.append('Multiple leaf_profile is used by fex: ' +
                                            ','.join(port_leaf_profile))
                            continue
                        else:
                            leaf_profile = port_leaf_profile[0]
                        required.append('manually check node fex exist already')
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if fex_dict == {}:
                            fex_dict = self.session.get_fex_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if fex.isdigit():
                            pass
                        else:
                            required.append('provided fex id ' + fex + '  must be a number')
                            continue
                        if fex not in [','.join(sorted(fex_dict[fex_name]['fexid'])) for fex_name in fex_dict.keys()
                                   if node in fex_dict[fex_name]['nodes']]:
                            required.append('provided fex id ' + fex + ' does not exit on node ' + node_name)
                            continue
                        ports = [sorted(fex_dict[fex_name]['interfaces']) for fex_name in fex_dict.keys()
                                 if node in fex_dict[fex_name]['nodes'] and fex_dict[fex_name]['fexid'] == [fex]][0]
                        port_operst = []
                        port_selector = []
                        port_leaf_profile = []
                        for node_port_name in ports:
                            if port_dict[node_port_name]['operst'] != 'down':
                                required.append(
                                    'provided port ' + node_port_name +
                                    ' is currently operst ' + port_dict[node_port_name]['operst'])
                                port_operst.append(node_port_name + ' : ' + port_dict[node_port_name]['operst'])
                            if port_dict[node_port_name]['selector'] not in port_selector:
                                port_selector.append(port_dict[node_port_name]['selector'])
                            if port_dict[node_port_name]['leaf_profile'] not in port_leaf_profile:
                                port_leaf_profile.append(port_dict[node_port_name]['leaf_profile'])
                        if port_operst != []:
                            continue
                        if len(port_selector) != 1:
                            required.append('Multiple Interface selector is used by fex: ' +
                                            ','.join(port_selector))
                            continue
                        else:
                            selector = port_selector[0]
                        if len(port_leaf_profile) != 1:
                            required.append('Multiple leaf_profile is used by fex: ' +
                                            ','.join(port_leaf_profile))
                            continue
                        else:
                            leaf_profile = port_leaf_profile[0]
                    ipg_name = [fex_name.split('/')[0] for fex_name in fex_dict.keys()
                                 if node in fex_dict[fex_name]['nodes'] and fex_dict[fex_name]['fexid'] == [fex]][0]
                    ipg_type = 'fexbundle'
                    int_profile_name = node
                    int_profile_attr = {}
                    if leaf_profile != 'None':
                        int_profile_attr['leaf_profile'] = leaf_profile
                        int_profile_name = leaf_profile
                    if int_profile_name not in infra_obj_dict['infraAccPortP'].keys():
                        infra_obj_dict['infraAccPortP'][int_profile_name] = \
                            self.session.do_int_profile(node, 'modified', int_profile_attr)
                    int_selector_name = int_profile_name + '/fex' + fex
                    hport_attr = {}
                    if selector != 'None':
                        hport_attr['selector'] = selector
                    infra_obj_dict['infraHPortS'][int_selector_name] = \
                        self.session.do_fex_interface_selector('None', 'None', 'None', 'None', fex,'deleted',
                                                               None, hport_attr)
                    infra_obj_dict['infraFexP'][node + '-' + fex] = {
                        "infraFexP": {"attributes": {"name": ipg_name, "status": 'deleted'}, "children": []}}

                if function == 'create tenant':
                    try:
                        tenant_name = str(command['tenant'])
                        descr = str(command['descr'])
                    except:
                        required.append('require tenant descr')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant does not exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if tenant_name in tenants:
                            required.append('provided tenant ' + tenant_name + ' already exist ')
                            continue
                    tenant_attr = {}
                    if descr != 'None':
                        tenant_attr = {'descr': descr}
                    tenant_obj_dict['fvTenant'][tenant_name] = \
                        self.session.do_tenant(tenant_name, 'created', tenant_attr)

                if function == 'delete tenant':
                    try:
                        tenant_name = str(command['tenant'])
                    except:
                        required.append('require tenant')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        if tenant_dict == {}:
                            tenant_dict = self.session.get_tenant_dict()
                        if tenant_dict[tenant_name]['epg'] != []:
                            required.append('provided tenant ' + tenant_name + ' has EPG/EPGs ')
                            continue

                    tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'deleted')

                if function == 'create context':
                    try:
                        tenant_name = str(command['tenant'])
                        ctx_name = str(command['ctx'])
                        descr = str(command['descr'])
                    except:
                        required.append('require tenant ctx')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if ctx_name_dict == {}:
                            ctx_name_dict = self.session.get_ctx_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        ctx_dn = 'uni/tn-' + tenant_name + '/ctx-' + ctx_name
                        if ctx_dn in ctx_name_dict.keys():
                            required.append('provided context ' + ctx_name + ' already exist ')
                            continue
                        if not ctx_name.startswith('VRF_'):
                            required.append(
                                'provided context ' + ctx_name + ' does not match naming convention VRF_<Function> ')
                            continue
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    ctx_attr = {'intractx': 'enforced'}
                    if descr != 'None': ctx_attr['descr'] = descr
                    tenant_obj_dict['fvCtx'][tenant_name + '/' + ctx_name] = \
                        self.session.do_context(ctx_name, 'created', ctx_attr)

                if function == 'delete context':
                    try:
                        tenant_name = str(command['tenant'])
                        ctx_name = str(command['ctx'])
                    except:
                        required.append('require tenant ctx')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if ctx_name_dict == {}:
                            ctx_name_dict = self.session.get_ctx_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        ctx_dn = 'uni/tn-' + tenant_name + '/ctx-' + ctx_name
                        if ctx_dn not in ctx_name_dict.keys():
                            required.append('provided context: ' + ctx_name + ' does not exist ')
                            continue
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    ctx_attr = None
                    tenant_obj_dict['fvCtx'][tenant_name + '/' + ctx_name] = \
                        self.session.do_context(ctx_name, 'deleted', ctx_attr)

                if function == 'create bd':
                    try:
                        tenant_name = str(command['tenant'])
                        ctx_name = str(command['ctx'])
                        bd_name = str(command['bd'])
                        bd_type = str(command['bd_type'])
                        subnet_name = str(command['subnet'])
                        scope = str(command['scope'])
                        l3out_name = str(command['l3out'])
                        descr = str(command['descr'])
                        bd_tenant_name = tenant_name
                    except:
                        required.append('require tenant ctx bd subnet scope l3out descr')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant, ctx, l3out exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if ctx_name_dict == {}:
                            ctx_name_dict = self.session.get_ctx_name_dict()
                        if bd_name_dict == {}:
                            bd_name_dict = self.session.get_bd_name_dict()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        if subnet_name != 'None' and bd_type == 'l3':
                            try:
                                subnet = netaddr.IPNetwork(str(subnet_name))
                                subnet_name = str(subnet.ip) + '/' + str(subnet.prefixlen)
                                if str(subnet.ip) == str(subnet.network):
                                    required.append('provided subnet ' + subnet_name + ' is a network address')
                                    continue
                                if str(subnet.ip) == str(subnet.broadcast):
                                    required.append('provided subnet ' + subnet_name + ' is a broadcast address')
                                    continue
                            except:
                                required.append('provided subnet ' + subnet_name + ' is not a valid IP address')
                                continue
                            if scope != 'private' and scope != 'public' and scope != 'private,shared':
                                required.append(
                                    'provided scope ' + scope + ' options are private, public, private,shared')
                                continue
                        ctx_dn = 'uni/tn-' + bd_tenant_name + '/ctx-' + ctx_name
                        if ctx_dn not in ctx_name_dict.keys():
                            if bd_tenant_name + '/' + ctx_name not in tenant_obj_dict['fvCtx'].keys():
                                required.append('provided context: ' + ctx_name + ' does not exist in the tenant ' +
                                            bd_tenant_name)
                                continue
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn in bd_name_dict.keys():
                            required.append('provided bd ' + bd_name + ' already exist in the tenant ' + bd_tenant_name)
                            continue
                        if not bd_name.startswith('BD_'):
                            required.append(
                                'provided bd ' + bd_name + ' does not match naming convention BD_<Function> ')
                            continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')
                    if bd_type == 'l2':
                         bd_attr = {'unicastRoute': 'no', 'limitiplearn': 'no', 'arpflood': 'yes',
                                    'unkunicast': 'flood'}
                    else:
                         bd_attr = {'unicastRoute': 'yes', 'limitiplearn': 'yes', 'arpflood': 'no',
                                    'unkunicast': 'proxy'}
                    if descr != 'None':
                        bd_attr['descr'] = descr
                    if l3out_name == 'None': l3out_name = None
                    bd = self.session.do_bd(bd_name, 'created', ctx_name, l3out_name, bd_attr)
                    tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = bd
                    subnet_attr = {'scope': scope}
                    if subnet_name == 'None': subnet_name = None
                    if subnet_name and bd_type != 'l2':
                        self.session.do_subnet_to_bd(subnet_name, bd, 'created', subnet_attr)

                if function == 'delete bd':
                    try:
                        tenant_name = str(command['tenant'])
                        bd_name = str(command['bd'])
                        bd_tenant_name = tenant_name
                    except:
                        required.append('require tenant bd')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant and bd exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        if bd_dict == {}:
                            bd_dict = self.session.get_bd_dict()
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn not in bd_dict.keys():
                            required.append(
                                'provided bd ' + bd_name + ' does not exist in the tenant ' + bd_tenant_name)
                            continue
                        else:
                            if bd_dict[bd_dn]['epg'] != []:
                                required.append(
                                    'provided bd ' + bd_name + ' is currently assigned to epg ' +
                                    ','.join(bd_dict[bd_dn]['epg']))
                                continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')
                    tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = \
                        self.session.do_bd(bd_name, 'deleted')

                if function == 'modify bd':
                    try:
                        tenant_name = str(command['tenant'])
                        ctx_name = str(command['ctx'])
                        bd_name = str(command['bd'])
                        routing = str(command['routing'])
                        arp = str(command['arp'])
                        unicast = str(command['unicast'])
                        mac = str(command['mac'])
                        descr = str(command['descr'])
                        bd_tenant_name = tenant_name
                    except:
                        required.append('require tenant ctx bd routing arp unicast mac descr')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant,app profile, and  epg already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        if ctx_name != 'None':
                            if ctx_dict == {}:
                                ctx_dict = self.session.get_ctx_name_dict()
                            ctx_dn = 'uni/tn-' + bd_tenant_name + '/ctx-' + ctx_name
                            if ctx_dn not in ctx_dict.keys():
                                required.append(
                                    'provided context ' + ctx_name + ' does not exist in the tenant ' + bd_tenant_name)
                                continue
                        if bd_dict == {}:
                            bd_dict = self.session.get_bd_dict()
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn not in bd_dict.keys():
                            required.append(
                                'provided bd ' + bd_name + ' does not exist in the tenant ' + bd_tenant_name)
                            continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')

                    if routing != 'None' or arp != 'None' or unicast != 'None'  or mac != 'None' or descr != 'None':
                        bd_attr = {}
                        if routing != 'None': bd_attr['unicastRoute'] = routing
                        if arp != 'None': bd_attr['arpflood'] = arp
                        if unicast != 'None': bd_attr['unkunicast'] = unicast
                        if mac != 'None': bd_attr['multicast'] = mac
                        if descr != 'None': bd_attr['descr'] = descr
                    else:
                        bd_attr = None
                    if ctx_name == 'None': ctx_name = None
                    tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = \
                        self.session.do_bd(bd_name, 'modified', ctx_name, None, bd_attr)

                if function == 'create app profile':
                    try:
                        tenant_name = str(command['tenant'])
                        app_name = str(command['app'])
                    except:
                        required.append('require tenant app')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn in app_name_dict.keys():
                            required.append('provided app profile ' + app_name + ' already exist ')
                            continue
                        if not app_name.startswith('AP_'):
                            required.append(
                                'provided app profile ' + app_name + ' does not match naming convention AP_<Function> ')
                            continue

                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = self.session.do_app(app_name, 'created')

                if function == 'delete app profile':
                    try:
                        tenant_name = str(command['tenant'])
                        app_name = str(command['app'])
                    except:
                        required.append('require tenantapp')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            required.append('provided app profile ' + app_name + ' does not exist ')
                            continue
                        else:
                            if epg_dict == {}:
                                epg_dict = self.session.get_epg_dict()
                            epgs = [epg_dn for epg_dn in epg_dict.keys() if
                                    app_dn == 'uni/tn-' + epg_dict[epg_dn]['tenant'] + '/ap-' + epg_dict[epg_dn]['app']]
                            if epgs:
                                required.append('provided app profile: ' + app_name + ' has EPG/EPGs ')
                                continue

                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = self.session.do_app(app_name, 'deleted')

                if function == 'create epg':
                    try:
                        tenant_name = str(command['tenant'])
                        bd_name = str(command['bd'])
                        app_name = str(command['app'])
                        epg_name = str(command['epg'])
                        domain_name = str(command['domain'])
                        descr = str(command['descr'])
                    except:
                        required.append('require tenant bd app epg domain descr')
                        continue
                    if validate == 'no':
                        if dom_dict == {}:
                            dom_dict = self.session.get_domain_dict()
                        if 'uni/phys-' + domain_name not in dom_dict.keys() and \
                                'uni/vmmp-VMware/dom-' + domain_name not in dom_dict.keys():
                            required.append('provided domain ' + domain_name + ' does not exist')
                            continue
                        else:
                            domain_type = str([dom_dict[dom]['type'] for dom in dom_dict.keys() if
                                               'uni/phys-' + domain_name == dom or
                                               'uni/vmmp-VMware/dom-' + domain_name == dom][0])
                        required.append('manually check tenant,app profile, and phys or vvm domain exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if bd_name_dict == {}:
                            bd_name_dict = self.session.get_bd_name_dict()
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                                required.append('provided app profile: ' + app_name + ' does not exist ')
                                continue
                        bd_dn = 'uni/tn-' + tenant_name + '/BD-' + bd_name
                        if bd_dn not in bd_name_dict.keys():
                            bd_dn = 'uni/tn-common/BD-' + bd_name
                            if bd_dn not in bd_name_dict.keys():
                                if tenant_name + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                                    if 'common' + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                                        required.append(
                                            'provided bd ' + bd_name + ' does not exist in the tenant ' + tenant_name +
                                            ' or in common tenant')
                                        continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + ' already exist in app profile ' + app_name)
                            continue
                        if dom_dict == {}:
                            dom_dict = self.session.get_domain_dict()
                        if 'uni/phys-' + domain_name not in dom_dict.keys() and \
                                'uni/vmmp-VMware/dom-' + domain_name not in dom_dict.keys():
                            required.append('provided domain ' + domain_name + ' does not exist')
                            continue
                        domain_type = str([dom_dict[dom]['type'] for dom in dom_dict.keys() if
                                           'uni/phys-' + domain_name == dom or
                                           'uni/vmmp-VMware/dom-' + domain_name == dom][0])
                        if not epg_name.startswith('EPG_'):
                            required.append(
                                'provided epg ' + epg_name + ' does not match naming convention EPG_<Function> ')
                            continue
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] =\
                            self.session.do_app(app_name, 'modified')
                    epg_attr = {'prefGrMemb': 'include', 'intraepg': 'unenforced'}
                    if descr != 'None': epg_attr['descr'] = descr
                    epg = self.session.do_epg(epg_name, 'created', bd_name, epg_attr)
                    tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = epg
                    self.session.do_domain_to_epg(domain_name, domain_type, epg, 'created')

                if function == 'delete epg':
                    try:
                        tenant_name = str(command['tenant'])
                        app_name = str(command['app'])
                        epg_name = str(command['epg'])
                    except:
                        required.append('require tenant app epg')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant,app profile, and  epg already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            required.append('provided app profile: ' + app_name + ' does not exist ')
                            continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn not in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + ' does not exist in the app profile ' +
                                            app_name)
                            continue
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    bd_name = None
                    epg_attr = None
                    epg = self.session.do_epg(epg_name, 'deleted', bd_name, epg_attr)
                    tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = epg

                if function == 'modify epg':
                    try:
                        tenant_name = str(command['tenant'])
                        bd_name = str(command['bd'])
                        app_name = str(command['app'])
                        epg_name = str(command['epg'])
                        prefgrp = str(command['prefgrp'])
                        intraepg = str(command['intraepg'])
                        descr = str(command['descr'])
                    except:
                        required.append('require tenant bd app epg prefgrp intraepg')
                        continue
                    if validate == 'no':
                        required.append('manually check tenant,app profile, and  epg already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            required.append('provided app profile: ' + app_name + ' does not exist ')
                            continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn not in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + 'does not exist in app profile ' + app_name)
                            continue
                        if bd_name != 'None':
                            if bd_name_dict == {}:
                                bd_name_dict = self.session.get_bd_name_dict()
                            bd_dn = 'uni/tn-' + tenant_name + '/BD-' + bd_name
                            if bd_dn not in bd_name_dict.keys():
                                bd_dn = 'uni/tn-common/BD-' + bd_name
                                if bd_dn not in bd_name_dict.keys():
                                    if tenant_name + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                                        if 'common' + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                                            required.append(
                                                'provided bd ' + bd_name + ' does not exist in the tenant ' +
                                                tenant_name + ' or in common tenant')
                                            continue
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    if bd_name == 'None': bd_name = None
                    if prefgrp != 'None' or intraepg != 'None' or descr != 'None':
                        epg_attr = {}
                        if prefgrp != 'None': epg_attr['prefgrp'] = prefgrp
                        if intraepg != 'None': epg_attr['intraepg'] = intraepg
                        if descr != 'None': epg_attr['descr'] = descr
                    else:
                        epg_attr = None
                    epg = self.session.do_epg(epg_name, 'modified', bd_name, epg_attr)
                    tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = epg

                if function == 'create network l3':
                    try:
                        tenant_name = str(command['tenant'])
                        ctx_name = str(command['ctx'])
                        app_name = str(command['app'])
                        domain_name = str(command['domain'])
                        subnet_name = str(command['subnet'])
                        scope = str(command['scope'])
                        l3out_name = str(command['l3out'])
                        descr = str(command['descr'])
                        bd_tenant_name = 'common'
                    except:
                        required.append('require tenant ctx app grpnum domain encap subnet scope descr')
                        continue
                    if validate == 'no':
                        if domain_name.startswith('PDOM'):
                            domain_type = 'physDomP'
                        else:
                            if dom_dict == {}:
                                dom_dict = self.session.get_domain_dict()
                            if 'uni/phys-' + domain_name not in dom_dict.keys() and \
                                    'uni/vmmp-VMware/dom-' + domain_name not in dom_dict.keys():
                                required.append('provided domain ' + domain_name + ' does not exist')
                                continue
                            else:
                                domain_type = str([dom_dict[dom]['type'] for dom in dom_dict.keys() if
                                                   'uni/phys-' + domain_name == dom or
                                                   'uni/vmmp-VMware/dom-' + domain_name == dom][0])
                        try:
                            subnet = netaddr.IPNetwork(str(subnet_name))
                            subnet_name = str(subnet.network) + '_' + str(subnet.prefixlen)
                            gateway = str(subnet[-2]) + '/' + str(subnet.prefixlen)
                            bd_name = 'BD_' + subnet_name
                            epg_name = 'EPG_' + subnet_name
                        except:
                            required.append('provided subnet ' + subnet_name + ' is not a valid IP address')
                            continue
                        required.append('manually check tenant,app profile, and phys or vvm domain exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if ctx_name_dict == {}:
                            ctx_name_dict = self.session.get_ctx_name_dict()
                        if bd_name_dict == {}:
                            bd_name_dict = self.session.get_bd_name_dict()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if dom_dict == {}:
                            dom_dict = self.session.get_domain_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                                required.append('provided app profile ' + app_name + ' does not exist ')
                                continue
                        if 'uni/phys-' + domain_name not in dom_dict.keys() and \
                                'uni/vmmp-VMware/dom-' + domain_name not in dom_dict.keys():
                            required.append('provided domain ' + domain_name + ' does not exist')
                            continue
                        else:
                            domain_type = str([dom_dict[dom]['type'] for dom in dom_dict.keys() if
                                               'uni/phys-' + domain_name == dom or
                                               'uni/vmmp-VMware/dom-' + domain_name == dom][0])
                        try:
                            subnet = netaddr.IPNetwork(str(subnet_name))
                            subnet_name = str(subnet.network) + '_' + str(subnet.prefixlen)
                            gateway = str(subnet[-2]) + '/' + str(subnet.prefixlen)
                            bd_name = 'BD_' + subnet_name
                            epg_name = 'EPG_' + subnet_name
                        except:
                            required.append('provided subnet ' + subnet_name + ' is not a valid IP address')
                            continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + ' already exist in the app profile ' +
                                            app_name)
                            continue
                        ctx_dn = 'uni/tn-' + bd_tenant_name + '/ctx-' + ctx_name
                        if ctx_dn not in ctx_name_dict.keys():
                            if bd_tenant_name + '/' + ctx_name not in tenant_obj_dict['fvCtx'].keys():
                                required.append('provided context: ' + ctx_name + ' does not exist in the tenant ' +
                                                bd_tenant_name)
                                continue
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn in bd_name_dict.keys():
                            required.append('provided bd ' + bd_name + ' already exist in the tenant ' + bd_tenant_name)
                            continue
                        if scope != 'private' and scope != 'public' and scope != 'private,shared':
                            required.append('provided scope ' + scope + ' options are private, public, private,shared')
                            continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    bd_attr = {'unicastRoute': 'yes', 'limitiplearn': 'yes', 'arpflood': 'no', 'unkunicast': 'proxy'}
                    if descr != 'None': bd_attr['descr'] = descr
                    bd = self.session.do_bd(bd_name, 'created', ctx_name, l3out_name, bd_attr)
                    tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = bd
                    subnet_attr = {'scope': scope}
                    self.session.do_subnet_to_bd(gateway, bd, 'created', subnet_attr)
                    epg_attr = {'prefgrp': 'include'}
                    if descr != 'None': epg_attr['descr'] = descr
                    epg = self.session.do_epg(epg_name, 'created', bd_name, epg_attr)
                    tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = epg
                    self.session.do_domain_to_epg(domain_name, domain_type, epg, 'created')

                if function == 'create network l2':
                    try:
                        tenant_name = str(command['tenant'])
                        ctx_name = str(command['ctx'])
                        app_name = str(command['app'])
                        grpnum = str(command['grpnum'])
                        domain_name = str(command['domain'])
                        encap = str(command['encap'])
                        descr = str(command['descr'])
                        l3out_name = None
                        bd_tenant_name = 'common'
                    except:
                        required.append('require tenant ctx app grpnum domain encap descr')
                        continue
                    if validate == 'no':
                        if domain_name.startswith('PDOM'):
                            domain_type = 'physDomP'
                        else:
                            if dom_dict == {}:
                                dom_dict = self.session.get_domain_dict()
                            if 'uni/phys-' + domain_name not in dom_dict.keys() and \
                                    'uni/vmmp-VMware/dom-' + domain_name not in dom_dict.keys():
                                required.append('provided domain ' + domain_name + ' does not exist')
                                continue
                            else:
                                domain_type = str([dom_dict[dom]['type'] for dom in dom_dict.keys() if
                                                   'uni/phys-' + domain_name == dom or
                                                   'uni/vmmp-VMware/dom-' + domain_name == dom][0])
                        if len(grpnum) != 2 and grpnum.isdigit():
                            required.append('provided group number ' + grpnum + ' must be a two digit number ')
                            continue
                        if encap.isdigit():
                            if len(encap) == 1:
                                encap = '000' + encap
                            elif len(encap) == 2:
                                encap = '00' + encap
                            elif len(encap) == 3:
                                encap = '0' + encap
                            elif len(encap) == 4:
                                pass
                            else:
                                required.append('provided vlan ' + encap + ' is more than a four digit number ')
                                continue
                        else:
                            required.append('provided vlan ' + encap + ' must be a number ')
                            continue
                        bd_name = 'BD_L2_VL' + encap + '_' + grpnum
                        epg_name = 'EPG_L2_VL' + encap + '_' + grpnum
                        required.append('manually check tenant,app profile, and phys or vvm domain exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if ctx_name_dict == {}:
                            ctx_name_dict = self.session.get_ctx_name_dict()
                        if bd_name_dict == {}:
                            bd_name_dict = self.session.get_bd_name_dict()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if dom_dict == {}:
                            dom_dict = self.session.get_domain_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                                required.append('provided app profile ' + app_name + ' does not exist ')
                                continue
                        if 'uni/phys-' + domain_name not in dom_dict.keys() and \
                                'uni/vmmp-VMware/dom-' + domain_name not in dom_dict.keys():
                            required.append('provided domain ' + domain_name + ' does not exist')
                            continue
                        else:
                            domain_type = str([dom_dict[dom]['type'] for dom in dom_dict.keys() if
                                               'uni/phys-' + domain_name == dom or
                                               'uni/vmmp-VMware/dom-' + domain_name == dom][0])
                        if len(grpnum) != 2 and grpnum.isdigit():
                            required.append('provided group number: ' + grpnum + ' must be a two digit number ')
                            continue
                        if encap.isdigit():
                            if len(encap) == 1:
                                encap = '000' + encap
                            elif len(encap) == 2:
                                encap = '00' + encap
                            elif len(encap) == 3:
                                encap = '0' + encap
                            elif len(encap) == 4:
                                pass
                            else:
                                required.append('provided vlan: ' + encap + ' is more than a four digit number ')
                                continue
                        else:
                            required.append('provided vlan ' + encap + ' must be a number ')
                            continue
                        bd_name = 'BD_L2_VL' + encap + '_' + grpnum
                        epg_name = 'EPG_L2_VL' + encap + '_' + grpnum
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + ' already exist in the app profile ' +
                                            app_name)
                            continue
                        ctx_dn = 'uni/tn-' + bd_tenant_name + '/ctx-' + ctx_name
                        if ctx_dn not in ctx_name_dict.keys():
                            if bd_tenant_name + '/' + ctx_name not in tenant_obj_dict['fvCtx'].keys():
                                required.append('provided context: ' + ctx_name + ' does not exist in the tenant ' +
                                                bd_tenant_name)
                                continue
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn in bd_name_dict.keys():
                            required.append('provided bd ' + bd_name + ' already exist in the tenant ' + bd_tenant_name)
                            continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')
                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    bd_attr = {'unicastRoute': 'no', 'limitiplearn': 'no', 'arpflood': 'yes', 'unkunicast': 'flood'}
                    if descr != 'None': bd_attr['descr'] = descr
                    bd = self.session.do_bd(bd_name, 'created', ctx_name, l3out_name, bd_attr)
                    tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = bd
                    epg_attr = {'prefgrp': 'include'}
                    if descr != 'None': epg_attr['descr'] = descr
                    epg = self.session.do_epg(epg_name, 'created', bd_name, epg_attr)
                    tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = epg
                    self.session.do_domain_to_epg(domain_name, domain_type, epg, 'created')

                if function == 'create static binding':
                    try:
                        tenant_name = str(command['tenant'])
                        app_name = str(command['app'])
                        epg_name = str(command['epg'])
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                        encap = str(command['encap'])
                        mode = str(command['mode'])
                        ipg_name = str(command['ipg'])
                        ipg_type = str(command['ipg_type'])
                        ipg_type_list = ['accbundle-node', 'accbundle-link', 'accportgrp', 'direct', 'vpc', 'pc']
                    except:
                        required.append('require tenant app epg node port ipg encap mode')
                        continue
                    if validate == 'no':
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if ipg_type == 'accbundle-node' or ipg_type == 'vpc' or ipg_type == 'accbundle-link' \
                                or ipg_type == 'pc':
                            if ipg_name == 'None':
                                required.append('require ipg_name if validate is no')
                                continue
                        if ipg_type not in ipg_type_list:
                            required.append(
                                'provided ipg_type ' + node_name + '-' + port_name + ' ' + ipg_type + ' is unknown')
                            continue
                        if node_name.isdigit():
                            node = node_name
                            if node in switch_vpcpair_dict.keys():
                                node1, node2 = sorted(switch_vpcpair_dict[node]['nodes'])
                            else:
                                print int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[1]) - \
                                      int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[0]) == 1,\
                                    int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[1]), \
                                    int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[0])
                                if int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[1]) - \
                                        int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[0]) == 1:
                                    if int(sorted(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'])[0]) % 2 == 0:
                                        if int(node) % 2 == 0:
                                            node1 = node
                                            node2 = str(int(node) + 1)
                                        else:
                                            node1 = str(int(node) - 1)
                                            node2 = node
                                    else:
                                        if int(node) % 2 == 0:
                                            node1 = str(int(node) - 1)
                                            node2 = node
                                        else:
                                            node1 = node
                                            node2 = str(int(node) + 1)
                                else:
                                    required.append('node id on fabric are not consecutive')
                                    continue
                            pod = '1'
                        else:
                            required.append('provided node must be a number if validate is no')
                            continue
                        if encap.isdigit():
                            encap = 'vlan-' + encap
                        else:
                            required.append('provided vlan ' + encap + ' must be a number ')
                            continue
                        if mode != 'regular' and mode != 'native' and mode != 'untagged':
                            required.append('provided mode ' + mode + ' must be a regular or native or untagged')
                            continue
                        required.append('manually check tenant,app profile,node,port already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if epg_dict == {}:
                            epg_dict = self.session.get_epg_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                                required.append('provided app profile: ' + app_name + ' does not exist ')
                                continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn not in epg_dict.keys():
                            if tenant_name + '/' + app_name + '/' + epg_name not in tenant_obj_dict['fvAEPg'].keys():
                                required.append('provided epg ' + epg_name + ' does not exist in the app profile ' +
                                            app_name)
                                continue
                            epg_obj_dict = tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name]
                        if encap.isdigit():
                            encap = 'vlan-' + encap
                        else:
                            required.append('provided vlan ' + encap + ' must be a number ')
                            continue
                        if mode != 'regular' and mode != 'native' and mode != 'untagged':
                            required.append('provided mode ' + mode + ' must be a regular or native or untagged')
                            continue
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        if port_dict[node + '-' + port_name]['epg'] != '':
                            if 'untagged' in port_dict[node + '-' + port_name]['mode']:
                                required.append(
                                    'provided port ' + node + '-' + port_name +
                                    ' is currently assigned to an epg as untagged')
                                continue
                            if 'native' in port_dict[node + '-' + port_name]['mode']:
                                if mode != 'regular':
                                    required.append(
                                        'provided port ' + node + '-' + port_name +
                                        ' is currently assigned to an epg as native ')
                                    continue
                            if encap in port_dict[node + '-' + port_name]['encap']:
                                required.append('provided port ' + node + '-' + port_name + ' already bound to ' +
                                                encap + ' on another epg')
                                continue
                            if 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name in \
                                    port_dict[node + '-' + port_name]['epg']:
                                required.append('provided port ' + node + '-' + port_name + ' already bound to epg ' +
                                                epg_name)
                                continue
                        if ipg_name != 'None':
                            if ipg_name != port_dict[node + '-' + port_name]['ipg']:
                                required.append('provided ipg name ' + ipg_name + ' does not match ipg on ' +
                                                node + '-' + port_name + ' which is ' +
                                                port_dict[node + '-' + port_name]['ipg'])
                                continue
                        ipg_name = port_dict[node + '-' + port_name]['ipg']
                        if ipg_name == '':
                            required.append('provided port  ' + node + '-' + port_name +
                                            ' is currently not assigned to an ipg')
                            continue
                        else:
                            if ipg_name in ipg_dict.keys():
                                if ipg_type == 'vpc' or ipg_type == 'accbundle-node':
                                    if port_dict[node + '-' + port_name]['type'] != 'accbundle-node':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a vpc port')
                                        continue
                                if ipg_type == 'pc' or ipg_type == 'accbundle-link':
                                    if port_dict[node + '-' + port_name]['type'] != 'accbundle-link':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a pc port')
                                        continue
                                if ipg_type == 'direct' or ipg_type == 'accportgrp':
                                    if port_dict[node + '-' + port_name]['type'] != 'accportgrp':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a direct port')
                                        continue
                                ipg_type = ipg_dict[ipg_name]['type']
                                ipg_aep_doms = ipg_dict[ipg_name]['domain']
                                ipg_epg_dom_list = [ipg_aep_dom for ipg_aep_dom in ipg_aep_doms if
                                                    'uni/phys-' + ipg_aep_dom in epg_dict[epg_dn]['domain']]
                                if ipg_epg_dom_list == []:
                                    epg_dom_obj_dict = {}
                                    if tenant_name + '/' + app_name + '/' + epg_name in tenant_obj_dict['fvAEPg'].keys():
                                        epg_obj_dict = tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name]
                                        for ipg_aep_dom in ipg_aep_doms:
                                            epg_dom_obj_dict = self.session.get_obj_dict(
                                                'fvRsDomAtt', 'fvAEPg', epg_obj_dict, 'uni/phys-' + ipg_aep_dom, 'tDn')
                                            if epg_dom_obj_dict != {}:
                                                break
                                    if epg_dom_obj_dict == {}:
                                        required.append('provided physical domains on port ' +
                                                        node + '-' + port_name +
                                                        ' does not match those available on the epg ' + epg_name)
                                        continue

                            else:
                                required.append('provided ipg_name ' + ipg_name + ' is unknown')
                                continue
                        if ipg_type not in ipg_type_list:
                            required.append(
                                'provided port type ' + node_name + '-' + port_name + ' ' + ipg_type + ' is unknown')
                            continue

                        node = str(switch_dict[node_name]['id'])
                        pod = str(switch_dict[node_name]['pod'])
                        if node in switch_vpcpair_dict.keys():
                            node1, node2 = sorted(switch_vpcpair_dict[node]['nodes'])
                        else:
                            node1 = node
                            node2 = 'None'

                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    if tenant_name + '/' + app_name + '/' + epg_name not in tenant_obj_dict['fvAEPg'].keys():
                        tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = self.session.do_epg(
                            epg_name, 'modified')
                    if ipg_type == 'accbundle-node' or ipg_type == 'vpc':
                        host = ipg_name
                        if node2 != 'None':
                            path = 'topology/pod-' + pod + '/protpaths-' + node1 + '-' + node2 + '/pathep-[' + host + ']'
                    elif ipg_type == 'accbundle-link' or ipg_type == 'pc':
                        host = ipg_name
                        path = 'topology/pod-' + pod + '/protpaths-' + node + '/pathep-[' + host + ']'
                    elif ipg_type == 'accportgrp' or ipg_type == 'direct':
                        host = port_name
                        if len(port_name.split('/')) > 2:
                            fex = str(port_name.split('eth')[1].split('/')[0])
                            host = 'eth' + str(port_name.split('eth' + fex + '/')[1])
                            path = 'topology/pod-' + pod + '/paths-' + node + '/extpaths-' + fex + '/pathep-[' + host + ']'
                        else:
                            path = 'topology/pod-' + pod + '/paths-' + node + '/pathep-[' + host + ']'
                    path_attr = {'mode': mode, 'imedcy': 'lazy', 'encap': encap}
                    tenant_obj_dict['fvRsPathAtt'][tenant_name + '/' + app_name + '/' + epg_name + '/' + path] = \
                        self.session.do_static_port(path, 'created', path_attr)

                if function == 'delete static binding':
                    try:
                        tenant_name = str(command['tenant'])
                        app_name = str(command['app'])
                        epg_name = str(command['epg'])
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                        ipg_name = str(command['ipg'])
                        ipg_type = str(command['ipg_type'])
                        ipg_type_list = ['accbundle-node', 'accbundle-link', 'accportgrp', 'direct', 'vpc', 'pc']
                    except:
                        required.append('require tenant app epg node port ipg ipg_type')
                        continue
                    if validate == 'no':
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if ipg_type == 'accbundle-node' or ipg_type == 'vpc' or ipg_type == 'accbundle-link' \
                                or ipg_type == 'pc':
                            if ipg_name == 'None':
                                required.append('require ipg_name if validate is no')
                                continue
                        if ipg_type not in ipg_type_list:
                            required.append(
                                'provided port type ' + node_name + '-' + port_name + ' ' + ipg_type + ' is unknown')
                            continue
                        if node_name.isdigit():
                            node = node_name
                            if node in switch_vpcpair_dict.keys():
                                node1, node2 = sorted(switch_vpcpair_dict[node]['nodes'])
                            else:
                                if int(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'][1]) - int(
                                        switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'][0]) == 1:
                                    if int(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'][0]) % 2 == 0:
                                        if int(node) % 2 == 0:
                                            node1 = node
                                            node2 = str(int(node) + 1)
                                        else:
                                            node1 = str(int(node) - 1)
                                            node2 = node
                                    else:
                                        if int(node) % 2 == 0:
                                            node1 = str(int(node) - 1)
                                            node2 = node
                                        else:
                                            node1 = node
                                            node2 = str(int(node) + 1)
                                else:
                                    required.append('provided node1 ' + node1 + ' and node2 ' + node2 +
                                                    ' are not consecutive')
                                    continue

                            pod = '1'
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        required.append('manually check tenant,app profile,node,port already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            required.append('provided app profile ' + app_name + ' does not exist ')
                            continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn not in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + ' does not exist in the app profile ' +
                                            app_name)
                            continue
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        if 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name not in \
                                port_dict[node + '-' + port_name]['epg']:
                            required.append('provided port ' + node + '-' + port_name + ' is not bound to epg ' +
                                            epg_name)
                            continue
                        if ipg_name != 'None':
                            if ipg_name != port_dict[node + '-' + port_name]['ipg']:
                                required.append('provided ipg name ' + ipg_name + ' does not match ipg on ' +
                                                node + '-' + port_name + ' which is ' +
                                                port_dict[node + '-' + port_name]['ipg'])
                                continue
                        ipg_name = port_dict[node + '-' + port_name]['ipg']
                        if ipg_name == '':
                            required.append('provided port  ' + node + '-' + port_name +
                                            ' is currently not assigned to an ipg')
                            continue
                        else:
                            if ipg_name in ipg_dict.keys():
                                if ipg_type == 'vpc' or ipg_type == 'accbundle-node':
                                    if port_dict[node + '-' + port_name]['type'] != 'accbundle-node':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a vpc port')
                                        continue
                                if ipg_type == 'pc' or ipg_type == 'accbundle-link':
                                    if port_dict[node + '-' + port_name]['type'] != 'accbundle-link':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a pc port')
                                        continue
                                if ipg_type == 'direct' or ipg_type == 'accportgrp':
                                    if port_dict[node + '-' + port_name]['type'] != 'accportgrp':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a direct port')
                                        continue
                                ipg_type = ipg_dict[ipg_name]['type']
                            else:
                                required.append('ipg_name ' + ipg_name + ' is unknown')
                                continue
                        if ipg_type not in ipg_type_list:
                            required.append(
                                'provided port type ' + node_name + '-' + port_name + ' ' + ipg_type + ' is unknown')
                            continue

                        node = str(switch_dict[node_name]['id'])
                        pod = str(switch_dict[node_name]['pod'])
                        if node in switch_vpcpair_dict.keys():
                            node1, node2 = sorted(switch_vpcpair_dict[node]['nodes'])
                        else:
                            node1 = node
                            node2 = 'None'

                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    if tenant_name + '/' + app_name + '/' + epg_name not in tenant_obj_dict['fvAEPg'].keys():
                        tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = \
                            self.session.do_epg(epg_name, 'modified')

                    if ipg_type == 'accbundle-node' or ipg_type == 'vpc':
                        host = ipg_name
                        if node2 != 'None':
                            path = 'topology/pod-' + pod + '/protpaths-' + node1 + '-' + node2 + \
                                   '/pathep-[' + host + ']'
                    elif ipg_type == 'accbundle-link' or ipg_type == 'pc':
                        host = ipg_name
                        path = 'topology/pod-' + pod + '/protpaths-' + node + '/pathep-[' + host + ']'
                    elif ipg_type == 'accportgrp' or ipg_type == 'direct':
                        host = port_name
                        if len(port_name.split('/')) > 2:
                            fex = str(port_name.split('eth')[1].split('/')[0])
                            host = 'eth' + str(port_name.split('eth' + fex + '/')[1])
                            path = 'topology/pod-' + pod + '/paths-' + node + '/extpaths-' + fex + \
                                   '/pathep-[' + host + ']'
                        else:
                            path = 'topology/pod-' + pod + '/paths-' + node + '/pathep-[' + host + ']'
                    path_attr = None
                    tenant_obj_dict['fvRsPathAtt'][tenant_name + '/' + app_name + '/' + epg_name + '/' + path] = \
                        self.session.do_static_port(path, 'deleted', path_attr)

                if function == 'modify static binding':
                    try:
                        tenant_name = str(command['tenant'])
                        app_name = str(command['app'])
                        epg_name = str(command['epg'])
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                        encap = str(command['encap'])
                        mode = str(command['mode'])
                        ipg_name = str(command['ipg'])
                        ipg_type = str(command['ipg_type'])
                        ipg_type_list = ['accbundle-node', 'accbundle-link', 'accportgrp', 'direct', 'vpc', 'pc']
                    except:
                        required.append('require tenant app epg node port ipg ipg_type')
                        continue
                    if validate == 'no':
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if ipg_type == 'accbundle-node' or ipg_type == 'vpc' or ipg_type == 'accbundle-link' \
                                or ipg_type == 'pc':
                            if ipg_name == 'None':
                                required.append('require ipg_name if validate is no')
                                continue
                        if ipg_type not in ipg_type_list:
                            required.append(
                                'provided port type ' + node_name + '-' + port_name + ' ' + ipg_type + ' is unknown')
                            continue
                        if node_name.isdigit():
                            node = node_name
                            if node in switch_vpcpair_dict.keys():
                                node1, node2 = sorted(switch_vpcpair_dict[node]['nodes'])
                            else:
                                if int(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'][1]) - int(
                                        switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'][0]) == 1:
                                    if int(switch_vpcpair_dict[switch_vpcpair_dict.keys()[0]]['nodes'][0]) % 2 == 0:
                                        if int(node) % 2 == 0:
                                            node1 = node
                                            node2 = str(int(node) + 1)
                                        else:
                                            node1 = str(int(node) - 1)
                                            node2 = node
                                    else:
                                        if int(node) % 2 == 0:
                                            node1 = str(int(node) - 1)
                                            node2 = node
                                        else:
                                            node1 = node
                                            node2 = str(int(node) + 1)
                                else:
                                    required.append('provided node1 ' + node1 + ' and node2 ' + node2 +
                                                    ' are not consecutive')
                                    continue

                            pod = '1'
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        if encap != 'None':
                            if encap.isdigit():
                                encap = 'vlan-' + encap
                            else:
                                required.append('provided vlan ' + encap + ' must be a number ')
                                continue
                        if mode != 'None':
                            if mode != 'regular' and mode != 'native' and mode != 'untagged':
                                required.append('provided mode ' + mode + ' must be a regular or native or untagged')
                                continue
                        required.append('manually check tenant,app profile,node,port already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if ipg_dict == {}:
                            ipg_dict = self.session.get_ipg_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if epg_name_dict == {}:
                            epg_name_dict = self.session.get_epg_name_dict()
                        if app_name_dict == {}:
                            app_name_dict = self.session.get_app_name_dict()
                        if tenant_name not in tenants:
                            required.append('provided tenant ' + tenant_name + ' does not exist ')
                            continue
                        app_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name
                        if app_dn not in app_name_dict.keys():
                            required.append('provided app profile ' + app_name + ' does not exist ')
                            continue
                        epg_dn = 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name
                        if epg_dn not in epg_name_dict.keys():
                            required.append('provided epg ' + epg_name + ' does not exist in the app profile ' +
                                            app_name)
                            continue
                        if encap != 'None':
                            if encap.isdigit():
                                encap = 'vlan-' + encap
                            else:
                                required.append('provided vlan ' + encap + ' must be a number ')
                                continue
                        if mode != 'None':
                            if mode != 'regular' and mode != 'native' and mode != 'untagged':
                                required.append('provided mode ' + mode + ' must be a regular or native or untagged')
                                continue
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        if mode != 'None':
                            if port_dict[node + '-' + port_name]['epg'] != '':
                                if 'untagged' in port_dict[node + '-' + port_name]['mode']:
                                    if mode != 'untagged':
                                        required.append(
                                            'provided port ' + node + '-' + port_name +
                                            ' is currently assigned to an epg as untagged')
                                        continue
                                if 'native' in port_dict[node + '-' + port_name]['mode']:
                                    if mode != 'regular':
                                        required.append(
                                            'provided port ' + node + '-' + port_name +
                                            ' is currently assigned to an epg as native ')
                                        continue
                        if encap != 'None':
                            if encap in port_dict[node + '-' + port_name]['encap']:
                                required.append('provided port ' + node + '-' + port_name + ' already bound to ' +
                                                encap + ' on another epg')
                                continue
                        if 'uni/tn-' + tenant_name + '/ap-' + app_name + '/epg-' + epg_name not in \
                                port_dict[node + '-' + port_name]['epg']:
                            required.append('provided port ' + node + '-' + port_name + ' is not bound to epg ' +
                                            epg_name)
                            continue
                        if ipg_name != 'None':
                            if ipg_name != port_dict[node + '-' + port_name]['ipg']:
                                required.append('provided ipg name ' + ipg_name + ' does not match ipg on ' +
                                                node + '-' + port_name + ' which is ' +
                                                port_dict[node + '-' + port_name]['ipg'])
                                continue
                        ipg_name = port_dict[node + '-' + port_name]['ipg']
                        if ipg_name == '':
                            required.append('provided port  ' + node + '-' + port_name +
                                            ' is currently not assigned to an ipg')
                            continue
                        else:
                            if ipg_name in ipg_dict.keys():
                                if ipg_type == 'vpc' or ipg_type == 'accbundle-node':
                                    if port_dict[node + '-' + port_name]['type'] != 'accbundle-node':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a vpc port')
                                        continue
                                if ipg_type == 'pc' or ipg_type == 'accbundle-link':
                                    if port_dict[node + '-' + port_name]['type'] != 'accbundle-link':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a pc port')
                                        continue
                                if ipg_type == 'direct' or ipg_type == 'accportgrp':
                                    if port_dict[node + '-' + port_name]['type'] != 'accportgrp':
                                        required.append('provided port ' + node + '-' + port_name +
                                                        ' is not a direct port')
                                        continue
                                ipg_type = ipg_dict[ipg_name]['type']
                            else:
                                required.append('ipg_name ' + ipg_name + ' is unknown')
                                continue
                        if ipg_type not in ipg_type_list:
                            required.append(
                                'provided port type ' + node_name + '-' + port_name + ' ' + ipg_type + ' is unknown')
                            continue

                        node = str(switch_dict[node_name]['id'])
                        pod = str(switch_dict[node_name]['pod'])
                        if node in switch_vpcpair_dict.keys():
                            node1, node2 = sorted(switch_vpcpair_dict[node]['nodes'])
                        else:
                            node1 = node
                            node2 = 'None'

                    if tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][tenant_name] = self.session.do_tenant(tenant_name, 'modified')
                    if tenant_name + '/' + app_name not in tenant_obj_dict['fvAp'].keys():
                        tenant_obj_dict['fvAp'][tenant_name + '/' + app_name] = \
                            self.session.do_app(app_name, 'modified')
                    if tenant_name + '/' + app_name + '/' + epg_name not in tenant_obj_dict['fvAEPg'].keys():
                        tenant_obj_dict['fvAEPg'][tenant_name + '/' + app_name + '/' + epg_name] = \
                            self.session.do_epg(epg_name, 'modified')

                    if ipg_type == 'accbundle-node' or ipg_type == 'vpc':
                        host = ipg_name
                        if node2 != 'None':
                            path = 'topology/pod-' + pod + '/protpaths-' + node1 + '-' + node2 + \
                                   '/pathep-[' + host + ']'
                    elif ipg_type == 'accbundle-link' or ipg_type == 'pc':
                        host = ipg_name
                        path = 'topology/pod-' + pod + '/protpaths-' + node + '/pathep-[' + host + ']'
                    elif ipg_type == 'accportgrp' or ipg_type == 'direct':
                        host = port_name
                        if len(port_name.split('/')) > 2:
                            fex = str(port_name.split('eth')[1].split('/')[0])
                            host = 'eth' + str(port_name.split('eth' + fex + '/')[1])
                            path = 'topology/pod-' + pod + '/paths-' + node + '/extpaths-' + fex + \
                                   '/pathep-[' + host + ']'
                        else:
                            path = 'topology/pod-' + pod + '/paths-' + node + '/pathep-[' + host + ']'
                    if mode != 'None' or encap != 'None':
                        path_attr = {}
                        if mode != 'None': path_attr['mode'] = mode
                        if encap != 'None': path_attr['encap'] = encap
                    else:
                        path_attr = None
                    tenant_obj_dict['fvRsPathAtt'][tenant_name + '/' + app_name + '/' + epg_name + '/' + path] = \
                        self.session.do_static_port(path, 'modified', path_attr)

                if function == 'create dhcprelay label':
                    try:
                        dhcprelay_name = str(command['dhcprelay'])
                        bd_name = str(command['bd'])
                        bd_tenant_name = 'common'
                    except:
                        required.append('require dhcprelay bd')
                        continue
                    if validate == 'no':
                        required.append('manually check dhcprelay, bd already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if dhcprelay_dict == {}:
                            dhcprelay_dict = self.session.get_dhcprelay_name_dict()
                        if bd_dict == {}:
                            bd_dict = self.session.get_bd_dict()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn not in bd_dict.keys():
                            if bd_tenant_name + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                                required.append(
                                    'provided bd ' + bd_name + ' does not exist in the tenant ' + bd_tenant_name)
                                continue
                        if dhcprelay_name not in dhcprelay_dict.keys():
                                required.append('provided dhcprelay ' + dhcprelay_name + ' does not exist')
                                continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')
                    if bd_tenant_name + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                        tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = self.session.do_bd(bd_name,'modified')
                    tenant_obj_dict['dhcpLbl'][bd_tenant_name + '/' + bd_name + '/' + dhcprelay_name] = \
                        self.session.do_dhcprelay_label(dhcprelay_name, 'created')

                if function == 'delete dhcprelay label':
                    try:
                        dhcprelay_name = str(command['dhcprelay'])
                        bd_name = str(command['bd'])
                        bd_tenant_name = 'common'
                    except:
                        required.append('require dhcprelay bd')
                        continue
                    if validate == 'no':
                        required.append('manually check dhcprelay, bd already exist ')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if dhcprelay_dict == {}:
                            dhcprelay_dict = self.session.get_dhcprelay_name_dict()
                        if bd_dict == {}:
                            bd_dict = self.session.get_bd_dict()
                        if bd_tenant_name not in tenants:
                            required.append('provided tenant ' + bd_tenant_name + ' does not exist ')
                            continue
                        bd_dn = 'uni/tn-' + bd_tenant_name + '/BD-' + bd_name
                        if bd_dn not in bd_dict.keys():
                            required.append(
                                'provided bd ' + bd_name + ' does not exist in the tenant ' + bd_tenant_name)
                            continue
                        if dhcprelay_name not in dhcprelay_dict.keys():
                            required.append('provided dhcprelay ' + dhcprelay_name + ' does not exist')
                            continue
                    if bd_tenant_name not in tenant_obj_dict['fvTenant'].keys():
                        tenant_obj_dict['fvTenant'][bd_tenant_name] = self.session.do_tenant(bd_tenant_name, 'modified')
                    if bd_tenant_name + '/' + bd_name not in tenant_obj_dict['fvBD'].keys():
                        tenant_obj_dict['fvBD'][bd_tenant_name + '/' + bd_name] = self.session.do_bd(bd_name,'modified')
                    tenant_obj_dict['dhcpLbl'][bd_tenant_name + '/' + bd_name + '/' + dhcprelay_name] = \
                        self.session.do_dhcprelay_label(dhcprelay_name, 'deleted')

                if function == 'create vlanid':
                    try:
                        vlanpool_name = str(command['vlanpool'])
                        encap = str(command['encap'])
                    except:
                        required.append('require vlanpool')
                        continue
                    if validate == 'no':
                        if encap.isdigit():
                            encap = 'vlan-' + encap
                        else:
                            required.append('provided vlan ' + encap + ' must be a number ')
                            continue
                        required.append('manually check vlanpool already exist ')
                    else:
                        if vlanpool_dict == {}:
                            vlanpool_dict = self.session.get_vlanpool_dict()
                        poolvlan = [vlanpool for vlanpool in vlanpool_dict.keys() if
                                            vlanpool_dict[vlanpool]['name'] == vlanpool_name and
                                            vlanpool_dict[vlanpool]['type'] == 'static']
                        if len(poolvlan) == 0:
                            required.append('provided static vlanpool ' + vlanpool_name + ' does not exist')
                            continue
                        if encap.isdigit():
                            if int(encap) in vlanpool_dict[poolvlan[0]]['vlan']:
                                required.append('provided vlanid ' + encap + ' already exist in ' + vlanpool_name)
                                continue
                        if encap.isdigit():
                            encap = 'vlan-' + encap
                        else:
                            required.append('provided vlan ' + encap + ' must be a number ')
                            continue
                    if vlanpool_name not in infra_obj_dict['fvnsVlanInstP'].keys():
                        infra_obj_dict['fvnsVlanInstP'][vlanpool_name] = \
                            self.session.do_vlanpool(vlanpool_name, 'static', 'modified')
                    infra_obj_dict['fvnsEncapBlk'][vlanpool_name + '/' + encap] = \
                        self.session.do_vlanpool_encap(encap, encap, 'created')

                if function == 'disable port':
                    try:
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                    except:
                        required.append('require node port')
                        continue
                    if validate == 'no':
                        if node_name.isdigit():
                            node = node_name
                            pod = '1'
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        required.append('manually check pod is 1 and node,port exist already')
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                            pod = str(switch_dict[node_name]['pod'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        if port_dict[node + '-' + port_name]['adminst'] != 'up':
                            required.append('provided port ' + node + '-' + port_name +
                                            ' admin status is ' + port_dict[node + '-' + port_name]['adminst'])
                            continue
                    host = port_name
                    if len(port_name.split('/')) > 2:
                        fex = str(port_name.split('eth')[1].split('/')[0])
                        host = 'eth' + str(port_name.split('eth' + fex + '/')[1])
                        path = 'topology/pod-' + pod + '/paths-' + node + '/extpaths-' + fex + '/pathep-[' + host + ']'
                    else:
                        path = 'topology/pod-' + pod + '/paths-' + node + '/pathep-[' + host + ']'
                    if 'outofsvc' not in fabric_obj_dict['fabricOOServicePol'].keys():
                        fabric_obj_dict['fabricOOServicePol']['outofsvc'] = {
                            "fabricOOServicePol": {"attributes": {}, "children": []}}

                    fabric_obj_dict['fabricRsOosPath'][node_name + '-' + port_name] = \
                        self.session.do_oospath(path, 'created')

                if function == 'enable port':
                    try:
                        node_name = str(command['node'])
                        port_name = str(command['port'])
                    except:
                        required.append('require node port')
                        continue
                    if validate == 'no':
                        if node_name.isdigit():
                            node = node_name
                            pod = '1'
                        else:
                            required.append('provided node ' + node_name + ' must be a number if validate is no')
                            continue
                        required.append('manually check pod is 1 and node,port exist already')
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node_name not in switch_dict.keys():
                            required.append('provided node ' + node_name + ' is not valid')
                            continue
                        else:
                            node = str(switch_dict[node_name]['id'])
                            pod = str(switch_dict[node_name]['pod'])
                        if node + '-' + port_name not in port_dict.keys():
                            required.append('provided port ' + node + '-' + port_name + ' is not valid')
                            continue
                        if port_dict[node + '-' + port_name]['adminst'] != 'down':
                            required.append('provided port ' + node + '-' + port_name +
                                            ' admin status is ' + port_dict[node + '-' + port_name]['adminst'])
                            continue
                    host = port_name
                    if len(port_name.split('/')) > 2:
                        fex = str(port_name.split('eth')[1].split('/')[0])
                        host = 'eth' + str(port_name.split('eth' + fex + '/')[1])
                        path = 'topology/pod-' + pod + '/paths-' + node + '/extpaths-' + fex + '/pathep-[' + host + ']'
                    else:
                        path = 'topology/pod-' + pod + '/paths-' + node + '/pathep-[' + host + ']'
                    if 'outofsvc' not in fabric_obj_dict['fabricOOServicePol'].keys():
                        fabric_obj_dict['fabricOOServicePol']['outofsvc'] = {
                            "fabricOOServicePol": {"attributes": {}, "children": []}}

                    fabric_obj_dict['fabricRsOosPath'][node_name + '-' + port_name] = \
                        self.session.do_oospath(path, 'deleted')
                
                if function == 'create switch':
                    try:
                        node1 = str(command['node1'])
                        node2 = str(command['node2'])
                        vpc_id = str(command['vpc_id'])
                    except:    
                        required.append('require node1 node2 vpc_id')
                        continue
                    if validate == 'no':
                        if node1 != 'None':
                            if  node1.isdigit():
                                pass
                            else:
                                required.append('provided node1 ' + node1 + ' must be a number if validate is no')
                                continue
                        if node2 != 'None':
                            if  node2.isdigit():
                                pass
                            else:
                                required.append('provided node2 ' + node2 + ' must be a number if validate is no')
                                continue
                    else:
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if vpcpair_dict == {}:
                            vpcpair_dict = self.session.get_vpcpair_dict()
                        if switch_vpcpair_dict == {}:
                            switch_vpcpair_dict = self.session.get_switch_vpcpair_dict()
                        if node1 != 'None':
                            if node1 not in switch_dict.keys():
                                required.append('provided node1 ' + node1 + ' is not valid')
                                continue
                            else:
                                node1 = str(switch_dict[str(node1)]['id'])
                        if node2 != 'None':
                            if node2 not in switch_dict.keys():
                                required.append('provided node2 ' + node2 + ' is not valid')
                                continue
                            else:
                                node2 = str(switch_dict[str(node2)]['id'])
                        if node1 != 'None' and node2 != 'None':
                            if int(node1) >= int(node2):
                                required.append('provided node1 ' + node1 + ' should be less than node2 ' + node2)
                                continue
                        if node1 in switch_vpcpair_dict.keys():
                            required.append('There is already a vpc pair between nodes ' +
                                            ' and '.join(switch_vpcpair_dict[node1]['nodes']))
                            continue
                        if node2 in switch_vpcpair_dict.keys():
                            required.append('There is already a vpc pair between nodes ' +
                                            ' and '.join(switch_vpcpair_dict[node2]['nodes']))
                            continue
                        if vpc_id in vpcpair_dict.keys():
                            required.append('provided vpc_id ' + vpc_id + ' is already in use by nodes ' +
                                           ', '.join(vpcpair_dict[vpc_id]['nodes']))
                            continue
                    if node1 != 'None':
                        infra_obj_dict['infraNodeP'][node1] = self.session.do_switch_profile(node1, 'created', True)
                        infra_obj_dict['infraAccPortP'][node1] = self.session.do_int_profile(node1, 'created')
                    if node2 != 'None':
                        infra_obj_dict['infraNodeP'][node2] = self.session.do_switch_profile(node2, 'created', True)
                        infra_obj_dict['infraAccPortP'][node2] = self.session.do_int_profile(node2, 'created')                        
                    if node1 != 'None' and node2 != 'None':   
                        if 'vpcProt' not in fabric_obj_dict['fabricProtPol'].keys():
                            fabric_obj_dict['fabricProtPol']['vpcProt'] = \
                                {"fabricProtPol": {"attributes": {}, "children": []}}
                        fabric_obj_dict['fabricExplicitGEp'][node1+'-'+node2] = \
                            self.session.do_switch_vpcprotgrp(node1, node2, 'created',vpc_id)

                if function == 'delete switch':
                    try:
                        node1 = str(command['node1'])
                        node2 = str(command['node2'])
                    except:    
                        required.append('require node1 node2 vpc_id')
                        continue
                    if validate == 'no':
                        if node1 != 'None':
                            if  node1.isdigit():
                                pass
                            else:
                                required.append('provided node1 ' + node1 + ' must be a number if validate is no')
                                continue
                        if node2 != 'None':
                            if  node2.isdigit():
                                pass
                            else:
                                required.append('provided node2 ' + node2 + ' must be a number if validate is no')
                                continue
                    else:
                        if port_dict == {}:
                            port_dict = self.session.get_port_dict()
                        if switch_dict == {}:
                            switch_dict = self.session.get_switch_dict()
                        if node1 != 'None':
                            if node1 not in switch_dict.keys():
                                required.append('provided node1 ' + node1 + ' is not valid')
                                continue
                            else:
                                node1 = str(switch_dict[str(node1)]['id'])
                        if node2 != 'None':
                            if node2 not in switch_dict.keys():
                                required.append('provided node2 ' + node2 + ' is not valid')
                                continue
                            else:
                                node2 = str(switch_dict[str(node2)]['id'])
                        if node1 != 'None' and node2 != 'None':
                            if int(node1) >= int(node2):
                                required.append('provided node1 ' + node1 + ' should be less than node2 ' + node2)
                                continue
                        port_up = [port for port in port_dict.keys() if
                                   (port_dict[port]['node'] == node1 or port_dict[port]['node'] == node2) and
                                    port_dict[port]['operst'] == 'up' and 'fabric' in port_dict[port]['usage']]
                        if len(port_up) >= 1:
                            required.append('The following fabric ports are up: ' + ','.join(sorted(port_up)))
                            continue

                    if node1 != 'None':
                        infra_obj_dict['infraNodeP'][node1] = self.session.do_switch_profile(node1, 'deleted')
                        infra_obj_dict['infraAccPortP'][node1] = self.session.do_int_profile(node1, 'deleted')
                    if node2 != 'None':
                        infra_obj_dict['infraNodeP'][node2] = self.session.do_switch_profile(node2, 'deleted')
                        infra_obj_dict['infraAccPortP'][node2] = self.session.do_int_profile(node2, 'deleted')                        
                    if node1 != 'None' and node2 != 'None':   
                        if 'vpcProt' not in fabric_obj_dict['fabricProtPol'].keys():
                            fabric_obj_dict['fabricProtPol']['vpcProt'] = \
                                {"fabricProtPol": {"attributes": {}, "children": []}}
                        fabric_obj_dict['fabricExplicitGEp'][node1+'-'+node2]= \
                            self.session.do_switch_vpcprotgrp(node1, node2, 'deleted')
                
                if function == 'create snapshot':
                    try:
                        target = str(command['target'])
                        descr = str(command['descr'])
                    except:
                        required.append('require target description')
                        continue
                    if validate == 'no':
                        if target != 'None' and target != 'fabric':
                            required.append('manually check tenant exist already')
                    else:
                        if tenants == {}:
                            tenants = self.session.get_tenants()
                        if target not in tenants and target != 'fabric':
                            required.append('provided tenant ' + target + ' does not exist ')
                            continue
                    snapshot_attr = {}
                    if descr != 'None': snapshot_attr['descr'] = descr
                    else: snapshot_attr['descr'] = ''
                    if target != 'None' and target != 'fabric': snapshot_attr['targetdn'] = 'uni/tn-'+target
                    if target == 'fabric': snapshot_attr['targetdn'] = ''
                    fabric_obj_dict['configExportP']['aciconfigs' + '/' + target] = \
                        self.session.do_snapshot('aciconfigs', 'aciconfigs', 'created,modified', snapshot_attr)

                if function == 'delete snapshot':
                    try:
                        filename = str(command['filename'])
                    except:
                        required.append('require filename')
                        continue
                    if validate == 'no':
                        if snapshot_dict == {}:
                            snapshot_dict = self.session.get_snapshot_dict()
                        if filename not in snapshot_dict.keys():
                            required.append('provide filename ' + filename + ' does not exist ')
                            continue
                        else:
                            snapshot_name = snapshot_dict[filename]['name']
                            snapshot_dn = snapshot_dict[filename]['dn']
                            export_policy = snapshot_dn.split('/configexp-')[1].split(']')[0]
                    else:
                        if snapshot_dict == {}:
                            snapshot_dict = self.session.get_snapshot_dict()
                        if filename not in snapshot_dict.keys():
                            required.append('provide filename ' + filename + ' does not exist ')
                            continue
                        else:
                            snapshot_name = snapshot_dict[filename]['name']
                            snapshot_dn = snapshot_dict[filename]['dn']
                            export_policy = snapshot_dn.split('/configexp-')[1].split(']')[0]
                    fabric_obj_dict['configSnapshot'][filename] = \
                        self.session.do_snapshot(snapshot_name, export_policy, 'deleted')
                   
            if infra_obj_dict['infraAccPortP'] != {} or infra_obj_dict['infraFexP'] != {} or \
                    infra_obj_dict['infraFuncP'] != {} or infra_obj_dict['infraNodeP'] != {} or \
                    infra_obj_dict['fvnsVlanInstP'] != {}:

                infra = {"infraInfra": {"attributes": {"dn": "uni/infra"}, "children": []}}
                for name in infra_obj_dict['infraHPortS'].keys():
                    name = name.split('/')
                    if name[0] in infra_obj_dict['infraAccPortP'].keys():
                        infra_obj_dict['infraAccPortP'][(name[0])]['infraAccPortP']['children'].append(
                            infra_obj_dict['infraHPortS'][('/').join(name)])
                    elif name[0] in infra_obj_dict['infraFexP'].keys():
                        infra_obj_dict['infraFexP'][(name[0])]['infraFexP']['children'].append(
                            infra_obj_dict['infraHPortS'][('/').join(name)])
                for  name in  infra_obj_dict['infraFexGrp'].keys():
                    infra_obj_dict['infraFexP'][name]['infraFexP']['children'].append(
                        infra_obj_dict['infraFexGrp'][name])
                for  name in  infra_obj_dict['infraAccPortP'].keys():
                    infra['infraInfra']['children'].append(infra_obj_dict['infraAccPortP'][name])
                for  name in  infra_obj_dict['infraFexP'].keys():
                    infra['infraInfra']['children'].append(infra_obj_dict['infraFexP'][name])
                for  name in  infra_obj_dict['infraNodeP'].keys():
                    infra['infraInfra']['children'].append(infra_obj_dict['infraNodeP'][name])
                    
                for  name in  infra_obj_dict['infraAccGrp'].keys():
                    infra_obj_dict['infraFuncP']['funcp']['infraFuncP']['children'].append(
                        infra_obj_dict['infraAccGrp'][name])
                for  name in  infra_obj_dict['infraFuncP'].keys():
                    infra['infraInfra']['children'].append(infra_obj_dict['infraFuncP'][name])

                for name in infra_obj_dict['fvnsEncapBlk'].keys():
                    name = name.split('/')
                    infra_obj_dict['fvnsVlanInstP'][name[0]]['fvnsVlanInstP']['children'].append(
                        infra_obj_dict['fvnsEncapBlk'][('/').join(name)])
                for  name in  infra_obj_dict['fvnsVlanInstP'].keys():
                    infra['infraInfra']['children'].append(infra_obj_dict['fvnsVlanInstP'][name])

                result_json.append(infra)
                
            if fabric_obj_dict['fabricOOServicePol'] != {} or fabric_obj_dict['fabricProtPol'] != {}:
                fabric = {"fabricInst": {"attributes": {"dn":"uni/fabric"}, "children": []}}
                for  name in  fabric_obj_dict['fabricRsOosPath'].keys():
                    fabric_obj_dict['fabricOOServicePol']['outofsvc']['fabricOOServicePol']['children'].append(
                        fabric_obj_dict['fabricRsOosPath'][name])
                for  name in  fabric_obj_dict['fabricOOServicePol'].keys():
                    fabric['fabricInst']['children'].append(fabric_obj_dict['fabricOOServicePol'][name])
                
                for  name in  fabric_obj_dict['fabricExplicitGEp'].keys():
                    fabric_obj_dict['fabricProtPol']['vpcProt']['fabricProtPol']['children'].append(
                        fabric_obj_dict['fabricExplicitGEp'][name])
                for  name in  fabric_obj_dict['fabricProtPol'].keys():
                    fabric['fabricInst']['children'].append(fabric_obj_dict['fabricProtPol'][name])

                for  name in  fabric_obj_dict['configExportP'].keys():
                    fabric['fabricInst']['children'].append(fabric_obj_dict['configExportP'][name])
                result_json.append(fabric)

            if fabric_obj_dict['configSnapshot'] != {} or fabric_obj_dict['configExportP'] != {}:
                for name in fabric_obj_dict['configExportP'].keys():
                    result_json.append(fabric_obj_dict['configExportP'][name])
                for name in fabric_obj_dict['configSnapshot'].keys():
                    result_json.append(fabric_obj_dict['configSnapshot'][name])

            if tenant_obj_dict['fvTenant'] != {}:
                for name in tenant_obj_dict['fvRsPathAtt'].keys():
                    name = name.split('/')
                    tenant_obj_dict['fvAEPg'][(name[0] + '/' + name[1] + '/' + name[2])]['fvAEPg']['children'].append(
                        tenant_obj_dict['fvRsPathAtt']['/'.join(name)])
                for name in tenant_obj_dict['fvAEPg'].keys():
                    name = name.split('/')
                    tenant_obj_dict['fvAp'][(name[0] + '/' + name[1])]['fvAp']['children'].append(
                        tenant_obj_dict['fvAEPg']['/'.join(name)])
                for name in tenant_obj_dict['fvCtx'].keys():
                    name = name.split('/')
                    tenant_obj_dict['fvTenant'][name[0]]['fvTenant']['children'].append(
                        tenant_obj_dict['fvCtx']['/'.join(name)])
                for name in tenant_obj_dict['dhcpLbl'].keys():
                    name = name.split('/')
                    tenant_obj_dict['fvBD'][(name[0] + '/' + name[1])]['fvBD']['children'].append(
                        tenant_obj_dict['dhcpLbl']['/'.join(name)])
                for name in tenant_obj_dict['fvBD'].keys():
                    name = name.split('/')
                    tenant_obj_dict['fvTenant'][name[0]]['fvTenant']['children'].append(
                        tenant_obj_dict['fvBD']['/'.join(name)])
                for name in tenant_obj_dict['fvAp'].keys():
                    name = name.split('/')
                    tenant_obj_dict['fvTenant'][name[0]]['fvTenant']['children'].append(
                        tenant_obj_dict['fvAp']['/'.join(name)])
                for name in tenant_obj_dict['fvTenant'].keys():
                    result_json.append(tenant_obj_dict['fvTenant'][name])

            if result_json is not []:
                if send_to_apic == 'yes':
                    post_url, post_resp = self.session.send_to_apic(result_json)

            if required is not []:
                if isinstance( required, list):
                    for warning in required:
                        if warning not in warnings:
                            warnings.append(warning)
                else:
                    warnings = required
            return result_json, post_url, post_resp, warnings
