import re
import sys, os
import json
import csv
from os import system
from math import sqrt
from argparse import ArgumentParser
from collections import OrderedDict
from pprint import pprint
from random import uniform, randint, shuffle, choice
from ipaddress import ip_address, IPv6Address
import numpy as np
from collections import Counter

NODE_RELATED_MESSAGES = 0
SESSION_RELATED_MESSAGES = 1

PFCP_ELEMS = OrderedDict([(NODE_RELATED_MESSAGES, { 'name': 'nodeRelatedMessages',
                                                    'procs': OrderedDict([(1, 'HeartbeatRequest'),
                                                                          (2, 'HeartbeatResponse'),
                                                                          (3, 'PFDManagementRequest'),
                                                                          (4, 'PFDManagementResponse'),
                                                                          (5, 'AssociationSetupRequest'),
                                                                          (6, 'AssociationSetupResponse'),
                                                                          (7, 'AssociationUpdateRequest'),
                                                                          (8, 'AssociationUpdateResponset'),
                                                                          (9, 'AssociationReleaseRequest'),
                                                                          (10, 'AssociationReleaseResponse'),
                                                                          (11, 'VersionNotSupportedResponse'),
                                                                          (12, 'NodeReportRequest'),
                                                                          (13, 'NodeReportResponse'),
                                                                          (14, 'SessionSetDeletionRequest'),
                                                                          (15, 'SessionSetDeletionResponse')]) }),
                          (SESSION_RELATED_MESSAGES, { 'name': 'sessionRelatedMessages',
                                                       'procs': OrderedDict([(50, 'SessionEstablishmentRequest'),
                                                                             (51, 'SessionEstablishmentResponse'),
                                                                             (52, 'SessionModificationRequest'),
                                                                             (53, 'SessionModificationResponse'),
                                                                             (54, 'SessionDeletionRequest'),
                                                                             (55, 'SessionDeletionResponse'),
                                                                             (56, 'SessionReportRequest'),
                                                                             (57, 'SessionReportResponse')]) })])


def to_json_convertation(file):
    tshark_exe = r"c:\Program Files\Wireshark\tshark.exe"
    if file.endswith('.pcap') or file.endswith('.pcapng'):
        cmd = '"{}" -r {} -T json >{}'.format(tshark_exe, file, '{}.json'.format(file.partition('.')[0]))
        print("command '" + cmd + "' is executed")
        system(cmd)
        print("convertation to json successfylly ended")
    elif file.endswith('.json'):
        print("no need to convert to json")
    else:
        print('unknown command. Make sure, that you use pcap, pcapng or json file')


def save_to_csv(file_to_write, lines_to_write):
    with open(file_to_write, 'w') as file:
        for line in lines_to_write:
            file.write((','.join(line)) + '\n')

# start of the features extracting block

class CurrentPacketParser:
    def __init__(self, packet):
        #common stats
        self.ip_src = packet['_source']['layers']['ipv6']['ipv6.src_host']
        self.ip_dst = packet['_source']['layers']['ipv6']['ipv6.dst_host']
        self.port_src = int(packet['_source']['layers']['udp']['udp.srcport'])
        self.port_dst = int(packet['_source']['layers']['udp']['udp.dstport'])
        self.utc_time = float((packet['_source']['layers']['frame']['frame.time_epoch']))
        self.tcp_len = int(packet['_source']['layers']['frame']['frame.len'])
        self.hop_limit = int(packet['_source']['layers']['ipv6']['ipv6.hlim'])

        self.cmd_type = None
        for elem_code in PFCP_ELEMS.keys():
            proc_code = int(packet['_source']['layers']['pfcp']['pfcp.msg_type'])
            if proc_code in PFCP_ELEMS[elem_code]['procs'].keys():
                self.cmd_type = '{}:{}'.format(elem_code, proc_code)
        assert (self.cmd_type is not None)

class FeaturesExtracting:
    def __init__(self, ):
        self.features_dict = OrderedDict({})
        #this was in the header_creating() function
        self.field_names = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'first_pkt_time', 'last_pkt_time', 'avg_hops', 'avg_packet_len']
        for elem in PFCP_ELEMS.values():
            for proc in elem['procs'].values():
                self.field_names += ['{}:{}'.format(elem['name'], proc)]

    def create_keys(self, parsed_packet):
        if parsed_packet.ip_src < parsed_packet.ip_dst:
            ip_pair = '{} : {}'.format(parsed_packet.ip_src, parsed_packet.ip_dst)
            port_pair = '{}:{}'.format(parsed_packet.port_src, parsed_packet.port_dst)
        elif parsed_packet.ip_src > parsed_packet.ip_dst:
            ip_pair = '{} : {}'.format(parsed_packet.ip_dst, parsed_packet.ip_src)
            port_pair = '{}:{}'.format(parsed_packet.port_dst, parsed_packet.port_src)
        return (ip_pair, port_pair)

    def insert_highlevel_keys(self, parsed_packet):
        (ip_pair, port_pair) = self.create_keys(parsed_packet)
        if ip_pair not in self.features_dict.keys():
            self.features_dict[ip_pair] = OrderedDict({})
        if port_pair not in self.features_dict[ip_pair].keys():
            self.features_dict[ip_pair][port_pair] = [parsed_packet]
        else:
            self.features_dict[ip_pair][port_pair] = self.features_dict[ip_pair][port_pair] + [parsed_packet]

    def insert_packet_stats(self):
        temp_dict = []
        for port_key in self.features_dict.values():
            for packet_stats in port_key.values(): #port_key contains the link to the packets stats, in list format

                first_pkt_time = min(map(lambda x: x.utc_time, packet_stats))
                last_pkt_time = max(map(lambda x: x.utc_time, packet_stats))
                ip_src = packet_stats[0].ip_src #[0] since port_key is an ordered dict
                ip_dst = packet_stats[0].ip_dst
                port_src = packet_stats[0].port_src
                port_dst = packet_stats[0].port_dst
                hops_avg = sum(list(map(lambda x: x.hop_limit, packet_stats))) / len(list(map(lambda x: x.hop_limit, packet_stats)))
                pkt_len_avg = sum(list(map(lambda x: x.tcp_len, packet_stats))) / len(list(map(lambda x: x.tcp_len, packet_stats)))

                line = [str(ip_src), str(ip_dst), str(port_src), str(port_dst), '{:.6f}'.format(first_pkt_time),
                         '{:.6f}'.format(last_pkt_time), '{:.0f}'.format(hops_avg), '{:.0f}'.format(pkt_len_avg)]

                for elem_code in PFCP_ELEMS.keys():
                    for proc_code in PFCP_ELEMS[elem_code]['procs'].keys():
                        line += [str(len(list(filter(lambda x: x.cmd_type == '{}:{}'.format(elem_code, proc_code), packet_stats))))]

                temp_dict += [line]
        return temp_dict

    def get_field_names(self):
        return self.field_names

    def get_field_val_by_name(self, fields, name):
        field_pos = None
        try:
            field_pos = self.field_names.index(name)
        except ValueError:
            print("field with name '" + name + "' was not found")
        assert(field_pos is not None)
        return fields[field_pos]

# start of the anomaly generating block

def avg(list_num):
    return sum(list(map(lambda x: float(x), list_num))) / len(list_num)

def stdev(list_num):
    return sqrt(avg(list(map(lambda x: (float(x) - avg(list_num)) ** 2, list_num))))

def rnd(dict_num):
    return dict_num['avg'] + (uniform(0, dict_num['max'] - dict_num['avg'])
                              if randint(0, 1) == 0 else -uniform(0, dict_num['avg'] - dict_num['min']))

class DatasetExpansion:
    # statistical characteristics extraction
    def __init__(self, norm_features_recs, norm_features_stats=None):
        self.norm_features_recs = norm_features_recs

        if norm_features_stats is None:
            norm_features_stats = norm_features_recs.insert_packet_stats()

        # for date in utc-format
        self.last_first_pkt_time = float(norm_features_recs.get_field_val_by_name(norm_features_stats[-1], 'first_pkt_time'))
        fst_pkt_times = [float(norm_features_recs.get_field_val_by_name(elem, 'first_pkt_time')) for elem in norm_features_stats]
        diff_fst_pkt_times = list(map(lambda x: abs(float(x[1]) - float(x[0])), zip(fst_pkt_times, fst_pkt_times[1:])))
        durs = [float(norm_features_recs.get_field_val_by_name(elem, 'last_pkt_time')) - float(norm_features_recs.get_field_val_by_name(elem, 'first_pkt_time'))
                for elem in norm_features_stats]
        self.diff_fst_pkt_time = {'avg': avg(diff_fst_pkt_times), 'min': min(diff_fst_pkt_times), 'max': max(diff_fst_pkt_times)}
        self.pkt_dur = {'avg': avg(durs), 'min': min(durs), 'max': max(durs)}

        self.src_ips = [(norm_features_recs.get_field_val_by_name(elem, 'src_ip')) for elem in norm_features_stats]
        self.dst_ips = [(norm_features_recs.get_field_val_by_name(elem, 'dst_ip')) for elem in norm_features_stats]

        src_ports_range = [(norm_features_recs.get_field_val_by_name(elem, 'src_port')) for elem in norm_features_stats]
        dst_ports_range = [(norm_features_recs.get_field_val_by_name(elem, 'dst_port')) for elem in norm_features_stats]
        self.ports_range = set([int(i) for i in (src_ports_range + dst_ports_range)])
        self.min_port = min(self.ports_range)
        self.max_port = max(self.ports_range)

        # this block extracts column under current field and collects its statistical characteristics
        self.stat_field_vals = {}
        for field in self.norm_features_recs.get_field_names():
            if field not in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'first_pkt_time', 'last_pkt_time']:
                field_column = [float(norm_features_recs.get_field_val_by_name(elem, field)) for elem in norm_features_stats]
                self.stat_field_vals[field] = {'avg': avg(field_column), 'min': min(field_column), 'max': max(field_column), 'stdev': stdev(field_column)}

    def create_ms_for_ditestamp(self):
        ms1 = ''.join(str(randint(0, 9)) for i in range(6))
        ms = ''
        for i in range(6):
            digit = randint(0, 9)
            ms += str(digit)
        return ms

    def create_datestamp(self, datestamp):
        #datestamp1 = datestamp
        ms = self.create_ms_for_ditestamp()
        #afc = randint(-300, 300)
        datestamp += randint(-300, 300)
        ds = f'{str(datestamp).partition(".")[0]}.{ms}'
        return float(ds)

    def create_normal_record(self):
        temp_list = []
        for field in self.norm_features_recs.get_field_names():
            if field == 'first_pkt_time':
                self.last_first_pkt_time += abs(rnd(self.diff_fst_pkt_time))
                self.last_first_pkt_time = self.create_datestamp(self.last_first_pkt_time)# expand time as +- 5 mins
                temp_list += [str(self.last_first_pkt_time)]
            elif field == 'last_pkt_time':
                temp_list += [str(self.last_first_pkt_time + abs(rnd(self.pkt_dur)))]
            elif field == 'src_ip':
                temp_ip = choice(self.src_ips)
                new_ip = int(ip_address(temp_ip)) + randint(-5, 5)
                temp_list += [str(ip_address(new_ip))]
            elif field == 'dst_ip':
                temp_ip = choice(self.dst_ips)
                new_ip = int(ip_address(temp_ip)) + randint(-5, 5)
                temp_list += [str(ip_address(new_ip))]
            elif field == 'src_port' or field == 'dst_port':
                port = choice(list(self.ports_range))
                temp_list += [str(port + randint(-10, 10))]
            else:
                temp_list += [str(int(rnd(self.stat_field_vals[field])))]
        return temp_list


class RndAnomalyGenerator:
    # statistical characteristics extraction
    def __init__(self, norm_features_recs, norm_features_stats=None):
        self.norm_features_recs = norm_features_recs

        if norm_features_stats is None:
            norm_features_stats = norm_features_recs.insert_packet_stats()

        # for date in utc-format
        self.last_first_pkt_time = float(
            norm_features_recs.get_field_val_by_name(norm_features_stats[-1], 'first_pkt_time'))
        fst_pkt_times = [float(norm_features_recs.get_field_val_by_name(elem, 'first_pkt_time')) for elem in
                         norm_features_stats]
        diff_fst_pkt_times = list(map(lambda x: abs(float(x[1]) - float(x[0])), zip(fst_pkt_times, fst_pkt_times[1:])))
        durs = [float(norm_features_recs.get_field_val_by_name(elem, 'last_pkt_time')) - float(
            norm_features_recs.get_field_val_by_name(elem, 'first_pkt_time'))
                for elem in norm_features_stats]
        self.diff_fst_pkt_time = {'avg': avg(diff_fst_pkt_times), 'min': min(diff_fst_pkt_times),
                                  'max': max(diff_fst_pkt_times)}
        self.pkt_dur = {'avg': avg(durs), 'min': min(durs), 'max': max(durs)}

        # this block extracts column under current field and collects its statistical characteristics
        self.stat_field_vals = {}
        for field in self.norm_features_recs.get_field_names():
            if field not in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'first_pkt_time', 'last_pkt_time']:
                field_column = [float(norm_features_recs.get_field_val_by_name(elem, field)) for elem in
                                norm_features_stats]
                self.stat_field_vals[field] = {'avg': avg(field_column), 'min': min(field_column),
                                               'max': max(field_column), 'stdev': stdev(field_column)}

    def create_abnormal_record(self):
        fields_for_rnd = [field for field in self.norm_features_recs.get_field_names() if 'Request' in field]
        rnd_num = randint(1, len(fields_for_rnd))
        bin_lst = [1] * rnd_num + [0] * (len(fields_for_rnd) - rnd_num)
        shuffle(bin_lst)
        temp_list = []
        for field in self.norm_features_recs.get_field_names():
            if field == 'first_pkt_time':
                self.last_first_pkt_time += abs(rnd(self.diff_fst_pkt_time))
                temp_list += [str(self.last_first_pkt_time)]
            elif field == 'last_pkt_time':
                temp_list += [str(self.last_first_pkt_time + abs(rnd(self.pkt_dur)))]
            elif field == 'src_ip' or field == 'dst_ip':
                temp_list += [str(ip_address(42540766411282592856903984951653826561))] # ivp6 = 2001:db8::1
                # temp_list += [str(IPv6Address(randint(0, 2 ** 128 - 1)))] #random ipv6
                # temp_list += [str(ip_address(randint(0, 2 ** 32 - 1)))] # random ipv4
            elif field == 'src_port' or field == 'dst_port':
                temp_list += [str(randint(0, 2 ** 16 - 1))]
            elif 'Request' in field:
                if bin_lst[fields_for_rnd.index(field)] == 1:  # insert anomaly value
                    temp_list += [str(
                        int(self.stat_field_vals[field]['avg'] + (3 + randint(0, 1)) * self.stat_field_vals[field]['stdev']))]
                else:
                    temp_list += [str(int(rnd(self.stat_field_vals[field])))]
            else:
                temp_list += [str(int(rnd(self.stat_field_vals[field])))]
        return temp_list


if __name__ == '__main__':
    # all this stuff only to make user enter command as 'script_name.py -f filename.pcap/json' -n num_anomalies
    # so we can extract filename to continue work

    '''
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-f', '--files', type=str, dest='filename', required=True,
                            help='set input files (extensions: pcap, pcapng or json)')
    arg_parser.add_argument('-n', '--n_anomalies', type=int, help='insert n anomalies')

    args = arg_parser.parse_args()
    n_anomalies = args.n_anomalies

    if len(args.filename.split(',')) > 1:  # we want to work only with one file for one run
        right_command = 'script_name.py -f filename.pcap'
        print(r"Unknown command. Make sure, that you use command's format as '{}'".format(right_command))
        sys.exit()

    pcap_file = str(args.filename)
    print('n_anomalies: ' + str(n_anomalies))
    print('{} loading completed'.format(pcap_file))
    '''
    pcap_file = 'n4.pcap'

    to_json_convertation(pcap_file)  # you can guess what this means
    json_file = pcap_file.partition('.')[0] + '.json'
    print('{} creating completed'.format(json_file))

    # working with json-file
    with open(json_file, 'r', encoding='utf-8') as file:
        packets = json.load(file)
    print('{} loading completed'.format(json_file))

    # features extracting
    features = FeaturesExtracting()

    for pkt in packets:
        if 'pfcp' not in pkt['_source']['layers']:
            continue
        record = CurrentPacketParser(pkt)
        features.insert_highlevel_keys(record)

    # only to inform that program is working
    print('len(tcp_records):', len(features.features_dict))
    for ip_pair in features.features_dict.keys():
        print('len(tcp_records[{}]): {}'.format(ip_pair, len(features.features_dict[ip_pair])))
        for port_pair in features.features_dict[ip_pair].keys():
            print('len(tcp_records[{}][{}]): {}'.format(ip_pair, port_pair, len(features.features_dict[ip_pair][port_pair])))

    n_anomalies = 5

    normal_csv_file = re.sub(r'^(.+)\.json$', r'\1_normal.csv', json_file)
    field_names = features.get_field_names()
    features_list = features.insert_packet_stats()
    save_to_csv(normal_csv_file, [field_names] + features_list)
    print('file {} was written'.format(normal_csv_file))

    normal_generated_csv_file = re.sub(r'^(.+)\.json$', r'\1_normal_generated.csv', json_file)
    expanded = DatasetExpansion(features, features_list)
    normals = [expanded.create_normal_record() for _ in range(10)]
    for line in normals:
        print(line)
    save_to_csv(normal_generated_csv_file, [field_names] + normals)

'''
    anomaly_csv_file = re.sub(r'^(.+)\.json$', r'\1_anomalies.csv', json_file)
    if n_anomalies is not None:
        rag = RndAnomalyGenerator(features, features_list)
        anomalies = [rag.create_abnormal_record() for _ in range(n_anomalies)]
        save_to_csv(anomaly_csv_file, [field_names] + anomalies)
    print('file {} was written'.format(anomaly_csv_file))
'''

