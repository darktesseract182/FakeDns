#!/usr/bin/env python
# -*- coding: utf-8 -*-
""" FakeDns fork by Al-Azif"""

from __future__ import print_function

import re
import socketserver
import socket
import sys


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(self, server_address, request_handler):
        self.address_family = socket.AF_INET
        socketserver.UDPServer.__init__(self, server_address, request_handler)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        (data, s) = self.request
        respond(data, self.client_address, s)


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        tipo = (ord(data[2]) >> 3) & 15
        if tipo == 0:
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.domain += data[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(data[ini])
            self.type = data[ini:][1:3]
        else:
            self.type = data[-4:-2]


def _get_question_section(query):
    start_idx = 12
    end_idx = start_idx
    num_questions = (ord(query.data[4]) << 8) | ord(query.data[5])

    while num_questions > 0:
        while query.data[end_idx] != '\0':
            end_idx += ord(query.data[end_idx]) + 1
        end_idx += 5
        num_questions -= 1

    return query.data[start_idx:end_idx]


class DNSResponse(object):
    def __init__(self, query):
        self.id = query.data[:2]
        self.flags = '\x81\x80'
        self.questions = query.data[4:6]
        self.rranswers = '\x00\x01'
        self.rrauthority = '\x00\x00'
        self.rradditional = '\x00\x00'
        self.query = _get_question_section(query)
        self.pointer = '\xc0\x0c'
        self.type = None
        self.dnsclass = '\x00\x01'
        self.ttl = '\x00\x00\x00\x01'
        self.length = None
        self.data = None

    def make_packet(self):
        try:
            return self.id + self.flags + self.questions + self.rranswers + \
                self.rrauthority + self.rradditional + self.query + \
                self.pointer + self.type + self.dnsclass + self.ttl + \
                self.length + self.data
        except (TypeError, ValueError):
            pass


class A(DNSResponse):
    def __init__(self, query, record):
        super(A, self).__init__(query)
        self.type = '\x00\x01'
        self.length = '\x00\x04'
        self.data = self.get_ip(record)

    @staticmethod
    def get_ip(dns_record):
        ip = dns_record
        return ''.join(chr(int(x)) for x in ip.split('.'))


class AAAA(DNSResponse):
    def __init__(self, query, address):
        super(AAAA, self).__init__(query)
        self.type = '\x00\x1c'
        self.length = '\x00\x10'
        self.data = address

    def get_ip_6(host, port=0):
        result = socket.getaddrinfo(host, port, socket.AF_INET6)
        ip = result[0][4][0]


class CNAME(DNSResponse):
    def __init__(self, query):
        super(CNAME, self).__init__(query)
        self.type = '\x00\x05'


class PTR(DNSResponse):
    def __init__(self, query, ptr_entry):
        super(PTR, self).__init__(query)
        self.type = '\x00\x0c'
        self.ttl = '\x00\x00\x00\x00'
        ptr_split = ptr_entry.split('.')
        ptr_entry = '\x07'.join(ptr_split)
        self.data = '\x09{}\x00'.format(ptr_entry)
        self.length = chr(len(ptr_entry) + 2)
        if self.length < '\xff':
            self.length = '\x00{}'.format(self.length)


class TXT(DNSResponse):
    def __init__(self, query, txt_record):
        super(TXT, self).__init__(query)
        self.type = '\x00\x10'
        self.data = txt_record
        self.length = chr(len(txt_record) + 1)
        if self.length < '\xff':
            self.length = '\x00{}'.format(self.length)
        self.length += chr(len(txt_record))


class NONEFOUND(DNSResponse):
    def __init__(self, query):
        super(NONEFOUND, self).__init__(query)
        self.type = query.type
        self.flags = '\x81\x83'
        self.rranswers = '\x00\x00'
        self.length = '\x00\x00'
        self.data = '\x00'
        print('>> Built NONEFOUND response')


class Rule (object):
    def __init__(self, rule_type, domain, ip):
        self.type = rule_type
        self.domain = domain
        self.ip = ip

    def match(self, req_type, domain, addr):
        try:
            req_type = TYPE[req_type]
        except KeyError:
            return None

        try:
            assert self.type == req_type
        except AssertionError:
            return None

        try:
            assert self.domain.match(domain)
        except AssertionError:
            return None

        return self.ip


def respond(data, addr, s):
    p = DNSQuery(data)
    response = rules.match(p, addr[0])
    s.sendto(response, addr)
    return response


class RuleError_BadRegularExpression(Exception):
    def __init__(self, lineno):
        print('>> Malformed Regular Expression on rulefile line #{}'.format(lineno))


class RuleError_BadRuleType(Exception):
    def __init__(self, lineno):
        print('>> Rule type unsupported on rulefile line #{}'.format(lineno))


class RuleError_BadFormat(Exception):
    def __init__(self, lineno):
        print('>> Not Enough Parameters for rule on rulefile line #{}'.format(lineno))


class RuleEngine2:
    def __init__(self, file_):
        self.match_history = {}
        self.rule_list = []

        with open(file_, 'r') as rulefile:
            rules = rulefile.readlines()
            lineno = 0

            for rule in rules:
                if len(rule.strip()) == 0 or rule == '\n':
                    continue

                if len(rule.split()) < 3:
                    raise RuleError_BadFormat(lineno)

                s_rule = rule.split()
                rule_type = s_rule[0].upper()
                domain = s_rule[1]
                ip = s_rule[2]

                if rule_type not in TYPE.values():
                    raise RuleError_BadRuleType(lineno)
                try:
                    domain = re.compile(domain)
                except:
                    raise RuleError_BadRegularExpression(lineno)

                # TODO: Fix or remove this
                # Deal With Special IPv6 Nonsense
                # if rule_type.upper() == 'AAAA':
                #     tmp_ip_array = []
                #     for ip in ips:
                #         if _is_shorthand_ip(ip):
                #             ip = _explode_shorthand_ip_string(ip)
                #         ip = ip.replace(':', '').decode('hex')
                #         tmp_ip_array.append(ip)
                #     ips = tmp_ip_array

                self.rule_list.append(Rule(rule_type, domain, ip))

                lineno += 1

            print('>> Parsed {} rules from {}'.format(len(self.rule_list), file_))

    def match(self, query, addr):
        for rule in self.rule_list:
            result = rule.match(query.type, query.domain, addr)
            if result is not None:
                response_data = result

                if response_data.lower() == 'none':
                    return NONEFOUND(query).make_packet()

                response = CASE[query.type](query, response_data)

                print('>> Matched Request: {}'.format(query.domain))
                return response.make_packet()

        try:
            s = socket.socket(type=socket.SOCK_DGRAM)
            s.settimeout(3.0)
            addr = ('{}'.format('8.8.8.8'), 53)
            s.sendto(query.data, addr)
            data = s.recv(1024)
            s.close()
            print('>> Unmatched Request: {}'.format(query.domain))
            return data
        except socket.error:
            print('>> Error was handled by sending NONEFOUND')
            return NONEFOUND(query).make_packet()


def main():
    global rule_list
    global rules
    global TYPE
    global CASE

    TYPE = {
        '\x00\x01': 'A',
        '\x00\x1c': 'AAAA',
        '\x00\x05': 'CNAME',
        '\x00\x0c': 'PTR',
        '\x00\x10': 'TXT',
        '\x00\x0f': 'MX',
        '\x00\x06': 'SOA'
    }

    CASE = {
        '\x00\x01': A,
        '\x00\x1c': AAAA,
        '\x00\x05': CNAME,
        '\x00\x0c': PTR,
        '\x00\x10': TXT
    }

    rules = RuleEngine2('dns.conf')
    rule_list = rules.rule_list

    interface = '0.0.0.0'
    port = 53

    try:
        server = ThreadedUDPServer((interface, port), UDPHandler)
    except socket.error:
        sys.exit('>> Could not start server -- is another program on udp:53?')

    server.daemon = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit('>> Exiting...')


if __name__ == '__main__':
    main()
