#!/usr/bin/env python3
"""This script offers to work with Wallarm Cloud API"""
import datetime
import json
import socket
from urllib.parse import urlparse
import requests
from elasticsearch import Elasticsearch
from .exceptions import NonSuccessResponse
from .helpers import _Decorators


class WallarmAPI:

    def __init__(self, uuid='', secret='', api='api.wallarm.com'):
        self.__uuid = uuid
        self.__secret = secret
        self.__api = api
        self.clientid = self.get_clientid()

    @_Decorators.try_decorator
    def get_clientid(self):
        client_url = f'https://{self.__api}/v1/objects/client'
        client_body = {"filter": {}}
        with requests.post(client_url, json=client_body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
        return response.json().get('body')[0].get('id')

    @_Decorators.try_decorator
    async def get_attack(self, start='today', end=None, limit=100):
        """The method to fetch attacks by filter"""

        if start in ['today', 'last day', 'yesterday']:
            start = int((datetime.date.today() - datetime.timedelta(1)).strftime("%s"))
        if start == 'last week':
            start = int((datetime.date.today() - datetime.timedelta(7)).strftime("%s"))

        url = f'https://{self.__api}/v1/objects/attack'
        body = {"filter": {"vulnid": None, "!type": ["warn"],
                           "time": [[start, end]]},
                "limit": limit, "offset": 0, "order_by": "first_time", "order_desc": True}
        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
            return response.json()

    @_Decorators.try_decorator
    async def get_vuln(self, limit=100):
        """The method to get vulnerabilities information"""

        url = f'https://{self.__api}/v1/objects/vuln'
        body = {"limit": limit, "offset": 0, "filter": {"status": "open"}, "order_by": "threat", "order_desc": True}
        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
        return response.json()

    @_Decorators.try_decorator
    async def get_action(self, hint_type=None, limit=1000):
        """The method to get action information"""

        url = f'https://{self.__api}/v1/objects/action'
        # body = {"filter": {"hints_count": [[1, None]], "hint_type": ["uploads", "binary_data", "variative_values",
        # "variative_keys", "variative_by_regex", "vpatch", "regex", "experimental_regex", "middleware", "brute_counter",
        # "dirbust_counter", "experimental_stamp", "disable_ld_context", "attack_rechecker", "parse_mode", "parser_state",
        # "overlimit_res", "disable_stamp", "disable_regex", "disable_attack_type", "max_serialize_data_size", "sensitive_data",
        # "optional_parameter", "required_parameter", "attack_rechecker_rewrite", "wallarm_mode", "set_response_header", "tag",
        # "html_response_content_type_regex", "html_response_max_values_per_key"]}, "limit": 1000, "offset": 0}
        if not hint_type:
            body = {"filter": {}, "limit": limit, "offset": 0}
        else:
            body = {"filter": {"hint_type": [hint_type]}, "limit": limit, "offset": 0}

        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
        return response.json()

    @_Decorators.try_decorator
    async def get_hint(self):
        """The method to get hint information"""

        url = f'https://{self.__api}/v1/objects/hint'
        body = {"filter": {}, "order_by": "updated_at", "order_desc": True, "limit": 1000, "offset": 0}
        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
        return response.json()

    @_Decorators.try_decorator
    async def get_blacklist(self):
        """The method to get blacklist information"""

        url = f'https://{self.__api}/v3/blacklist'
        body = {f"filter[clientid]": self.clientid, "limit": 1000}
        with requests.get(url, params=body,
                          headers={'X-WallarmAPI-UUID': self.__uuid, 'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
        return response.json()

    @_Decorators.try_decorator
    async def get_blacklist_hist(self, start='today', end=None):
        """The method to get blacklist history"""

        if start in ['today', 'last day', 'yesterday']:
            start = int((datetime.date.today() - datetime.timedelta(1)).strftime("%s"))
        if start == 'last week':
            start = int((datetime.date.today() - datetime.timedelta(7)).strftime("%s"))
        if start == 'last month':
            start = int((datetime.date.today() - datetime.timedelta(30)).strftime("%s"))

        url = f'https://{self.__api}/v3/blacklist/history'
        continuation = None
        full_resp = {}
        flag = True
        body = {"filter[clientid]": self.clientid, "filter[start_time]": start, "filter[end_time]": end,
                "limit": 1000, "continuation": continuation}
        while True:
            with requests.get(url, params=body,
                              headers={'X-WallarmAPI-UUID': self.__uuid,
                                       'X-WallarmAPI-Secret': self.__secret}) as response:
                if response.status_code not in [200, 201, 202, 204, 304]:
                    raise NonSuccessResponse()
            continuation = response.json().get('body').get('continuation')

            if flag:
                full_resp = response.json()

            if continuation is not None:
                body['continuation'] = continuation
                if not flag:
                    full_resp['body']['objects'].extend(response.json().get('body').get('objects'))
            else:
                break
            flag = False
        return full_resp

    async def create_vpatch(self, instance=None, domain='example.com', action_name='.env'):
        """The method to create vpatch for an instance"""

        url = f'https://{self.__api}/v1/objects/hint/create'
        body = {"type": "vpatch", "action": [{"point": ["action_name"], "type": "iequal", "value": action_name},
                                             {"point": ["action_ext"], "type": "absent", "value": ""},
                                             {"point": ["header", "HOST"], "type": "iequal",
                                              "value": domain}],
                "clientid": self.clientid, "validated": True, "point": [["action_name"]], "attack_type": "any"}
        if instance:
            body['action'].append({"point": ["instance"], "type": "equal", "value": instance})

        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse()
        return response.json()


class SenderData:

    def __init__(self, address='http://localhost:9200', http_auth=None):
        if http_auth is not None:
            http_auth = (urlparse(f'http://{http_auth}@example.com').username,
                         urlparse(f'http://{http_auth}@example.com').password)
            self.es = Elasticsearch([address], http_auth=http_auth)
        else:
            self.es = Elasticsearch([address])
        self.address = address

    async def send_to_elastic(self, data, index='wallarm'):
        """This function sends data to ELK"""
        self.es.index(body=data, index=index)
        return print('Sent successfully')

    async def send_to_collector(self, data, tag=None, token=None, verify=True):
        """This function sends data to HTTP/HTTPS/TCP/UDP Socket"""
        addr = urlparse(self.address)
        host = addr.hostname
        port = addr.port
        scheme = addr.scheme
        socket_data = f'{tag}: {data}'
        socket_data = json.dumps(socket_data).encode()

        if scheme in ['http', 'https']:
            if token:
                if tag:
                    with requests.post(f'{self.address}/{tag}', json=data, verify=verify) as response:
                        if response.status_code not in [200, 201, 202, 204, 304]:
                            raise NonSuccessResponse()
                else:
                    with requests.post(f'{self.address}/services/collector/event/1.0', json={'event': data},
                                       headers={'Authorization': f'Splunk {token}'}, verify=verify) as response:
                        if response.status_code not in [200, 201, 202, 204, 304]:
                            raise NonSuccessResponse()
            else:
                with requests.post(f'{self.address}/{tag}', json=data, verify=verify) as response:
                    if response.status_code not in [200, 201, 202, 204, 304]:
                        raise NonSuccessResponse()
        elif scheme == 'tcp':
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(socket_data)
        elif scheme == 'udp':
            while len(socket_data) > 0:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((host, port))
                    s.send(socket_data[:500])
                socket_data = socket_data[500:]
        else:
            print("Specify one of the following schemes: http://, https://, tcp://, udp://")
        print('Sent successfully')
