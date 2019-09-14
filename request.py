import argparse
import datetime
import json
from builtins import print

import requests
import time
import sys
import os
import getpass

from elasticsearch import Elasticsearch


class Data(object):

    def __init__(self, data):
        self.__dict__ = data

    def __getitem__(self, data):
        self.__dict__ = data

    def length(self):
        return len(self.__dict__['body'])


def send_to_elastic(**kwargs):
    # es = Elasticsearch([{'host': 'localhost', 'port': '9200'}])
    es = Elasticsearch(['http://localhost:9200'], http_auth=('elastic', 'changeme'))

    # Send the data into es
    if 'attack' in kwargs:
        for key, value in kwargs.items():
            print("The value of {} is {}".format(key, value))
            es.index(index='attack', ignore=400, doc_type='wlrm', body=value)

    if 'hit' in kwargs:
        for key, value in kwargs.items():
            es.index(index='hit', ignore=400, doc_type='wlrm', body=value)

    if 'detail' in kwargs:
        for key, value in kwargs.items():
            es.index(index='detail', ignore=400, doc_type='wlrm', body=value)

    if 'blacklist' in kwargs:
        for key, value in kwargs.items():
            es.index(index='blacklist', ignore=400, doc_type='wlrm', body=value)

    if 'vulns' in kwargs:
        for key, value in kwargs.items():
            es.index(index='vulns', ignore=400, doc_type='wlrm', body=value)


class HandlerAPI(object):

    def __init__(self, *args):
        self.api = args[0]
        self.auth = args[1]
        if self.auth == 'username':
            self.username = args[2]
            self.password = args[3]
        if self.auth == 'uuid':
            self.uuid = args[2]
            self.secret = args[3]
        self.unixtime = args[4]
        self.login = f'https://{self.api}/v1/login'
        self.attack = f'https://{self.api}/v1/objects/attack'
        self.hit = f'https://{self.api}/v1/objects/hit'
        self.details = f'https://{self.api}/v2/hit/details'
        self.vulns = f'https://{self.api}/v1/objects/vuln'
        self.user = f'https://{self.api}/v1/user'
        self.blacklist = f'https://{self.api}/v3/blacklist'
        self.blacklist_hist = f'https://{self.api}/v3/blacklist/history'

    def __del__(self):
        print("Object has been deleted")

    def authentication(self):

        # Credentials for API
        login_payload = {"username": f"{self.username}", "password": f"{self.password}"}

        # One more option to get credentials (not secure as two previous since someone with sudo right will see in
        # 'ps elf' resolved $PASSWORD)
        # login_payload = {"username": sys.argv[0], "password": sys.argv[1]}

        if self.username is not None and self.password is not None:
            try:
                # Login request
                login_resp = requests.post(self.login, json=login_payload)
                login_resp.raise_for_status()
                login_resp.encoding = 'utf-8'
                self.cookies = login_resp.cookies
                login_json = login_resp.json()
                self.token = login_json['body']['token']
                # If login was successful send next requests you need
                if login_resp.status_code == requests.codes.ok:
                    # User parameters
                    user_payload = {"token": self.token}
                    self.user_resp = requests.post(self.user, params=user_payload, cookies=self.cookies)
                    print("Successfully authenticated")
                else:
                    print("Login phase was failed")
                    sys.exit(1)

            except requests.exceptions.SSLError as err:
                print(f'SSL ERROR OCCURRED: \n{err}')
                sys.exit(1)
            except requests.exceptions.ConnectionError as err:
                print(f'CONNECTION ERROR OCCURRED: \n{err}')
                sys.exit(1)

            except requests.exceptions.HTTPError as err:
                print(f'HTTP ERROR OCCURRED: \n{err}')
                sys.exit(1)

            except requests.exceptions.RequestException as err:
                print(f'Other error occurred: \n{err}')
                sys.exit(42)

    def get_clientid(self):
        if hasattr(self, "uuid") and hasattr(self, "secret"):
            if self.uuid is not None and self.secret is not None:
                self.user_resp = requests.post(self.user, headers={'X-WallarmAPI-UUID': self.uuid,
                                                                   'X-WallarmAPI-Secret': self.secret})
        self.clientid = self.user_resp.json()['body']['clientid']
        print(f"Client id is {self.clientid}")

    def get_attack(self):

        if hasattr(self, "uuid") and hasattr(self, "secret"):
            attack_payload = {
                "filter": {"clientid": [self.clientid], "vulnid": None, "!type": ["warn"],
                           "time": [[self.unixtime, None]]},
                "limit": 50, "offset": 0, "order_by": "first_time", "order_desc": True}
            attack_resp = requests.post(self.attack, json=attack_payload,
                                        headers={'X-WallarmAPI-UUID': self.uuid,
                                                 'X-WallarmAPI-Secret': self.secret})
        else:
            attack_payload = {
                "filter": {"clientid": [self.clientid], "vulnid": None, "!type": ["warn"],
                           "time": [[self.unixtime, None]]},
                "limit": 50, "offset": 0, "order_by": "first_time", "order_desc": True, "token": self.token}
            attack_resp = requests.post(self.attack, json=attack_payload, cookies=self.cookies)

        attack_pretty = json.dumps(json.loads(attack_resp.text), indent=2)

        try:
            send_to_elastic(attack=attack_pretty)
        except:
            pass
        finally:
            print("The attacks haven't been sent to elastic due to problems with the connection to it")
            # Writing attacks to the file "attack.json"
            with open("attack.json", 'w') as f:
                json.dump(json.loads(attack_resp.text)['body'], f, indent=2)

            self.attack_obj = Data(attack_resp.json())
            self.size_of_attack = self.attack_obj.length()
            # print(self.attack_obj.__dict__)

    def get_hit(self):

        # Flush files if it exists
        f = open("hits.json", "w")
        f.write('')

        try:
            for i in range(self.size_of_attack):
                attack_id = self.attack_obj.body[i]['attackid']
                attack_id = attack_id.split(':')
                if hasattr(self, "uuid") and hasattr(self, "secret"):
                    hit_payload = {"filter": [
                        {"vulnid": None, "!type": ["warn", "marker"], "!domain": ["127.0.0.1", "www.127.0.0.1"],
                         "time": [[self.unixtime, None]], "clientid": [self.clientid],
                         "!experimental": True, "attackid": [attack_id[0], attack_id[1]]}],
                        "limit": 50, "offset": 0, "order_by": "time", "order_desc": True}
                    hit_resp = requests.post(self.hit, json=hit_payload, headers={'X-WallarmAPI-UUID': self.uuid,
                                                 'X-WallarmAPI-Secret': self.secret})
                else:
                    hit_payload = {"filter": [
                        {"vulnid": None, "!type": ["warn", "marker"], "!domain": ["127.0.0.1", "www.127.0.0.1"],
                         "time": [[self.unixtime, None]], "clientid": [self.clientid],
                         "!experimental": True, "attackid": [attack_id[0], attack_id[1]]}],
                        "limit": 50, "offset": 0, "order_by": "time", "order_desc": True, "token": self.token}
                    hit_resp = requests.post(self.hit, json=hit_payload, cookies=self.cookies)

                hit_pretty = json.dumps(json.loads(hit_resp.text), indent=2)

                if hit_resp.status_code == requests.codes.ok:
                    try:
                        send_to_elastic(hit=hit_pretty)
                    except:
                        pass
                    finally:
                        print("The attacks haven't been sent to elastic due to problems with the connection to it")
                        # Open file in append mode. If file does not exist, it creates a new file.
                        f = open("hits.json", "a")
                        f.write(json.dumps(json.loads(hit_resp.text)['body'], sort_keys=True, indent=2))
                        f.close()
                else:
                    print('HTTP status code is not 200')
                    sys.exit(1)

                # Create instance of class Data in order to appeal to body directly as part of object
                self.hit_obj = Data(hit_resp.json())
                self.size_of_hit = self.hit_obj.length()

        except KeyError as err:
            print(
                f'Either the response is empty or no key you tried to get: \n{err} \nPerhaps, you may need to increase the '
                f'time range')
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print(f'Other error occurred: \n{err}')
            sys.exit(1)

    def get_details(self):

        f = open("details.json", "w")
        f.write('')

        for i in range(self.size_of_attack):
            for k in range(self.size_of_hit):
                hit_id = self.hit_obj.body[k]['id']
                if hasattr(self, "uuid") and hasattr(self, "secret"):
                    details_payload = {"id": f"{hit_id[0]}:{hit_id[1]}"}
                    self.details_resp = requests.get(self.details, params=details_payload,
                                                     headers={'X-WallarmAPI-UUID': self.uuid,
                                                    'X-WallarmAPI-Secret': self.secret})
                else:
                    details_payload = {"id": f"{hit_id[0]}:{hit_id[1]}", "token": self.token}
                    self.details_resp = requests.get(self.details, params=details_payload, cookies=self.cookies)

                details_pretty = json.dumps(json.loads(self.details_resp.text), indent=2)

                if self.details_resp.status_code == requests.codes.ok:
                    try:
                        send_to_elastic(details=details_pretty)
                    except:
                        pass
                    finally:
                        print("The details of attacks haven't been sent to elastic due to problems with the connection to it")
                        f = open("details.json", "a")
                        f.write(json.dumps(json.loads(self.details_resp.text)['body'], sort_keys=True, indent=2))
                        f.close()
                else:
                    print('HTTP status code is not 200')
                    sys.exit(1)

    def get_blacklist(self):

        f = open("blacklist.json", "w")
        f.write('')
        f = open("blacklist_history.json", "w")
        f.write('')

        # Current blacklist fetching
        attack_delay = 600
        if hasattr(self, "uuid") and hasattr(self, "secret"):
            blacklist_payload = {"attack_delay": attack_delay, "filter[clientid]": self.clientid}
            self.blacklist_resp = requests.get(self.blacklist, params=blacklist_payload,
                                                    headers={'X-WallarmAPI-UUID': self.uuid,
                                                    'X-WallarmAPI-Secret': self.secret})
        else:
            blacklist_payload = {"attack_delay": attack_delay, "filter[clientid]": self.clientid, "token": self.token}
            self.blacklist_resp = requests.get(self.blacklist, params=blacklist_payload, cookies=self.cookies)

        blacklist_pretty = json.dumps(json.loads(self.blacklist_resp.text), indent=2)

        if self.blacklist_resp.status_code == requests.codes.ok:
            try:
                send_to_elastic(blacklist=blacklist_pretty)
            except:
                pass
            finally:
                print("The blacklist hasn't been sent to elastic due to problems with the connection to it")
                f = open("blacklist.json", "a")
                f.write(json.dumps(json.loads(self.blacklist_resp.text)['body'], sort_keys=True, indent=2))
                f.close()

        # Blacklist history
        if hasattr(self, "uuid") and hasattr(self, "secret"):
            blacklist_hist_payload = {"filter[clientid]": self.clientid, "filter[start_time]": self.unixtime,
                                  "filter[end_time]": None}
            self.blacklist_hist_resp = requests.get(self.blacklist_hist, params=blacklist_hist_payload,
                                                    headers={'X-WallarmAPI-UUID': self.uuid,
                                                    'X-WallarmAPI-Secret': self.secret})
        else:
            blacklist_hist_payload = {"filter[clientid]": self.clientid, "filter[start_time]": self.unixtime,
                                  "filter[end_time]": None, "token": self.token}
            self.blacklist_hist_resp = requests.get(self.blacklist_hist, params=blacklist_hist_payload, cookies=self.cookies)

        blacklist_hist_pretty = json.dumps(json.loads(self.blacklist_hist_resp.text), indent=2)
        f = open("blacklist_history.json", "a")
        f.write(json.dumps(json.loads(self.blacklist_hist_resp.text)['body'], sort_keys=True, indent=2))
        f.close()

    def get_vuln(self):

        f = open("vulnerabilities.json", "w")
        f.write('')

        # Vulnerabilities
        if hasattr(self, "uuid") and hasattr(self, "secret"):
            vulns_payload = {"limit": 50, "offset": 0, "filter": {"status": "open"}, "order_by": "threat",
                             "order_desc": True}
            self.vulns_resp = requests.get(self.vulns, params=vulns_payload, headers={'X-WallarmAPI-UUID': self.uuid,
                                                    'X-WallarmAPI-Secret': self.secret})
        else:
            vulns_payload = {"limit": 50, "offset": 0, "filter": {"status": "open"}, "order_by": "threat",
                             "order_desc": True, "token": self.token}
            self.vulns_resp = requests.get(self.vulns, params=vulns_payload, cookies=self.cookies)

        vulns_pretty = json.dumps(json.loads(self.vulns_resp.text), indent=2)

        if self.vulns_resp.status_code == requests.codes.ok:
            try:
                send_to_elastic(vulns=vulns_pretty)
            except:
                pass
            finally:
                print("The vulnerabilities haven't been sent to elastic due to problems with the connection to it")
                f = open("vulnerabilities.json", "a")
                f.write(json.dumps(json.loads(self.vulns_resp.text)['body'], sort_keys=True, indent=2))
                f.close()


def parsing_arguments():
    parser = argparse.ArgumentParser(
        prog='''request.py''',
        usage='''python %(prog)s [options] (batch)''',
        description='''This script may be used for request Wallarm API and send output directly to elasticsearch 
        without any filtering''',
        epilog="""This is PoC""",
        add_help=False)

    parser._action_groups.pop()
    action = parser.add_argument_group('Mode arguments')
    optional = parser.add_argument_group('Optional arguments')

    action.add_argument('--batch', action='store_true', help='start in batch mode')
    optional.add_argument('--help', action='help', default=argparse.SUPPRESS, help='show this help message and exit')

    args = parser.parse_args()

    return args


def get_env():
    username = None
    password = None
    uuid = None
    secret = None

    try:
        api = os.environ['WALLARM_API']
        if "WALLARM_USERNAME" in os.environ and "WALLARM_PASSWORD" in os.environ:
            username = os.environ['WALLARM_USERNAME']
            password = os.environ['WALLARM_PASSWORD']
        if "WALLARM_UUID" in os.environ and "WALLARM_SECRET" in os.environ:
            uuid = os.environ['WALLARM_UUID']
            secret = os.environ['WALLARM_SECRET']
    except NameError:
        print("WALLARM_API env variable is not defined")

        return api, username, password, uuid, secret


def get_pass(method):
    api = input("API domain (without https://): ")
    if api == 'api.wallarm.com' or api == 'us1.api.wallarm.com':
        if method == 'username':
            username = input("Username: ")
            password = getpass.getpass(prompt='Password: ')
        if method == 'uuid':
            username = input("UUID: ")
            password = getpass.getpass(prompt='Secret: ')
    else:
        print("That's not Wallarm API address")
        sys.exit(1)

    return api, username, password


def get_filter():
    isValid = False
    fail = 0
    while not isValid and fail != 5:
        date_in = input("Choose date for the fetching data\nDate in format dd-mm-YYYY: ")
        try:
            day, month, year = map(int, date_in.split('-'))
            if year >= 2019:
                # date = datetime.datetime.strptime(date_in, "%d-%m-%Y")
                d = datetime.date(year, month, day)
                unixtime = int(time.mktime(d.timetuple()))
                isValid = True
            else:
                print('Year less than 2019. Try year => 2019')
        except ValueError:
            print("That's not the correct format! Try again: \n")
            fail += 1
            if fail == 4:
                print("One attempt left")
    if not isValid:
        print("Sorry, follow the rules, input the correct format date")
        sys.exit(1)

    return unixtime


def main():
    # Parsing arguments. In case --batch is presented use env variables (
    # $WALLARM_API/$WALLARM_USERNAME/$WALLARM_PASSWORD/WALLARM_UUID/WALLARM_SECRET) correspondingly, otherwise,
    # interactive mode is on

    args = parsing_arguments()
    if args.batch:
        api, username, password, uuid, secret = get_env()
        if username is not None and password is not None:
            now = int(datetime.datetime.now())
            unixtime = now - datetime.timedelta(days=7)
            handler_object = HandlerAPI(api, "username", username, password, unixtime)
            handler_object.get_clientid()
            handler_object.get_attack()
        elif uuid is not None and secret is not None:
            now = int(datetime.datetime.now())
            unixtime = now - datetime.timedelta(days=7)
            handler_object = HandlerAPI(api, "uuid", uuid, secret, unixtime)
            handler_object.get_clientid()
            handler_object.get_attack()
        else:
            print("Environment is not exported. Use interactive mode (start script without arguments) or set "
                  "environment variables correspomdingly")
            sys.exit(1)
    else:
        print("Choose the way to authorize on a cloud\n1. Username/Password\n2. UUID/Secret\nType 1 or 2")
        auth_input = input("Method to authorize is: ")

        if auth_input == "1":
            api, username, password = get_pass('username')
            unixtime = get_filter()
            handler_object = HandlerAPI(api, "username", username, password, unixtime)
            handler_object.authentication()
        elif auth_input == "2":
            api, uuid, secret = get_pass('uuid')
            unixtime = get_filter()
            handler_object = HandlerAPI(api, "uuid", uuid, secret, unixtime)
        else:
            print("Input the correct number")
            sys.exit(1)
        handler_object.get_clientid()
        # handler_object.get_attack()
        # handler_object.get_hit()
        # handler_object.get_details()
        handler_object.get_blacklist()
        handler_object.get_vuln()

    # Deleting of the object manually
    # del handler_object


if __name__ == '__main__':
    main()
