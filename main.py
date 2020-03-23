#!/usr/bin/env python3

import asyncio
import json


from wallarm_api.wlrm import WallarmAPI, SenderData
from wallarm_api.settings import UUID, SECRET, API


async def main():
    api_call = WallarmAPI(uuid=UUID, secret=SECRET, api=API)
    attacks = asyncio.create_task(api_call.get_attack(start='last day'))
    vulns = asyncio.create_task(api_call.get_vuln())
    action = asyncio.create_task(api_call.get_action())
    hint = asyncio.create_task(api_call.get_hint())
    blacklist = asyncio.create_task(api_call.get_blacklist())
    blacklist_hist = asyncio.create_task(api_call.get_blacklist_hist(start='last week'))
    create_rule = asyncio.create_task(api_call.create_vpatch(instance='1', domain='wallarm.com', action_name='.git'))

    tasks = [attacks, vulns, action, hint, blacklist, blacklist_hist]
    # tasks = [attacks]

    results = await asyncio.gather(*tasks)
    [print(json.dumps(result, sort_keys=True, indent=4)) for result in results]

    # elastic = SenderData(address='http://localhost:9200', user='elastic', passwd='changeme')
    # [asyncio.create_task(send_to_elastic.send_to_collector(result['body'], token='TOKEN'), name=f'tcp_{i}') for i, result in
    #  enumerate(results)]
    #
    # sumo = SenderData(address='https://sumologic.collector.com')
    # [asyncio.create_task(sumo.send_to_collector(result['body'], token='TOKEN'), name=f'tcp_{i}') for i, result in
    #  enumerate(results)]
    #
    # # Splunk/Fluentd http
    # http = SenderData(address='https://localhost:8088')
    # [asyncio.create_task(http.send_to_collector(result['body'], token='TOKEN', verify=False), name=f'http_{i}') for i, result in enumerate(results)]
    #
    # sys_tcp = SenderData(address='tcp://localhost:514')
    # [asyncio.create_task(sys_tcp.send_to_collector(result['body'], token='TOKEN'), name=f'tcp_{i}') for i, result in
    #  enumerate(results)]
    #
    # sys_udp = SenderData(address='udp://localhost:514')
    # [asyncio.create_task(sys_udp.send_to_collector(result['body'], token='TOKEN'), name=f'udp_{i}') for i, result in
    #  enumerate(results)]


if __name__ == '__main__':
    asyncio.run(main())
