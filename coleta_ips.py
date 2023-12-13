import requests
import json
import atexit
from typing import List, Dict
from contextlib import suppress

# elasticdump

HONEYPOT_AUTH_HEADER = {"Authorization": "Basic dXN1YXJpbzpBd2Vzb21lLXBvdA=="}
url_search_ = 'https://sauron.dataverso.net:64297/es/_search?'
src_ip = "src_ip"
honeypot_type = "type"
headers = HONEYPOT_AUTH_HEADER

def get_url(url: str, data_dict: dict, headers_dict: dict, timeout: int = 60):
	try:
		return requests.get(url, headers=headers_dict, timeout=timeout, json=data_dict, verify=False,)
	except:
		return None

def get_search_dict() -> dict:
	search_dict = \
	{
	  "size": 0,
	  "aggs": {
		"ips": {
		  "terms": {
			"field": "src_ip.keyword",
			"size": 1000
		  },
		  "aggs": {
			"filtered_dest_port": {
				"terms": {
				  "field": "dest_port",
				  "size": 1000
				}
			  }
		  }
		}
	  },
	  "query": {
		"range": {
		  "@timestamp": {
			"gte": "now-1h/h",
			"lte": "now/h"
		  }
		}
	  }
	}

	return search_dict
def search_ips_in_honeynet():
	search_dict = get_search_dict()
	response_pesquisa = get_url(url=url_search_, data_dict=search_dict, headers_dict=headers)
	ips = json.loads(response_pesquisa.content.decode())
	print(response_pesquisa.content)

	with open('ips.json', 'w') as f:
		json.dump(ips, f, indent=4)

def formata_json():

	with open('ips.json', "r") as f:
		ips_atacantes_json = json.load(f)

	lista_ips = ips_atacantes_json['aggregations']['ips']['buckets']
	ips_atacantes = list(dict())

	# Se o IP ja esta na lista, verificar se a porta em questao também ja esta
	for ip in lista_ips:
		ip_atual = ip['key']
		ports_list = ip["filtered_dest_port"]["buckets"]
		ports = set()
		for port in ports_list:
			ports.add(port["key"])

		ip_atacante = {"ip_address": ip_atual, "ports": list(ports)}
		ips_atacantes.append(ip_atacante)

	print(ips_atacantes)

	with open("ips_atacantes.json", "w") as f:
		json.dump(ips_atacantes, f, indent=4)

search_ips_in_honeynet()
formata_json()