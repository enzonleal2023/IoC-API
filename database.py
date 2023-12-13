import sqlite3
import json
import sys
import ipaddress

conection = sqlite3.connect('attackers_ips.db')
cursor = conection.cursor()

# -c to execute


def create_database():
    cursor.execute(
        '''
            CREATE TABLE attackers (ip TEXT PRIMARY KEY, ports TEXT);
        '''
    )


def verifica_se_porta_existe(ip):
    cursor.execute("SELECT ports FROM attackers WHERE ip = ?", (ip['ip_address'],))
    portas = cursor.fetchall()
    portas_list = portas[0][0].split(',')
    portas_lista = []
    for porta in portas_list:
        portas_lista.append(porta)

    for porta in ip['ports']:
        if str(porta) not in portas_lista:
            portas_lista.append(porta)

    return portas_lista


def insert_into_database():
    with open('ips_atacantes.json', 'r') as file:
        data = sorted(json.load(file), key=lambda k: k['ip_address'])

    for ip in data:
        query = "SELECT EXISTS(SELECT 1 FROM attackers WHERE ip = ? LIMIT 1)"
        cursor.execute(query, (ip['ip_address'],))
        exists = cursor.fetchone()[0]
        ports_string = ','.join(map(str, ip['ports']))
        if ipaddress.ip_address(ip['ip_address']).version == 6:
            break

        # ip_to_int = int(ip['ip_address'].replace('.', ''))
        # print(ip_to_int)

        ip_to_int = ip['ip_address']

        if exists:
            ports_not_in_database = verifica_se_porta_existe(ip)
            ports_not_in_database_ordered = sorted(ports_not_in_database)
            ports_string = ','.join(map(str, ports_not_in_database_ordered))
            cursor.execute('''UPDATE attackers SET ports = ? WHERE ip = ?''', (ports_string, ip_to_int))
        else:
            cursor.execute('''INSERT INTO attackers (ip, ports) VALUES (?, ?)''', (ip_to_int, ports_string))


if len(sys.argv) >= 2:
    create = sys.argv[1]
    if create == '-c':
        create_database()

insert_into_database()
conection.commit()
