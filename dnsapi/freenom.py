#!/usr/bin/env python3
import os
import re
import sys
import bs4
import json
import logging
import requests
import urllib.parse

try:
    import lxml
    PARSER = 'lxml'
except:
    PARSER = 'html.parser'


def trim(s: str) -> str:
    return re.sub(r'\s+', ' ', s).strip()


def logging_table(titles, rows, length: int):
    format_func = lambda x: f'{x:<{length + 1}s}'

    logging.info(' '.join(map(format_func, titles)))
    for row in rows:
        logging.info(' '.join(map(format_func, row)))


def login(sess: requests.Session):
    r = sess.post(
        'https://my.freenom.com/dologin.php',
        headers = {
            'Referer': 'https://my.freenom.com/clientarea.php',
        },
        data = {
            'username': os.environ['FREENOM_USERNAME'],
            'password': os.environ['FREENOM_PASSWORD'],
        },
    )

    if 400 <= r.status_code < 600:
        logging.error('Login request failed')
        logging.error(r.content)
        r.raise_for_status()
    else:
        query = urllib.parse.urlparse(r.url).query
        if urllib.parse.parse_qs(query).get('incorrect') == 'true':
            logging.error('Login failed: incorrect details')
            sys.exit(1)


def list_domains(sess: requests.Session) -> list:
    # Domain List: name, registration date, expiry date, status, type, manage url
    uri = 'https://my.freenom.com/clientarea.php?action=domains'
    r = sess.get(
        uri,
        headers = {
            'Referer': 'https://my.freenom.com/clientarea.php',
        },
    )
    r.raise_for_status()

    html = bs4.BeautifulSoup(r.content, PARSER)
    domain_content = html('section', class_ = 'domainContent')
    assert len(
        domain_content
    ) == 1, 'Domains page should only contain one domainContent section'

    maxlen = 10
    titles = []
    rows = []
    for tr in domain_content[0]('tr'):
        if len(tr('th')) > 0:
            for th in tr('th'):
                text = trim(th.text)
                if text:
                    titles.append(text)
        else:
            is_domain = True
            rows.append([])
            for td in tr('td'):
                text = trim(td.text)
                if text == 'Manage Domain':
                    assert len(
                        td('a')
                    ) == 1, 'More than one link found in Manage Domain column'
                    rows[-1].append(
                        urllib.parse.urljoin(uri,
                                             td('a')[0]['href']))
                elif text:
                    rows[-1].append(text)
                    if is_domain:
                        maxlen = max(maxlen, len(text))
                        is_domain = False

    logging.info('Domain List:')
    logging_table(titles, rows, maxlen)
    return rows


def manage_domain(
        uri: str,
        domain: str,
        sess: requests.Session,
        action: str,
        records: list = None,
):
    query = urllib.parse.urlparse(uri).query
    domain_id = urllib.parse.parse_qs(query).get('id')
    if not domain_id:
        logging.error(f'Unable to get domain id from {uri}')
        return

    domain_id: str = domain_id[0]
    logging.debug(f'domain id "{domain_id}"')

    next_uri = f'https://my.freenom.com/clientarea.php?managedns={domain}&domainid={domain_id}'

    # simulate browser
    # r = sess.get(
    #     uri,
    #     headers = {'Referer': 'https://my.freenom.com/clientarea.php?action=domains'},
    # )
    # r = sess.get(
    #     next_uri,
    #     headers = {'Referer': uri},
    # )
    uri = next_uri

    params = {'dnsaction': action}
    if action == 'delete':
        params['managedns'] = domain
        params['domainid'] = domain_id
        for record in records:
            params['name'] = record['name']
            params['ttl'] = record['ttl']
            params['records'] = record['type']
            params['value'] = record['value']
            r = sess.get(
                f'https://my.freenom.com/clientarea.php',
                params = params,
                headers = {'Referer': uri},
            )
            r.raise_for_status()
    elif action == 'add':
        for i in range(len(records)):
            params[f'addrecord[{i}][name]'] = records[i]['name']
            params[f'addrecord[{i}][type]'] = records[i]['type']
            params[f'addrecord[{i}][ttl]'] = records[i]['ttl']
            params[f'addrecord[{i}][value]'] = records[i]['value']

        r = sess.post(
            uri,
            data = params,
            headers = {'Referer': uri},
        )
        r.raise_for_status()
    # elif action == 'modify': # not modify currently
    else:
        logging.error(f'Unknown action {action} for domain {domain}')
        return


def main():
    if len(sys.argv) < 4:
        logging.error(f'Usage: {sys.argv[0]} <action> <domain> <value>')
        sys.exit(1)

    action, full_domain, value = sys.argv[1:4]
    records = [
        {
            'name': full_domain,
            'ttl': '600',
            'type': 'TXT',
            'value': value,
        },
    ]

    with requests.session() as sess:
        login(sess)
        domains = list_domains(sess)

        for domain in domains:
            if full_domain.endswith(domain[0]):
                manage_domain(domain[-1], domain[0], sess, action, records)
                return


if __name__ == "__main__":
    logging.basicConfig(
        level = logging.DEBUG,
        format = '%(asctime)s %(levelname)s %(message)s',
        datefmt = "%H:%M:%S")
    main()