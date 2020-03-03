#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dnstwist import DomainFuzz, TldDict, DomainThread, UrlParser, generate_json
import re
import sys, os
import socket
import signal
import time
import argparse
import threading
from random import randint
from os import path
import smtplib
import json
from datetime import datetime
import requests
from os import environ
import boto3
from botocore.exceptions import ClientError
from botocore.client import Config
from loguru import logger



config = Config(connect_timeout=5, read_timeout=5, retries={'max_attempts': 0})


try:
    import queue
except ImportError:
    import Queue as queue

TMP_FOLDER = 'tmp'
FILES_PRE_REGISTED_DOMAIN = "registered_domains_"

def fuzzing(host):
    START_TIME = datetime.now()
    domains=[]
    logger.debug(host)
    url = UrlParser(host['host'])
    dfuzz = DomainFuzz(url.domain)
    dfuzz.generate()
    domains = dfuzz.domains
    tlddict = TldDict(url.domain)
    # tlddict.load_dict(args.tld)
    tlddict.generate()
    domains += tlddict.domains

    jobs = queue.Queue()

    global threads
    threads = []

    for i in range(len(domains)):
        jobs.put(domains[i])

    for i in range(100):
        worker = DomainThread(jobs)
        worker.setDaemon(True)

        worker.uri_scheme = url.scheme
        worker.uri_path = url.path
        worker.uri_query = url.query

        worker.domain_orig = url.domain

        worker.option_extdns = True
        worker.option_whois = True

        worker.start()
        threads.append(worker)
    qperc = 0
    while not jobs.empty():
        qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
        if qcurr - 15 >= qperc:
            qperc = qcurr
            logger.debug('%u%%' % qperc)
        time.sleep(1)
    for worker in threads:
        worker.stop()
        worker.join()

    domains_registered = [d for d in domains if len(d) > 2]
    f = open(f"{TMP_FOLDER}/domains_{url.domain}.json","w")
    f.write(generate_json(domains))
    f.close()
    f = open(f"{TMP_FOLDER}/{FILES_PRE_REGISTED_DOMAIN}{url.domain}.json","w")
    f.write(generate_json(domains_registered))
    f.close()
    logger.debug(f"Fuzzing time use:{datetime.now()-START_TIME}")
    return len(domains),len(domains_registered)


def clean_tmp(folder="tmp"):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            logger.debug('Failed to delete %s. Reason: %s' % (file_path, e))

def crawer(host, caution_codes):
    START_TIME = datetime.now()
    count_urls=0
    cautions=[]
    urls=['/','/api/','/api/js/trust.codes.js','/trust.codes.js']
    contents = ["trust", "code", "authentic"] + host['customer'].split(' ')
    if os.path.isfile(f"{TMP_FOLDER}/{FILES_PRE_REGISTED_DOMAIN}{host['host']}.json"):
        domains = [domain['domain-name'] for domain in json.loads(open(f"{TMP_FOLDER}/{FILES_PRE_REGISTED_DOMAIN}{host['host']}.json").read())]
        codes = [code for code in caution_codes if host['host'] in code]
        for target_domain in domains:
            if not (target_domain == host['host']):
                for code in codes:
                    urls.append(f"/{code.split('/')[-1]}/")
                for url in urls:
                    count_urls=count_urls+1
                    whole_url = f"https://{target_domain}{url}"
                    try:
                        request = requests.get(whole_url, timeout=1)
                        logger.debug(f"getting {whole_url}")
                        time.sleep(0.1)
                        if request.status_code == 200:
                            for content in contents:
                                if content and content in request.content.decode('utf8').lower():
                                    cautions.append({"url": whole_url, "content": content})
                    except Exception as ex:
                        logger.debug(f'{whole_url} {ex}')
    return count_urls,cautions

def notify(body_text):
    # I scaned x urls for x hosts(y fuzzing domains,z are registerd).
    # Time used zz minuted.
    # xx suspicious pages found
    SENDER = "notifications@trust.codes"
    RECIPIENT = eval(os.getenv("RECIPIENTS",'["ken@trust.codes"]'))
    CHARSET = 'UTF-8'
    SUBJECT = "Hosts scaning result  {}".format(datetime.now().strftime('%Y-%m-%d'))

    """Send email."""
    try:
        email_client = boto3.client(
            'ses',region_name='ap-southeast-2', config=config)
    #Provide the contents of the email.
        response = email_client.send_email(
            Destination={
                'ToAddresses': RECIPIENT
            },
            Message={
                'Body': {
                    'Text': {
                        'Charset': CHARSET,
                        'Data': (body_text),
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER
        )
        logger.debug(f"Email sent to {RECIPIENT} {body_text}")
    except ClientError as e:
        logger.debug(e.response['Error']['Message']) 

def main():
    START_TIME = datetime.now()
    DEBUG_MAX_HOSTS = False or environ.get("DEBUG_MAX_HOSTS")
    DEBUG_SENT_EMAIL = False or environ.get("DEBUG_SENT_EMAIL")
    count_hosts = 0
    count_domains = 0
    count_regis_domains = 0
    count_urls = 0
    hosts = json.loads(open(f"./files/hosts.json").read())
    extra_host = json.loads(open(f"./files/extra_hosts.json").read())
    exclude_domains = []
    hosts = [host for host in (hosts + extra_host) if not host['host'] in exclude_domains]
    logger.debug(f"{len(hosts)} hosts found")
    cautions = []
    if not DEBUG_SENT_EMAIL:
        clean_tmp(TMP_FOLDER)
        if DEBUG_MAX_HOSTS:
            hosts = hosts[:1]
        i=0
        for host in hosts:
            logger.debug(f"fuzzing {i}/{len(hosts)} {host}")
            len_domains, len_regised = fuzzing(host)
            count_domains = count_domains + len_domains
            count_regis_domains = count_regis_domains + len_regised
            
        caution_codes = [code['url'] for code in json.loads(open(f"./files/caution_codes.json").read())]
        i=0
        for host in hosts:
            logger.debug(f"crawling {i}/{len(hosts)} {host}")
            count_hosts = count_hosts + 1
            new_count_urls, new_cautions = crawer(host, caution_codes)
            count_urls = count_urls+new_count_urls
            cautions = cautions + new_cautions
        logger.debug(cautions)
    logger.debug(f"Time use:{datetime.now()-START_TIME}")
    cautions_str = '\n'
    for caution in cautions:
        cautions_str=cautions_str+"{caution['content']} found in {caution['url']}\n"
    mail_content = f"""{len(cautions) } suspicious pages found.{cautions_str}
            Scaned {count_urls} urls for {count_hosts} hosts({count_domains} fuzzing domains,{count_regis_domains} are registerd).
            Time used: {datetime.now()-START_TIME}."""
    notify(mail_content)


if __name__ == '__main__':
    main()
