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

class CrawlerThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.jobs = queue
        self.kill_received = False

    def run(self):
        while not self.kill_received:
            try:
                target_domain, codes, urls,contents = self.jobs.get(block=False)
            except queue.Empty:
                self.kill_received = True
                return
            logger.debug(f"crawling  {target_domain}")
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.122 Safari/537.36'
            headers = {'User-Agent': user_agent}
            for url in urls:
                whole_url = f"https://{target_domain}{url}"
                try:
                    request = requests.get(whole_url,headers=headers, timeout=1)
                    logger.debug(f"getting {target_domain} {whole_url}")
                    time.sleep(0.1)
                    if request.status_code == 200:
                        for content in contents:
                            if content and content in request.content.decode('utf8').lower():
                                cautions.append({"url": whole_url, "content": content,"domain":target_domain})
                except Exception as ex:
                    logger.debug(f'{target_domain} {whole_url} {ex}')
            self.jobs.task_done()
    def stop(self):
        self.kill_received=True
def crawer(host, caution_codes):
    START_TIME = datetime.now()
    global threads, cautions
    count_urls=0
    cautions=[]
    urls=['/','/api/','/api/js/trust.codes.js','/trust.codes.js']
    contents = ["trust", "code", "authentic"] + host['customer'].split(' ')

    exclude_domains = json.loads(open(f"./files/exclude_domains.json").read())
    if os.path.isfile(f"{TMP_FOLDER}/{FILES_PRE_REGISTED_DOMAIN}{host['host']}.json"):
        domains = [domain['domain-name'] for domain in json.loads(open(f"{TMP_FOLDER}/{FILES_PRE_REGISTED_DOMAIN}{host['host']}.json").read())]
        domains = [domain for domain in domains if not domain in exclude_domains]
        codes = [code for code in caution_codes if host['host'] in code]

        for code in codes:
            urls.append(f"/{code.split('/')[-1]}/")
        count_urls=len(urls)
        jobs = queue.Queue()
        threads = []
        for target_domain in domains:
            if not (target_domain == host['host']):
                jobs.put((target_domain,codes,urls,contents))
                
        for i in range(50):
            worker =CrawlerThread(jobs)
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
                
    return count_urls,cautions

def notify(body_text):
    # I scaned x urls for x hosts(y fuzzing domains,z are registerd).
    # Time used zz minuted.
    # xx suspicious pages found
    SENDER = "notifications@trust.codes"
    RECIPIENT = eval(os.getenv("RECIPIENTS",'["support@trust.codes"]'))
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
    DEBUG_MAX_HOSTS = False or eval(environ.get("DEBUG_MAX_HOSTS","0"))
    DEBUG_SENT_EMAIL = False or environ.get("DEBUG_SENT_EMAIL")
    DEBUG_EXCLUDE_TRUSTCODES = True and eval(environ.get("DEBUG_EXCLUDE_TRUSTCODES",'1'))
    DEBUG_INGNORE_CAUTION_CODES = True and eval(environ.get("DEBUG_EXCLUDE_TRUSTCODES",'1'))
    count_hosts = 0
    count_domains = 0
    count_regis_domains = 0
    count_urls = 0
    hosts = json.loads(open(f"./files/hosts.json").read())
    extra_host = json.loads(open(f"./files/extra_hosts.json").read())
    exclude_domains = json.loads(open(f"./files/exclude_domains.json").read())
    logger.debug(f"Exclude list: {exclude_domains}")
    hosts = [host for host in (hosts + extra_host)]
    if DEBUG_EXCLUDE_TRUSTCODES:
        hosts = [host for host in hosts if not (host['host'].endswith('.trust.codes') or host['host'].endswith('.green.codes'))]
    logger.debug(f"{len(hosts)} hosts found")
    cautions = []
    if not DEBUG_SENT_EMAIL:
        clean_tmp(TMP_FOLDER)
        i = 0
        if DEBUG_MAX_HOSTS:
            hosts=hosts[:DEBUG_MAX_HOSTS]
        for host in hosts[:3]:
            i=i+1
            logger.debug(f"fuzzing {i}/{len(hosts)} {host}")
            len_domains, len_regised = fuzzing(host)
            count_domains = count_domains + len_domains
            count_regis_domains = count_regis_domains + len_regised
            
        caution_codes = [code['url'] for code in json.loads(open(f"./files/caution_codes.json").read())]
        if DEBUG_INGNORE_CAUTION_CODES:
            caution_codes=[]
        i=0
        for host in hosts:
            i=i+1
            logger.debug(f"crawling {i}/{len(hosts)} {host}")
            count_hosts = count_hosts + 1
            new_count_urls, new_cautions = crawer(host, caution_codes)
            count_urls = count_urls+new_count_urls
            cautions = cautions + new_cautions
        logger.debug(cautions)
    logger.debug(f"Time use:{datetime.now()-START_TIME}")
    cautions_str = '\n'
    domains=[]
    for caution in cautions:
        cautions_str=cautions_str+f"{caution['content']} found in {caution['url']}\n"
        domains.append(caution['domain'])
    domains = list(set(domains))
    mail_content = f"""{len(cautions) } suspicious pages found.{cautions_str}
            Scaned {count_urls} urls for {count_hosts} hosts({count_domains} fuzzing domains,{count_regis_domains} are registerd).
            Time used: {datetime.now() - START_TIME}. 

            Domains:
            {json.dumps(domains)}
            """

    
    try:
        notify(mail_content)
    except Exception as ex:
        notify(mail_content)


if __name__ == '__main__':
    main()
