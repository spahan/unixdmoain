#!/usr/bin/env python

import imaplib
import email
import sqlite
import datetime
import re
import logging
import socket
import time

from optparse import OptionParser
from cgi import parse_qs

WORKDIR = '/var/www/f2b/'
DATADIR = '/var/www/f2b/'
DATABASE = 'fail2ban.sqlite'

def openSqlite():
    ''' Open (and optionally create) the sql database '''
    con = sqlite.connect("%s%s" % (DATADIR, DATABASE))
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS ban ( 
        mail_id INT PRIMARY KEY, 
        banned_ip TEXT, 
        banned_name TEXT,
        service_ip TEXT, 
        service_name TEXT,
        time TEXT)''')
    con.commit()
    return con

def application(environ, start_response):
    '''wsgi entry point'''
    status = '200 OK'

    parameters = parse_qs(environ.get('QUERY_STRING'))

    bip = environ.get('REMOTE_ADDR')
    if 'bh' in parameters:
        try:
            bip = socket.gethostbyname(parameters['bh'][0])
        except Exception, e:
            pass
    sip = None
    if 'sh' in parameters:
        try:
            sip = socket.gethostbyname(parameters['sh'][0])
        except Exception, e:
            pass
    output = ['''<html>
    <head>
        <title>fail2ban check</title>
        <style>
            .active { background-color : red; }
            .recent { background-color : orange; }
        </style>
        <script>
            function setType(t) {
                document.forms[0].sh.name=t;
            }
        </script>
    </head>
    <body>
    <form>
        <input name="sh" type="text" length="20"/>
        <button onclick="setType('sh');">service</button>
        <button onclick="setType('bh');">client</button>
    </form>
    
''']
    if sip: output.append('<p>Checking for bans on service %s</p>' % sip)
    else: output.append('<p>Checking for banned ip %s</p>' % bip)

    sql_con = openSqlite()
    sql = sql_con.cursor()

    if sip:
        sql.execute('SELECT * FROM ban WHERE service_ip == "%s"' % sip)
    else:
        sql.execute('SELECT * FROM ban WHERE banned_ip == "%s"' % bip)
    bans = sql.fetchall()

    five_mins_ago = datetime.datetime.today() - datetime.timedelta(0,0,0,0,0,1)
    one_day_ago = datetime.datetime.today() - datetime.timedelta(1)
    output.append('<table><tr><th>banned host</th><th>service host</th><th>Date</th></tr>')
    reversed_output = []
    for ban in bans:
        ban_time = time.strptime(ban[5][0:-6],'%a, %d %b %Y %H:%M:%S')
        ban_time = datetime.datetime(*ban_time[0:6])
        if ban_time > five_mins_ago: active = "active"
        elif ban_time > one_day_ago: active = "recent"
        else: active = ""
        reversed_output.append('<tr class="%s"><td>%s (%s)</td><td>%s (%s)</td><td>%s</td></tr>' % (active, ban[2],ban[1],ban[4],ban[3],ban[5]))
    reversed_output.reverse()
    output.extend(reversed_output)

    response_headers = [('Content-type', 'text/html')]
    start_response(status, response_headers)

    return output


def scanMailbox():
    ''' connect to fail2ban mailbox and scan for new ban mails
        raises exception if a error occures '''
    RE_banned_ip = re.compile('^\[Fail2Ban] SSH: banned ([\d\.]*)$')
    RE_service_name = re.compile('^from (\S+)\s+.*by\s+smtp[12]priv\.unibas\.ch\s+with\s+ESMTP;.*$', re.S)
    MAILSERVER = 'mail.unibas.ch'
    MAILACCOUNT = 'root-urz@unibas.ch'
    MAILPASSWD = 'xxxx' # check if exchange accepts certificates or kerberos ticket
    
    imap = imaplib.IMAP4_SSL(MAILSERVER,993)
    status, data = imap.login(MAILACCOUNT,MAILPASSWD)
    imap.select('Fail2Ban')

    db = openSqlite()
    dbc = db.cursor()
    
    date = (datetime.date.today() - datetime.timedelta(1)).strftime('%d-%b-%Y') 
    status, mails = imap.uid('search', None, '(SENTSINCE %s SUBJECT "banned")' % date)
    logging.debug('scanMailbox: imap search returned %s', status)
    logging.debug("scanMailbox: imap search result is:\n%s", mails)
    for mail_id in mails[0].split():
        dbc.execute('SELECT * from ban WHERE mail_id = %s' % mail_id)
        if dbc.fetchone():
            logging.info('scanMailbox: skipping %s as we already processed it', mail_id)
        else:
            status, raw_mail = imap.uid('fetch', mail_id, '(RFC822)')
            logging.debug('scanMailbox: imap fetch returned %s', status)
            logging.debug("scanMailbox: imap fetch result is:\n%s", raw_mail)
            mail = email.message_from_string(raw_mail[0][1])
            banned_ip = RE_banned_ip.match(mail['Subject']).group(1)
            logging.debug('scanMailbox: banned_ip is %s', banned_ip)
            try:
                banned_name = socket.gethostbyaddr(banned_ip)[0]
            except Exception, e:
                banned_name = banned_ip
            logging.debug('scanMailbox: banned_name is %s', banned_name)
            # fail2ban does not send the source server name? scan headers for the host
            for rcv_header in mail.get_all('Received'):
                service_name = RE_service_name.match(rcv_header)
                if service_name:
                    service_name = service_name.group(1)
                    break
            if banned_ip and service_name:
                service_ip = socket.gethostbyname(service_name)
                logging.info('scanMailbox: %s (%s) banned %s (%s) at %s ', service_name, service_ip, banned_name, banned_ip, mail.get('Date'))
                dbc.execute('INSERT INTO ban VALUES(%s,"%s","%s","%s", "%s", "%s")' % (mail_id, banned_ip, banned_name, service_ip, service_name, mail.get('Date')))
            else:
                logging.warning('scanMailbox: failed to parse %s', mail_id)
                logging.info("scanMailbox: mail content was:\n%s", mail)
    db.commit()
    dbc.close()
    db.close()

if __name__ == "__main__":
    parser  = OptionParser()
    parser.add_option("-L", "--Level", type="int", dest="loglevel", help="Set Loglevel", default=30)
    options, args = parser.parse_args()
    logging.basicConfig(level=options.loglevel)
    scanMailbox()
