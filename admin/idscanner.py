#!/usr/bin/env python2
"""
scan the SCANDIR every SLEEPTIME for new idfiles and process them.
idfiles are pushed into a queue instance where MAXTHREAD workers are waiting
and processing the idfiles. 
Processing means, add / remove or change the password of a kdc user principal.
Every idfile can only be processed once, then it is removed

(c) 2010, marco.hoehle@unibas.ch
"""

import os
import logging
from threading import Thread
from Queue import Queue
from Queue import Empty
from time import sleep
from datetime import datetime
import UniDomain.UniDomain as UniDomain



SCANDIR = "/home/idmsync/queue/"
SLEEPTIME = 1
MAXTHREAD = 8

KEYTAB = "/root/janitor/janitor.keytab"



#-------------------------------------------------------------
class Worker(Thread):
    def __init__(self, princ, queue):
        self.queue = queue
        self.princ = princ
        Thread.__init__(self)

    def run(self):
        while True:
            try:
                idfile = self.queue.get(timeout=4)
            except Empty:
                if __debug__: logging.debug("%s - queue is empty, terminate." % self.getName())
                return()
            try:
                self.process(idfile)
            except IOError: 
                logging.warn("%s - %s does not exist but was still in queue, removed." % (self.getName(), idfile))

    def process(self, idfile):
        threadID = self.getName()
        if __debug__: logging.debug("%s - process %s " % (threadID, idfile))
        fd = open(idfile, "r")
        pwd = fd.read()
        uid = idfile.split("/")[-1]
        princ = self.princ
        if pwd:
            if __debug__: logging.debug("%s - got user %s\n" % (threadID, uid) )
            if len(princ.authen.list_users(uid)) == 0:
                if __debug__: logging.debug("%s - \'%s\' - does not exists, create new." % (threadID, uid) )
                logging.info(princ.authen.add_user(uid,pwd))
            else:
                if __debug__: logging.debug("%s - \'%s\' exists, change password " % (threadID, uid) )
                logging.info(princ.authen.change_user_password( uid, pwd))
        else:
            if len(princ.authen.list_users(uid)) > 0:
                logging.info("%s - got user %s with NULL password (remove user from KDC)." % (threadID, uid) )
                logging.info(princ.authen.delete_user(uid))
        try:
            os.unlink(idfile)
        except OSError:
            logging.warn("%s - another thread seems to have cleanup up our linkfile %s." % (threadID, idfile) )
    



def serv_forever(SCANDIR=SCANDIR):
    while True:
        userlist = os.listdir(SCANDIR)
        if userlist:
            roger = UniDomain.janitor(KEYTAB=KEYTAB)
            if __debug__: logging.debug(userlist)
            queue = Queue()
            [ Worker(roger, queue).start() for i in range(MAXTHREAD) ]
            [ queue.put("%s/%s" % (SCANDIR, uid)) for uid in userlist ]
            logging.info("(%s) processing queue (%d items) ... " % (datetime.now(), len(userlist)) ) 
            while not queue.empty():  
                sleep(SLEEPTIME)
            logging.info("(%s) queue done." % datetime.now() ) 
            roger = None
            sleep(10)
            os.system("killall kadmin")
        sleep(SLEEPTIME)



if __name__ == "__main__": 
    logging.basicConfig(level=logging.DEBUG)
    try:
        logging.info("(%s) Daemon started, press CTRL+C or send sighup/sigterm/sigkill to exit" % datetime.now())
        serv_forever()
    except KeyboardInterrupt:
        logging.info("(%s) Daemon stopped via keystroke" % datetime.now())
    





