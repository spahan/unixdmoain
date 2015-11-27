#!/usr/bin/python
# coding: utf-8


"""
kinit for unibas cell
"""



REALM = "UD.UNIBAS.CH"
# REALM = "CUS.URZ.UNIBAS.CH"
cell = "cus.urz.unibas.ch"
# DEBUG = True
DEBUG = False




import subprocess
import sys
import os
from getpass import getpass
import datetime 


def showres((stdout, stderr)):
    if stdout: 
        print stdout
    if stderr: 
        print("-"*40)
        print stderr


def convert_expiration(exdate, extime):
    month = int(exdate.split("/")[0])
    day = int(exdate.split("/")[1])
    year = int("20%s" % exdate.split("/")[2])
    hour = int(extime.split(":")[0])
    min = int(extime.split(":")[1])
    sec = int(extime.split(":")[2])
    return( datetime.datetime(year, month, day, hour, min, sec) )


def klist():
    sess = subprocess.Popen("klist", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return(sess.communicate())


def klistprinc():
    def test_krbtgt(stdout):
        stdout = stdout.split("\n")
        KRBTGT = "krbtgt/%s@%s" % (REALM, REALM)
        for e in stdout:
            if KRBTGT in e:
                now_dt = datetime.datetime.now()
                tgt_dt = convert_expiration(e.split()[2], e.split()[3])
                if now_dt.strftime("%s") > tgt_dt.strftime("%s"):
                    print("WARN: your ticket has expired -> need to renew interactive ! ")
                    return(False)
                else:
                    return(now_dt)
        return(False)

    def get_princname(stdout):
        PSTRING = "Default principal: "
        if PSTRING in stdout:
            start = stdout.index(PSTRING)
            end = stdout[start:].index("\n")
            start += len(PSTRING)
            end -= len(PSTRING)
            return(stdout[start:][:end])
        else: 
            return(False)
    stdout, stderr = klist()
    princ = get_princname(stdout)
    tgt = test_krbtgt(stdout)
    if princ and tgt: 
        return(princ)
    else: 
        return(False)
    
    


def kinit():
    princ = None
    if len(sys.argv) > 1:
        user = "%s@%s" % (sys.argv[1], REALM)
        passwd = getpass(prompt='password for %s : ' % user)
        KINIT = ["kinit", user]
    else:
        princ = klistprinc()
        if princ: 
            user = princ
            passwd = "\n"
            KINIT = ["kinit", "-R"]
        else:
            user = "%s@%s" % (raw_input("please give your username : "), REALM)
            if user ==("@%s" % REALM): user = "%s@%s" % (os.getenv("USER"), REALM)
            passwd = getpass(prompt='password for %s : ' % user)
            KINIT = ["kinit", user]
    if DEBUG: print KINIT
    # [ KINIT.append(e) for e in sys.argv[1:] ]
    sess = subprocess.Popen(KINIT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    showres(sess.communicate(passwd))


def aklog():
    if DEBUG: 
        # AKLOG = ["aklog", "-d", "-c" , cell, "-k", cell.upper()]
        AKLOG = ["aklog", "-d", "-c" , cell, "-k", REALM]
        # AKLOG = ["aklog", "-d", "-c" , cell, "-k", cell.upper(), "-setpag"]
        # AKLOG = ["aklog", "-d", "-c" , cell, "-k", REALM, "-setpag"]
    else: 
        AKLOG = ["aklog", "-c" , cell, "-k", REALM]
        # AKLOG = ["aklog", "-c" , cell, "-k", cell.upper()]
        # AKLOG = ["aklog", "-c" , cell, "-k", cell.upper(), "-setpag"]
    if DEBUG: print AKLOG
    sess = subprocess.Popen(AKLOG, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    showres(sess.communicate())


def show_token():
    sess = subprocess.Popen("tokens", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return(sess.communicate())
    


def main():
    if DEBUG: showres(klist())
    kinit()
    aklog()
    showres(show_token())


if __name__ == "__main__": main()



