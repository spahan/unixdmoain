#coding: utf-8


"""
defines some query and update classes for pts and volser

"""


CELL = "cus.urz.unibas.ch"


import subprocess
import re
import os


def call(CMD):
    sess = subprocess.Popen(CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return(sess.communicate())
def showres((stdout, stderr)):
    if stdout: 
        for line in stdout.split("\n"):
            if len(line) > 0: print(line)
    if stderr: 
        for line in stderr.split("\n"):
            if len(line) > 0: print(line)




class AccessDenied(Exception):
    def __init__(self, message="Exception: AccessDenied"):
        self.msg = message
    def __str__(self):
        return(self.msg)

class PTSError(Exception): 
    def __init__(self, message="Exception: ProtectionServerError"):
        self.args = message

class VLError(Exception):
    def __init__(self, message="Exception: VolumeServerError"):
        self.args = message




class ProtectionServer(object):
    def __init__(self):
        self.listent()

    def listent(self):
        self.user = {}
        self.group = {}
        CMD = "pts listent -users -groups -cell %s " % CELL
        sout, serr = call(CMD.split())
        entries = sout.split("\n")[1:]
        [ entries.remove(e) for e in entries if len(e) == 0 ]
        if not entries:
            raise AccessDenied("could not read PTS, permission denied ?")
        for line in entries:
            Name, ID, Owner, Creator = line.split()
            ID, Owner, Creator = int(ID), int(Owner), int(Creator)
            if ID >= 0:
                # self.user[Name] = (ID, Owner, Creator)
                self.user[Name] = ID
            else:
                # self.group[Name] = (ID, Owner, Creator)
                self.group[Name] = ID

    def createuser(self, uid, uidNumber):
        if uidNumber <= 0:
            raise PTSError("wrong uidNumber for createuser")
        if len(uid) <= 0:
            raise PTSError("wrong uid given for createuser")
        if uid in self.user.keys() or uid in self.group.keys():
            raise PTSError("uid does already exist in PTS")
        if uidNumber in self.user.values():
            raise PTSError("uidNumber does already exist in PTS")
        CMD = "pts createuser -name %s -id %d -cell %s" % (uid, uidNumber, CELL)
        showres( call(CMD.split()) )
        self.user[uid] = uidNumber

    def deleteuser(self, uid):
        if not uid in self.user.keys():
            raise PTSError("user entry cannot be deleted as it does not exist")
        CMD = "pts delete -nameorid %s -cell %s " % (uid, CELL)
        showres( call(CMD.split()) )
        null = self.user.pop(uid)
        print("User %s deleted from pts" % uid)
        
      


class VolumeServer(object):
    def __init__(self):
        self.vldb()
        CMD = "vos listaddrs -cell %s " % CELL
        sout, serr = call( CMD.split() )
        self.fileserv = sout.split("\n")[:-1]
        
    def vldb(self):
        volumes = []
        CMD = "vos listvldb -cell %s " % CELL
        sout, serr = call(CMD.split())
        entries = sout.split("\n")
        [ entries.remove(e) for e in entries if len(e) == 0 ]
        [ volumes.append(e.strip()) for e in entries if e[0].strip() ]
        self.volumes = volumes[1:-1]
        if not self.volumes:
            raise AccessDenied("could not read VolumeServer, permission denied ?")

    def __str__(self):
        msg = "Total volumes in vldb : %d" % len(self.volumes)
        return(msg)

    def create(self, voldata, quota=5000):
        volume, fileserver, partition = voldata
        if volume in self.volumes: 
            raise VLError("cannot create volume, exists already !")
        print("create volume \'%s\' on %s in partition %s " % voldata)
        CMD = "vos create -server %s -partition %s -name %s -maxquota %d -cell %s" % (fileserver, partition, volume, quota, CELL)
        showres( call(CMD.split()) )
        self.volumes.append(volume)
        CMD = "vos backup %s" % volume
        showres( call(CMD.split()) )

    def remove(self, voldata):
        volume, fileserver, partition = voldata
        CMD = "vos remove -server %s -partition %s -id %s -cell %s" % (fileserver, partition, volume, CELL)
        showres( call(CMD.split()) )

    def rename(self, oldname, newname):
        if not oldname in self.volumes: 
            raise VLError("cannot rename old volume, does not exist !")
        if newname in self.volumes: 
            raise VLError("cannot rename old volume, newname does ALREADY exist !")
        CMD = "vos rename -oldname %s -newname %s" % (oldname, newname)
        showres( call(CMD.split()) )
        self.volumes.remove(oldname)
        self.volumes.append(newname)

    def cleanup_orphaned(self):
        def remove(self, volume):
            print("remove orphaned volume : %s " % volume)
            voldata = self.examine(volume)
            self.remove(voldata)
        removed = re.compile(".*\.__REMOVED__")
        [ remove(self, volume) for volume in self.volumes if removed.match(volume) ]

    def examine(self, volume):
        CMD = "vos examine %s " % volume
        stdout, stderr = call(CMD.split()) 
        RW_server = re.compile(" *server.*partition.*RW Site")
        for line in stdout.split("\n"):
            if RW_server.match(line):
                fileserver, partition = line.split()[1:4:2]
                return( (volume, fileserver, partition) )
        raise VLError("no RW site found for volume")
        
 
       
 

            


def fs_mkm(volpath, volname, BACKUP=True):
    print("create mountpoint %s " % volpath)
    CMD = "fs mkm %s %s -cell %s -rw" % (volpath, volname, CELL)
    showres( call(CMD.split()) )
    if BACKUP:
        CMD = "vos backup %s" % volname
        showres( call(CMD.split()) )
        print("create backup mountpoint %s.backup " % volpath)
        CMD = "fs mkm %s.backup %s.backup" % (volpath, volname)
        showres( call(CMD.split()) )

def fs_rmm(volpath, BACKUP=True):
    print("remove mountpoint %s " % volpath)
    CMD = "fs rmm %s " % volpath
    showres( call(CMD.split()) )
    if BACKUP:
        print("remove backup mountpoint %s.backup " % volpath)
        CMD = "fs rmm %s.backup " % volpath
        showres( call(CMD.split()) )



def set_permissions(homeDir, uid, uidNumber):
    print("set permissions for %s " % homeDir)
    CMD = "fs sa -dir %s -acl %s all" % (homeDir, uid) 
    showres( call(CMD.split()) )
    CMD = "chmod 750 %s" % homeDir 
    showres( call(CMD.split()) )
    CMD = "chown %d %s" % (uidNumber, homeDir)
    showres( call(CMD.split()) )
        



def setup_user(pts, vos, usertuple, fstuple, quota=5000):
    uid, uidNumber, homeDir = usertuple
    fileserver, partition = fstuple
    
    uidNumber = int(uidNumber)
    uservol = "u.%s" % homeDir.split("/")[-1]
    homepath = "/".join(homeDir.split("/")[:-1])

    print("setup \'%s\' (%d) with volume \'%s\' on %s\'s partition %s." % (uid, uidNumber, uservol, fileserver, partition) )
    print("mountpath is : %s " % homepath)
    if not os.access(homepath, os.F_OK):
        print("%s does not exist, create ! " % homepath)
        os.makedirs(homepath,0755)
        os.chown(homepath, 0, 0)
        if not os.access(homepath, os.F_OK):
            raise Exception("CANNOT ACCESS BASE HOMEPATH FOR USERS ! ")

    try:
        pts.createuser(uid, uidNumber)
    except PTSError, msg:
        print("WARN: %s" % msg)
    try:
        vos.create((uservol, fileserver, partition), quota=quota )
    except VLError, msg:
        print("WARN: %s" % msg)

    fs_mkm( homeDir, uservol )
    set_permissions( homeDir, uid, uidNumber )
 
  


def disable_user(pts, vos, usertuple, fstuple):    
    uid, uidNumber, homeDir = usertuple
    fileserver, partition = fstuple
    uservol = "u.%s" % homeDir.split("/")[-1]

    print("remove mountpoints to userhome")
    fs_rmm( homeDir )

    print("remove userID %s " % uid )
    try:
        pts.deleteuser(uid)
    except PTSError, msg:
        print("WARN: %s" % msg)

    removeduservol = "u.%s.__REMOVED__" % homeDir.split("/")[-1] 
    print("rename userhome volume from %s to %s " % (uservol, removeduservol) )
    try:
        vos.rename(uservol, removeduservol )
    except VLError, msg:
        print("WARN: %s" % msg)




