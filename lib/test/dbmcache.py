

import UniDomain.UniDomain as UniDomain
import UniDomain.dbmcache as dbmcache



host = UniDomain.host()
db = dbmcache.dbmNode(dbpath=host.config["cachedir"])



