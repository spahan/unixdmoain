# various helpers for www

from UniDomain import Classes
import logging

def open_ud2_connection(env):
    config = Classes.Config(file='/opt/UD2/etc/www_conf.xml')
    authen = Classes.Authen(config).authenticate(ccpath=env['KRB5CCNAME'])
    if not authen:
        return ("403 Forbidden", "Can not validate kerberos Ticket Data")
        #return writeError(req, apache.HTTP_FORBIDDEN, "Can not validate kerberos Ticket Data")
    db = Classes.DB(authen).connect()
    if not db:
        return ("403 Forbidden", "Database Connection failed for user %s" % (env['REMOTE_USER']))
        #return writeError(req, apache.HTTP_FORBIDDEN, "Database Connection failed for user %s" % (req.subprocess_env['REMOTE_USER']))
    return (False, db)

# no longer needed as we always use backend ids.
def parse_id(id, db):
    if not id:
        return (False, db.home[0])
    if not any([id.endswith(home) for home in db.home]):
        return ("403 Forbidden", "You are not allowed to see this Object.")
    return (False, id)
