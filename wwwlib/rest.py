from mod_python import apache
from mod_python import util
import os.path
import urllib
import logging

debug = True

def handler(req):
    """
    This is called by Apache and maps the request to the resource class.
    Process of maping:
        1.  Try import a python script which handles this resource.
            The name will be determined by the *path_info* (see mod_python or apache cgi docs for details). while the last path part is treated as the resource ID.
            If no script was found, we return HTTP_NOT_FOUND
        2.  Check if the request method is in the allowedMethodes list of the imported script.
            If not, we set the allowed Methodes and return HTTP_METHOD_NOT_ALLOWED
            If the imported script does not define a allowedMethodes list, we return HTTP_NOT_FOUND
                assuming this is not a script to call, but some other thing.
        3. Parse the form data.
            #TODO: add support for JSON and XML. Currently only url-form-data is supported.
        4.  Call METHOD(req, id, args)
            req is the request object,
            id is the parsed id or None
            args is the mp_table object (may be empty)
            returns the return code from the function
            if the method is not defined, we return HTTP_NOT_IMPLEMENTED 
    """
    #Set log level here. For Production, disable both lines
    logging.basicConfig(level=logging.DEBUG) #Used for debug, lot of data, not recommended for simple error search.
    #logging.basicConfig(level=logging.INFO) #Used for error search with config.
    # 1.
    try:
        (mtype, mid) = req.path_info.lstrip('/').split('/',1)
    except ValueError, err:
        mtype = req.path_info.lstrip('/')
        mid = ''
    try:
        resourceModule = apache.import_module(mtype.strip('/').replace('/','.'), path=os.path.dirname(__file__))
    except Exception, err:
        if debug: raise
        return apache.HTTP_NOT_FOUND
     # 2.
    try: 
        allowedMethodes = resourceModule.allowedMethodes
    except AttributeError, err:
        if debug: raise
        return apache.HTTP_HTTP_NOT_FOUND
    if not req.method in allowedMethodes:
        req.allow_methods(resourceModule.allowedMethodes, 1)
        return apache.HTTP_METHOD_NOT_ALLOWED
    # 3.
    if not 'form' in dir(req):
        req.form = util.FieldStorage(req, True)
    # 4.
    try:
        return getattr(resourceModule, req.method)(req, urllib.unquote(mid))
    except AttributeError, err: 
        if debug: raise
        return apache.HTTP_NOT_IMPLEMENTED

def writeError(req, error, message):
    """Send a error page to client. Replaces http error page."""
    req.status = apache.HTTP_FORBIDDEN
    req.content_type = 'text/plain'
    req.write(message)
    return apache.OK