#!/usr/bin/env python
#! -*- coding: utf-8 -*-

### Copyright Rice University

# This program is licensed under the terms of the
# GNU General Affero License version 3 (or later).  Please see
# LICENSE.txt for details

###

"""
Notes from 2019: this is an old work-for-hire from some years ago, 
but is worth revisiting and discussing.  

I think this was a valid approach, but it suffers greatly from reply
attacks - if you can sniff my cookie, you can impersonate me.  Sniffing
the TLS session should provide a lot of protection, but at what point do we
stop and make every request validate itself - surely the CPU power now exists?

I think I am going to prefer to move entirely to client certificates / U2F

So this is provided as an example of a good days work, but I think cookies have
had their day.
/End notes from 2019


:mod:`sessioncache` is a standalone module providing the ability to
control persistent-session client cookies and profile-cookies.

:mod:`sessioncache.py` is a "low-level" piece, and is expected to be used
in conjunction with lower-level *authentication* systems such as OpenID
and with "higher-level" *authorisation* systems such as the flow-control in
:mod:`auth.py`

persistent-session
    This is the period of time during which a web server will
    accept a id-number presented as part of an HTTP request as a replacement for
    an actual valid form of authentication.  (we remember that someone
    authenticated a while ago, and assume no-one is able to impersonate them in
    the intervening time period)

persistent-session cookie
    This is a cookie set on a client browser that stores a
    id number pertaining to a persistant-session.  It will last beyond a browser
    shutdown, and is expected to be sent as a HTTP header as part of each
    request to the server.




Why? Because I was getting confused with lack of fine control over sessions
and because the Flask implementation relied heavily on encryption which
seems to be the wrong direction.
So we needed a server-side session cookie impl. with fairly fine control.

I intend to replace the existing SqlAlchemy based services
with pure psycopg2 implementations, but for now I will be content
not adding another feature to SA

Session Cache
~~~~~~~~~~~~~

The session cache needs to be a fast, distributed lookup system for
matching a random ID to a dict of user details.

We shall store the user details in the tabl;e session_cache




Discussion
~~~~~~~~~~

Caches are hard.  They need to be very very fast, and in this case
distributable.  Distributed caches are very very hard because we need to ensure
they are synched.

I feel redis makes an excellent cache choice in many circumstances - it is
blazingly fast for key-value lookups, it is simple, it is threadsafe (as in
threads in the main app do not maintain any pooling or thread issues other than
opening a socket or keeping it open) and it has decent synching options.

However the synching is serious concern, and as such using a centralised, fast,
database will allow us to move to production with a secure solution, without the
immediate reliance on cache-invalidation strategies.


Overview
~~~~~~~~

We have one single table, ``session_cache``.  This stores a json string (as a string, not 9.3 JSON type)
as value in a key value pair.  The key is a UUID-formatted string, passed in from the application.
It is expected we will never see a collission.

We have three commands:

* :meth:`set_session`

* :meth:`get_session`

* :meth:`delete_session`

With this we can test the whole lifecyle as below



Example Usage
~~~~~~~~~~~~~

We firstly pass in a badly formed id.::


>>> sid = "Dr. Evil"
>>> get_session(sid)
Traceback (most recent call last):
     ...
SessionError: Incorrect UUID format for sessionid...


OK, now lets use a properly formatted (but unlikely) UUID


>>> sid = "00000000-0000-0000-0000-000000000001"
>>> set_session(sid, {"name":"Paul"})
True
>>> userd = get_session(sid)
>>> print userd[0]
00000000-0000-0000-0000-000000000001
>>> delete_session(userd[0])


To do
-----

* greenlets & conn pooling
* wrap returned recordset in dict.
* pg's UUID type?


Standalone usage
----------------
::

    minimalconfd = {"app": {'pghost':'127.0.0.1',
                            'pgusername':'repo',
                            'pgpassword':'CHANGEME',
                            'pgdbname':'dbtest'}
                   }

    import sessioncache
    sessioncache.set_config(minimalconfd)
    sessioncache.initdb()
    sessioncache._fakesessionusers()
    sessioncache.get_session("00000000-0000-0000-0000-000000000000")
    {u'interests': None, u'user_id': u'cnxuser:75e06194-baee-4395-8e1a-566b656f6920', ...}
>>>

"""
import psycopg2
import json
import datetime


import logging
lgr = logging.getLogger("sessmodule")

#### (set to one hour for now)
FIXED_SESSIONDURATION_SECS = 3600
#### We fix this here, not in .ini files, as this is a security issue
#### as much as a config so should be changed with caution.

### Errors
class SessionError(Exception):
    pass
    


############
### CONFIG - module level global able to be set during start up.
############

CONFD = {}  # module level global to be setup


def set_config(confd):
    """
    """
    global CONFD
    CONFD.update(confd)

#####
## Helper methods
#####


def validate_uuid_format(uuidstr):
    """
    Given a string, try to ensure it is of type UUID.


    >>> validate_uuid_format("75e06194-baee-4395-8e1a-566b656f6920")
    True
    >>> validate_uuid_format("FooBar")
    False

    """
    l = uuidstr.split("-")
    res = [len(item) for item in l]
    if not res == [8, 4, 4, 4, 12]:
        return False
    else:
        return True

##############
### Database functions
##############


def getconn():
    """returns a connection object based on global confd.

    This is, at the moment, not a pooled connection getter.

    We do not want the ThreadedPool here, as it is designed for
    "real" threads, and listens to their states, which will be 'awkward'
    in moving to greenlets.

    We want a pool that will relinquish
    control back using gevent calls

    https://bitbucket.org/denis/gevent/src/5f6169fc65c9/examples/psycopg2_pool.py
    http://initd.org/psycopg/docs/pool.html

    :return ``psycopg2 connection obj``: conn obj
    :return psycopg2.Error:              or Err

    """
    try:
        lgr.info("CONFD is %s" % str(CONFD))
        conn = psycopg2.connect(host=CONFD['pghost'],
                                database=CONFD['pgdbname'],
                                user=CONFD['pgusername'],
                                password=CONFD['pgpassword'])
    except psycopg2.Error, e:
        lgr.info("Error making pg conn - %s" % str(e))
        raise e

    return conn


def run_query(insql, params):
    """trivial ability to run a query outside SQLAlchemy.

    :param insql: A correctly parameterised SQL stmt ready for psycopg driver.
    :param params: iterable of parameters to be inserted into insql

    :return a dbapi recordset: (list of tuples)

    run_query(conn, "SELECT * FROM tbl where id = %s;", (15,))

    issues: lots.

    * No fetch_iterator.
    * connection per query(see above)
    * We should at least return a dict per row with fields as keys.


    """
    conn = getconn()
    cur = conn.cursor()
    cur.execute(insql, params)
    rs = cur.fetchall()
    cur.close()
    connection_refresh(conn)
    return rs


def exec_stmt(insql, params):
    """
    trivial ability to run a *dm* query outside SQLAlchemy.

    :param insql: A correctly parameterised SQL stmt ready for psycopg driver.
    :param params: iterable of parameters to be inserted into insql

    :return a dbapi recordset: (list of tuples)
    """
    conn = getconn()
    cur = conn.cursor()
    cur.execute(insql, params)
    conn.commit()
    cur.close()
    connection_refresh(conn)  # I can rollback here, its a SELECT


def connection_refresh(conn):
    """
    Connections should be pooled and returned here.

    """
    conn.close()


#######
### Main functions
#######


def set_session(sessionid, userd):
    """Given a sessionid (generated according to ``cnxsessionid spec``
    elsewhere) and a ``userdict`` store in session cache with appropriate
    timeouts.

    :param sessionid: a UUID, that is to be the new sessionid
    :param userd:     python dict of format cnx-user-dict.
    :returns:         True on successful setting.
    Can raise SessionErrors

    TIMESTAMPS.  We are comparing the time now, with the expirytime of the
    cookie *in the database* This reduces the portability.

    This beats the previous solution of passing in python formatted UTC and then
    comparing on database.

    FIXME: bring comaprison into python for portability across cache stores.

    """
    lgr.debug("sessioncache-setsession")
    if not validate_uuid_format(sessionid):
        raise SessionError(
            "Incorrect UUID format for sessionid %s" % sessionid)

    SQL = """INSERT INTO session_cache (sessionid
                                        , userdict
                                        , session_startutc
                                        , session_endutc)
             VALUES                    (%s
                                        , %s
                                        , CURRENT_TIMESTAMP
                                        , CURRENT_TIMESTAMP + INTERVAL '%s SECONDS');"""
    try:
        lgr.debug("sessioncache - %s" % repr(userd.keys()))
        exec_stmt(SQL, [sessionid,
                        json.dumps(userd),
                        FIXED_SESSIONDURATION_SECS
                        ])
    except psycopg2.IntegrityError, e:
        ### This should never happen, but does in testing enough to trap.
        ### if it does, I guess the session is underattack, close it
        delete_session(sessionid)
        raise SessionError(str(e))
    return True


def delete_session(sessionid):
    """
    Remve from session_cache an existing but no longer wanted session(id)
    for whatever reason we want to end a session.

    :param sessionid: Sessionid from cookie
    :returns nothing if success.

    """
    if not validate_uuid_format(sessionid):
        raise SessionError(
            "Incorrect UUID format for sessionid %s" % sessionid)
    SQL = """DELETE FROM session_cache WHERE sessionid = %s;"""
    try:
        exec_stmt(SQL, [sessionid])
    except psycopg2.IntegrityError, e:
        ### Why did we try to close a non-existent session?
        raise SessionError(str(e))


def get_session(sessionid):
    """
    Given a sessionid, if it exists, and is "in date" then
       return userdict (oppostie of set_session)

    Otherwise return None
    (We do not error out on id not found)

    NB this depends heavily on co-ordinating the incoming TZ
    of the DB and the python app server - I am soley runnig the
    check on the dbase, which avoids that but does make it less portable.
    """
    if not validate_uuid_format(sessionid):
        raise SessionError(
            "Incorrect UUID format for sessionid %s" % sessionid)
    lgr("lookup %s type %s" % (sessionid, type(sessionid)))

    SQL = """SELECT userdict FROM session_cache WHERE sessionid = %s
             AND CURRENT_TIMESTAMP BETWEEN
                  session_startutc AND session_endutc;"""
    rs = run_query(SQL, [sessionid, ])
    if len(rs) != 1:
        return None
    else:
        return json.loads(rs[0][0])


def _fakesessionusers(sessiontype='fixed'):
    """a mechainsims to help with testing.
    :param:`sessiontype` can be either ``floating`` or ``fixed``

    ``fixed`` will set three sessionids of type all zeros + 1 / 2 and assign
    them three test users as below

    ``floating`` will randomly choose a "normal" uuid, and will always set
    edwoodward and will then have ed as a "real logged in user".  THis is
    expected to be for testing without faking openid logins.


    usage:
>> import sessioncache, json
>> userd = sessioncache.get_session("00000000-0000-0000-0000-000000000002")
>>> userd.keys()
[u'interests', u'user_id', u'suffix', u'firstname', u'title', u'middlename', u'lastname', u'imageurl', u'identifiers', u'affiliationinstitution_url', u'email', u'version', u'location', u'recommendations', u'preferredlang', u'affiliationinstitution', u'otherlangs', u'homepage', u'fullname', u'biography']

    """
    lgr.info("Calling fake sessioon")
    developertmpl = """{"interests": null,
                        "identifiers": [{"identifierstring":  "https://%(name)s.myopenid.com",
                                         "user_id": "%(uri)s",
                                         "identifiertype": "openid"}],
                        "user_id": "%(uri)s",
                        "suffix": null, "firstname": null, "title": null,
                        "middlename": null, "lastname": null, "imageurl": null,
                        "otherlangs": null, "affiliationinstitution_url": null,
                        "email": null, "version": null, "location": null,
                        "recommendations": null, "preferredlang": null,
                        "fullname": "%(name)s", "homepage": null,
                        "affiliationinstitution": null, "biography": null}"""

    developers = [{"name": "pbrian",
                   "uri": "cnxuser:75e06194-baee-4395-8e1a-566b656f6920",
                   "fakesessionid": "00000000-0000-0000-0000-000000000000"
                   },
                  {"name": "rossreedstrm",
                   "uri": "cnxuser:75e06194-baee-4395-8e1a-566b656f6921",
                   "fakesessionid": "00000000-0000-0000-0000-000000000001"
                   },
                  {"name": "edwoodward",
                   "uri": "cnxuser:75e06194-baee-4395-8e1a-566b656f6922",
                   "fakesessionid": "00000000-0000-0000-0000-000000000002"
                   }
                  ]

    if sessiontype == 'fixed':
        # clear down the cache - only use this in testing anyway
        exec_stmt("""DELETE from session_cache WHERE sessionid in
                  ('00000000-0000-0000-0000-000000000000',
                   '00000000-0000-0000-0000-000000000001',
                   '00000000-0000-0000-0000-000000000002');""", {})
        for dev in developers:
            js = developertmpl % dev
            tmpdict = json.loads(js)
            sid = dev['fakesessionid']
            set_session(sid, tmpdict)
    elif sessiontype == 'floating':
        js = developertmpl % developers[2]
        sid = uuid.uuid4()
        set_session(sid, js)
    else:
        raise SessionError("sessiontype Must be 'floating' or 'fixed'")


def initdb():
    """
    A helper function for creating the session table

    """
    SQL0 = """DROP TABLE IF EXISTS session_cache;"""

    SQL1 = """CREATE TABLE session_cache(
   sessionid  character varying NOT NULL,
   userdict   character varying NOT NULL,
   session_startUTC timestamptz,
   session_endUTC timestamptz);"""

    SQL2 = """ALTER TABLE ONLY session_cache
    ADD CONSTRAINT session_cache_pkey PRIMARY KEY (sessionid);"""

    exec_stmt(SQL0, {})
    exec_stmt(SQL1, {})
    exec_stmt(SQL2, {})


def maintenance_batch():
    """
    A holdng location for ways to clean up the session cache over time.
    These will need improvement and testing.


    """
    SQL = "REINDEX session_cache;"
    exec_stmt(SQL, {})


if __name__ == '__main__':
    import doctest
    val = doctest.ELLIPSIS+doctest.REPORT_ONLY_FIRST_FAILURE + \
        doctest.IGNORE_EXCEPTION_DETAIL
    doctest.testmod(optionflags=val)
