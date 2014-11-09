'''
Created on 30.10.2014

@author: mgr
'''
import ldap.filter

from SambaPosixLib.LDAPEntry import LDAPEntry
from SambaPosixLib.LDAPQuery import LDAPQuery
from SambaPosixLib.Logger import Logger
from SambaPosixLib.PosixValidator import PosixValidator as Validator
from __builtin__ import classmethod

class Group(LDAPEntry):
    '''
    classdocs
    '''


    def __init__(self,entry):
        '''
        Constructor
        '''
        LDAPEntry.__init__(self,entry)
        self.Logger = Logger()

    @classmethod
    def byName(cls, name, oLDAP):
        log = Logger()
        if not Validator.checkPosixName(name):
            log.error("%s is no valid POSIX group name" % name)
            return False
        results = oLDAP.search('(&(objectClass=group)(sAMAccountName=%s))' % name, True)
        if results is None or len(results) < 1:
            log.debug("No group called %s" % name)
            return False
        if len(results) > 1:
            log.error("AD database corrupt: %d entries for group name %s" % (len(results),name))
            return False

        return cls(results[0])

    @classmethod
    def byGID(cls, gid, oLDAP):
        log = Logger()
        if not Validator.checkPosixID(gid):
            log.error("%s is no valid POSIX GID" % gid)
            return False
        if oLDAP.schema().objectClass():
            entries = oLDAP.search('(&(objectClass=posixGroup)(gidNumber=%s))' % gid, True)
        else:
            entries = oLDAP.search('(&(objectClass=group)(gidNumber=%s))' % gid, True)
        if len(entries) > 1:
            accounts = []
            for record in entries:
                if 'sAMAccountName' in record:
                    accounts += record['sAMAccountName']
                else:
                    accounts += record.dn()
            log.error("%s all share gid %s" % (", ".join(accounts), gid))
            return False
        return cls(entries[0])

    @classmethod
    def byRID(cls, rid, oLDAP, sid = None):
        log = Logger()
        sid = oLDAP.getDomainSID(sid, rid, True)
        esid = ldap.filter.escape_filter_chars(sid,2)
        entries = oLDAP.search('(&(objectClass=group)(objectSid=%s))' % esid)
        if entries is not None and len(entries) > 1:
            log.error("AD database corrupt: %d entries for group SID %s" % (len(entries),oLDAP.decodeSID(sid)))
            return False
        if entries is None or len(entries) < 1:
            log.trace("Group SID %s not found!" % oLDAP.decodeSID(sid))
            return False
        return cls(entries[0])

    @classmethod
    def byDN(cls, dn, oLDAP):
        log = Logger()
        entry = oLDAP.readDN(dn)
        if entry is None:
            log.trace("Group DN: %s not found" % dn)
            return False
        if not 'objectClass' in entry[1] or not 'group' in entry[1]['objectClass']:
            log.error("Group DN: %s no group" % dn)
            return False
        return cls(entry)

    @classmethod
    def byMemberDN(cls, dn, oLDAP):
        entries = oLDAP.search('(&(objectClass=group)(member=%s))' % dn)
        for group in entries:
            yield cls(group)

    @classmethod
    def posixGroups(cls, oLDAP):
        log = Logger()
        if oLDAP.schema().objectClass():
            entries = oLDAP.search('(&(objectClass=posixGroup)(objectClass=group))', True)
        else:
            entries = oLDAP.search('(&(objectClass=group)(gidNumber=*))', True)

        if entries is None:
            log.trace("No valid POSIX groups found!")
            raise StopIteration
        for group in entries:
            yield cls(group)

    @classmethod
    def filterGroups(cls, oLDAP, filt = '(&(objectClass=group)(gidNumber=*))'):
        log = Logger()
        entries = oLDAP.search(filt, True)
        if entries is None:
            log.trace("No groups matching filter!")
            raise StopIteration
        for group in entries:
            yield cls(group)

    def resolveMembers(self, oLDAP, recursive = True):
        members = []
        for dn in self.values('member'):
            member = oLDAP.readDN(dn)
            if member is None:
                self.Logger.error("Group member %s does not exist" % dn)
            else:
                member = LDAPEntry(member)
                if member.hasAttribute('objectClass','user'):
                    if not oLDAP.schema().objectClass() or member.hasAttribute('objectClass','posixAccount'):
                        t = member.getSingleValue('uid')
                        if t is None:
                            t = member.getSingleValue('sAMAccountName')
                        members += [t]
                    else:
                        members += ['*' + member.getSingleValue('sAMAccountName')]
                elif member.hasAttribute('objectClass','group') and recursive:
                    member = self(member)
                    members += member.resolveMembers(oLDAP, recursive)
        return members

    def formatAsGetent(self, oLDAP, additional = []):
        out = []
        out += [self.getSingleValue('sAMAccountName')]
        out += ['*']
        out += [self.getSingleValue('gidNumber')]
        members = self.resolveMembers(oLDAP)
        if isinstance(additional, list ) and len(additional) > 0:
            unique = [x for x in additional if not x in members]
            members += unique
        members = ",".join(members)
        if 'memberUid' in self:
            members += " ("+",".join(self.values('memberUid'))+")"
        out += [members]
        return ":".join([x if x is not None else "" for x in out])

    def getRID(self):
        if not 'objectSid' in self:
            raise ValueError("Group object has no SID")
        sid = LDAPQuery.decodeSID(self['objectSid'][0])
        return int(sid.split('-')[-1])
