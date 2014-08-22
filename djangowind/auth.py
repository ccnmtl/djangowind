from django.conf import settings
from django.contrib.auth.models import User, Group
import urllib
import urllib2
from django.core.exceptions import ImproperlyConfigured
from warnings import warn
from django_statsd.clients import statsd
from xml.dom.minidom import parseString
from xml.etree import ElementTree


def validate_wind_ticket(ticketid):
    """
    checks a wind ticketid.
    if successful, it returns (True,username)
    otherwise it returns (False,error message)
    """
    statsd.incr('djangowind.validate_wind_ticket.called')
    if ticketid == "":
        return (False, 'no ticketid', '')
    wind_base = "https://wind.columbia.edu/"
    if hasattr(settings, 'WIND_BASE'):
        wind_base = getattr(settings, 'WIND_BASE')
    uri = wind_base + "validate?ticketid=%s" % ticketid
    response = urllib.urlopen(uri).read()
    lines = response.split("\n")
    if lines[0] == "yes":
        statsd.incr('djangowind.validate_wind_ticket.success')
        username = lines[1]
        groups = [line for line in lines[1:] if line != ""]
        return (True, username, groups)
    elif lines[0] == "no":
        statsd.incr('djangowind.validate_wind_ticket.fail')
        return (False, "The ticket was already used or was invalid.", [])
    else:
        statsd.incr('djangowind.validate_wind_ticket.invalid')
        return (False, "WIND did not return a valid response.", [])


def validate_cas2_ticket(ticketid, url):
    """
    checks a cas ticketid.
    if successful, it returns (True,username)
    otherwise it returns (False,error message)
    """
    statsd.incr('djangowind.validate_cas2_ticket.called')
    if ticketid == "":
        return (False, 'no ticketid', '')
    cas_base = "https://cas.columbia.edu/"
    if hasattr(settings, 'CAS_BASE'):
        cas_base = getattr(settings, 'CAS_BASE')
    uri = cas_base + "cas/serviceValidate?ticket=%s&service=%s" % (
        ticketid,
        urllib2.quote(url))
    response = urllib.urlopen(uri).read()
    try:
        dom = parseString(response)
        if dom.documentElement.nodeName != 'cas:serviceResponse':
            return (False, "CAS did not return a valid response.", [])

        failures = dom.getElementsByTagName('cas:authenticationFailure')
        if len(failures) > 0:
            statsd.incr('djangowind.validate_cas2_ticket.fail')
            return (False, "The ticket was already used or was invalid.", [])
        successes = dom.getElementsByTagName('cas:authenticationSuccess')
        if len(successes) > 0:
            statsd.incr('djangowind.validate_cas2_ticket.success')
            users = dom.getElementsByTagName('cas:user')
            username = str(users[0].firstChild.data)
            groups = [username]
            for g in dom.getElementsByTagName('cas:affiliation'):
                groups.append(g.firstChild.data)
            return (True, username, groups)

        statsd.incr('djangowind.validate_cas2_ticket.invalid')
        return (False, "CAS did not return a valid response.", [])
    except:
        statsd.incr('djangowind.validate_cas2_ticket.invalid')
        return (False, "CAS did not return a valid response.", [])


"""
here, we've nicked some code from

    <https://bitbucket.org/cpcc/django-cas/src/
    47d19f3a871fa744dabe884758f90fff6ba135d5/
    django_cas/backends.py?at=default#cl-89>

we couldn't quite use it directly because we need
to deal with SAML 1.1, which is *slightly* different
and we need a few more details on different error
cases to handle and the format that we want
affiliations returned in.

But the next few functions are largely adapted from
what was there.
"""


def get_saml_assertion(ticket):
    return (
        """<?xml version="1.0" encoding="UTF-8"?>"""
        """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://"""
        """schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV"""
        """:Header/><SOAP-ENV:Body><samlp:Request xmlns:"""
        """samlp="urn:oasis:names:tc:SAML:1.0:protocol"  """
        """MajorVersion="1" MinorVersion="1" """
        """RequestID="_192.168.16.51.1024506224022" """
        """IssueInstant="2002-06-19T17:03:44.022Z">"""
        """<samlp:AssertionArtifact>""" + ticket
        + """</samlp:AssertionArtifact></samlp:Request>"""
        """</SOAP-ENV:Body></SOAP-ENV:Envelope>""")

SAML_1_0_NS = 'urn:oasis:names:tc:SAML:1.0:'
SAML_1_0_PROTOCOL_NS = '{' + SAML_1_0_NS + 'protocol' + '}'
SAML_1_0_ASSERTION_NS = '{' + SAML_1_0_NS + 'assertion' + '}'


def validate_saml_ticket(ticketid, url):
    """
    checks a cas/saml ticketid.
    if successful, it returns (True,username, groups)
    otherwise it returns (False,error message, '')
    """
    statsd.incr('djangowind.validate_saml_ticket.called')
    if ticketid == "":
        return (False, 'no ticketid', '')
    cas_base = "https://cas.columbia.edu/"
    if hasattr(settings, 'CAS_BASE'):
        cas_base = getattr(settings, 'CAS_BASE')
    headers = {
        'soapaction': 'http://www.oasis-open.org/committees/security',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'accept': 'text/xml',
        'connection': 'keep-alive',
        'content-type': 'text/xml'}
    params = {'TARGET': url}
    uri = cas_base + "cas/samlValidate" + '?' + urllib.urlencode(params)
    url = urllib2.Request(uri, '', headers)
    data = get_saml_assertion(ticketid)
    url.add_data(data)

    page = urllib2.urlopen(url)
    response = page.read()
    try:
        user = None
        attributes = {}
        tree = ElementTree.fromstring(response)
        # Find the authentication status
        success = tree.find('.//' + SAML_1_0_PROTOCOL_NS + 'StatusCode')
        if success is None or success.attrib['Value'] != 'saml1p:Success':
            statsd.incr('djangowind.validate_saml_ticket.fail')
            return (False, "CAS/SAML Validation Failed", [])

        # look for a username, it will come in something like this:
        # <saml1:NameIdentifier>anp8</saml1:NameIdentifier>
        identifiers = tree.findall(
            './/' + SAML_1_0_ASSERTION_NS + 'NameIdentifier')
        if not identifiers or len(identifiers) < 1:
            statsd.incr('djangowind.validate_saml_ticket.invalid')
            return (False, "CAS did not return a valid response.", [])

        user = identifiers[0].text

        # pull out attributes. they come packaged up like this:

        # <saml1:Attribute AttributeName="affiliation"
        # AttributeNamespace="http://www.ja-sig.org/products/cas/">
        # <saml1:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
        # xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        # xsi:type="xs:string">cul.cunix.local:columbia.edu
        # </saml1:AttributeValue> ... </saml1:Attribute>

        attrs = tree.findall('.//' + SAML_1_0_ASSERTION_NS + 'Attribute')
        affils = [user]
        for at in attrs:
            if 'uid' in at.attrib.values():
                user = at.find(SAML_1_0_ASSERTION_NS + 'AttributeValue').text
                attributes['uid'] = user
            values = at.findall(SAML_1_0_ASSERTION_NS + 'AttributeValue')
            if len(values) > 1:
                values_array = []
                for v in values:
                    values_array.append(v.text)
                attributes[at.attrib['AttributeName']] = values_array
            else:
                attributes[at.attrib['AttributeName']] = values[0].text
        for a in attributes.get('affiliation', []):
            affils.append(a.strip())
        statsd.incr('djangowind.validate_saml_ticket.success')
        return (True, user, affils)

    except:
        statsd.incr('djangowind.validate_saml_ticket.invalid')
        return (False, "CAS did not return a valid response.", [])


class WindAuthBackend(object):
    supports_inactive_user = True

    def authenticate(self, ticket=None):
        statsd.incr('djangowind.windauthbackend.authenticate.called')
        if ticket is None:
            return None
        (response, username, groups) = validate_wind_ticket(ticket)
        if response is True:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                statsd.incr('djangowind.windauthbackend.create_user')
                user = User(username=username, password='wind user')
                user.set_unusable_password()
                user.save()

            for handler in self.get_profile_handlers():
                handler.process(user)

            for handler in self.get_mappers():
                handler.map(user, groups)
            return user
        else:
            # i don't know how to actually get this error message
            # to bubble back up to the user. must dig into
            # django auth deeper.
            statsd.incr('djangowind.windauthbackend.failure')
            pass
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def load_handler(self, path):
        i = path.rfind('.')
        module, attr = path[:i], path[i + 1:]
        try:
            mod = __import__(module, {}, {}, [attr])
        except ImportError, e:
            raise ImproperlyConfigured(
                'Error importing wind handler %s: "%s"' % (module, e))
        except ValueError, e:
            raise ImproperlyConfigured('Error importing wind handler.')
        try:
            cls = getattr(mod, attr)
        except AttributeError:
            raise ImproperlyConfigured(
                'Module "%s" does not define a "%s" authentication backend'
                % (module, attr))
        return cls()

    def get_mappers(self):
        mappers = []
        if not hasattr(settings, 'WIND_AFFIL_HANDLERS'):
            return []
        for mapper_path in settings.WIND_AFFIL_HANDLERS:
            mappers.append(self.load_handler(mapper_path))
        return mappers

    def get_profile_handlers(self):
        handlers = []
        if not hasattr(settings, 'WIND_PROFILE_HANDLERS'):
            return []
        for handler_path in settings.WIND_PROFILE_HANDLERS:
            handlers.append(self.load_handler(handler_path))
        return handlers


class CAS2AuthBackend(WindAuthBackend):
    def authenticate(self, ticket=None, url=None):
        statsd.incr('djangowind.cas2authbackend.authenticate.called')
        if ticket is None:
            return None
        if url is None:
            return None
        (response, username, groups) = validate_cas2_ticket(ticket, url)
        if response is True:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                statsd.incr('djangowind.cas2authbackend.create_user')
                user = User(username=username, password='CAS user')
                user.set_unusable_password()
                user.save()

            for handler in self.get_profile_handlers():
                handler.process(user)

            for handler in self.get_mappers():
                handler.map(user, groups)
            return user
        else:
            # i don't know how to actually get this error message
            # to bubble back up to the user. must dig into
            # django auth deeper.
            statsd.incr('djangowind.casauthbackend.failure')
            pass
        return None


class SAMLAuthBackend(WindAuthBackend):
    def authenticate(self, ticket=None, url=None):
        statsd.incr('djangowind.samlauthbackend.authenticate.called')
        if ticket is None:
            return None
        if url is None:
            return None
        (response, username, groups) = validate_saml_ticket(ticket, url)
        if response is True:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                statsd.incr('djangowind.samlauthbackend.create_user')
                user = User(username=username, password='CAS/SAML user')
                user.set_unusable_password()
                user.save()

            for handler in self.get_profile_handlers():
                handler.process(user)

            for handler in self.get_mappers():
                handler.map(user, groups)
            return user
        else:
            # i don't know how to actually get this error message
            # to bubble back up to the user. must dig into
            # django auth deeper.
            statsd.incr('djangowind.samlauthbackend.failure')
            pass
        return None


def _handle_ldap_entry(result_data):
    field_maps = [
        ('sn', 'lastname'),
        ('givenname', 'firstname'),
        ('givenName', 'firstname'),
        ('telephoneNumber', 'telephonenumber'),
    ]

    found = True
    r = dict()
    values = result_data[0][1]
    for k, v in values.items():
        r[k] = ", ".join(v)
        for a, b in field_maps:
            if k == a:
                r[b] = v[0]
    return (found, r)


def ldap_lookup(uni=""):
    statsd.incr('djangowind.ldap_lookup')
    try:
        import ldap
    except ImportError:
        statsd.incr('djangowind.ldap_lookup.import_failed')
        warn("""this requires the python ldap library.
you probably need to install 'python-ldap' (on linux) or
an equivalent""")
        raise

    LDAP_SERVER = "ldap.columbia.edu"
    BASE_DN = "o=Columbia University, c=us"
    if hasattr(settings, 'LDAP_SERVER'):
        LDAP_SERVER = settings.LDAP_SERVER
    if hasattr(settings, 'BASE_DN'):
        BASE_DN = settings.BASE_DN
    l = ldap.open(LDAP_SERVER)
    baseDN = BASE_DN
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    searchFilter = "uni=%s" % uni
    ldap_result_id = l.search(baseDN, searchScope, searchFilter,
                              retrieveAttributes)
    results_dict = {'found': False, 'lastname': '', 'firstname': ''}
    while 1:
        result_type, result_data = l.result(ldap_result_id, 0)
        if result_data == []:
            break
        else:
            if result_type == ldap.RES_SEARCH_ENTRY:
                (found, r) = _handle_ldap_entry(result_data)
                results_dict['found'] = True
                results_dict.update(r)

    if results_dict['lastname'] == "":
        results_dict['lastname'] = uni
    return results_dict


class CDAPProfileHandler(object):
    """ fills in email, last_name, first_name from CDAP """
    def process(self, user):
        statsd.incr('djangowind.cdap.called')
        if not user.email:
            user.email = user.username + "@columbia.edu"
        if not user.last_name or not user.first_name:
            try:
                r = ldap_lookup(user.username)
                if r.get('found', False):
                    statsd.incr('djangowind.cdap.found')
                    user.last_name = r.get('lastname', r.get('sn', ''))
                    user.first_name = r.get(
                        'firstname',
                        r.get('givenName', ''))
                else:
                    statsd.incr('djangowind.cdap.not_found')
            except ImportError:
                pass
        user.save()


class DummyProfileHandler(object):
    """ a profile handler to use for testing
    (don't want to have to make ldap requests during unit tests)"""
    def process(self, user):
        pass


class AffilGroupMapper(object):
    """ makes sure that the user is in a Group for every wind affil,
        autovivifying Groups if necessary """

    def map(self, user, affils):
        statsd.incr('djangowind.affilgroupmapper.map.called')
        # we also make a "pseudo" affil group ALL_CU
        # that contains *anyone* who's logged in through WIND
        affils.append("ALL_CU")

        # by default, WIND affils include a group named for
        # the uni for each user. This is not usually desirable
        # so we strip it out, but there's a setting that lets
        # you turn it back on.
        remove_uni = True
        if hasattr(settings, 'WIND_AFFIL_GROUP_INCLUDE_UNI_GROUP'):
            if settings.WIND_AFFIL_GROUP_INCLUDE_UNI_GROUP is True:
                remove_uni = False

        for affil in affils:
            if remove_uni and (affil == user.username):
                continue
            try:
                group = Group.objects.get(name=affil)
            except Group.DoesNotExist:
                statsd.incr('djangowind.affilgroupmapper.create_group')
                group = Group(name=affil)
                group.save()
            user.groups.add(group)
        user.save()


class StaffMapper(object):
    """ if the user is in one of the specified wind affil groups,
        it makes sure that the user is set as 'staff' """

    def __init__(self):
        if not hasattr(settings, 'WIND_STAFF_MAPPER_GROUPS'):
            self.groups = []
        else:
            self.groups = settings.WIND_STAFF_MAPPER_GROUPS

    def map(self, user, affils):
        statsd.incr('djangowind.staffmapper.map.called')
        for affil in affils:
            if affil in self.groups:
                statsd.incr('djangowind.staffmapper.map.is_staff')
                user.is_staff = True
                user.save()
                return


class SuperuserMapper(object):
    """ if the user is in one of the specified wind affil groups,
        it makes sure that the user is set as 'superuser' """

    def __init__(self):
        if not hasattr(settings, 'WIND_SUPERUSER_MAPPER_GROUPS'):
            self.groups = []
        else:
            self.groups = settings.WIND_SUPERUSER_MAPPER_GROUPS

    def map(self, user, affils):
        statsd.incr('djangowind.superusermapper.map.called')
        for affil in affils:
            if affil in self.groups:
                statsd.incr('djangowind.superusermapper.map.is_superuser')
                user.is_superuser = True
                user.is_staff = True
                user.save()
                return
