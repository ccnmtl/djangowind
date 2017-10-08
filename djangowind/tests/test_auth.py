from __future__ import unicode_literals

try:
    from urllib.error import URLError
except ImportError:
    from urllib2 import URLError

try:
    from urllib.request import Request
except ImportError:
    from urllib2 import Request

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from http.client import HTTPResponse
except ImportError:
    from httplib import HTTPResponse

try:
    from unittest.mock import Mock, patch
except ImportError:
    from mock import Mock, patch

from django.test import TestCase
from djangowind.auth import (
    get_saml_assertion,
    validate_cas2_ticket, BaseAuthBackend,
    CAS2AuthBackend, validate_saml_ticket, SAMLAuthBackend,
    AffilGroupMapper, StaffMapper, SuperuserMapper,
    _handle_ldap_entry, _handle_ldap3_entry,
)

from django.contrib.auth.models import User, Group
import os.path


@patch('djangowind.auth.urlopen')
class ValidateTRCasTicketTest(TestCase):
    def setUp(self):
        self.response = Mock(spec=HTTPResponse)

    def test_validate_ticket_success(self, mock_urlopen):
        self.response.read.return_value = tr_affils()
        mock_urlopen.return_value = self.response

        with self.settings(CAS_BASE="https://cas.example.com/"):
            self.assertEqual(
                validate_cas2_ticket(
                    "foo",
                    ("https://slank.ccnmtl.columbia.edu/"
                     "accounts/caslogin/?next=/")),
                (True, "test_claim",
                 ["test_claim", "crs-3", "crs-1"]))
            mock_urlopen.assert_called_with(
                "https://cas.example.com/cas/serviceValidate?"
                "ticket=foo&service=https%3A//"
                "slank.ccnmtl.columbia.edu/accounts/caslogin/%3Fnext%3D/")


@patch('djangowind.auth.urlopen')
class ValidateCas2TicketTest(TestCase):
    def setUp(self):
        self.response = Mock(spec=HTTPResponse)

    def test_no_ticket(self, mock_urlopen):
        self.assertEqual(
            validate_cas2_ticket("", ""),
            (False, 'no ticketid', ''))

    def test_validate_ticket_success(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
            "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
            "\t\t<cas:user>anp8</cas:user>\n"
            "\n"
            "\n"
            "\t</cas:authenticationSuccess>\n"
            "</cas:serviceResponse>\n")
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8', ['anp8']))
        mock_urlopen.assert_called_with(
            "https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
            "&service=https%3A//slank.ccnmtl.columbia.edu/accounts/"
            "caslogin/%3Fnext%3D/")

    def test_validate_ticket_success_with_groups(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
            "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
            "\t\t<cas:user>anp8</cas:user>\n"
            "\t\t<cas:attributes>\n"
            "\t\t\t<cas:affiliation>group1</cas:affiliation>\n"
            "\t\t\t<cas:affiliation>group2</cas:affiliation>\n"
            "\t\t</cas:attributes>\n"
            "\n"
            "\n"
            "\t</cas:authenticationSuccess>\n"
            "</cas:serviceResponse>\n")
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8', ['anp8', 'group1', 'group2']))
        mock_urlopen.assert_called_with(
            "https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
            "&service=https%3A//slank.ccnmtl.columbia.edu/accounts/"
            "caslogin/%3Fnext%3D/")

    def test_validate_ticket_fail(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http"
            "://www.yale.edu/tp/cas'>\n\t<cas:authenticationFailure "
            "code='INVALID_SERVICE'>\n\t\tticket &#039;ST-181952-OK0"
            "qr5suLueHccqPfgIT-idmcasprod2&#039; does not match supp"
            "lied service.  The original service was &#039;https://"
            "slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/&#039;"
            "and the supplied service was &#039;https://slank.ccnmtl."
            "columbia.edu/accounts/caslogin/&#039;.\n\t</cas:authenti"
            "cationFailure>\n</cas:serviceResponse>")
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "The ticket was already used or was invalid.", []))
        mock_urlopen.assert_called_with(
            "https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
            "&service=https%3A//slank.ccnmtl.columbia.edu/accounts/"
            "caslogin/%3Fnext%3D/")

    def test_validate_ticket_invalid_response(self, mock_urlopen):
        self.response.read.return_value = \
            "holy crap! I'm not a valid CAS response!"
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "CAS did not return a valid response.", []))
        mock_urlopen.assert_called_with(
            "https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
            "&service=https%3A//slank.ccnmtl.columbia.edu/accounts/"
            "caslogin/%3Fnext%3D/")

    def test_validate_ticket_alternate_case_base(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
            "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
            "\t\t<cas:user>anp8</cas:user>\n"
            "\n"
            "\n"
            "\t</cas:authenticationSuccess>\n"
            "</cas:serviceResponse>\n")
        mock_urlopen.return_value = self.response

        with self.settings(CAS_BASE="https://cas.example.com/"):
            self.assertEqual(
                validate_cas2_ticket(
                    "foo",
                    ("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/")),
                (True, 'anp8', ['anp8']))
            mock_urlopen.assert_called_with(
                "https://cas.example.com/cas/serviceValidate?ticket=foo"
                "&service=https%3A//slank.ccnmtl.columbia.edu/accounts/"
                "caslogin/%3Fnext%3D/")

    def test_validate_tr_success(self, mock_urlopen):
        """ for teachrecovery, we authenticate against a drupal
        CAS server. The documented response looks like this:
        https://gist.github.com/cravecode/6679b68d14a7250c8fe9
        """
        self.response.read.return_value = TR_SUCCESS
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'test_claim', ['test_claim', u'crs-3', u'crs-1']))
        mock_urlopen.assert_called_with(
            "https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
            "&service=https%3A//slank.ccnmtl.columbia.edu/accounts/"
            "caslogin/%3Fnext%3D/")


TR_SUCCESS = """<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
<cas:authenticationSuccess>
<cas:user>test_claim</cas:user>
<cas:attributes>
<cas:attraStyle>Jasig</cas:attraStyle>
<cas:uid>17</cas:uid>
<cas:mail>testing_claim@example.com</cas:mail>
<cas:created>1427489791</cas:created>
<cas:language></cas:language>
<cas:drupal_roles>authenticated user</cas:drupal_roles>
<cas:courses>crs-3</cas:courses>
<cas:courses>crs-1</cas:courses>
</cas:attributes>
</cas:authenticationSuccess>
</cas:serviceResponse>"""

SAML_FAIL = (
    """<?xml version="1.0" encoding="UTF-8"?>"""
    """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/"""
    """soap/envelope/"><SOAP-ENV:Body>"""
    """<saml1p:Response xmlns:saml1p="urn:oasis:names:tc:SAML:"""
    """1.0:protocol" IssueInstant="2014-07-08T14:54:12.319Z" """
    """MajorVersion="1" MinorVersion="1" Recipient="https://"""
    """slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/" """
    """ResponseID="_bbe8789c1945768311c301153550b5f2">"""
    """<saml1p:Status><saml1p:StatusCode Value="saml1p:Fail"/>"""
    """</saml1p:Status></saml1p:Response></SOAP-ENV:Body>"""
    """</SOAP-ENV:Envelope>""")

SAML_SUCCESS_1 = (
    """<?xml version="1.0" encoding="UTF-8"?>"""
    """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/"""
    """soap/envelope/"><SOAP-ENV:Body>"""
    """<saml1p:Response xmlns:saml1p="urn:oasis:names:tc:SAML:"""
    """1.0:protocol" IssueInstant="2014-07-08T14:54:12.319Z" """
    """MajorVersion="1" MinorVersion="1" Recipient="https://"""
    """slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/" """
    """ResponseID="_bbe8789c1945768311c301153550b5f2">"""
    """<saml1p:Status><saml1p:StatusCode Value="saml1p:Success"/>"""
    """</saml1p:Status><saml1:Assertion """
    """xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion" """
    """AssertionID="_395efddb58e8822ba78b980a2811eada" """
    """IssueInstant="2014-07-08T14:54:12.319Z" """
    """Issuer="localhost" MajorVersion="1" MinorVersion="1">"""
    """<saml1:Conditions NotBefore="2014-07-08T14:54:12.319Z" """
    """NotOnOrAfter="2014-07-08T14:54:42.319Z">"""
    """<saml1:AudienceRestrictionCondition><saml1:Audience>"""
    """https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"""
    """</saml1:Audience></saml1:AudienceRestrictionCondition>"""
    """</saml1:Conditions><saml1:AuthenticationStatement """
    """AuthenticationInstant="2014-07-08T14:45:50.352Z" """
    """AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:unspecified">"""
    """<saml1:Subject><saml1:NameIdentifier>anp8</saml1:NameIdentifier>"""
    """<saml1:SubjectConfirmation><saml1:ConfirmationMethod>"""
    """urn:oasis:names:tc:SAML:1.0:cm:artifact</saml1:ConfirmationMethod>"""
    """</saml1:SubjectConfirmation></saml1:Subject>"""
    """</saml1:AuthenticationStatement><saml1:AttributeStatement>"""
    """<saml1:Subject><saml1:NameIdentifier>anp8</saml1:NameIdentifier>"""
    """<saml1:SubjectConfirmation><saml1:ConfirmationMethod>"""
    """urn:oasis:names:tc:SAML:1.0:cm:artifact</saml1:ConfirmationMethod>"""
    """</saml1:SubjectConfirmation></saml1:Subject>"""
    """<saml1:Attribute AttributeName="lastPasswordChangeDate" """
    """AttributeNamespace="http://www.ja-sig.org/products/cas/">"""
    """<saml1:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">Tue Apr 29 10:07:21 EDT 2014"""
    """</saml1:AttributeValue></saml1:Attribute>""")

SAML_SUCCESS_2 = (
    """</saml1:AttributeStatement></saml1:Assertion>"""
    """</saml1p:Response></SOAP-ENV:Body></SOAP-ENV:Envelope>""")

SAML_AFFILS = (
    """<saml1:Attribute """
    """AttributeName="affiliation" """
    """AttributeNamespace="http://www.ja-sig.org/products/cas/">"""
    """<saml1:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">cul.cunix.local:columbia.edu"""
    """</saml1:AttributeValue><saml1:AttributeValue """
    """xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">libinfosys.cunix.local:columbia.edu"""
    """</saml1:AttributeValue><saml1:AttributeValue """
    """xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">staff.cunix.local:columbia.edu"""
    """</saml1:AttributeValue><saml1:AttributeValue """
    """xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">student.cunix.local:columbia.edu"""
    """</saml1:AttributeValue><saml1:AttributeValue """
    """xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">tlc.cunix.local:columbia.edu"""
    """</saml1:AttributeValue><saml1:AttributeValue """
    """xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">tlc-pt.cunix.local:columbia.edu"""
    """</saml1:AttributeValue><saml1:AttributeValue """
    """xmlns:xs="http://www.w3.org/2001/XMLSchema" """
    """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" """
    """xsi:type="xs:string">tlcxml.cunix.local:columbia.edu"""
    """</saml1:AttributeValue></saml1:Attribute>"""
)


def saml_success_no_affils():
    return SAML_SUCCESS_1 + SAML_SUCCESS_2


def saml_success_affils():
    return SAML_SUCCESS_1 + SAML_AFFILS + SAML_SUCCESS_2


def open_affils(fn):
    return open(
        os.path.join(
            os.path.dirname(__file__),
            fn)
    ).read()


def jonah_affils():
    return open_affils("jonah_affils.txt")


def tr_affils():
    return open_affils("tr_affils.txt")


class GetSAMLAssertionTest(TestCase):
    def test_can_post_data(self):
        cas_base = 'https://example.com'
        url = 'https://example.com/abc'
        headers = {
            'soapaction': 'http://www.oasis-open.org/committees/security',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'accept': 'text/xml',
            'connection': 'keep-alive',
            'content-type': 'text/xml'
        }
        params = {'TARGET': url}
        uri = '{}cas/samlValidate?{}'.format(cas_base, urlencode(params))
        request = Request(uri, '', headers)
        request.data = get_saml_assertion('ticket')
        try:
            urlopen(request)
        except URLError:
            # As long as this isn't a TypeError, and the url request
            # was actually made, then we can assert that
            # get_saml_assertion() is good. This is to prevent an
            # issue introduced since Python 3:
            #
            #  POST data should be bytes or an iterable of bytes. It
            #  cannot be of type str.
            #
            pass


@patch('djangowind.auth.urlopen')
class ValidateSAMLTicketTest(TestCase):
    def setUp(self):
        self.response = Mock(spec=HTTPResponse)

    def test_no_ticket(self, mock_urlopen):
        self.assertEqual(
            validate_saml_ticket("", ""),
            (False, 'no ticketid', ''))

    def test_validate_ticket_success(self, mock_urlopen):
        self.response.read.return_value = saml_success_no_affils()
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8', ['anp8']))

    def test_validate_ticket_success_with_groups(self, mock_urlopen):
        self.response.read.return_value = saml_success_affils()
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8',
             ['anp8', 'cul.cunix.local:columbia.edu',
              'libinfosys.cunix.local:columbia.edu',
              'staff.cunix.local:columbia.edu',
              'student.cunix.local:columbia.edu',
              'tlc.cunix.local:columbia.edu',
              'tlc-pt.cunix.local:columbia.edu',
              'tlcxml.cunix.local:columbia.edu']))

    def test_validate_ticket_fail(self, mock_urlopen):
        self.response.read.return_value = SAML_FAIL
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "CAS/SAML Validation Failed", []))

    def test_validate_ticket_invalid_response(self, mock_urlopen):
        self.response.read.return_value = \
            "holy crap! I'm not a valid CAS response!"
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "CAS did not return a valid response.", []))

    def test_validate_ticket_alternate_cas_base(self, mock_urlopen):
        self.response.read.return_value = saml_success_no_affils()
        mock_urlopen.return_value = self.response

        with self.settings(CAS_BASE="https://cas.example.com/"):
            self.assertEqual(
                validate_saml_ticket(
                    "foo",
                    ("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/")),
                (True, 'anp8', ['anp8']))

    def test_validate_ticket_with_jonah_affils(self, mock_urlopen):
        self.response.read.return_value = jonah_affils()
        mock_urlopen.return_value = self.response

        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'jb2410',
             ['jb2410', 'cul.cunix.local:columbia.edu',
              'culblogs.cunix.local:columbia.edu',
              'digdante.cunix.local:columbia.edu',
              'etsgroup.cunix.local:columbia.edu',
              'libinfosys.cunix.local:columbia.edu',
              'spc.cunix.local:columbia.edu',
              'staff.cunix.local:columbia.edu',
              'tlc.cunix.local:columbia.edu',
              'tlc-pt.cunix.local:columbia.edu',
              'tlcxml.cunix.local:columbia.edu',
              't1.y2011.s001.cy4199.a&hh.st.course:columbia.edu',
              't1.y2008.s002.cy5010.a&h.st.course:columbia.edu',
              't3.y2008.s001.ca4469.arch.st.course:columbia.edu',
              't3.y2010.s001.ca4642.arch.st.course:columbia.edu',
              't1.y2010.s001.cb8210.buec.st.course:columbia.edu',
              't3.y2008.s001.cj6019.jour.st.course:columbia.edu',
              't3.y2009.s001.cj9042.jour.st.course:columbia.edu',
              't1.y2009.s001.cj9055.jour.st.course:columbia.edu',
              't3.y2011.s002.cj9900.jour.st.course:columbia.edu',
              't1.y2010.s007.cy4901.mstu.st.course:columbia.edu',
              't1.y2008.s005.cy6901.mstu.st.course:columbia.edu',
              't1.y2011.s001.ck4220.nmed.st.course:columbia.edu',
              't1.y2009.s001.co2206.nyug.st.course:columbia.edu',
              't3.y2010.s001.cg4010.ohma.st.course:columbia.edu',
              't1.y2008.s001.cg8247.pols.st.course:columbia.edu',
              't3.y2009.s001.cj0002.resi.st.course:columbia.edu',
              't1.y2010.s001.cj0002.resi.st.course:columbia.edu',
              't3.y2010.s001.cj0002.resi.st.course:columbia.edu',
              't1.y2011.s001.cj0002.resi.st.course:columbia.edu',
              't1.y2012.s001.cj0001.rsrh.st.course:columbia.edu',
              't3.y2012.s001.cj0001.rsrh.st.course:columbia.edu',
              't1.y2013.s001.cj0001.rsrh.st.course:columbia.edu',
              't3.y2013.s001.cj0001.rsrh.st.course:columbia.edu',
              't1.y2014.s001.cj0001.rsrh.st.course:columbia.edu',
              't3.y2014.s001.cj0001.rsrh.st.course:columbia.edu',
              't3.y2009.s001.cg8200.soci.st.course:columbia.edu']))


@patch('djangowind.auth.urlopen')
class BaseAuthBackendTest(TestCase):
    def setUp(self):
        self.response = Mock(spec=HTTPResponse)

    def test_get_user(self, mock_urlopen):
        w = BaseAuthBackend()
        # no pre-existing user
        r = w.get_user(1)
        self.assertEqual(r, None)
        # now the other case
        u = User.objects.create(username="test")
        r = w.get_user(u.id)
        self.assertEqual(r, u)


@patch('djangowind.auth.urlopen')
class CAS2AuthBackendTest(TestCase):
    def setUp(self):
        self.response = Mock(spec=HTTPResponse)

    def test_authenticate_no_ticket(self, mock_urlopen):
        w = CAS2AuthBackend()
        self.assertEqual(w.authenticate(None), None)

    def test_authenticate_success(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
            "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
            "\t\t<cas:user>anp8</cas:user>\n"
            "\n"
            "\n"
            "\t</cas:authenticationSuccess>\n"
            "</cas:serviceResponse>\n")
        mock_urlopen.return_value = self.response

        w = CAS2AuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r.username, "anp8")
        self.assertFalse(r.has_usable_password())
        mock_urlopen.assert_called_with(
            'https://cas.columbia.edu/cas/serviceValidate?ticket=foo'
            '&service=https%3A//slank.ccnmtl.columbia.edu/'
            'accounts/caslogin/%3Fnext%3D/')

        with self.settings(
                WIND_PROFILE_HANDLERS=['djangowind.auth.DummyProfileHandler']):
            w = CAS2AuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertFalse(r.has_usable_password())

    def test_authenticate_success_existing_user(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
            "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
            "\t\t<cas:user>anp8</cas:user>\n"
            "\n"
            "\n"
            "\t</cas:authenticationSuccess>\n"
            "</cas:serviceResponse>\n")
        mock_urlopen.return_value = self.response

        u = User.objects.create(username="anp8")
        u.set_password("something other than unusable")
        u.save()
        w = CAS2AuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r.username, "anp8")
        self.assertNotEqual(r.password, "!")
        mock_urlopen.assert_called_with(
            'https://cas.columbia.edu/cas/serviceValidate?ticket=foo'
            '&service=https%3A//slank.ccnmtl.columbia.edu/'
            'accounts/caslogin/%3Fnext%3D/')

    def test_authenticate_failure(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http"
            "://www.yale.edu/tp/cas'>\n\t<cas:authenticationFailure "
            "code='INVALID_SERVICE'>\n\t\tticket &#039;ST-181952-OK0"
            "qr5suLueHccqPfgIT-idmcasprod2&#039; does not match supp"
            "lied service.  The original service was &#039;https://"
            "slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/&#039;"
            "and the supplied service was &#039;https://slank.ccnmtl."
            "columbia.edu/accounts/caslogin/&#039;.\n\t</cas:authenti"
            "cationFailure>\n</cas:serviceResponse>")
        mock_urlopen.return_value = self.response

        w = CAS2AuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r, None)
        mock_urlopen.assert_called_with(
            'https://cas.columbia.edu/cas/serviceValidate?ticket=foo'
            '&service=https%3A//slank.ccnmtl.columbia.edu/'
            'accounts/caslogin/%3Fnext%3D/')

    def test_authenticate_success_with_mappers(self, mock_urlopen):
        self.response.read.return_value = (
            "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
            "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
            "\t\t<cas:user>anp8</cas:user>\n"
            "\n"
            "\n"
            "\t</cas:authenticationSuccess>\n"
            "</cas:serviceResponse>\n")
        mock_urlopen.return_value = self.response

        with self.settings(
                WIND_AFFIL_HANDLERS=['djangowind.auth.AffilGroupMapper']):
            w = CAS2AuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertFalse(r.has_usable_password())
            mock_urlopen.assert_called_with(
                'https://cas.columbia.edu/cas/serviceValidate?ticket=foo'
                '&service=https%3A//slank.ccnmtl.columbia.edu/'
                'accounts/caslogin/%3Fnext%3D/')


@patch('djangowind.auth.urlopen')
class SAMLAuthBackendTest(TestCase):
    def setUp(self):
        self.response = Mock(spec=HTTPResponse)

    def test_authenticate_no_ticket(self, mock_urlopen):
        w = SAMLAuthBackend()
        self.assertEqual(w.authenticate(None), None)

    def test_authenticate_success(self, mock_urlopen):
        self.response.read.return_value = saml_success_affils()
        mock_urlopen.return_value = self.response

        w = SAMLAuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r.username, "anp8")
        self.assertFalse(r.has_usable_password())

        with self.settings(
                WIND_PROFILE_HANDLERS=['djangowind.auth.DummyProfileHandler']):
            w = SAMLAuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertFalse(r.has_usable_password())

    def test_authenticate_success_existing_user(self, mock_urlopen):
        self.response.read.return_value = saml_success_affils()
        mock_urlopen.return_value = self.response

        u = User.objects.create(username="anp8")
        u.set_password("something other than unusable")
        u.save()
        w = SAMLAuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r.username, "anp8")
        self.assertNotEqual(r.password, "!")

    def test_authenticate_failure(self, mock_urlopen):
        self.response.read.return_value = SAML_FAIL
        mock_urlopen.return_value = self.response

        w = SAMLAuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r, None)

    def test_authenticate_success_with_mappers(self, mock_urlopen):
        self.response.read.return_value = saml_success_affils()
        mock_urlopen.return_value = self.response

        with self.settings(
                WIND_AFFIL_HANDLERS=['djangowind.auth.AffilGroupMapper']):
            w = SAMLAuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertFalse(r.has_usable_password())


class AffilGroupMapperTest(TestCase):
    def test_map(self):
        u = User.objects.create(username="testuser")
        m = AffilGroupMapper()
        m.map(u, ["testuser"])
        self.assertEqual(Group.objects.filter(name="ALL_CU").count(), 1)
        self.assertEqual(Group.objects.filter(name="testuser").count(), 0)
        with self.settings(WIND_AFFIL_GROUP_INCLUDE_UNI_GROUP=True):
            m.map(u, ["testuser"])
            self.assertEqual(Group.objects.filter(name="ALL_CU").count(), 1)
            self.assertEqual(Group.objects.filter(name="testuser").count(), 1)


class StaffMapperTest(TestCase):
    def test_map(self):
        m = StaffMapper()
        u = User.objects.create(username="testuser")
        m.map(u, [])
        self.assertFalse(u.is_staff)
        m.map(u, ["testuser"])
        self.assertFalse(u.is_staff)
        with self.settings(WIND_STAFF_MAPPER_GROUPS=["testuser"]):
            m = StaffMapper()
            m.map(u, ["testuser"])
            self.assertTrue(u.is_staff)


class SuperuserMapperTest(TestCase):
    def test_map(self):
        m = SuperuserMapper()
        u = User.objects.create(username="testuser")
        m.map(u, [])
        self.assertFalse(u.is_staff)
        self.assertFalse(u.is_superuser)
        m.map(u, ["testuser"])
        self.assertFalse(u.is_staff)
        self.assertFalse(u.is_superuser)
        with self.settings(WIND_SUPERUSER_MAPPER_GROUPS=["testuser"]):
            m = SuperuserMapper()
            m.map(u, ["testuser"])
            self.assertTrue(u.is_staff)
            self.assertTrue(u.is_superuser)


class HandleLdapEntryTest(TestCase):
    def test_handle_ldap_entry_empty(self):
        d = (('ignore', dict()),)
        r = _handle_ldap_entry(d)
        self.assertEqual(r[0], True)
        self.assertEqual(r[1], dict())

    def test_handle_ldap_entry(self):
        d = (('ignore', dict(one=['a', 'b', 'c'], sn=['d', 'e', 'f'])),)
        r = _handle_ldap_entry(d)
        self.assertEqual(r[0], True)
        self.assertEqual(
            r[1], {'lastname': 'd', 'one': 'a, b, c', 'sn': 'd, e, f'})


class HandleLdap3EntryTest(TestCase):
    def test_handle_ldap3_entry_empty(self):
        e = dict(attributes=dict())
        r = _handle_ldap3_entry(e)
        self.assertEqual(r, dict())

    def test_handle_ldap3_entry(self):
        e = {'dn': u'uni=anp8,ou=People,o=Columbia University,c=US',
             'attributes': {
                 u'telephoneNumber': [u'+1 212 854 1813'],
                 u'departmentNumber': [u'1612303'],
                 u'cuMiddlename': [u'N.'],
                 u'cn': [u'Anders N. Pearson'],
                 u'title': [u'Manager, Web Infrastructure'],
                 u'objectClass': [u'person', u'organizationalPerson',
                                  u'inetOrgPerson', u'cuPerson',
                                  u'cuRestricted', u'eduPerson'],
                 u'campusphone': [u'MS 4-1813'],
                 u'sn': [u'Pearson'],
                 u'uni': u'anp8',
                 u'mail': [u'anders@columbia.edu'],
                 u'postalAddress': [u'somewhere'],
                 u'givenName': [u'Anders'],
                 u'ou': [u'CU Information Technology']},
             'raw_attributes': {
                 u'telephoneNumber': ['+1 212 854 1813'],
                 u'departmentNumber': ['1612303'],
                 u'cuMiddlename': ['N.'],
                 u'cn': ['Anders N. Pearson'],
                 u'title': ['Manager, Web Infrastructure'],
                 u'objectClass': ['person', 'organizationalPerson',
                                  'inetOrgPerson', 'cuPerson',
                                  'cuRestricted', 'eduPerson'],
                 u'campusphone': ['MS 4-1813'],
                 u'sn': ['Pearson'], u'uni': ['anp8'],
                 u'mail': ['anders@columbia.edu'],
                 u'postalAddress': ['somewhere'],
                 u'givenName': ['Anders'],
                 u'ou': ['CU Information Technology']},
             'type': 'searchResEntry'}
        r = _handle_ldap3_entry(e)
        self.assertEqual(r['uni'], 'anp8')
        self.assertEqual(r['sn'], 'Pearson')
        self.assertEqual(r['firstname'], 'Anders')
        self.assertEqual(r['lastname'], 'Pearson')
