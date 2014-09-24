from django.test import TestCase
from httpretty import HTTPretty, httprettified
from djangowind.auth import validate_wind_ticket, WindAuthBackend
from djangowind.auth import validate_cas2_ticket, CAS2AuthBackend
from djangowind.auth import validate_saml_ticket, SAMLAuthBackend
from djangowind.auth import AffilGroupMapper, StaffMapper, SuperuserMapper
from djangowind.auth import _handle_ldap_entry
from django.contrib.auth.models import User, Group
import os.path


class ValidateWindTicketTest(TestCase):
    def test_no_ticket(self):
        self.assertEqual(
            validate_wind_ticket(""),
            (False, 'no ticketid', ''))

    @httprettified
    def test_validate_ticket_success(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="yes\nanders"
        )
        self.assertEqual(
            validate_wind_ticket("foo"),
            (True, 'anders', ['anders']))

    @httprettified
    def test_validate_ticket_success_with_groups(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="yes\nanders\ngroup1\ngroup2"
        )
        self.assertEqual(
            validate_wind_ticket("foo"),
            (True, 'anders', ['anders', 'group1', 'group2']))

    @httprettified
    def test_validate_ticket_fail(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="no\nanders"
        )
        self.assertEqual(
            validate_wind_ticket("foo"),
            (False, "The ticket was already used or was invalid.", []))

    @httprettified
    def test_validate_ticket_invalid_response(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="holy crap! I'm not a valid WIND response!"
        )
        self.assertEqual(
            validate_wind_ticket("foo"),
            (False, "WIND did not return a valid response.", []))

    @httprettified
    def test_validate_ticket_alternate_wind_base(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://foo.example.com/validate?ticket=foo",
            body="yes\nanders"
        )
        with self.settings(WIND_BASE="https://foo.example.com/"):
            self.assertEqual(
                validate_wind_ticket("foo"),
                (True, 'anders', ['anders']))


class ValidateCas2TicketTest(TestCase):
    def test_no_ticket(self):
        self.assertEqual(
            validate_cas2_ticket("", ""),
            (False, 'no ticketid', ''))

    @httprettified
    def test_validate_ticket_success(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
             "&https%3A//slank.ccnmtl.columbia.edu/accounts/"
             "caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
                "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
                "\t\t<cas:user>anp8</cas:user>\n"
                "\n"
                "\n"
                "\t</cas:authenticationSuccess>\n"
                "</cas:serviceResponse>\n")
        )
        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8', ['anp8']))

    @httprettified
    def test_validate_ticket_success_with_groups(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
             "&https%3A//slank.ccnmtl.columbia.edu/accounts/"
             "caslogin/?next=/"),
            body=(
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
        )

        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8', ['anp8', 'group1', 'group2']))

    @httprettified
    def test_validate_ticket_fail(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?"
             "ticket=foo&https%3A//slank.ccnmtl.columbia.edu/"
             "accounts/caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http"
                "://www.yale.edu/tp/cas'>\n\t<cas:authenticationFailure "
                "code='INVALID_SERVICE'>\n\t\tticket &#039;ST-181952-OK0"
                "qr5suLueHccqPfgIT-idmcasprod2&#039; does not match supp"
                "lied service.  The original service was &#039;https://"
                "slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/&#039;"
                "and the supplied service was &#039;https://slank.ccnmtl."
                "columbia.edu/accounts/caslogin/&#039;.\n\t</cas:authenti"
                "cationFailure>\n</cas:serviceResponse>")
        )
        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "The ticket was already used or was invalid.", []))

    @httprettified
    def test_validate_ticket_invalid_response(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?"
             "ticket=foo&https%3A//slank.ccnmtl.columbia.edu/"
             "accounts/caslogin/?next=/"),
            body="holy crap! I'm not a valid CAS response!"
        )
        self.assertEqual(
            validate_cas2_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "CAS did not return a valid response.", []))

    @httprettified
    def test_validate_ticket_alternate_case_base(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.example.com/cas/serviceValidate?ticket=foo"
             "&https%3A//slank.ccnmtl.columbia.edu/accounts/"
             "caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
                "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
                "\t\t<cas:user>anp8</cas:user>\n"
                "\n"
                "\n"
                "\t</cas:authenticationSuccess>\n"
                "</cas:serviceResponse>\n")
        )
        with self.settings(CAS_BASE="https://cas.example.com/"):
            self.assertEqual(
                validate_cas2_ticket(
                    "foo",
                    ("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/")),
                (True, 'anp8', ['anp8']))

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


def jonah_affils():
    return open(
        os.path.join(
            os.path.dirname(__file__),
            "jonah_affils.txt")
    ).read()


class ValidateSAMLTicketTest(TestCase):
    def test_no_ticket(self):
        self.assertEqual(
            validate_saml_ticket("", ""),
            (False, 'no ticketid', ''))

    @httprettified
    def test_validate_ticket_success(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=saml_success_no_affils())
        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (True, 'anp8', ['anp8']))

    @httprettified
    def test_validate_ticket_success_with_groups(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=saml_success_affils()
        )

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

    @httprettified
    def test_validate_ticket_fail(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=SAML_FAIL)
        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "CAS/SAML Validation Failed", []))

    @httprettified
    def test_validate_ticket_invalid_response(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body="holy crap! I'm not a valid CAS response!"
        )
        self.assertEqual(
            validate_saml_ticket(
                "foo",
                "https://slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/"),
            (False, "CAS did not return a valid response.", []))

    @httprettified
    def test_validate_ticket_alternate_cas_base(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.example.com/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=saml_success_no_affils())
        with self.settings(CAS_BASE="https://cas.example.com/"):
            self.assertEqual(
                validate_saml_ticket(
                    "foo",
                    ("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/")),
                (True, 'anp8', ['anp8']))

    @httprettified
    def test_validate_ticket_with_jonah_affils(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=jonah_affils()
        )
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


class WindAuthBackendTest(TestCase):
    def test_authenticate_no_ticket(self):
        w = WindAuthBackend()
        self.assertEqual(w.authenticate(None), None)

    @httprettified
    def test_authenticate_success(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="yes\nanders"
        )
        w = WindAuthBackend()
        r = w.authenticate("foo")
        self.assertEqual(r.username, "anders")
        self.assertEqual(r.password, "!")

        with self.settings(
                WIND_PROFILE_HANDLERS=['djangowind.auth.DummyProfileHandler']):
            w = WindAuthBackend()
            r = w.authenticate("foo")
            self.assertEqual(r.username, "anders")
            self.assertEqual(r.password, "!")

    @httprettified
    def test_authenticate_success_existing_user(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="yes\nanders"
        )
        u = User.objects.create(username="anders")
        u.set_password("something other than unusable")
        u.save()
        w = WindAuthBackend()
        r = w.authenticate("foo")
        self.assertEqual(r.username, "anders")
        self.assertNotEqual(r.password, "!")

    @httprettified
    def test_authenticate_failure(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="no\nanders"
        )
        w = WindAuthBackend()
        r = w.authenticate("foo")
        self.assertEqual(r, None)

    @httprettified
    def test_authenticate_success_with_mappers(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            "https://wind.columbia.edu/validate?ticket=foo",
            body="yes\nanders"
        )
        with self.settings(
                WIND_AFFIL_HANDLERS=['djangowind.auth.AffilGroupMapper']):
            w = WindAuthBackend()
            r = w.authenticate("foo")
            self.assertEqual(r.username, "anders")
            self.assertEqual(r.password, "!")

    def test_get_user(self):
        w = WindAuthBackend()
        # no pre-existing user
        r = w.get_user(1)
        self.assertEqual(r, None)
        # now the other case
        u = User.objects.create(username="test")
        r = w.get_user(u.id)
        self.assertEqual(r, u)


class CAS2AuthBackendTest(TestCase):
    def test_authenticate_no_ticket(self):
        w = CAS2AuthBackend()
        self.assertEqual(w.authenticate(None), None)

    @httprettified
    def test_authenticate_success(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
             "&https%3A//slank.ccnmtl.columbia.edu/accounts/"
             "caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
                "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
                "\t\t<cas:user>anp8</cas:user>\n"
                "\n"
                "\n"
                "\t</cas:authenticationSuccess>\n"
                "</cas:serviceResponse>\n")
        )

        w = CAS2AuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r.username, "anp8")
        self.assertEqual(r.password, "!")

        with self.settings(
                WIND_PROFILE_HANDLERS=['djangowind.auth.DummyProfileHandler']):
            w = CAS2AuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertEqual(r.password, "!")

    @httprettified
    def test_authenticate_success_existing_user(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
             "&https%3A//slank.ccnmtl.columbia.edu/accounts/"
             "caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
                "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
                "\t\t<cas:user>anp8</cas:user>\n"
                "\n"
                "\n"
                "\t</cas:authenticationSuccess>\n"
                "</cas:serviceResponse>\n")
        )

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

    @httprettified
    def test_authenticate_failure(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?"
             "ticket=foo&https%3A//slank.ccnmtl.columbia.edu/"
             "accounts/caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http"
                "://www.yale.edu/tp/cas'>\n\t<cas:authenticationFailure "
                "code='INVALID_SERVICE'>\n\t\tticket &#039;ST-181952-OK0"
                "qr5suLueHccqPfgIT-idmcasprod2&#039; does not match supp"
                "lied service.  The original service was &#039;https://"
                "slank.ccnmtl.columbia.edu/accounts/caslogin/?next=/&#039;"
                "and the supplied service was &#039;https://slank.ccnmtl."
                "columbia.edu/accounts/caslogin/&#039;.\n\t</cas:authenti"
                "cationFailure>\n</cas:serviceResponse>")
        )

        w = CAS2AuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r, None)

    @httprettified
    def test_authenticate_success_with_mappers(self):
        HTTPretty.register_uri(
            HTTPretty.GET,
            ("https://cas.columbia.edu/cas/serviceValidate?ticket=foo"
             "&https%3A//slank.ccnmtl.columbia.edu/accounts/"
             "caslogin/?next=/"),
            body=(
                "\n\n\n<cas:serviceResponse xmlns:cas='http://www."
                "yale.edu/tp/cas'>\n\t<cas:authenticationSuccess>\n"
                "\t\t<cas:user>anp8</cas:user>\n"
                "\n"
                "\n"
                "\t</cas:authenticationSuccess>\n"
                "</cas:serviceResponse>\n")
        )

        with self.settings(
                WIND_AFFIL_HANDLERS=['djangowind.auth.AffilGroupMapper']):
            w = CAS2AuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertEqual(r.password, "!")


class SAMLAuthBackendTest(TestCase):
    def test_authenticate_no_ticket(self):
        w = SAMLAuthBackend()
        self.assertEqual(w.authenticate(None), None)

    @httprettified
    def test_authenticate_success(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=saml_success_affils()
        )

        w = SAMLAuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r.username, "anp8")
        self.assertEqual(r.password, "!")

        with self.settings(
                WIND_PROFILE_HANDLERS=['djangowind.auth.DummyProfileHandler']):
            w = SAMLAuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertEqual(r.password, "!")

    @httprettified
    def test_authenticate_success_existing_user(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=saml_success_affils()
        )

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

    @httprettified
    def test_authenticate_failure(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=SAML_FAIL)

        w = SAMLAuthBackend()
        r = w.authenticate(
            "foo",
            url=("https://slank.ccnmtl.columbia.edu/accounts/"
                 "caslogin/?next=/"))
        self.assertEqual(r, None)

    @httprettified
    def test_authenticate_success_with_mappers(self):
        HTTPretty.register_uri(
            HTTPretty.POST,
            ("https://cas.columbia.edu/cas/samlValidate?"
             "TARGET=https%3A%2F%2Fslank.ccnmtl.columbia.edu"
             "%2Faccounts%2Fcaslogin%2F%3Fnext%3D%2F"),
            body=saml_success_affils()
        )

        with self.settings(
                WIND_AFFIL_HANDLERS=['djangowind.auth.AffilGroupMapper']):
            w = SAMLAuthBackend()
            r = w.authenticate(
                "foo",
                url=("https://slank.ccnmtl.columbia.edu/accounts/"
                     "caslogin/?next=/"))
            self.assertEqual(r.username, "anp8")
            self.assertEqual(r.password, "!")


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
