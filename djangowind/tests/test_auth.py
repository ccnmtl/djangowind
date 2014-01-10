from django.test import TestCase
from httpretty import HTTPretty, httprettified
from djangowind.auth import validate_wind_ticket, WindAuthBackend
from djangowind.auth import AffilGroupMapper, StaffMapper, SuperuserMapper
from djangowind.auth import _handle_ldap_entry
from django.contrib.auth.models import User, Group


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