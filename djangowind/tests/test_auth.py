from django.test import TestCase
from httpretty import HTTPretty, httprettified
from djangowind.auth import validate_wind_ticket, WindAuthBackend
from django.contrib.auth.models import User


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
