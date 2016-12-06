from django.test import TestCase
from django.test.client import Client


class TestLoginView(TestCase):
    def setUp(self):
        self.c = Client()

    def test_logged_out(self):
        r = self.c.get("/accounts/login/")
        self.assertEqual(r.status_code, 200)
        self.assertTrue('cas_base' in r.context)
