from __future__ import unicode_literals

from django.test import TestCase


class DummyTest(TestCase):
    def test_nothing(self):
        self.assertTrue(1 == 1)
