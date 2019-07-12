from __future__ import unicode_literals

from django.conf import settings
from django.contrib.auth.forms import AuthenticationForm


def context_processor(request):
    d = {
        'WIND_BASE': getattr(settings, 'WIND_BASE', None),
        'WIND_SERVICE': getattr(settings, 'WIND_SERVICE', None),
        'CAS_BASE': getattr(settings, 'CAS_BASE', None),
    }

    is_authed = request.user.is_authenticated

    if not is_authed:
        d['login_form'] = AuthenticationForm(request)

    return d
