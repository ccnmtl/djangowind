from django.contrib.auth.decorators import login_required
from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import get_object_or_404, render_to_response

from django.contrib.auth import authenticate, login
from auth import WindAuthBackend
from django.conf import settings
from django.contrib.sites.models import Site

from django.contrib.auth.forms import AuthenticationForm
from django import forms
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.sites.models import Site, RequestSite
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.utils.translation import ugettext as _

from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response, get_object_or_404
from django.contrib.sites.models import Site, RequestSite
from django.http import HttpResponseRedirect, Http404
from django.template import RequestContext
from django.utils.http import urlquote, base36_to_int
from django.utils.translation import ugettext as _
from django.contrib.auth.models import User
from django.views.decorators.cache import never_cache


# copied from django.contrib.auth.views
# and extended with WIND settings so they can be specified
# in the settings.py instead of hard-coded into templates

def login(request, template_name='registration/login.html', redirect_field_name=REDIRECT_FIELD_NAME):
    "Displays the login form and handles the login action."
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            # Light security check -- make sure redirect_to isn't garbage.
            if not redirect_to or '//' in redirect_to or ' ' in redirect_to:
                redirect_to = settings.LOGIN_REDIRECT_URL
            from django.contrib.auth import login
            login(request, form.get_user())
            if request.session.test_cookie_worked():
                try:
                    request.session.delete_test_cookie()
                except KeyError:
                    pass # somehow this always works in the core django
                         # but often breaks in here even though it's
                         # just a copy/paste of the core django login code
            return HttpResponseRedirect(redirect_to)
    else:
        form = AuthenticationForm(request)
    request.session.set_test_cookie()

    if Site._meta.installed:
        current_site = Site.objects.get_current()
    else:
        current_site = RequestSite(request)
    return render_to_response(template_name, {
        'form': form,
        redirect_field_name: redirect_to,
        'site_name': current_site.name,
        'site' : current_site,
        'wind_base' : settings.WIND_BASE,
        'wind_service' : settings.WIND_SERVICE,
    }, context_instance=RequestContext(request))
login = never_cache(login)


def windlogin(request, redirect_field_name=REDIRECT_FIELD_NAME):
    """ validates the WIND ticket and logs the user in """
    u = authenticate(ticket=request.GET['ticketid'])
    if u is not None:
        redirect_to = request.REQUEST.get(redirect_field_name, '')
        # Light security check -- make sure redirect_to isn't garbage.
        if not redirect_to or '//' in redirect_to or ' ' in redirect_to:
            from django.conf import settings
            redirect_to = settings.LOGIN_REDIRECT_URL
        from django.contrib.auth import login
        login(request, u)
        try:
            request.session.delete_test_cookie()
        except KeyError:
            pass # sometimes this just fails
        return HttpResponseRedirect(redirect_to)        
    else:
        return HttpResponse("could not login through WIND")

