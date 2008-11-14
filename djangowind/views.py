# Create your views here.
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse,HttpResponseRedirect
from django.shortcuts import get_object_or_404, render_to_response

from django.contrib.auth import authenticate, login
from auth import WindAuthBackend
from django.conf import settings
from django.contrib.sites.models import Site

from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.forms import PasswordResetForm, PasswordChangeForm
from django import oldforms
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.sites.models import Site, RequestSite
from django.http import HttpResponseRedirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.utils.translation import ugettext as _

# copied from django.contrib.auth.views
# and extended with WIND settings so they can be specified
# in the settings.py instead of hard-coded into templates

def login(request, template_name='registration/login.html', redirect_field_name=REDIRECT_FIELD_NAME):
    "Displays the login form and handles the login action."
    manipulator = AuthenticationForm(request)
    redirect_to = request.REQUEST.get(redirect_field_name, '')
    if request.POST:
        errors = manipulator.get_validation_errors(request.POST)
        if not errors:
            # Light security check -- make sure redirect_to isn't garbage.
            if not redirect_to or '//' in redirect_to or ' ' in redirect_to:
                from django.conf import settings
                redirect_to = settings.LOGIN_REDIRECT_URL
            from django.contrib.auth import login
            login(request, manipulator.get_user())
            request.session.delete_test_cookie()
            return HttpResponseRedirect(redirect_to)
    else:
        errors = {}
    request.session.set_test_cookie()

    if Site._meta.installed:
        current_site = Site.objects.get_current()
    else:
        current_site = RequestSite(request)
    from django.conf import settings
    return render_to_response(template_name, {
        'form': oldforms.FormWrapper(manipulator, request.POST, errors),
        redirect_field_name: redirect_to,
        'site_name': current_site.name,
        'site' : current_site,
        'wind_base' : settings.WIND_BASE,
        'wind_service' : settings.WIND_SERVICE,
    }, context_instance=RequestContext(request))



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
        request.session.delete_test_cookie()
        return HttpResponseRedirect(redirect_to)        
    else:
        return HttpResponse("could not login through WIND")

