from __future__ import unicode_literals

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.shortcuts import render_to_response

from django.contrib.auth import authenticate
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.views import logout as auth_logout_view
from django.conf import settings
from django.contrib.sites.models import Site

from django.contrib.auth.forms import AuthenticationForm
from django.template import RequestContext
try:
    from django.contrib.sites.requests import RequestSite
except ImportError:
    from django.contrib.sites.models import RequestSite
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.urlresolvers import reverse

from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django_statsd.clients import statsd

# copied from django.contrib.auth.views
# and extended with WIND settings so they can be specified
# in the settings.py instead of hard-coded into templates

SESSION_KEY = 'edu.columbia.wind'


@csrf_exempt
def login(request, template_name='registration/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME):
    "Displays the login form and handles the login action."
    redirect_to = request.POST.get(
        redirect_field_name,
        request.GET.get(redirect_field_name, ''))

    if request.method == "POST":
        statsd.incr('djangowind.login.called')
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            statsd.incr('djangowind.login.valid_form')
            # Light security check -- make sure redirect_to isn't garbage.
            if not redirect_to:
                redirect_to = settings.LOGIN_REDIRECT_URL
            django_login(request, form.get_user())
            if request.session.test_cookie_worked():
                try:
                    request.session.delete_test_cookie()
                except KeyError:
                    # somehow this always works in the core django
                    # but often breaks in here even though it's
                    # just a copy/paste of the core django login code
                    pass
            statsd.incr('djangowind.login_succeeded')
            return HttpResponseRedirect(redirect_to)
        else:
            statsd.incr('djangowind.login.invalid_form')
    else:
        form = AuthenticationForm(request)
    request.session.set_test_cookie()

    protocol = "https"
    if not request.is_secure():
        protocol = "http"
    request.session['cas_service_url'] = (
        protocol + "://%s%s?next=%s" % (
            request.get_host(), reverse('cas-login'),
            request.GET.get('next', '/')))

    if Site._meta.installed:
        current_site = Site.objects.get_current()
    else:
        current_site = RequestSite(request)

    return render_to_response(template_name, {
        'form': form,
        redirect_field_name: redirect_to,
        'site_name': current_site.name,
        'site': current_site,
        'wind_base': get_wind_base(),
        'cas_base': get_cas_base(),
        'wind_service': get_wind_service(),
    }, context_instance=RequestContext(request))
login = never_cache(login)


# don't know why django.conf.settings doesn't
# support .get() type access...
def get_wind_base():
    if hasattr(settings, 'WIND_BASE'):
        return settings.WIND_BASE
    else:
        return None


def get_wind_service():
    if hasattr(settings, 'WIND_SERVICE'):
        return settings.WIND_SERVICE
    else:
        return None


def get_cas_base():
    if hasattr(settings, 'CAS_BASE'):
        return settings.CAS_BASE
    else:
        return None


@csrf_exempt
def logout(request, next_page=None,
           template_name='registration/logged_out.html',
           redirect_field_name=REDIRECT_FIELD_NAME):
    was_wind_login = SESSION_KEY in request.session
    django_logout(request)
    statsd.incr('djangowind.logout')
    if was_wind_login and hasattr(settings, 'WIND_BASE'):
        return HttpResponseRedirect('%slogout' % settings.WIND_BASE)
    elif was_wind_login and hasattr(settings, 'CAS_BASE'):
        return HttpResponseRedirect('%scas/logout' % settings.CAS_BASE)
    else:
        return auth_logout_view(request, next_page, template_name,
                                redirect_field_name)


@csrf_exempt
def windlogin(request, redirect_field_name=REDIRECT_FIELD_NAME):
    """ validates the WIND ticket and logs the user in """
    if 'ticketid' in request.GET:
        statsd.incr('djangowind.windlogin.called')
        u = authenticate(ticket=request.GET['ticketid'])
        if u is not None:
            redirect_to = request.GET.get(redirect_field_name, '')
            # Light security check -- make sure redirect_to isn't garbage.
            if not redirect_to:
                redirect_to = settings.LOGIN_REDIRECT_URL
            from django.contrib.auth import login
            login(request, u)
            statsd.incr('djangowind.windlogin.success')
            try:
                request.session.delete_test_cookie()
                request.session[SESSION_KEY] = True
            except KeyError:
                pass  # sometimes this just fails
            return HttpResponseRedirect(redirect_to)
        else:
            statsd.incr('djangowind.windlogin.auth_failure')
    else:
        statsd.incr('djangowind.windlogin.no_ticketid')
    return HttpResponseForbidden("could not login through WIND")


@csrf_exempt
def caslogin(request, redirect_field_name=REDIRECT_FIELD_NAME):
    """ validates the WIND ticket and logs the user in """
    ticketid_field_name = getattr(settings, 'CAS_TICKETID_FIELD_NAME',
                                  'ticketid')
    if ticketid_field_name in request.GET:
        statsd.incr('djangowind.caslogin.called')
        protocol = "https"
        if not request.is_secure():
            protocol = "https"

        # if we didn't have one stashed in the session
        # the best guess is that it was for django admin
        # so, this is a bit magic, but I don't have any better
        # ideas right now
        default_next = getattr(settings, 'CAS_DEFAULT_NEXT',
                               "/admin/&this_is_the_login_form=1")
        url = request.session.get(
            'cas_service_url',
            protocol + "://" + request.get_host() + "/accounts/caslogin/"
            + "?next=" + default_next
        )
        u = authenticate(ticket=request.GET[ticketid_field_name], url=url)
        if u is not None:
            redirect_to = request.GET.get(redirect_field_name, '')
            # Light security check -- make sure redirect_to isn't garbage.
            if not redirect_to:
                redirect_to = settings.LOGIN_REDIRECT_URL
            from django.contrib.auth import login
            login(request, u)
            statsd.incr('djangowind.caslogin.success')
            try:
                request.session.delete_test_cookie()
                request.session[SESSION_KEY] = True
            except KeyError:
                pass  # sometimes this just fails
            return HttpResponseRedirect(redirect_to)
        else:
            statsd.incr('djangowind.caslogin.auth_failure')
    else:
        statsd.incr('djangowind.caslogin.no_ticketid')
    return HttpResponseForbidden("could not login through CAS")
