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
from django.contrib.sites.models import RequestSite
from django.contrib.auth import REDIRECT_FIELD_NAME

from django.views.decorators.cache import never_cache
from django_statsd.clients import statsd

# copied from django.contrib.auth.views
# and extended with WIND settings so they can be specified
# in the settings.py instead of hard-coded into templates

SESSION_KEY = 'edu.columbia.wind'


def login(request, template_name='registration/login.html',
          redirect_field_name=REDIRECT_FIELD_NAME):
    "Displays the login form and handles the login action."
    redirect_to = request.REQUEST.get(redirect_field_name, '')
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

    if Site._meta.installed:
        current_site = Site.objects.get_current()
    else:
        current_site = RequestSite(request)
    return render_to_response(template_name, {
        'form': form,
        redirect_field_name: redirect_to,
        'site_name': current_site.name,
        'site': current_site,
        'wind_base': settings.WIND_BASE,
        'wind_service': settings.WIND_SERVICE,
    }, context_instance=RequestContext(request))
login = never_cache(login)


def logout(request, next_page=None,
           template_name='registration/logged_out.html',
           redirect_field_name=REDIRECT_FIELD_NAME):
    was_wind_login = SESSION_KEY in request.session
    django_logout(request)
    statsd.incr('djangowind.logout')
    if was_wind_login:
        return HttpResponseRedirect('%slogout' % settings.WIND_BASE)
    else:
        return auth_logout_view(request, next_page, template_name,
                                redirect_field_name)


def windlogin(request, redirect_field_name=REDIRECT_FIELD_NAME):
    """ validates the WIND ticket and logs the user in """
    if 'ticketid' in request.GET:
        statsd.incr('djangowind.windlogin.called')
        u = authenticate(ticket=request.GET['ticketid'])
        if u is not None:
            redirect_to = request.REQUEST.get(redirect_field_name, '')
            # Light security check -- make sure redirect_to isn't garbage.
            if not redirect_to:
                from django.conf import settings
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
