Basic Usage
===========

(you will of course need django's built in auth, sessions, and sites
apps installed. That's done for you on a default install but if you've
changed things, you might need to re-enable those and do a syncdb. The
current version of djangowind works with Django 1.0)

In your django app, you'll need to do a few things to enable it.

First, add 'djangowind' to INSTALLED_APPS in settings.py. Then add::

  AUTHENTICATION_BACKENDS = ('djangowind.auth.WindAuthBackend','django.contrib.auth.backends.ModelBackend',)
  WIND_BASE = "https://wind.columbia.edu/"
  WIND_SERVICE = "cnmtl_full_np"

to settings.py. 'django.contrib.auth.backends.ModelBackend' is
django's standard built-in auth backend that checks the
username/password against the database. The example config leaves that
in as the second in the AUTHENTICATION_BACKENDS. That will let you use
both WIND authentication and standard django database accounts in the
same app. If you want to restrict things to *only* WIND, just take out
the ModelBackend entry (be sure to leave it as a tuple or
list). WIND_BASE and WIND_SERVICE aren't strictly necessary as those
are the defaults in the code.

Djangowind uses the django.core.context_processors.request template
context processor, so that needs to be enabled. So add the following
to your settings as well::

  TEMPLATE_CONTEXT_PROCESSORS = (
      'django.contrib.auth.context_processors.auth',
      'django.template.context_processors.debug',
      'django.template.context_processors.request',
  )

Now, in urls.py, add the mapping::

  ('^accounts/',include('djangowind.urls')),

to your urlpatterns. This will keep all the auth stuff under
'/accounts/' the same as the standard django auth. You can, of course,
override that behavior by using different mappings (but be careful to
also change the relevant templates if you change that).  The only
other required step for basic usage is to override the default login
template (since we need to include a "login through wind" button). Add
a 'registration/login.html' template to your app's templates with
content something like the following::

  {% extends "base.html" %}
  {% block content %}
  {% if form.has_errors %}
  <p>Your username and password didn't match. Please try again.</p>
  {% endif %}
  <form method="get" action="{{ wind_base }}login">
  <input type="hidden" name="service" value="{{ wind_service }}" />
  <input type="hidden" name="destination"
  value="http://{{ request.get_url }}/accounts/windlogin/?next={{ next }}" />
  <p>If you have a Columbia UNI, you already have an account and can
  login through WIND with it</p>
  <input type="submit" value="Here" />
  </form>
  <p>otherwise: </p>
  <form method="post" action=".">
  <table>
  <tr><td><label for="id_username">Username:</label></td><td>{{ form.username }}</td></tr>
  <tr><td><label for="id_password">Password:</label></td><td>{{ form.password }}</td></tr>
  </table>
  <input type="submit" value="login" />
  <input type="hidden" name="next" value="{{ next }}" />
  </form>
  {% endblock %}

Alternatively, if that exact template code is suitable for you, you
can just make sure that djangowind's template directory is in your
TEMPLATE_PATHS. But you'll probably want to customize your login page.
You'll also want to make sure that the domain is set correctly in the
Sites table for your site.  At this point, everything should basically
work the same as with regular Django Auth (with obvious exceptions of
password related things) and you can refer to the `documentation
<http://docs.djangoproject.com/en/dev/topics/auth/>`_. Ie, you can use
a @login_required decorator on a view and the user will have to go
through that login screen and login via WIND to access the resource.
If you have extra fields that you want on user objects, you will
probably want to read about `UserProfile
<http://www.b-list.org/weblog/2006/jun/06/django-tips-extending-user-model/>`_
objects.
