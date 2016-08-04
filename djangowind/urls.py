from __future__ import unicode_literals

from django.conf.urls import url
from .views import (
    login, windlogin, caslogin, logout,
)
from django.contrib.auth.views import (
    logout_then_login, redirect_to_login, password_reset,
    password_reset_done, password_change, password_change_done,
)

urlpatterns = [
    url(r'^login/$', login),
    url(r'^windlogin/$', windlogin),
    url(r'^caslogin/$', caslogin, {}, 'cas-login'),
    url(r'^logout/$', logout),

    url(r'^logout_then_login/$', logout_then_login),
    url(r'^redirect_to_login/$', redirect_to_login),
    url(r'^password_reset/$', password_reset),
    url(r'^password_reset_done/$', password_reset_done),
    url(r'^password_change/$', password_change),
    url(r'^password_change_done/$', password_change_done),
]
