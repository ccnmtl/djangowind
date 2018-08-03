from __future__ import unicode_literals

from django.conf.urls import url
from .views import (
    login, caslogin, logout,
)

from django.contrib.auth.views import (
    logout_then_login, redirect_to_login,
    PasswordResetView, PasswordResetDoneView,
    PasswordChangeView, PasswordChangeDoneView,
    PasswordResetConfirmView, PasswordResetCompleteView
)

urlpatterns = [
    url(r'^login/$', login),
    url(r'^caslogin/$', caslogin, {}, 'cas-login'),
    url(r'^logout/$', logout),

    url(r'^logout_then_login/$', logout_then_login),
    url(r'^redirect_to_login/$', redirect_to_login),

    url('^password_change/done/', PasswordChangeDoneView.as_view(),
        name='password_change_done'),
    url('^password_change/', PasswordChangeView.as_view(),
        name='password_change'),

    url('^password_reset/done/', PasswordResetDoneView.as_view(),
        name='password_reset_done'),
    url('^password/reset/confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/',
        PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    url('^password/reset/complete/',
        PasswordResetCompleteView.as_view(),
        name='password_reset_complete'),
    url('^password_reset/', PasswordResetView.as_view(),
        name='password_reset')
]
