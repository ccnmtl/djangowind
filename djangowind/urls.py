from __future__ import unicode_literals

from django.urls import path, re_path
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
    path('login/', login),
    path('caslogin/', caslogin, {}, 'cas-login'),
    path('logout/', logout),

    path('logout_then_login/', logout_then_login),
    path('redirect_to_login/', redirect_to_login),

    path('password_change/done/', PasswordChangeDoneView.as_view(),
         name='password_change_done'),
    path('password_change/', PasswordChangeView.as_view(),
         name='password_change'),

    path('password_reset/done/', PasswordResetDoneView.as_view(),
         name='password_reset_done'),
    re_path(r'^password/reset/confirm/(?P<uidb64>[0-9A-Za-z]+)-(?P<token>.+)/',
            PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password/reset/complete/',
         PasswordResetCompleteView.as_view(),
         name='password_reset_complete'),
    path('password_reset/', PasswordResetView.as_view(),
         name='password_reset')
]
