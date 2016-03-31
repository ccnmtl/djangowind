from __future__ import unicode_literals

from django.conf.urls import patterns

urlpatterns = patterns('',
                       (r'^login/$', 'djangowind.views.login'),
                       (r'^windlogin/$', 'djangowind.views.windlogin'),
                       (r'^caslogin/$', 'djangowind.views.caslogin',
                        {}, 'cas-login'),
                       (r'^logout/$', 'djangowind.views.logout'),
                       (r'^logout_then_login/$',
                        'django.contrib.auth.views.logout_then_login'),
                       (r'^redirect_to_login/$',
                        'django.contrib.auth.views.redirect_to_login'),
                       (r'^password_reset/$',
                        'django.contrib.auth.views.password_reset'),
                       (r'^password_reset_done/$',
                        'django.contrib.auth.views.password_reset_done'),
                       (r'^password_change/$',
                        'django.contrib.auth.views.password_change'),
                       (r'^password_change_done/$',
                        'django.contrib.auth.views.password_change_done')
                       )
