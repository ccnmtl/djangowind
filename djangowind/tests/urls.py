from django.conf.urls import include, url
import djangowind.views

urlpatterns = [
    url(r'^accounts/', include('djangowind.urls')),
]
