from django.conf.urls import include, url

urlpatterns = [
    url(r'^accounts/', include('djangowind.urls')),
]
