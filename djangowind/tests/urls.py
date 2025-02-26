from django.urls import include, path

urlpatterns = [
    path('accounts/', include('djangowind.urls')),
]
