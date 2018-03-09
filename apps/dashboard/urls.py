from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^signin$', views.signin),
    url(r'^register$', views.register),
    url(r'^dashboard$', views.dashboard),
    url(r'^users/register$', views.create_user),
    url(r'^logout$', views.logout),
    url(r'^users/signin$', views.signin_user),
    url(r'^users/(?P<id>\d+)/destroy$', views.destroy),
    url(r'^users/(?P<id>\d+)/delete$', views.delete),
    url(r'^users/new$', views.new)
]