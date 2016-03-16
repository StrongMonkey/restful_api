from django.conf.urls import url
from . import views
urlpatterns = [
    url(r'^v1/api_list/$', views.api_list),
    url(r'^v1/google_oauth2/login/$', views.login),
    url(r'^index/$', views.index),
    url(r'^v1/google_oauth/complete/$', views.complete),
    url(r'^v1/google_oauth2/login/authenticate/$', views.auth),
    url(r'^v1/google_oauth2/logout/$', views.logout),
    url(r'^v1/users/$', views.users),
    url(r'^v1/users/(?P<user_id>[0-9]+)/$', views.profile),
    url(r'^v1/requests/$', views.requests),
    url(r'^v1/requests/(?P<request_id>[0-9]+)/$', views.detail_request),
    url(r'^v1/proposals/$', views.proposals),
    url(r'^v1/proposals/(?P<proposal_id>[0-9]+)/$', views.detail_proposal),
    url(r'^v1/dates/$', views.dates),
    url(r'^v1/dates/(?P<date_id>[0-9]+)/$', views.detail_dates)
]
