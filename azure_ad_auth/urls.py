from .views import auth, complete, logout
from django.conf.urls import url


urlpatterns = [
    url(r'^login/$', auth, name='azure_login'),
    url(r'^logout/$', logout, name='azure_logout'),
    url(r'^complete/$', complete, name='azure_complete'),
]
