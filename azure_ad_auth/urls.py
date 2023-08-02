from .views import auth, complete, logout
from django.urls import re_path


urlpatterns = [
    re_path(r'^login/$', auth, name='azure_login'),
    re_path(r'^logout/$', logout, name='azure_logout'),
    re_path(r'^complete/$', complete, name='azure_complete'),
]
