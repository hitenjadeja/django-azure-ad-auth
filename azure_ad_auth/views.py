import logging
from .backends import AzureActiveDirectoryBackend
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login, logout as django_logout
from django import VERSION
from django.http import HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
import uuid

if VERSION[0] < 2:
    from django.core.urlresolvers import reverse
else:
    from django.urls import reverse

try:
    # Python 3
    from urllib.parse import urlparse
except ImportError:
    # Python 2
    from urlparse import urlparse

logger = logging.getLogger(__name__)

@never_cache
def auth(request):
    backend = AzureActiveDirectoryBackend()
    redirect_uri = request.build_absolute_uri(reverse(complete))
    nonce = str(uuid.uuid4())
    request.session['nonce'] = nonce
    state = str(uuid.uuid4())
    request.session['state'] = state
    login_url = backend.login_url(
        redirect_uri=redirect_uri,
        nonce=nonce,
        state=state
    )
    return HttpResponseRedirect(login_url)


@never_cache
def logout(request):
    django_logout(request)
    
    backend = AzureActiveDirectoryBackend()
    redirect_uri = request.build_absolute_uri(reverse(auth))
    logout_url = backend.logout_url(redirect_uri)
    return HttpResponseRedirect(logout_url)


@never_cache
@csrf_exempt
def complete(request):
    backend = AzureActiveDirectoryBackend()
    method = 'GET' if backend.RESPONSE_MODE == 'fragment' else 'POST'
    original_state = request.session.get('state')
    state = getattr(request, method).get('state')
    if not original_state or original_state == state:
        token = getattr(request, method).get('id_token')
        nonce = request.session.get('nonce')
        user = backend.authenticate(request=request, token=token, nonce=nonce)
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(get_login_success_url(request))
        else:
            logger.error(f'Could not authenticate user')
    else:
        logger.error('State did not match')
        
    return HttpResponseRedirect('failure')


def get_login_success_url(request):
    redirect_to = request.GET.get(REDIRECT_FIELD_NAME, '')
    netloc = urlparse(redirect_to)[1]
    if not redirect_to:
        redirect_to = settings.LOGIN_REDIRECT_URL
    elif netloc and netloc != request.get_host():
        redirect_to = settings.LOGIN_REDIRECT_URL
    return redirect_to
