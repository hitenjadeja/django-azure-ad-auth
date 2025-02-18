import logging
from .utils import get_token_payload, get_token_payload_email, get_login_url, get_logout_url, RESPONSE_MODE, get_token_payload_field
from base64 import urlsafe_b64encode
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist
try:
    from django.contrib.auth import get_user_model
except ImportError:
    from django.contrib.auth.models import User

    def get_user_model(*args, **kwargs):
        return User
from hashlib import sha1

logger = logging.getLogger(__name__)


class AzureActiveDirectoryBackend(object):
    USER_CREATION = getattr(settings, 'AAD_USER_CREATION', True)
    USER_MAPPING = getattr(settings, 'AAD_USER_MAPPING', {})
    USER_STATIC_MAPPING = getattr(settings, 'AAD_USER_STATIC_MAPPING', {})
    GROUP_MAPPING = getattr(settings, 'AAD_GROUP_MAPPING', {})
    CUSTOMER_TENANT_ID = getattr(settings, 'CUSTOMER_TENANT_ID', False)
    RESPONSE_MODE = RESPONSE_MODE

    supports_anonymous_user = False
    supports_inactive_user = True
    supports_object_permissions = False

    def __init__(self):
        self.User = get_user_model()

    def login_url(self, redirect_uri, nonce, state):
        return get_login_url(
            redirect_uri=redirect_uri,
            nonce=nonce,
            state=state
        )

    def logout_url(self, redirect_uri):
        return get_logout_url(redirect_uri=redirect_uri)

    def authenticate(self, request=None, token=None, nonce=None, **kwargs):
        if token is None:
            return None

        payload = get_token_payload(token=token, nonce=nonce)
        tid = get_token_payload_field(payload, "tid")
        customer_tenant_id = self.CUSTOMER_TENANT_ID
        if "," in customer_tenant_id:
            customer_tenant_id = customer_tenant_id.split(",")
        else:
            customer_tenant_id = [customer_tenant_id]
        if customer_tenant_id and tid and tid not in customer_tenant_id:
            if not tid:
                logger.error(f"tid was empty: {tid} payload: {payload}")
                if payload:
                    logger.error(f"payload keys: {payload.keys()}")
            else:
                logger.error(f"Another tenant id:{tid} tried to login.")
                logger.error(f"payload:{payload}")
                logger.error(f"customer_tenant_id:{customer_tenant_id}")
            return
        email = get_token_payload_email(payload)

        if email is None:
            return None

        email = email.lower()

        new_user = {'email': email}

        users = self.User.objects.filter(email__iexact=email)
        if len(users) == 0 and self.USER_CREATION:
            user = self.create_user(new_user, payload)

            # Try mapping group claims to matching groups
            self.add_user_to_group(user, payload)
        elif len(users) == 1:
            user = users[0]

            # Try mapping group claims to matching groups
            self.add_user_to_group(user, payload)
        else:
            logger.error(f"{len(users)} found, something is wrong")
            return

        user.backend = '{}.{}'.format(self.__class__.__module__, self.__class__.__name__)
        return user

    def get_user(self, user_id):
        try:
            user = self.User.objects.get(pk=user_id)
            return user
        except self.User.DoesNotExist:
            return None

    def add_user_to_group(self, user, payload):
        if user is not None and 'groups' in payload:
            for groupid in payload['groups']:
                if groupid not in self.GROUP_MAPPING:
                    continue
                group_name = self.GROUP_MAPPING[groupid]
                try:
                    group = Group.objects.get(name=group_name)
                    user.groups.add(group)
                except ObjectDoesNotExist:
                    pass

    def create_user(self, user_kwargs, payload):
        username_field = getattr(self.User, 'USERNAME_FIELD', 'username').replace("'", "")
        email = user_kwargs.get('email', None)

        if username_field and username_field != 'email' and email:
            user_kwargs[username_field] = self.username_generator(email)

        for user_field, token_field in self.USER_MAPPING.items():
            if token_field not in payload:
                continue
            user_kwargs[user_field] = payload[token_field]

        for user_field, val in self.USER_STATIC_MAPPING.items():
            user_kwargs[user_field] = val

        return self.User.objects.create_user(**user_kwargs)

    @staticmethod
    def username_generator(email):
        username = urlsafe_b64encode(sha1(email.encode('utf-8')).digest()).rstrip(b'=')
        try:
            username = username.decode("utf-8")
        except Exception as e:
            pass
        return username

