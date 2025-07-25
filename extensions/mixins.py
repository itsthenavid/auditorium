from django_redis import get_redis_connection
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.contrib.auth import get_user_model
import logging
from django.http import HttpResponseNotAllowed

from accounts.forms import EmailVerificationForm

# Create your Django Mixins here.

logger = logging.getLogger(__name__)
User = get_user_model()


class RateLimitMixin:
    """
    Mixin to apply rate limiting to specified HTTP methods in Class-Based Views.
    
    Attributes:
        rate (str): Rate limit in the format 'count/minutes' (e.g., '3/5m').
        key (str): Key to identify the user (e.g., 'user' for user ID).
        template_name (str): Template to render when rate limit is exceeded.
        rate_limit_methods (list): HTTP methods to apply rate limiting to (e.g., ['POST', 'GET']).
    """
    rate = '3/5m'
    key = 'user'
    template_name = 'accounts/verify-email.html'
    rate_limit_methods = ['POST']

    def dispatch(self, request, *args, **kwargs):
        """Apply rate limiting to specified HTTP methods."""
        if request.method in self.rate_limit_methods:
            try:
                conn = get_redis_connection('default')
                user_key = f"ratelimit:{self.key}:{request.user.id if request.user.is_authenticated else 'anonymous'}"
                
                # Increment request count
                count = conn.incr(user_key)
                logger.debug(f"Request count for {user_key} ({request.method}): {count}")
                if count == 1:
                    # Set expiration time
                    minutes = int(self.rate.split('/')[1].rstrip('m'))
                    conn.expire(user_key, minutes * 60)
                    logger.debug(f"Set expire for {user_key} to {minutes * 60} seconds")
                
                # Check rate limit
                limit = int(self.rate.split('/')[0])
                if count > limit:
                    messages.error(request, _("You've hit the rate limit! Try again in 5 minutes."))
                    context = {'form': kwargs.get('form', None) or EmailVerificationForm()}
                    logger.info(f"Rate limit exceeded for {user_key} ({request.method})")
                    return render(request, self.template_name, context)
            except Exception as e:
                logger.error(f"Rate limit error: {str(e)}")
                raise
        
        return super().dispatch(request, *args, **kwargs)

class RequireGetMixin:
    """
    Mixin to restrict view to GET requests only.
    """
    def dispatch(self, request, *args, **kwargs):
        """Allow only GET requests, return 405 for others."""
        if request.method != 'GET':
            logger.debug(f"Non-GET request blocked: {request.method}")
            return HttpResponseNotAllowed(['GET'])
        return super().dispatch(request, *args, **kwargs)
