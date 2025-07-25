from functools import wraps
from django_redis import get_redis_connection
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _
from django.contrib import messages

# Create your customized decorators here.

def custom_ratelimit(rate='3/5m', key='user', method='POST'):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.method == method:
                conn = get_redis_connection('default')
                user_key = f"ratelimit:{key}:{request.user.id if request.user.is_authenticated else 'anonymous'}"
                
                count = conn.incr(user_key)
                if count == 1:
                    minutes = int(rate.split('/')[1].rstrip('m'))
                    conn.expire(user_key, minutes * 60)
                
                limit = int(rate.split('/')[0])
                if count > limit:
                    messages.error(request, _("You have exceeded the rate limit. Please try again, 5 minutes later."))
                    template_name = getattr(view_func, 'template_name', 'accounts/verify-email.html')
                    context = {'form': kwargs.get('form', None) or request.POST.get('form', None)}
                    return render(request, template_name, context)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
