from django_redis import get_redis_connection
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _
from django.contrib import messages
from django.contrib.auth import get_user_model
import logging
from django.http import HttpResponseNotAllowed
from django.utils.timezone import now
import traceback
from django.shortcuts import redirect

from accounts.forms import EmailVerificationForm

# Create your mixins here.

logger = logging.getLogger(__name__)
User = get_user_model()

class RateLimitMixin:
    rate = '3/5m'
    key = 'user'
    template_name = 'accounts/verify-email.html'
    rate_limit_methods = ['POST']

    def _clear_old_messages(self, conn, user_key, exclude_tags=None):
        try:
            existing_messages = conn.hgetall(user_key)
            for msg_id, msg_data in existing_messages.items():
                try:
                    parts = msg_data.decode('utf-8', errors='ignore').split('|')
                    if len(parts) != 3:
                        logger.error(f"Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {msg_data}")
                        conn.hdel(user_key, msg_id)
                        continue
                    tags = parts[1]
                    expires_at = float(parts[2])
                    if expires_at < now().timestamp() * 1000:
                        conn.hdel(user_key, msg_id)
                        logger.debug(f"Deleted expired message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                        continue
                    if exclude_tags and any(tag in tags for tag in exclude_tags):
                        continue
                    conn.hdel(user_key, msg_id)
                    logger.debug(f"Deleted message {msg_id.decode('utf-8', errors='ignore')} from {user_key}")
                except (UnicodeDecodeError, IndexError, ValueError) as e:
                    logger.error(f"Invalid message format in {user_key} for msg_id {msg_id.decode('utf-8', errors='ignore')}: {str(e)}")
                    conn.hdel(user_key, msg_id)
        except Exception as e:
            logger.error(f"Error clearing old messages from {user_key}: {str(e)}\n{traceback.format_exc()}")

    def _add_error_message(self, conn, user_key, message_text, error_details=""):
        try:
            self._clear_old_messages(conn, user_key, exclude_tags=['rate-limit', 'retry-attempt'])
            message_id = f"msg-error-{self.request.user.id}-{int(now().timestamp())}"
            message_data = f"{message_text}|persistent error|{int(now().timestamp() + 5 * 60 * 1000)}"
            conn.hset(user_key, message_id, message_data)
            conn.expire(user_key, 5 * 60)
            messages.error(self.request, message_text, extra_tags=f'persistent error {int(now().timestamp() + 5 * 60 * 1000)}')
            logger.error(f"Error message added: {message_text}, Details: {error_details}")
        except Exception as e:
            logger.error(f"Error adding error message to {user_key}: {str(e)}\n{traceback.format_exc()}")

    def dispatch(self, request, *args, **kwargs):
        if request.method in self.rate_limit_methods:
            try:
                if not request.user.is_authenticated:
                    logger.error("User is not authenticated")
                    return redirect('account_login')

                conn = get_redis_connection('default')
                try:
                    conn.ping()
                    logger.debug("Redis connection successful")
                except Exception as e:
                    logger.error(f"Redis connection failed: {str(e)}\n{traceback.format_exc()}")
                    self._add_error_message(conn, f"persistent_messages:{request.user.id}", _("Failed to connect to Redis. Please try again."), str(e))
                    return render(request, self.template_name, {'form': EmailVerificationForm()})

                user_key = f"ratelimit:{self.key}:{request.user.id if request.user.is_authenticated else 'anonymous'}"
                
                try:
                    count = conn.incr(user_key)
                    logger.debug(f"Request count for {user_key} ({request.method}): {count}")
                    if count == 1:
                        minutes = int(self.rate.split('/')[1].rstrip('m'))
                        conn.expire(user_key, minutes * 60)
                        logger.debug(f"Set expire for {user_key} to {minutes * 60} seconds")
                except Exception as e:
                    logger.error(f"Error incrementing rate limit count: {str(e)}\n{traceback.format_exc()}")
                    self._add_error_message(conn, f"persistent_messages:{request.user.id}", _("Error processing rate limit. Please try again."), str(e))
                    return render(request, self.template_name, {'form': EmailVerificationForm()})

                limit = int(self.rate.split('/')[0])
                if count > limit:
                    try:
                        ttl = conn.ttl(user_key)
                        if ttl <= 0:
                            ttl = 5 * 60
                            conn.expire(user_key, ttl)
                        expires_at = int(now().timestamp() * 1000) + ttl * 1000
                        logger.debug(f"Rate limit exceeded for {user_key}, expires at {expires_at}")
                        self._clear_old_messages(conn, f"persistent_messages:{request.user.id}", exclude_tags=['retry-attempt'])
                        message_id = f"msg-rate-limit-{request.user.id}-{int(now().timestamp())}"
                        message_text = _("You've hit the rate limit! Try again in <span class=\"timer\"></span>.")
                        message_data = f"{message_text}|persistent warning rate-limit|{expires_at}"
                        conn.hset(f"persistent_messages:{request.user.id}", message_id, message_data)
                        conn.expire(f"persistent_messages:{request.user.id}", ttl)
                        messages.warning(request, message_text, extra_tags=f'persistent warning rate-limit {expires_at}')
                        context = {'form': kwargs.get('form', None) or EmailVerificationForm()}
                        logger.info(f"Rate limit exceeded for {user_key} ({request.method})")
                        return render(request, self.template_name, context)
                    except Exception as e:
                        logger.error(f"Error handling rate limit: {str(e)}\n{traceback.format_exc()}")
                        self._add_error_message(conn, f"persistent_messages:{request.user.id}", _("Error processing rate limit. Please try again."), str(e))
                        return render(request, self.template_name, {'form': EmailVerificationForm()})
            except Exception as e:
                logger.error(f"Unexpected error in RateLimitMixin: {str(e)}\n{traceback.format_exc()}")
                try:
                    conn = get_redis_connection('default')
                    self._add_error_message(conn, f"persistent_messages:{request.user.id}", _("An unexpected error occurred. Please try again or contact support."), str(e))
                except:
                    logger.error(f"Failed to add error message to Redis: {str(e)}\n{traceback.format_exc()}")
                    messages.error(request, _("An unexpected error occurred. Please try again or contact support."), extra_tags='persistent error')
                return render(request, self.template_name, {'form': EmailVerificationForm()})
        
        return super().dispatch(request, *args, **kwargs)


class RequireGetMixin:
    def dispatch(self, request, *args, **kwargs):
        if request.method != 'GET':
            logger.debug(f"Non-GET request blocked: {request.method}")
            return HttpResponseNotAllowed(['GET'])
        return super().dispatch(request, *args, **kwargs)
