import json
import logging
import time
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_redis import get_redis_connection

logger = logging.getLogger(__name__)

# API endpoint to handle persistent messages in Redis.

@csrf_exempt
def persistent_messages(request):
    """
    API endpoint to fetch or delete persistent messages from Redis.
    Supports both authenticated and anonymous users (using session_key).
    """
    logger.debug(f"[API] persistent_messages called with method {request.method}")
    
    # Modified: Use session_key for anonymous users, user.id for authenticated
    if request.user.is_authenticated:
        redis_key = f"persistent_messages:{request.user.id}"
        logger.debug(f"[API] Using authenticated user key: {redis_key}")
    else:
        if not request.session.session_key:
            request.session.create()
        redis_key = f"persistent_messages:{request.session.session_key}"
        logger.debug(f"[API] Using anonymous session key: {redis_key}")
    
    if request.method == 'GET':
        try:
            conn = get_redis_connection('default')
            messages = []
            redis_data = conn.hgetall(redis_key)
            logger.debug(f"[API] Fetched Redis data for {redis_key}: {redis_data}")
            
            for message_id, message_data in redis_data.items():
                try:
                    message_data_str = message_data.decode('utf-8')
                    parts = message_data_str.split('|', 2)
                    if len(parts) != 3:
                        logger.error(f"[API] Invalid message format for {message_id.decode('utf-8')}: {message_data_str}")
                        conn.hdel(redis_key, message_id)
                        continue
                    text, tags, expires_at = parts
                    
                    if 'code-verification' in tags:
                        logger.debug(f"[API] Processing code-verification message {message_id.decode('utf-8')}: text='{text[:50]}...', tags='{tags}', expires_at={expires_at}")
                    
                    try:
                        expires_at_ms = int(float(expires_at)) if expires_at and expires_at.strip() else None
                        if expires_at_ms is not None:
                            current_time_ms = int(time.time() * 1000)
                            logger.debug(f"[API] Processing message {message_id.decode('utf-8')}: expires_at={expires_at_ms}, current_time={current_time_ms}")
                            if expires_at_ms < current_time_ms:
                                logger.debug(f"[API] Message {message_id.decode('utf-8')} expired, removing from Redis")
                                conn.hdel(redis_key, message_id)
                                continue
                            messages.append({
                                'messageId': message_id.decode('utf-8'),
                                'text': text,
                                'tags': tags,
                                'expiresAt': expires_at_ms
                            })
                        else:
                            logger.warning(f"[API] No valid expires_at for message {message_id.decode('utf-8')}, keeping it")
                            messages.append({
                                'messageId': message_id.decode('utf-8'),
                                'text': text,
                                'tags': tags,
                                'expiresAt': None
                            })
                    except (ValueError, TypeError) as e:
                        logger.error(f"[API] Invalid expires_at format for {message_id.decode('utf-8')}: {expires_at}, error: {str(e)}")
                        conn.hdel(redis_key, message_id)
                        continue
                except Exception as e:
                    logger.error(f"[API] Error processing message {message_id.decode('utf-8')}: {str(e)}")
                    conn.hdel(redis_key, message_id)
                    continue
            
            login_messages = [msg for msg in messages if 'code-verification' in msg.get('tags', '')]
            if login_messages:
                logger.debug(f"[API] Found {len(login_messages)} login code messages")
                for msg in login_messages:
                    logger.debug(f"[API] Login message: ID={msg['messageId']}, expires_at={msg['expiresAt']}, has_timer_span={'<span class=\"timer\">' in msg['text']}")
            
            logger.debug(f"[API] Returning messages: {messages}")
            return JsonResponse({'status': 'success', 'messages': messages})
        except Exception as e:
            logger.error(f"[API] Critical error fetching messages: {str(e)}", exc_info=True)
            return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)
    
    elif request.method == 'DELETE':
        try:
            conn = get_redis_connection('default')
            data = json.loads(request.body)
            message_id = data.get('messageId')
            if not message_id:
                logger.error("[API] No messageId provided in DELETE request")
                return JsonResponse({'status': 'error', 'message': 'No messageId provided'}, status=400)
            if conn.hexists(redis_key, message_id):
                conn.hdel(redis_key, message_id)
                logger.debug(f"[API] Deleted message {message_id} from Redis")
                return JsonResponse({'status': 'success'})
            else:
                logger.warning(f"[API] Message {message_id} not found in Redis")
                return JsonResponse({'status': 'error', 'message': 'Message not found'}, status=404)
        except json.JSONDecodeError:
            logger.error("[API] Invalid JSON in DELETE request")
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f"[API] Error deleting message: {str(e)}", exc_info=True)
            return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)
    
    else:
        logger.error(f"[API] Method {request.method} not allowed")
        return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)
