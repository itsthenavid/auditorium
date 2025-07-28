from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_redis import get_redis_connection
from django.contrib.auth.decorators import login_required
import json
import logging
from django.utils.timezone import now

logger = logging.getLogger(__name__)

@csrf_exempt
@login_required
def persistent_messages_api(request):
    conn = get_redis_connection('default')
    user_key = f"persistent_messages:{request.user.id}"
    logger.debug(f"Processing {request.method} request for user_key: {user_key}")

    if request.method == 'GET':
        try:
            messages = conn.hgetall(user_key)
            logger.debug(f"Raw messages from Redis: {messages}")
            result = [
                {
                    'messageId': msg_id.decode(),
                    'text': msg_data.decode().split('|')[0],
                    'tags': msg_data.decode().split('|')[1],
                    'expiresAt': float(msg_data.decode().split('|')[2])
                } for msg_id, msg_data in messages.items() if float(msg_data.decode().split('|')[2]) > now().timestamp() * 1000
            ]
            logger.debug(f"Filtered messages: {result}")
            return JsonResponse({'messages': result})
        except Exception as e:
            logger.error(f"Error retrieving messages from Redis: {str(e)}")
            return JsonResponse({'status': 'error', 'message': f'Failed to retrieve messages: {str(e)}'}, status=500)

    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            logger.debug(f"Received POST data: {data}")
            if 'messageId' in data and 'text' in data and 'tags' in data and 'expiresAt' in data:
                conn.hset(user_key, data['messageId'], f"{data['text']}|{data['tags']}|{data['expiresAt']}")
                duration = 15 if 'email-verification' in data['tags'] else 5
                conn.expire(user_key, duration * 60)
                logger.debug(f"Stored message {data['messageId']} in Redis")
                return JsonResponse({'status': 'success'})
            return JsonResponse({'status': 'error', 'message': 'Invalid data'}, status=400)
        except Exception as e:
            logger.error(f"Error storing message in Redis: {str(e)}")
            return JsonResponse({'status': 'error', 'message': f'Failed to store message: {str(e)}'}, status=500)

    elif request.method == 'DELETE':
        try:
            data = json.loads(request.body)
            logger.debug(f"Received DELETE data: {data}")
            if 'messageId' in data:
                conn.hdel(user_key, data['messageId'])
                logger.debug(f"Deleted message {data['messageId']} from Redis")
                return JsonResponse({'status': 'success'})
            return JsonResponse({'status': 'error', 'message': 'Invalid data'}, status=400)
        except Exception as e:
            logger.error(f"Error deleting message from Redis: {str(e)}")
            return JsonResponse({'status': 'error', 'message': f'Failed to delete message: {str(e)}'}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)
