from django.utils import timezone

from celery import shared_task

from .models import Post

@shared_task
def auto_publish_posts():
    posts = Post.objects.filter(status=str(0), publish_datetime__lte=timezone.now())
    for post in posts:
        post.status = str(1)
        post.save()
