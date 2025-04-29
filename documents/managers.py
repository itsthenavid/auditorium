from django.db.models import Manager
from django.utils.timezone import now

# Create your Model Managers here.


class HallActivatedManager(Manager):
    
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True)


class PostActivatedManager(Manager):
    
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True).exclude(publish_datetime__gte=now()).\
        filter(status=str(1)).exclude(hall__is_active=False).select_related('hall')
