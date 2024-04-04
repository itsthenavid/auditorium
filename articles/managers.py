from django.db.models import Manager
from django.db.models.query import QuerySet
from django.utils.timezone import now

# Create your Model Managers here.


class ActiveArticleManager(Manager):

    def get_queryset(self) -> QuerySet:
        return super(ActiveArticleManager, self).get_queryset()\
        .filter(is_active=True).filter(status=str(1))\
        .exclude(publish_datetime__gte=now())
