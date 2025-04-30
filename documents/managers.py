from django.db.models import Manager, F
from django.utils.timezone import now
from django.contrib.postgres.search import SearchRank, SearchVector, SearchQuery

# Create your Model Managers here.


class HallActivatedManager(Manager):
    
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True)


class PostActivatedManager(Manager):
    
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True).exclude(publish_datetime__gte=now()).\
        filter(status=str(1)).exclude(hall__is_active=False).select_related('hall')
    

class PostManager(Manager):
    def search(self, query, language_code=None):
        if not query:
            return self.get_queryset().none()

        search_query = SearchQuery(query, config='simple')
        queryset = self.get_queryset()

        if language_code:
            queryset = queryset.filter(translations__language_code=language_code)

        return queryset.annotate(
            rank=SearchRank(F('search_vector'), search_query)
        ).filter(search_vector=search_query).order_by('-rank')
