from django.utils.translation import gettext_lazy as _

from .models import IPAddress

# Create your middlewares here.


class SaveIPAddressMiddleware:
    """
    Middleware to save the IP address of the user in the request object.
    This middleware should be added to the MIDDLEWARE setting in Django settings.py.
    It will add the user's IP address to the request object as 'user_ip'.        
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        
        try:
            ip_address = IPAddress.objects.get(ip_address=ip)
        except IPAddress.DoesNotExist:
            ip_address = IPAddress(ip_address=ip)
            ip_address.save()
        request.user_ip = ip_address

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

        return response
