from django.db import models
from django.utils.translation import gettext_lazy as _

# Create your models here.


class IPAddress(models.Model):
    """
    Model to store the IP address of the user.
    This model is used to store the IP address of the user who is currently logged in.
    It is used to track the user's activity on the website.
    """

    ip_address = models.GenericIPAddressField(
        verbose_name=_("IP Address"),
        help_text=_("IP address of the user."),
        unique=True,
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("Created At"),
        help_text=_("Date and time when the IP address was created."),
    )

    class Meta:
        verbose_name = _("IP Address")
        verbose_name_plural = _("IP Addresses")

    def __str__(self):
        return self.ip_address
