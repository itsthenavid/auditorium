from django import template

# # Create your customized Django Template Tags here.

register = template.Library()

@register.filter
def split(value, delimiter):
    """Split a string by the given delimiter and return a list."""
    return value.split(delimiter)
