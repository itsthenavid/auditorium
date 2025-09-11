from django import template

# Create your Template Tags here.

register = template.Library()

@register.filter
def divided_by(value, arg):
    try:
        return float(value) / float(arg)
    except (ValueError, ZeroDivisionError):
        return None
