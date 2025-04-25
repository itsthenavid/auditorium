from .jalali import jalali

from django.utils import timezone

# Create your Django utils here.

def persian_datetime_converter(time):
    persian_months = (
        "فروردین",
        "اُردیبهشت",
        "خرداد",

        "تیر",
        "مرداد",
        "شهریور",

        "مهر",
        "آبان",
        "آذر",

        "دی",
        "بهمن",
        "اسفند",
    )

    time_to_str = "{},{},{}".format(time.year, time.month, time.day)
    time_to_tuple = jalali.Gregorian(time_to_str).persian_tuple()

    time = timezone.localtime(time)

    time_to_list = list(time_to_tuple)

    for i, month in enumerate(persian_months):
        if time_to_list[1] == i + 1:
            time_to_list[1] = month
            break
    
    output = "{}اُمِ {} {}، به‌ساعت {}:{}".format(
        time_to_list[2],
        time_to_list[1],
        time_to_list[0],
        time.hour,
        time.minute
    )

    return output
