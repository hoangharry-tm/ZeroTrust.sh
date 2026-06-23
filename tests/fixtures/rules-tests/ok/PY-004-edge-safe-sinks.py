# PY-004 EDGE/SAFE: sinks that should NOT fire due to safeguards
# ORM exclusions, non-LLM function names, and sanitized inputs
from django.db import models
from django.http import JsonResponse


class Item(models.Model):
    name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        app_label = "catalog"


def search_view(request):
    """Django ORM query must NOT fire PY-004."""
    q = request.GET.get("q", "")
    results = Item.objects.filter(name__icontains=q).values("id", "name")
    return JsonResponse({"items": list(results)})


def process_data(data: dict) -> str:
    """Function name has 'process' not matching LLM regex."""
    return f"processed: {data.get('key', '')}"


def handle_event(request):
    """Function name 'handle' not matching LLM regex."""
    payload = request.GET.get("payload", "")
    output = process_data({"key": payload})
    return JsonResponse({"output": output})


def calculate_total(request):
    """Function name 'calculate' not matching LLM regex."""
    price = request.GET.get("price", "0")
    qty = request.GET.get("qty", "1")
    total = float(price) * int(qty)
    return JsonResponse({"total": total})
