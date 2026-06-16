# PY-004 SAFE: Django ORM query call — must NOT fire on .query() that is SQL, not LLM
# The rule excludes `from django.db import models` context
from django.db import models
from django.http import JsonResponse


class Product(models.Model):
    name = models.CharField(max_length=255)
    category = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        app_label = "catalog"


def search_products(request):
    """Search products via Django ORM — query() is safe SQL, not an LLM sink."""
    search_term = request.GET.get("q", "")
    category = request.GET.get("category", "")

    # This is a Django ORM query — NOT an LLM call
    # The rule's pattern-not-inside for django.db import should exclude this
    results = Product.objects.filter(
        name__icontains=search_term,
        category=category,
    ).values("id", "name", "price")

    return JsonResponse({"products": list(results)})
