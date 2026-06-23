# PY-004 SAFE: Django view with Django ORM query — NOT an LLM sink
# The rule should exclude Django ORM query() calls
from django.db import models
from django.http import JsonResponse
from django.views import View


class Product(models.Model):
    name = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    class Meta:
        app_label = "catalog"


class ProductSearchView(View):
    """Search products via Django ORM — safe, not an LLM sink."""

    def get(self, request):
        search = request.GET.get("q", "")
        results = Product.objects.filter(
            name__icontains=search,
        ).values("id", "name", "price")
        return JsonResponse({"products": list(results)})
