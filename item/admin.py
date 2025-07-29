from django.contrib import admin
from .models import category, Item , review

admin.site.register(category)
admin.site.register(review)
admin.site.register(Item)