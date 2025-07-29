from django.db import models
from django.contrib.auth.models import User
from django.db.models import Avg

class category(models.Model):
    name=models.CharField(max_length=255)
    
    class Meta: 
        # category lai order ma rakhna 
        ordering = ('name',)

        # Spelling Milauna
        verbose_name_plural = 'Categories'
    
    def __str__(self):
        # Cateogy lai afno naam dina lai
        return self.name

class Item(models.Model):
    Category = models.ForeignKey(category, related_name='items', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    price = models.FloatField()
    image = models.ImageField(upload_to='item_images', blank=True, null=True)
    is_available = models.BooleanField(default=False)
    is_negotiable = models.BooleanField(default=False)
    location = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    facebook = models.CharField(max_length=255, blank=True, null=True, help_text='Enter Facebook link')
    instagram = models.CharField(max_length=255, blank=True, null=True, help_text='Enter Instagram link')
    qr = models.ImageField(upload_to='item_images', blank=True, null=True, help_text='Upload QR code image')
    created_by = models.ForeignKey(User, related_name='items', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def average_rating(self):
        avg_rating = review.objects.filter(item=self).aggregate(avg_rating=Avg('rating'))
        return avg_rating['avg_rating'] if avg_rating['avg_rating'] else 0

    def __str__(self):
        return self.name

class  review(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    review_desp = models.CharField(max_length=100)
    rating = models.IntegerField()
