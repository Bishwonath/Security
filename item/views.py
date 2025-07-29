from django.shortcuts import render, get_object_or_404, redirect
from django.db.models import Q
from .models import Item, category, review
from django.contrib.auth.decorators import login_required
from .forms import NewItemForm, EditItemForm
from django.db.models import Avg
from django.db import IntegrityError
from django.contrib import messages




from django.db.models import Avg

def items(request):
    query = request.GET.get('query', '')
    category_id = request.GET.get('Category', 0)
    sort_by_price = request.GET.get('sort', '')
    sort_by_rating = request.GET.get('sort', '')
    is_negotiable = request.GET.get(' is_negotiable', '')
    min_price = request.GET.get('min_price', '')
    max_price = request.GET.get('max_price', '')


    categories = category.objects.all()
    items = Item.objects.filter(is_available=True)

    if category_id:
        items = items.filter(Category__id=category_id)
    if query:
        items = items.filter(Q(name__icontains=query) | Q(description__icontains=query))

    if sort_by_price == 'highest':
        items = items.order_by('-price')
    elif sort_by_price == 'lowest':
        items = items.order_by('price')

    if sort_by_rating == 'highest_rated':
        items = items.annotate(avg_rating=Avg('review__rating')).exclude(avg_rating__isnull=True).order_by('-avg_rating')
    elif sort_by_rating == 'lowest_rated':
        items = items.annotate(avg_rating=Avg('review__rating')).exclude(avg_rating__isnull=True).order_by('avg_rating')

    if request.method == 'GET':
        is_negotiable = request.GET.get('is_negotiable', '')
        min_price = request.GET.get('min_price', '')
        max_price = request.GET.get('max_price', '')

        # Filter items based on is_negotiable
        if is_negotiable != '':
            items = items.filter(is_negotiable=is_negotiable)

        # Filter items based on price range
        if min_price:
            items = items.filter(price__gte=min_price)
        if max_price:
            items = items.filter(price__lte=max_price)
    # ... (existing code)

    return render(request, 'item/items.html', {
        'items': items,
        'query': query,
        'categories': categories,
        'category_id': int(category_id),
        'sort_by_price': sort_by_price,
        'sort_by_rating': sort_by_rating,
        'is_negotiable': is_negotiable,
        'min_price': min_price,
        'max_price': max_price,
    })



def detail(request, pk):
    item = get_object_or_404(Item, pk=pk)
    reviews = review.objects.filter(item=item)
    avg_rating = reviews.aggregate(Avg('rating'))['rating__avg']


    related_items = Item.objects.filter(Category=item.Category, is_available=True).exclude(pk=pk)[0:3]

    if request.method == 'POST':
        star_rating = request.POST.get('rating')
        item_review = request.POST.get('item_review')

        try:
            review.objects.create(user=request.user, item=item, rating=star_rating, review_desp=item_review)
        except IntegrityError:
            messages.error(request, "Please fill all the fields")
        else:
            # Redirect to the same detail page after successful review submission so that the user should not resubmit data on reload
            return redirect('item:detail', pk=pk)

    return render(request, 'item/detail.html', {
        'item': item,
        'reviews': reviews,
        'related_items': related_items,
        'avg_rating': avg_rating,         
        
    })



@login_required
def new(request):
    if request.method == 'POST':
        form = NewItemForm(request.POST, request.FILES)

        if form.is_valid():
            item = form.save(commit=False)
            item.created_by = request.user
            item.save()
            return redirect('item:detail', pk=item.id)

    else:
        form = NewItemForm()

    return render(request, 'item/form.html', {
        'form': form,
        'title': 'New Item'
    })

@login_required
def delete(request, pk):
    item = get_object_or_404(Item, pk=pk, created_by=request.user)
    item.delete()
    return redirect('dashboard:index')



@login_required
def edit(request,pk):
    item = get_object_or_404(Item, pk=pk, created_by=request.user)

    if request.method == 'POST':
        form = EditItemForm(request.POST, request.FILES , instance=item)

        if form.is_valid():
            form.save()
            return redirect('item:detail', pk=item.id)

    else:
        form = EditItemForm(instance=item)

    return render(request, 'item/form.html', {
        'form': form,
        'title': 'Edit item'
    })






