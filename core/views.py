from django.shortcuts import redirect, render
from item.models import category, Item
from .forms import SignupForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect
from .forms import EditProfileForm
from django.contrib import messages
from .forms import EditProfileForm, CustomPasswordChangeForm
from django.contrib.auth import logout
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.db.models import Avg

from django.db.models import Avg, Min

def index(request):
    items = Item.objects.filter(is_available=True).order_by('-id')[:4]
    highest_rated_items = Item.objects.annotate(avg_rating=Avg('review__rating')).exclude(avg_rating__isnull=True).order_by('-avg_rating')[:4]
    cheapest_items = Item.objects.filter(is_available=True).order_by('price')[:4]
    categories = category.objects.all()

    return render(request, 'core/index.html', {
        'categories': categories,
        'items': items,
        'highest_rated_items': highest_rated_items,
        'cheapest_items': cheapest_items,
    })



def contact(request):
    return render(request, 'core/contact.html')

def faq(request):
    return render(request ,'core/faq.html')

def privacy(request):
    return render(request ,'core/privacy.html')

def terms(request):
    return render(request ,'core/terms.html')

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, f"Welcome, {user.username}!")
                return redirect('core:index')
            else:
                messages.error(request, "Invalid username or password.")
                return render(request, 'core/login.html', {'form': form})

    else:
        form = AuthenticationForm()

    return render(request, 'core/login.html', {'form': form})

def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)

        if form.is_valid():
            password1 = form.cleaned_data.get('password1')
            password2 = form.cleaned_data.get('password2')

            if password1 != password2:
                messages.error(request, "Passwords do not match.")
                return render(request, 'core/signup.html', {'form': form})

            form.save()
            messages.success(request, "Account created successfully. You can now log in.")
            return redirect('/login')

    else:
        form = SignupForm()

    return render(request, 'core/signup.html', {'form': form})
    
@login_required
def edit_profile(request):
    if request.method == 'POST':
        if 'change_user_info' in request.POST:
            user_form = EditProfileForm(request.POST, instance=request.user)
            if user_form.is_valid():
                user_form.save()
                messages.success(request, 'Your profile information was successfully updated.')
                return redirect('core:index')
            else:
                messages.error(request, 'Please correct the errors below.')
        elif 'change_password' in request.POST:
            password_form = CustomPasswordChangeForm(user=request.user, data=request.POST)
            if password_form.is_valid():
                password_form.save()
                update_session_auth_hash(request, password_form.user)
                messages.success(request, 'Your password was successfully updated.')
                return redirect('core:index')
            else:
                messages.error(request, 'Please correct the errors below.')
    else:
        user_form = EditProfileForm(instance=request.user)
        password_form = CustomPasswordChangeForm(user=request.user)

    return render(request, 'core/edit_profile.html', {
        'user_form': user_form,
        'password_form': password_form,
    })



@login_required
def delete_account(request):
    if request.method == 'POST':
        request.user.delete()
        logout(request)
        messages.success(request, 'Your account has been successfully deleted.')
        return redirect('core:index')

    user_form = EditProfileForm(instance=request.user)
    password_form = CustomPasswordChangeForm(user=request.user)

    return render(request, 'core/edit_profile.html', {
        'user_form': user_form,
        'password_form': password_form,
    })

def logout_view(request):
    logout(request)
    return redirect ("core:login")