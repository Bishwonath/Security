from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('', include('core.urls')),
    path('items/', include('item.urls')),
    path('dashboard/' , include('dashboard.urls')),
    path('inbox/',include('conversation.urls')),
    path('admin/', admin.site.urls),
    path('reset_password/', auth_views.PasswordResetView.as_view(template_name='core/password_reset.html'), name='reset_password'),
    
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(template_name='core/password_reset_sent.html'), name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='core/password_reset_form.html'), name='password_reset_confirm'),
    
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(template_name='core/password_reset_done.html'), name='password_reset_complete'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
