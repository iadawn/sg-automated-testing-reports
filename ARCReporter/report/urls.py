from django.urls import path
from .views import report, input, GetDetails, dashboard, resetCache
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', dashboard, name='dashboard'),
    path('details', GetDetails, name='details'),
    path('input', input, name='input'),
    path('display', report, name='report'),
    path('cache', resetCache, name='resetCache'),
    # path('trash', deleteEntry, name='trash'),
    path('login', auth_views.LoginView.as_view(template_name='report/login.html'), name='login'),
    path('logout', auth_views.LogoutView.as_view(template_name='report/logout.html'), name='logout'),


]