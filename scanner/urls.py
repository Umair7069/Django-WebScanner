from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='scan_url'),
    path('results/<int:target_id>/', views.results, name='results'),  
]