from django.urls import path
from .views import CheckDomainRecordAPIView,CheckSSLStatusAPIView

urlpatterns = [
    path('check-domain/',CheckDomainRecordAPIView.as_view() , name='check-domain'),
    path('check-ssl/',CheckSSLStatusAPIView.as_view() , name='check-check-ssl'),
]