from django.urls import re_path
from .consumer import IMConsumer

websocket_urlpatterns = [
    re_path(r'ws/$', IMConsumer.as_asgi()),
]
