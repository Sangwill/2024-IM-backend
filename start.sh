#!/bin/sh
python3 manage.py makemigrations board
python3 manage.py migrate

# Run with daphne
daphne -b 0.0.0.0 -p 80 DjangoHW.asgi:application