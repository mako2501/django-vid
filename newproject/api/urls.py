from django.urls import path
from .views import notes_list, simulate_login, create_note, note_detail

#pamietac by dodac to do urls.py projektu
urlpatterns = [
    path('simulate-login/', simulate_login, name='simulate_login'),  # gener tokenu

    path('notes/', notes_list, name='notes_list'),
    path('notes/create/', create_note, name='create_note'),
    path('notes/<int:pk>/', note_detail, name='note_detail'),

]