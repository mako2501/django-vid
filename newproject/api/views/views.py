''''
#stary views z .api - można usunać
#widoki sa w views

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializer import NoteSerializer
#from .models import Note
from .models.note import Note
from django.http import JsonResponse
from datetime import datetime, timedelta
import jwt
from django.conf import settings

#f. view jako arg. otrzymuje request a zwraca response
@api_view(['POST'])
def create_note(request):
    #if not hasattr(request, 'user_id'):
    if not hasattr(request, 'user_data') or 'user_id' not in request.user_data:
        return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # kopia by moc nadpisac `user_id`
    data = request.data.copy()
    #data['user_id'] = request.user_id
    data['user_id'] = request.user_data.get('user_id')

    serializer = NoteSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
def note_detail(request, pk):
    try:
        note = Note.objects.get(pk=pk)
    except Note.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    #czy dane usera sa dostepne
    if not hasattr(request, 'user_data') or 'user_id' not in request.user_data:
        return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

    # czy użytkownik jest właścicielem notatki
    #if note.user_id != request.user_id:
    if note.user_id != request.user_data.get('user_id'):    
        return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
    
    if request.method == 'GET':
        # zwroc wszystkie dane notatki
        serializer = NoteSerializer(note)
        return Response(serializer.data)

    elif request.method == 'PUT':
        #przygotowanie danych do aktualizacji
        data = request.data.copy()
        #dodanie user id przed zapisaniem - serializer wymaga tego pola a ja go nie rpzysylam
        data['user_id'] = note.user_id        

        # aktualizacja danych notatki
        serializer = NoteSerializer(note, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)  # po aktualizacji zwraca dane
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        # usuwa notatke
        note.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

def notes_list(request):
    #if not hasattr(request, 'user_id'):
    if not hasattr(request, 'user_data') or 'user_id' not in request.user_data:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    
    notes = Note.objects.all().values('title', 'content','user_id')
    #notes = Note.objects.filter(user_id=request.user_id).values('title', 'content','user_id') #tylko tego usera
    return JsonResponse(list(notes), safe=False)
    

#widok do tworzenia tokena jwt symuloujacego logowanie - zwraca token
def simulate_login(request):
    # jakis id
    user_id = 2

    # pozostałe dane usera - nie musza byc ustawiane
    #permissions = []
    roles = [] # - najwyzej bedzie pusta lista
    
    # tworzenie payload tokenuJWT
    payload = {
        "user_id": user_id,
        #"permissions": permissions,
        "roles": roles,  
        "exp": datetime.utcnow() + timedelta(minutes=60),  # czas waznosci
        "iat": datetime.utcnow()
    }

    # generowanie tokneu JWT
    token = jwt.encode(payload, getattr(settings, "JWT_SECRET_KEY", None), algorithm=getattr(settings, "JWT_ALGORITHM", "HS256"))

    return JsonResponse({"access_token": token})
'''