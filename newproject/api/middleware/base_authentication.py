"""
Author: 14798
Desc: Klasa abstrakcyjna dla middleware pośredniczacego w komuniakcji miedzy frontem, a serwerem Spring
"""

from django.http import JsonResponse
from .middleware_interface import AuthenticationInterface

class BaseAuthenticationMiddleware(AuthenticationInterface):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # spr. czy request ma byc przetwrzany
        if self.should_skip(request):
            return self.get_response(request)

        #pobierz token z requestu
        token = self.get_token_from_request(request)
        if not token:
            return JsonResponse({'error': 'Token not provided'}, status=401)
        
        # weryfikajca tokenu + pobranie hasha user id
        token_with_user_id = self.forward_token_to_api(token)

        if not token_with_user_id:
            return JsonResponse({'error': 'Invalid response from Spring API'}, status=502) #czy moze inny kod
        
        #jesli to nie token a jsonresp=api spring zwrocil blad
        if isinstance(token_with_user_id, JsonResponse):
            return token_with_user_id

        try:              
            user_id = self.decode_token(token_with_user_id)
            if user_id is None:
                return JsonResponse({'error':'Unauthorized'}, status=401)
        except ValueError as e:
            return JsonResponse({'error':str(e)}, status=400)
        
        #dodaj dane usera do requesta
        request.user_id = user_id

        print(f"Odszyfrowany user_id: {user_id}")  # spr id po odszyfr.

        # kontynuacja przetwarzania - w request znajduje się user_id
        return self.get_response(request)


