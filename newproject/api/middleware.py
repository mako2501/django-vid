import jwt
import requests
from django.http import JsonResponse

#klasa weryfikuje tokeny jwt - token otrzymywany w naglowku requesta - middleware zarejestrowany w settings 
#jwt zawierac ma id usera
class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        #nie sprawdzaj gdy simulate_login
        if request.path == '/api/simulate-login/':            
            return self.get_response(request)
        
        token = request.headers.get('Authorization')   #spr. czy posiada pole Auth i posiada token     
        if token and token.startswith("Bearer "):
            token = token.split(" ")[1]
            
            # weryfikacja tkoenu przez API Spring
            response = self.check_token_in_spring(token) #wysylam otrzymany token na 8080
            if response is None:
                return JsonResponse({'error': 'Unable to connect to Spring API'}, status=500)

            if response.status_code == 200:
                # token jest ważny, pobieram zwrocony token jak wyzej
                returned_token = response.json().get("Authorization", "").split(" ")[1]

                try:
                    decoded = jwt.decode(returned_token, "tajny_kod_dzilimy_go_z_api_Spring", algorithms=["HS256"]) 
                    request.user_id = decoded['user_id']  #wyciagam z niego id usera
                except jwt.ExpiredSignatureError:
                    return JsonResponse({'error': 'Token expired'}, status=401)
                except jwt.InvalidTokenError:
                    return JsonResponse({'error': 'Invalid token'}, status=401)                
                
            else:
                return JsonResponse({'error': 'Token is not valid in Spring API'}, status=401)
                
        else:
            return JsonResponse({'error': 'Token not provided'}, status=401)

        # wywołanie dalzsego wywolywania requestu
        response = self.get_response(request)

        return response
    #sprawddzenie na api spring prawidlowowsc otrzymanego tokenu
    def check_token_in_spring(self, token):
        
        headers = {
            'Authorization': f'Bearer {token}'  # w naglowku
        }
        
        try:
            # wysylka na 8080
            response = requests.get('http://localhost:8080/api/verify-token/', headers=headers)
            return response
        except requests.RequestException:
            # jesli jakikolwiek blad
            return None

#wczesniejsza klasa middleware, bez wysylania req. na spring, tyl;ko weryfikacja jwt z frontu
class JWTAuthenticationMiddleware2:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        #nie sprawdzaj gdy simulate_login
        if request.path == '/api/simulate-login/':            
            return self.get_response(request)
        
        token = request.headers.get('Authorization')
        
        if token and token.startswith("Bearer "):
            token = token.split(" ")[1]
            try:
                '''
                # weryfikacja tokenu JWT
                decoded = jwt.decode(token, "tajny_kod_dzilimy_go_z_api_Spring", algorithms=["HS256"])
                request.user_id = decoded['user_id']  # ustawienie user_id w obiekcie request

                response = self.check_token_in_spring(token)
                '''
               
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Token expired'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'error': 'Invalid token'}, status=401)
        else:
            return JsonResponse({'error': 'Token not provided'}, status=401)

        response = self.get_response(request)
        return response