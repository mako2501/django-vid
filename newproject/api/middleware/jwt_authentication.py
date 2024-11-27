import requests
from .base_authentication import BaseAuthenticationMiddleware
from django.conf import settings
import jwt

class JWTAuthenticationMiddleware(BaseAuthenticationMiddleware):
    def should_skip(self, request):
        #spr. czy sciezka jest na liscie ktore nie maja byc obslugiwane przez middleware
        return request.path in getattr(settings, 'SKIP_AUTHENTICATION_PATHS', [])

    def get_token_from_request(self, request):        
        token = request.headers.get('Authorization') #token z nagłówka
        if token and token.startswith("Bearer "): 
            return token.split(" ")[1] #Bearer jkdshfsjdgfsdjfgjgjh
        return None

    def forward_token_to_api(self, token):
        # tworze nagłówek z bearer tokenem
        headers = {'Authorization': f'Bearer {token}'}
        try:
            response = requests.get(getattr(settings, 'SPRING_API_VERIFY_URL', None), headers=headers)

            if response.status_code == 200:

                #userid w jwt w body           
                return response.json().get("jwt_user_id")
            
        except requests.RequestException as e:
            return None
    
    def decode_token(self, token):        
        try:
            decoded = jwt.decode(token, getattr(settings, "JWT_SECRET_KEY", None), algorithms=[getattr(settings, "JWT_ALGORITHM", "HS256")])

            return decoded.get('user_id')                

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    