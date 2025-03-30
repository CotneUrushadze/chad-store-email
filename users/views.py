from rest_framework.mixins import ListModelMixin, CreateModelMixin, RetrieveModelMixin
from rest_framework.viewsets import GenericViewSet
from users.serializers import UserSerializer, RegisterSerializar, PasswordResetSerializer
from users.models import User
from rest_framework import status, serializers, mixins, viewsets, permissions, response
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi



class UserViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    
    
class RegisterViewSet(CreateModelMixin, GenericViewSet):
    queryset = User.objects.all()
    serializer_class = RegisterSerializar



class ResetPasswordViewSet(GenericViewSet, CreateModelMixin,):
    serializer_class = PasswordResetSerializer
    
    def create(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # reset_url = request.build_absolute_uri(
            #     reverse( 'password-reset-confirm', kwargs={'uidb64': uid, 'token': token},)
            # )
            
            reset_url = f'http://127.0.0.1:8000/reset_password_confirm/{uid}/{token}'
            
            send_mail(
                'პაროლის აღდგენა',
                f'დააჭირეთ ლინკს რათა აღადგინოთ პაროლი {reset_url}',
                'noreply@example.com',
                [user.email],
                fail_silently=False,
            )
            
            return response.Response({'Massage': 'წერილი წარმატებით არის გაგზავნილი'}, status=status.HTTP_200_OK)
        return response.Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        