from django.shortcuts import render, get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib import auth
from django.contrib.auth import authenticate
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Claim, Staff
from .serializers import ClaimSerializer, StaffSerializer
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login
from django.db.models import Q
from datetime import datetime
from django.utils.timezone import now
from django.contrib.auth import get_user_model
import random
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie


@ensure_csrf_cookie
@api_view(['GET'])
def get_csrf_token(request):
    csrf_token = get_token(request)
    return Response({'csrf_token': csrf_token})

# Create your views here.
""" 
This is a login function that logs a user in and sets a cookie of access_token refresh_token and isLoggedIn
"""

@api_view(['POST'])
def register(request):
    data = request.data

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    phone_number = data.get("phone_number")
    role = data.get("role", "staff")
    password = data.get("password")
    password2 = data.get("password2")
    

    if not all([first_name, last_name, email, phone_number, password]):
        return Response({"status": "error", "message": "All fields are required"}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({
            "status": "error", 
            "message": "Email already registered"
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if Staff.objects.filter(phone_number=phone_number).exists():
        return Response({
            "status": "error", 
            "message": "Phone number already registered"
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if password != password2:
        return Response({
            "status": "error", 
            "message": "password does not match"
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.create_user(username=first_name, email=email, password=password, first_name=first_name, last_name=last_name)

        # Generate unique staff ID (e.g., ST-123456)
        staff_id = f"ST-{random.randint(100000, 999999)}"
        while Staff.objects.filter(staff_id=staff_id).exists():
            staff_id = f"ST-{random.randint(100000, 999999)}"

        staff = Staff.objects.create(employee=user, staff_id=staff_id, phone_number=phone_number, role=role)

        return Response({
            "status": "success",
            "message": "Staff registered successfully",
            "staff_id": staff.staff_id,
            "email": user.email,
            "role": staff.role
        }, status=status.HTTP_201_CREATED)

    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")

    try:
        if not email or not password:
            return Response({
                "status": "error",
                "message": "All fields are required"
            }, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, email=email, password=password)

        if not user:
            try:
                user = get_user_model().objects.get(email=email)
                if user.check_password(password):
                    auth_login(request, user)
                else:
                    user = None
            except get_user_model().DoesNotExist:
                user = None


        if user:
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            profile = Staff.objects.get(employee=user)

            profile_serializer = StaffSerializer(profile)

            response = Response({
                "status": "success",
                "auth": True,
                "message": "Login successful",
                "profile":profile_serializer.data
            }, status=status.HTTP_201_CREATED)

            response.set_cookie(
                key="access_token",
                value=access_token,
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                domain=".localhost",
                max_age=60 * 10,
                expires=60 * 10,
            )

            response.set_cookie(
                key="refresh_token",
                value=str(refresh),  
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                domain=".localhost",
                max_age=60 * 60 * 24 * 7, 
                expires=60 * 60 * 24 * 7,
            )

            response.set_cookie(
                key="isLoggedIn",
                value=True,
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                domain=".localhost",
                max_age=60 * 10,
                expires=60 * 10,
            )

            return response

        else:
            return Response({
                "status": "error",
                "message": "Invalid credentials"
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


""" 
This is a custom refresh token class that resfreshes the access_token if it expires
"""
class customTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.COOKIES.get("refresh_token")
            request.data['refresh'] = refresh_token

            response = super().post(request, *args, **kwargs)

            tokens = response.data
            access_token = tokens['access']

            res = Response({"refreshed":True}, status=status.HTTP_200_OK)

            res.set_cookie(
                key="access_token",
                value=access_token,
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                domain=".localhost",
                max_age=60 * 10,
                expires=60 * 10,
            )

            res.set_cookie(
                key="isLoggedIn",
                value=True,
                secure=True,
                httponly=True,
                samesite='None',
                path='/',
                domain=".localhost",
                max_age=60 * 10,
                expires=60 * 10,
            )

            return res

        except Exception as e:
            return Response({"refreshed":f"{e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)  

""" 
This is also the logout function as the function name says, it removes and destroys the current user's session and also removes the custom cookies
"""
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        auth.logout(request)

        res = Response({
            "status":"success",
            "message":"Log-Out Sucessfull"
        }, status=status.HTTP_200_OK)

        res.delete_cookie("isLoggedin")
        res.delete_cookie("access_token")
        res.delete_cookie("refresh_token")

        return res

    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_authentication(request):
    try:
        return Response({
            "status":"success",
            "auth":True
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   



""" 
This function create or initiates a new claim for a staff by collecting their dtata
"""

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_claim(request):
    data = request.data

    employee_first_name = data.get("first_name")
    employee_last_name = data.get("last_name")
    employee_email = data.get("employee_email")
    employee_number = data.get("phone_number")
    claim_amount = data.get("claim_amount")
    claim_reason = data.get("claim_reason")

    if not all([employee_first_name, employee_last_name, employee_email, employee_number, claim_amount, claim_reason]):
        return Response({
            "status": "error",
            "message": "All fields are required"
        }, status=status.HTTP_400_BAD_REQUEST)

    staff = get_object_or_404(Staff, phone_number=employee_number)

    try:
        if User.objects.filter(email=employee_email).exists():
            
            while True:
                claim_number = str(random.randint(10**9, 10**10 - 1))
                if not Claim.objects.filter(claim_number=claim_number).exists():
                    break

            claim = Claim.objects.create(
                staff=staff,
                claim_number=claim_number,
                amount=claim_amount,
                claim_reason=claim_reason,
                status="pending"
            )
            
            return Response({ 
                "status": "success",
                "message": "Claim Submitted",
                "claim_number": claim.claim_number
            }, status=status.HTTP_201_CREATED)
        
        else:
            return Response({
                "status": "error",
                "message": f"No staff available with name {employee_first_name} {employee_last_name}"
            }, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({
            "status": "error",
            "message": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_pending_claims(request):
    try:
        all_pending_claims = Claim.objects.filter(status='pending').order_by('-created_at')

        claim_serializer = ClaimSerializer(all_pending_claims, many=True)

        return Response({
            "status":"success",
            "message":"pending claim retrieved sucessfully",
            "data": claim_serializer.data
        }, status=status.HTTP_200_OK)
 
    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_all_claims(request):
    try:
        all_claims = Claim.objects.all().order_by('-created_at')

        claim_serializer = ClaimSerializer(all_claims, many=True)

        return Response({
            "status":"success",
            "message":"claim retrieved",
            "data": claim_serializer.data
        }, status=status.HTTP_200_OK)
 
    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_staff_claim(request, claim_number): 
    verify_claim = get_object_or_404(Claim, claim_number=claim_number)

    try:
        claim_Serializer = ClaimSerializer(verify_claim)

        return Response({
            "status":"success",
            "message":"Claim retrieved",
            "data": claim_Serializer.data
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

""" 
This function queries a specific staff's claims they made either paid or pending, i.e ( a staff's history claims)
"""

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_staff_claims(request):
    try:
        staff = get_object_or_404(Staff, employee=request.user)

        get_claims = Claim.objects.filter(staff=staff)

        if not get_claims.exists():
            return Response({
                "status": "error",
                "message": "No claims found for this staff"
            }, status=status.HTTP_404_NOT_FOUND)

        claims_serializer = ClaimSerializer(get_claims, many=True)

        return Response({
            "status": "success",
            "message": "Claims retrieved",
            "data": claims_serializer.data
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An unexpected error occurred: {e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def set_claim_to_paid(request, claim_number):
    verify_claim = get_object_or_404(Claim, claim_number=claim_number)

    try:
        verify_claim.status = "paid"
        verify_claim.save()

        return Response({
            "status":"success",
            "message":"Claim status updated to Paid",
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@api_view(['POST'])
def pay_claim(request, claim_number):
    staff_phone = request.data.get('staff_phone')

    try:
        claim = Claim.objects.get(claim_number=claim_number)

        if claim.status == "Paid":
            return Response({"status": "error", "message": "Claim has already been paid."}, status=status.HTTP_400_BAD_REQUEST)

        claim.status = "paid"
        claim.payment_date = datetime.now()
        claim.save()

        # Send SMS notification to staff
        # client = Client()  # Initialize Twilio client
        # message = client.messages.create(
        #     to=staff_phone,
        #     from_="your_twilio_number",
        #     body=f"Your claim {claim_number} has been successfully processed and payment is on the way!"
        # )

        # # Send SMS notification to accountant
        # # You could hardcode or dynamically fetch the accountant's phone number
        # accountant_phone = "accountant_phone_number"
        # message_to_accountant = client.messages.create(
        #     to=accountant_phone,
        #     from_="your_twilio_number",
        #     body=f"Claim {claim_number} for staff {staff_id} has been processed successfully."
        # )

        return Response({
            "status": "success",
            "message": "Claim paid successfully. SMS notifications sent."
        }, status=status.HTTP_200_OK)

    except Claim.DoesNotExist:
        return Response({"status": "error", "message": "Claim not found."}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_paid_claims(request):
    try:

        all_paid_claims = Claim.objects.filter(status='paid')

        claim_serializer = ClaimSerializer(all_paid_claims, many=True)

        return Response({
            "status":"success",
            "message":"paid history retrieved",
            "paid_claims": claim_serializer.data
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_today_paid_claims(request):
    try:
        today = now().date()

        paid_claims_today = Claim.objects.filter(
            status="paid", created_at__date=today
        ).order_by('-created_at')

        claim_serializer = ClaimSerializer(paid_claims_today, many=True)

        return Response({
            "status": "success",
            "message": "Paid history retrieved",
            "paid_claims": claim_serializer.data
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_payments(request):
    try:
        paid_claims = Claim.objects.filter(status="paid",).order_by('-created_at')

        payment_serializer = ClaimSerializer(paid_claims, many=True)

        return Response({
            "status":"success",
            "message":"Payments retrieved successful",
            "history": payment_serializer.data
        }, status=status.HTTP_200_OK)


    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_profile(request):
    data = request.data

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    phone_number = data.get("phone_number")

    try:
        if User.objects.filter(email=email).exists():
            return Response({
                "status":"error",
                "message":f"{email} already exists"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if Staff.objects.filter(phone_number=phone_number).exists():
            return Response({
                "status":"error",
                "message":f"Staff with {phone_number} already exists"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        request.user.email = email
        request.user.first_name = first_name
        request.user.last_name = last_name
        request.user.save()

        new_phone = Staff.objects.update_or_create(employee=request.user, defaults={"phone_number": phone_number},)

        return Response({
            "status":"success",
            "message":"Profile updated Successful"
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)   



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    data = request.data

    old_password = data.get("old_password")
    new_password = data.get("new_password")
    new_password2 = data.get("new_password2")

    try:
        if not request.user.check_password(old_password):
            return Response({
                "status": "error",
                "message": "The old password is incorrect"
            }, status=status.HTTP_400_BAD_REQUEST)

        if new_password != new_password2:
            return Response({
                "status": "error",
                "message": "The new passwords do not match"
            }, status=status.HTTP_400_BAD_REQUEST)

        if old_password == new_password:
            return Response({
                "status": "error",
                "message": "The new password cannot be the same as the old password"
            }, status=status.HTTP_400_BAD_REQUEST)

        request.user.set_password(new_password)
        request.user.save()

        return Response({
            "status": "success",
            "message": "Password updated successfully"
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_details(request):
    user = request.user

    try:
        # Retrieve staff details
        staff = Staff.objects.filter(employee=user).first()
        staff_id = staff.staff_id if staff else None
        phone_number = staff.phone_number if staff else None
        role = staff.role if staff else None

        return Response({
            'status': 'success',
            'message': 'User retrieved successfully',
            'data': {
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'staff_id': staff_id,
                'phone_number': phone_number,
                'role': role
            }
        }, status=200)

    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }, status=500)
