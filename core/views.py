from django.shortcuts import render, get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib import auth
from django.contrib.auth import authenticate
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Claim, Staff, Payments
from .serializers import ClaimSerializer, StaffSerializer
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login
from django.db.models import Q
from django.utils import timezone
from django.utils.timezone import now
from django.contrib.auth import get_user_model
import random
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
import requests
from datetime import datetime, timedelta
from django.db.models import Sum
from django.db.models.functions import TruncMonth
from django.db.models import Count
from django.db.models.functions import ExtractWeekDay
from django.db.models import Avg, F, ExpressionWrapper, fields


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
    role = data.get("role")
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
        user = User.objects.create_user(username=f"{first_name}_{last_name}", email=email, password=password, first_name=first_name, last_name=last_name)

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
        total_pending_claims = Claim.objects.filter(status='pending').count()

        claim_serializer = ClaimSerializer(all_pending_claims, many=True)

        return Response({
            "status":"success",
            "message":"pending claim retrieved sucessfully",
            "data": claim_serializer.data,
            "total_pending_claims": total_pending_claims
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
        total_claims = Claim.objects.all().count()

        claim_serializer = ClaimSerializer(all_claims, many=True)

        return Response({
            "status":"success",
            "message":"claim retrieved",
            "data": claim_serializer.data,
            "total_claims": total_claims
        }, status=status.HTTP_200_OK)
 
    except Exception as e:
        return Response({
            "status":"error",
            "message":f"{e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    



@api_view(["GET"])
@permission_classes([IsAuthenticated])
def get_recent_claims(request):
    try:
        # Get the last 10 recent claims
        recent_10_claims = Claim.objects.all().order_by('-created_at')[:10]

        claim_serializer = ClaimSerializer(recent_10_claims, many=True)

        return Response({
            "status":"success",
            "message":"claim retrieved",
            "data": claim_serializer.data,
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


    except Claim.DoesNotExist:
        return Response({
            "status": "error",
            "message": "Claim not found",
        }, status=status.HTTP_404_NOT_FOUND)    
    
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

        if staff:
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
        
        else:
            return Response({
                "status": "error",
                "message": f"staff not found",
            }, status=status.HTTP_400_BAD_REQUEST)

    
    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An unexpected error occurred: {e}",
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



HUTBUL_SENDER_ID = "glcxnwfw"

def send_sms(phone_number, message):
    url = "https://smsc.hubtel.com/v1/messages/send"
    params = {
        "clientsecret": "tvjaurmu",
        "clientid": "tquahyvu",
        "from": "Claim",
        "to": phone_number,
        "content": message
    }

    try:
        response = requests.get(url, params=params)
        response_data = response.json()

        if response.status_code == 200 and response_data.get("status") == "Success":
            return True
        else:
            print(f"Failed to send SMS: {response_data}")
            return False
    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        return False
    


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def pay_claim(request, claim_number):
    try:
        claim = Claim.objects.get(claim_number=claim_number)
        
        if claim.status == "Paid":
            return Response({
                "status": "error",
                 "message": "Claim has already been paid."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if hasattr(claim, "staff") and claim.staff and claim.staff.phone_number:
            staff_phone = claim.staff.phone_number
        else:
            return Response({
                "status": "error", 
                "message": "Staff phone number not found for this claim."
            },status=status.HTTP_400_BAD_REQUEST)
        
        claim.status = "paid"
        claim.payment_date = timezone.now()
        claim.save()
        
        # Send SMS to the Staff
        staff_message = f"Dear {claim.staff.employee.first_name}, your claim (#{claim_number}) of {claim.amount} has been successfully processed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. Payment is on the way!"
        send_sms(staff_phone, staff_message)

        # Send SMS to the accountant
        accountant = Staff.objects.filter(employee=request.user).first()
        if accountant and accountant.phone_number:
            accountant_message = (
                f"Payment of {claim.amount} for {claim.staff.employee.first_name} "
                f"{claim.staff.employee.last_name} (Claim #{claim_number}, Phone: {staff_phone}) "
                f"has been successfully processed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                f"by {accountant.employee.first_name} {accountant.employee.last_name}."
            )
            send_sms(accountant.phone_number, accountant_message)
        
        return Response({
            "status": "success",
            "message": "Claim paid successfully. SMS notifications sent."
        }, status=status.HTTP_200_OK)
        
    except Claim.DoesNotExist:
        return Response({
            "status": "error", 
            "message": "Claim not found."
            },status=status.HTTP_404_NOT_FOUND)
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

        Staff.objects.update_or_create(employee=request.user, defaults={"phone_number": phone_number},)

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

    staff_email = data.get("email")
    new_password = data.get("new_password")
    new_password2 = data.get("new_password2")

    try:

        if not all(staff_email, new_password, new_password2):
            return Response({
                "status":"success",
                "message":"All fields are required"
            }, status=status.HTTP_400_BAD_REQUEST)

        if new_password != new_password2:
            return Response({
                "status": "error",
                "message": "The new passwords do not match"
            }, status=status.HTTP_400_BAD_REQUEST)
        

        user = User.objects.get(email=staff_email)

        if user:
            user.password = new_password

            return Response({
                "status":"success",
                "message":f"Password has been changed for {user.first_name} {user.last_name}"
            }, status=status.HTTP_200_OK)

        else:
            return Response({
                "status":"error",
                "message":"Email does not exists"
            }, status=status.HTTP_400_BAD_REQUEST)    
            
        

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
                'role': role,
                'has_access': staff.is_blocked
            }
        }, status=200)

    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }, status=500)



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_users(request):
    try:
        
        users = Staff.objects.all()

        staff_serializers = StaffSerializer(users, many=True)

        return Response({
            "status":"success",
            "message":"retrieved",
            "data": staff_serializers.data
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response({
            "status": "error",
            "message": f"An error occurred: {str(e)}"
        }, status=500)



@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_staff(request, staff_id):
    try:

        staff = Staff.objects.get(staff_id=staff_id)
        staff_name_f = staff.employee.first_name
        staff_name_l = staff.employee.last_name
        user = staff.employee

        staff.delete()
        user.delete()

        return Response({
            "status":"success",
            "message":f"{staff_name_f} {staff_name_l} has been deleted"
        }, status=status.HTTP_200_OK)


    except Staff.DoesNotExist:
        return Response({
            "status": "error",
            "message": "Staff does not exist."
        }, status=status.HTTP_404_NOT_FOUND)        

    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def block_staff(request, staff_id):
    try:

        staff = Staff.objects.get(staff_id=staff_id)
        staff.is_blocked = True 
        staff.save()

        staff_name_f = staff.employee.first_name
        staff_name_l = staff.employee.last_name

        return Response({
            "status":"success",
            "message":f"{staff_name_f} {staff_name_l} has been blocked"
        }, status=status.HTTP_200_OK)

    except Staff.DoesNotExist:
        return Response({
            "status": "error",
            "message": "Staff does not exist."
        }, status=status.HTTP_404_NOT_FOUND)        

    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    




@api_view(['POST'])
@permission_classes([IsAuthenticated])
def unblock_staff(request, staff_id):
    try:

        staff = Staff.objects.get(staff_id=staff_id)
        staff.is_blocked = False 
        staff.save()

        staff_name_f = staff.employee.first_name
        staff_name_l = staff.employee.last_name

        return Response({
            "status":"success",
            "message":f"{staff_name_f} {staff_name_l} has been unblocked"
        }, status=status.HTTP_200_OK)

    except Staff.DoesNotExist:
        return Response({
            "status": "error",
            "message": "Staff does not exist."
        }, status=status.HTTP_404_NOT_FOUND)        

    except Exception as e:
        return Response({
            "status": "error", 
            "message": f"An error occurred: {str(e)}"
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    



# Get payments by month (for the last 6 months)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_monthly_payments(request):
    try:
        six_months_ago = datetime.now() - timedelta(days=180)
        
        monthly_payments = Payments.objects.filter(
            paid_at__gte=six_months_ago
        ).annotate(
            month=TruncMonth('paid_at')
        ).values('month').annotate(
            amount=Sum('claim__amount')
        ).order_by('month')
        
        result = []
        for item in monthly_payments:
            result.append({
                'month': item['month'].strftime('%b'),
                'amount': float(item['amount'])
            })
        
        return Response({
            "status":"success",
            "message":"",
            "data":result
        }, status=status.HTTP_200_OK)
    
    
    except Exception as e:
        return Response({
            "status":"error",
            "message": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_claims_by_status(request):
    try:
        status_counts = Claim.objects.values('status').annotate(
            value=Count('id')
        ).order_by('status')
        
        total_claims = Claim.objects.count()
        
        result = []
        for item in status_counts:
            status_name = dict(Claim.STATUS_CHOICES).get(item['status'], item['status'])
            percentage = (item['value'] / total_claims) * 100 if total_claims > 0 else 0
            
            result.append({
                'name': status_name,
                'value': percentage
            })
        
        return Response({'data': result, 'total_claims': total_claims})
    except Exception as e:
        return Response({'error': str(e)}, status=500)
    


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_processing_time_by_day(request):
    try:
        processing_time = Claim.objects.filter(
            status='paid',
            payment_date__isnull=False
        ).annotate(
            day_of_week=ExtractWeekDay('created_at'),
            process_time=ExpressionWrapper(
                F('payment_date') - F('created_at'),
                output_field=fields.DurationField()
            )
        )
        
        day_averages = processing_time.values('day_of_week').annotate(
            avg_days=Avg(ExpressionWrapper(
                F('process_time') / timedelta(days=1),
                output_field=fields.FloatField()
            ))
        ).order_by('day_of_week')
        
        day_map = {
            1: 'Sun', 2: 'Mon', 3: 'Tue', 4: 'Wed', 5: 'Thu', 6: 'Fri', 7: 'Sat'
        }
        
        result = []
        for item in day_averages:
            result.append({
                'day': day_map.get(item['day_of_week'], f"Day {item['day_of_week']}"),
                'time': round(item['avg_days'], 1)
            })
        
        return Response({
            "status":"success",
            "message":"",
            "data": result
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_claims_summary(request):
    try:
        total_payments = Payments.objects.count()
        total_amount_paid = Claim.objects.filter(status='paid').aggregate(
            total=Sum('amount')
        )['total'] or 0
        
        avg_claim_amount = Claim.objects.aggregate(
            avg=Avg('amount')
        )['avg'] or 0
        
        pending_count = Claim.objects.filter(status='pending').count()
        approved_count = Claim.objects.filter(status='approved').count()
        paid_count = Claim.objects.filter(status='paid').count()
        
        total_claims = Claim.objects.count()
        approval_rate = (approved_count + paid_count) / total_claims * 100 if total_claims > 0 else 0
        payment_rate = paid_count / total_claims * 100 if total_claims > 0 else 0
        
        return Response({
            'total_payments': total_payments,
            'total_amount_paid': float(total_amount_paid),
            'avg_claim_amount': float(avg_claim_amount),
            'pending_count': pending_count,
            'approved_count': approved_count,
            'paid_count': paid_count,
            'approval_rate': round(approval_rate, 1),
            'payment_rate': round(payment_rate, 1)
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)