from rest_framework import serializers
from .models import Claim, Staff
from django.contrib.auth.models import User


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
    


class StaffSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer()
    class Meta:
        model = Staff
        fields = ['employee', 'staff_id', 'phone_number', 'role', 'is_blocked']


class ClaimSerializer(serializers.ModelSerializer):
    staff = StaffSerializer()
    class Meta:
        model = Claim
        fields = ['staff', 'claim_number', 'amount', 'claim_reason', 'status', 'created_at', 'payment_date']      

