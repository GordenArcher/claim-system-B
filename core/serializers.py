from rest_framework import serializers
from .models import Claim, Staff, AuditTrail
from django.contrib.auth.models import User


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']
    


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



class AuditTrailSerializer(serializers.ModelSerializer):
    user = EmployeeSerializer()
    class Meta:
        model = AuditTrail
        fields = ['id', 'user', 'entity_type', 'entity_id', 'action', 'changes', 'timestamp']