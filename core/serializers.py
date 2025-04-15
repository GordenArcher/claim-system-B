from rest_framework import serializers
from .models import Claim, Accountant, AuditTrail
from django.contrib.auth.models import User


class EmployeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email']
    


class StaffSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer()
    class Meta:
        model = Accountant
        fields = ['employee', 'staff_number', 'phone_number', 'role', 'is_blocked']


class ClaimSerializer(serializers.ModelSerializer):
    class Meta:
        model = Claim
        fields = '__all__'    



class AuditTrailSerializer(serializers.ModelSerializer):
    user = EmployeeSerializer()
    class Meta:
        model = AuditTrail
        fields = ['id', 'user', 'full_name', 'entity_type', 'entity_id', 'action', 'changes', 'timestamp']