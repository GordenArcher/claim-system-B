from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator

# Create your models here.
class Staff(models.Model):
    USER_ROLES = (
        ('accountant', 'Accountant'),
        ('administrator', 'Administrator'),
        ('main_administrator', 'Main_Administrator'),
    )
    employee = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    staff_id = models.CharField(max_length=20, unique=True) 
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+233XXXXXXXXX'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=15, unique=True, null=True)
    role = models.CharField(max_length=20, choices=USER_ROLES, default='accountant')
    is_blocked = models.BooleanField(default=False, null=True, blank=True)

    def __str__(self):
        return f"{self.employee.username}"


class Claim(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('paid', 'Paid'),
    ]

    staff = models.ForeignKey(Staff, on_delete=models.CASCADE) 
    claim_number = models.CharField(max_length=20, unique=True)  
    amount = models.DecimalField(max_digits=10, decimal_places=2)  
    claim_reason = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  
    created_at = models.DateTimeField(auto_now_add=True)  
    payment_date = models.DateTimeField(null=True, blank=True)  
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Claim {self.claim_number} - {self.staff.staff_id} ({self.status})"



class Payments(models.Model):
    payment_id = models.AutoField(primary_key=True)
    claim = models.ForeignKey(Claim, on_delete=models.CASCADE, related_name='payment_history')
    paid_by = models.ForeignKey(Staff, on_delete=models.CASCADE, related_name='payments')
    paid_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment {self.payment_id} for Claim {self.claim.claim_number}"