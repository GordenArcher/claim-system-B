from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class Staff(models.Model):
    USER_ROLES = (
        ('staff', 'Staff'),
        ('accountant', 'Accountant'),
    )
    employee = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    staff_id = models.CharField(max_length=20, unique=True) 
    phone_number = models.IntegerField(unique=True, null=True)
    role = models.CharField(max_length=20, choices=USER_ROLES, default='staff')

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
