from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator
import uuid

class AuditTrail(models.Model):
    """
    Generic Audit Trail model to track changes across different models
    """
    ACTIONS = (
        ('create', 'Created'),
        ('update', 'Updated'),
        ('delete', 'Deleted'),
    )

    ENTITIES = (
        ('staff', 'Staff'),
        ('claim', 'Claim'),
        ('payment', 'Payment'),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, blank=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    full_name = models.CharField(max_length=1000, null=True, blank=True)
    entity_type = models.CharField(max_length=20, choices=ENTITIES, null=True, blank=True)
    entity_id = models.PositiveIntegerField()
    action = models.CharField(max_length=20, choices=ACTIONS, null=True, blank=True)
    changes = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    
    class Meta:
        verbose_name = 'Audit Trail'
        verbose_name_plural = 'Audit Trails'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user or self.full_name} - {self.action} {self.entity_type} at {self.timestamp}"

class Accountant(models.Model):
    USER_ROLES = (
        ('accountant', 'Accountant'),
        ('administrator', 'Administrator'),
        ('main_administrator', 'Main_Administrator'),
    )
    
    employee = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    staff_number = models.CharField(max_length=20, unique=True) 
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+233XXXXXXXXX'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=15, unique=True, null=True)
    role = models.CharField(max_length=20, choices=USER_ROLES, default='accountant')
    is_blocked = models.BooleanField(default=False, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return f"{self.employee.username}"

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        old_instance = Accountant.objects.filter(pk=self.pk).first() if not is_new else None
        
        super().save(*args, **kwargs)
        
        self._create_audit_trail(is_new, old_instance)

    def _create_audit_trail(self, is_new, old_instance):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            current_user = User.objects.get(username=self.employee.username)
        except User.DoesNotExist:
            current_user = None

        changes = {}
        if is_new:
            action = 'create'
            changes = {
                'staff_number': self.staff_number,
                'role': self.role,
                'phone_number': self.phone_number
            }
        else:
            action = 'update'
            if old_instance:
                for field in ['role', 'phone_number', 'is_blocked']:
                    old_value = getattr(old_instance, field)
                    new_value = getattr(self, field)
                    if old_value != new_value:
                        changes[field] = {
                            'old': old_value,
                            'new': new_value
                        }

        if changes:
            AuditTrail.objects.create(
                user=current_user,
                entity_type='staff',
                entity_id=self.id,
                action=action,
                changes=changes
            )

    def delete(self, *args, **kwargs):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            current_user = User.objects.get(username=self)
        except User.DoesNotExist:
            current_user = None

        deletion_details = {
            'staff_number': self.staff_number,
            'role': self.role,
            'phone_number': self.phone_number
        }

        super().delete(*args, **kwargs)

        AuditTrail.objects.create(
            user=current_user,
            entity_type='staff',
            entity_id=self.id,
            action='delete',
            changes=deletion_details
        )

class Claim(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('paid', 'Paid'),
    ]
    full_name = models.CharField(max_length=100, null=True, blank=True)
    claim_number = models.CharField(max_length=100, unique=True, null=True, blank=True)
    staff_number = models.CharField(max_length=20, null=True, blank=True) 
    phone_number = models.CharField(max_length=15, null=True, blank=True) 
    amount = models.DecimalField(max_digits=10, decimal_places=2)  
    claim_reason = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')  
    created_at = models.DateTimeField(null=True, blank=True)  
    payment_date = models.DateTimeField(null=True, blank=True)  
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Claim {self.claim_number} - {self.full_name} ({self.status})"

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        old_instance = Claim.objects.filter(pk=self.pk).first() if not is_new else None
        
        super().save(*args, **kwargs)
        
        self._create_audit_trail(is_new, old_instance)

    def _create_audit_trail(self, is_new, old_instance):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            current_user = User.objects.get(username="example_user")
        except User.DoesNotExist:
            current_user = None

        changes = {}
        if is_new:
            action = 'create'
            changes = {
                'claim_number': self.claim_number,
                'amount': float(self.amount),
                'status': self.status,
                'claim_reason': self.claim_reason
            }
        else:
            action = 'update'
            if old_instance:
                for field in ['status', 'amount', 'claim_reason']:
                    old_value = getattr(old_instance, field)
                    new_value = getattr(self, field)
                    if old_value != new_value:
                        changes[field] = {
                            'old': str(old_value),
                            'new': str(new_value)
                        }

        if changes:
            AuditTrail.objects.create(
                user=current_user,
                full_name=self.full_name,
                entity_type='claim',
                entity_id=self.id,
                action=action,
                changes=changes
            )

    def delete(self, *args, **kwargs):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            current_user = User.objects.get(username="example_user")
        except User.DoesNotExist:
            current_user = None

        deletion_details = {
            'claim_number': self.claim_number,
            'amount': float(self.amount),
            'status': self.status,
            'claim_reason': self.claim_reason
        }

        super().delete(*args, **kwargs)

        AuditTrail.objects.create(
            user=current_user,
            full_name=self.full_name,
            entity_type='claim',
            entity_id=self.id,
            action='delete',
            changes=deletion_details
        )

class Payments(models.Model):
    payment_id = models.AutoField(primary_key=True)
    claim = models.ForeignKey(Claim, on_delete=models.CASCADE, related_name='payment_history')
    paid_by = models.ForeignKey(Accountant, on_delete=models.CASCADE, related_name='payments')
    paid_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Payment {self.payment_id} for Claim {self.claim.claim_number}"

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        old_instance = Payments.objects.filter(pk=self.pk).first() if not is_new else None
        
        super().save(*args, **kwargs)
        
        self._create_audit_trail(is_new, old_instance)

    def _create_audit_trail(self, is_new, old_instance):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            current_user = User.objects.get(username=self.paid_by.employee.username)
        except User.DoesNotExist:
            current_user = None

        changes = {}
        if is_new:
            action = 'create'
            changes = {
                'payment_id': self.payment_id,
                'claim_number': self.claim.claim_number,
                'paid_by': self.paid_by.employee.username
            }
        
        if changes:
            AuditTrail.objects.create(
                user=current_user,
                entity_type='payment',
                entity_id=self.payment_id,
                action=action,
                changes=changes
            )

    def delete(self, *args, **kwargs):
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            current_user = User.objects.get(username=self.paid_by.employee.username)
        except User.DoesNotExist:
            current_user = None

        deletion_details = {
            'payment_id': self.payment_id,
            'claim_number': self.claim.claim_number,
            'paid_by': self.paid_by.staff_id
        }

        super().delete(*args, **kwargs)

        AuditTrail.objects.create(
            user=current_user,
            entity_type='payment',
            entity_id=self.payment_id,
            action='delete',
            changes=deletion_details
        )