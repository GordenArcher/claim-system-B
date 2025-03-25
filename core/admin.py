from django.contrib import admin
from .models import Staff, Claim, Payments, AuditTrail

# Register your models here.
class StaffAdmin(admin.ModelAdmin):
    list_display = ['employee', 'staff_id', 'phone_number', 'role', 'is_blocked']
    search_fields = ['employee', 'staff_id', 'phone_number', 'role', 'is_blocked']
    

    def __str__(self):
        return f"{self.employee} - {self.staff_id}"
    


class ClaimAdmin(admin.ModelAdmin):
    list_display = ['staff', 'claim_number', 'amount', 'claim_reason', 'status', 'created_at', 'payment_date']
    search_fields = ['staff', 'claim_number', 'amount', 'claim_reason', 'status', 'created_at', 'payment_date']
    list_filter = ['staff', 'claim_number', 'amount', 'claim_reason', 'status', 'created_at', 'payment_date']
    readonly_fields = ['created_at', 'payment_date']


    def __str__(self):
        return f"{self.staff.username} claimed {self.amount}"
    


class PaymentsAdmin(admin.ModelAdmin):
    list_display = ['payment_id', 'claim', 'paid_by', 'paid_at']
    search_fields = ['payment_id', 'claim', 'paid_by', 'paid_at']
    list_filter = ['payment_id', 'claim', 'paid_by', 'paid_at']



class AuditTrailAdmin(admin.ModelAdmin):
    list_display = ['user', 'entity_type', 'action', 'timestamp']
    list_filter = ['entity_type', 'action', 'timestamp']
    search_fields = ['user', 'entity_type', 'action', 'timestamp']
    readonly_fields = ['id', 'timestamp']



    

admin.site.register(Staff, StaffAdmin)    
admin.site.register(Claim, ClaimAdmin)    
admin.site.register(Payments, PaymentsAdmin)    
admin.site.register(AuditTrail, AuditTrailAdmin)    