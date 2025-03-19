from django.contrib import admin
from .models import Staff, Claim

# Register your models here.
class StaffAdmin(admin.ModelAdmin):
    list_display = ['employee', 'staff_id', 'phone_number', 'role']
    search_fields = ['employee', 'staff_id', 'phone_number', 'role']
    

    def __str__(self):
        return f"{self.employee} - {self.staff_id}"
    


class ClaimAdmin(admin.ModelAdmin):
    list_display = ['staff', 'claim_number', 'amount', 'claim_reason', 'status', 'created_at', 'payment_date']
    search_fields = ['staff', 'claim_number', 'amount', 'claim_reason', 'status', 'created_at', 'payment_date']


    def __str__(self):
        return f"{self.staff.username} claimed {self.amount}"
    

admin.site.register(Staff, StaffAdmin)    
admin.site.register(Claim, ClaimAdmin)    