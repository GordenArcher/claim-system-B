from django.urls import path
from . import views
from .views import customTokenRefreshView
from .views import get_csrf_token

urlpatterns = [
    path("get-csrf-token/", get_csrf_token, name='get-csrf-token'),
    path("auth/login/", views.login),
    path("auth/register/", views.register),
    path("auth/logout/", views.logout),
    path("auth/refresh/", customTokenRefreshView.as_view(), name='refresh_token'),
    path("auth/isAuthenticated/", views.check_authentication),
    path("upload_claim/", views.upload_claims_from_excel),
    path("pending_claims/", views.get_all_pending_claims),
    path("claims/paid/history/", views.get_all_paid_claims),
    path("all_claims/", views.get_all_claims),
    path("recent_claim/", views.get_recent_claims),
    path("claim/verify/", views.verify_staff_claim),
    path("delete_claim/<str:request_number>/", views.delete_claim),
    path("claim/staff/pay/<str:claim_number>/", views.pay_claim),
    path("claim/payments/history/", views.get_all_payments),
    path("profile/change_profile/", views.change_profile),
    path("staff/change_password/", views.change_password),
    path("profile/get_user/", views.get_user_details),
    path("users/", views.get_all_users),
    path("delete_staff/<str:staff_number>/", views.delete_staff),
    path("block_staff/<str:staff_number>/", views.block_staff),
    path("unblock_staff/<str:staff_number>/", views.unblock_staff),
    path("reports/monthly-payments/", views.get_monthly_payments),
    path("reports/claims-by-status/", views.get_claims_by_status),
    path("reports/processing-time/", views.get_processing_time_by_day),
    path("reports/claims-summary/", views.get_claims_summary),
    path("system/logs/", views.get_all_logs),
    path("system_audits/", views.get_audits),
    path("claim_processed/", views.get_top_claim_processors),
    path("get_query-dataa/", views.get_data_based_on_month),
    path("qr-code/", views.generate_qr),
    path("staff/save_phone/", views.save_phone),
]