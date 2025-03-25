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
    path("create_claim/", views.create_claim),
    path("pending_claims/", views.get_all_pending_claims),
    path("claims/paid/history/", views.get_all_paid_claims),
    path("claims/paid/today/", views.get_today_paid_claims),
    path("all_claims/", views.get_all_claims),
    path("recent_claim/", views.get_recent_claims),
    path("claim/verify/<int:claim_number>/", views.verify_staff_claim),
    path("staff/claims/", views.get_staff_claims),
    path("claim/staff/pay/<int:claim_number>/", views.pay_claim),
    path("claim/payments/history/", views.get_all_payments),
    path("profile/change_profile/", views.change_profile),
    path("staff/change_password/", views.change_password),
    path("profile/get_user/", views.get_user_details),
    path("users/", views.get_all_users),
    path("delete_staff/<str:staff_id>/", views.delete_staff),
    path("block_staff/<str:staff_id>/", views.block_staff),
    path("unblock_staff/<str:staff_id>/", views.unblock_staff),
    path("reports/monthly-payments/", views.get_monthly_payments),
    path("reports/claims-by-status/", views.get_claims_by_status),
    path("reports/processing-time/", views.get_processing_time_by_day),
    path("reports/claims-summary/", views.get_claims_summary),
    path("logs/users/", views.get_user_logs),
    path("logs/claims/", views.get_claim_logs),
    path("logs/payments/", views.get_payment_logs),
    path("system_audits/", views.get_audits),
    path("claim_processed/", views.get_top_claim_processors),
]