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
    path("claim/verify/<int:claim_number>/", views.verify_staff_claim),
    path("staff/claims/", views.get_staff_claims),
    path("claim/staff/pay/<int:claim_number>/", views.pay_claim),
    path("claim/payments/history/", views.get_all_payments),
    path("profile/change_profile/", views.change_profile),
    path("profile/change_password/", views.change_password),
    path("profile/get_user/", views.get_user_details),
]
