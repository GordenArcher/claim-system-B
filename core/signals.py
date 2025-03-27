import logging
import socket
import platform
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone
from .models import Claim, Payments

# Use core logger for consistent logging
logger = logging.getLogger('core')

def get_client_ip(request):
    """
    Attempt to get the client's IP address
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_system_info():
    """
    Retrieve system and network information
    """
    return {
        'hostname': socket.gethostname(),
        'os': platform.platform(),
        'python_version': platform.python_version()
    }

# User-related Logs
@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(
            f"User Creation: "
            f"Username={instance.username}, "
            f"Email={instance.email}, "
            f"First Name={instance.first_name}, "
            f"Last Name={instance.last_name}, "
            f"Is Staff={instance.is_staff}, "
            f"Date Joined={instance.date_joined}"
        )


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    try:
        system_info = get_system_info()
        request.session['login_time'] = str(timezone.now())
        
        logger.info(
            f"User Login: "
            f"Username={user.username}, "
            f"Email={user.email}, "
            f"IP Address={get_client_ip(request)}, "
            f"Timestamp={timezone.now()}, "
            f"Hostname={system_info['hostname']}, "
            f"OS={system_info['os']}"
        )
    except Exception as e:
        logger.error(f"Error logging user login: {e}")


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    try:
        logout_time = timezone.now()
        login_time_str = request.session.get('login_time')  # Retrieve stored login time
        session_duration = 'Unknown'

        if login_time_str:
            try:
                login_time = timezone.datetime.fromisoformat(login_time_str)  # Convert to datetime object
                duration = logout_time - login_time
                hours, remainder = divmod(duration.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                session_duration = f"{hours}h {minutes}m {seconds}s"
            except Exception as e:
                logger.error(f"Error calculating session duration: {e}")
                session_duration = 'Calculation Error'

        logger.info(
            f"User Logout: "
            f"Username={user.username}, "
            f"Email={user.email}, "
            f"IP Address={get_client_ip(request)}, "
            f"Logout Timestamp={logout_time}, "
            f"Session Duration={session_duration}"
        )
    except Exception as e:
        logger.error(f"Error logging user logout: {e}")


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, **kwargs):
    username = credentials.get('username', 'Unknown')
    logger.warning(
        f"Login Failure: "
        f"Attempted Username={username}, "
        f"Timestamp={timezone.now()}, "
        f"Failure Reason=Invalid Credentials"
    )

@receiver(pre_save, sender=Claim)
def log_claim_status_change(sender, instance, **kwargs):
    try:
        old_instance = Claim.objects.get(pk=instance.pk)
        if old_instance.status != instance.status:
            logger.info(
                f"Claim Status Change: "
                f"Claim Number={instance.claim_number}, "
                f"Staff ID={instance.staff.staff_id}, "
                f"Previous Status={old_instance.status}, "
                f"New Status={instance.status}, "
                f"Timestamp={timezone.now()}"
            )
    except Claim.DoesNotExist:
        pass

@receiver(post_save, sender=Claim)
def log_new_claim_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(
            f"New Claim Creation: "
            f"Claim Number={instance.claim_number}, "
            f"Staff ID={instance.staff.staff_id}, "
            f"Amount={instance.amount}, "
            f"Reason={instance.claim_reason}, "
            f"Initial Status={instance.status}, "
            f"Timestamp={timezone.now()}"
        )

@receiver(post_save, sender=Payments)
def log_new_payment(sender, instance, created, **kwargs):
    if created:
        logger.info(
            f"New Payment Recording: "
            f"Payment ID={instance.payment_id}, "
            f"Claim Number={instance.claim.claim_number}, "
            f"Paid By Staff ID={instance.paid_by.staff_id}, "
            f"Claim Amount={instance.claim.amount}, "
            f"Payment Timestamp={instance.paid_at}"
        )