import logging
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import Claim, Payments

# Use core logger for consistent logging
logger = logging.getLogger('core')

# User-related Logs
@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(f"User created: {instance.username}")

@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    logger.info(f"User {user.username} logged in")

@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    logger.info(f"User {user.username} logged out")

@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, **kwargs):
    logger.warning(f"Failed login attempt for username: {credentials.get('username', 'Unknown')}")

# Claim-related Logs
@receiver(pre_save, sender=Claim)
def log_claim_status_change(sender, instance, **kwargs):
    try:
        old_instance = Claim.objects.get(pk=instance.pk)
        if old_instance.status != instance.status:
            logger.info(f"Claim {instance.claim_number} status changed from {old_instance.status} to {instance.status}")
    except Claim.DoesNotExist:
        pass

@receiver(post_save, sender=Claim)
def log_new_claim_creation(sender, instance, created, **kwargs):
    if created:
        logger.info(f"New Claim created: {instance.claim_number} by Staff {instance.staff.staff_id}")

# Payment-related Logs
@receiver(post_save, sender=Payments)
def log_new_payment(sender, instance, created, **kwargs):
    if created:
        logger.info(f"New Payment {instance.payment_id} recorded for Claim {instance.claim.claim_number}")