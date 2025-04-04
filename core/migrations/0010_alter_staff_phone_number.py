# Generated by Django 5.1.6 on 2025-03-19 14:04

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0009_claim_payment_date_delete_payment'),
    ]

    operations = [
        migrations.AlterField(
            model_name='staff',
            name='phone_number',
            field=models.CharField(max_length=15, null=True, unique=True, validators=[django.core.validators.RegexValidator(message="Phone number must be entered in the format: '+233XXXXXXXXX'. Up to 15 digits allowed.", regex='^\\+?1?\\d{9,15}$')]),
        ),
    ]
