# Generated by Django 5.1.6 on 2025-04-14 22:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_audittrail_full_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='claim',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True, unique=True),
        ),
    ]
