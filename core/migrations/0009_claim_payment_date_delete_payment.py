# Generated by Django 5.1.6 on 2025-03-18 03:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0008_alter_claim_staff'),
    ]

    operations = [
        migrations.AddField(
            model_name='claim',
            name='payment_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.DeleteModel(
            name='Payment',
        ),
    ]
