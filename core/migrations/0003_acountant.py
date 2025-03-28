# Generated by Django 5.1.7 on 2025-03-15 22:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_alter_claim_staff_alter_staff_employee'),
    ]

    operations = [
        migrations.CreateModel(
            name='Acountant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('accountant_firstname', models.CharField(blank=True, max_length=255, null=True)),
                ('accountant_lastname', models.CharField(blank=True, max_length=255, null=True)),
                ('accountant_email', models.EmailField(blank=True, max_length=254, null=True, unique=True)),
                ('accountant_phonenumber', models.BigIntegerField(blank=True, null=True)),
                ('accountant_password', models.CharField(blank=True, max_length=255, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
            ],
        ),
    ]
