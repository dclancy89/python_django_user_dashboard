# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2018-03-09 16:00
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0003_auto_20180309_1552'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='description',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to='dashboard.Description'),
        ),
    ]
