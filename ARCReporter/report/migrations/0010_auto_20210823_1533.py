# Generated by Django 3.2.5 on 2021-08-23 15:33

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('report', '0009_auto_20210823_1532'),
    ]

    operations = [
        migrations.AddField(
            model_name='reportform',
            name='index',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='reportform',
            name='date',
            field=models.CharField(default=datetime.datetime(2021, 8, 23, 15, 33, 55, 345317, tzinfo=utc), max_length=100, unique=True),
        ),
    ]