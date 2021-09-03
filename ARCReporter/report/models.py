from django.forms import ModelForm
from django.db import models
from django import forms
from django.utils import timezone
from django.core.validators import validate_email
import json

domainFile = open('report/jsons/domain.json')
domain = json.load(domainFile)

dateFile = open('report/jsons/scanHistory.json')
dateData = json.load(dateFile)


# from .models import URL

class ReportForm(models.Model):
    hashKey = models.CharField(max_length=100000, null=True)
    url = models.CharField(max_length=100, null=True)

    scanID = models.CharField(max_length=100, unique=True, null=True)
    emails = models.CharField(max_length=100, null=True)
    topUrls = models.CharField(max_length=100, null=True)
    message = models.CharField(max_length=100, null=True)

    def __str__(self):

        return self.hashKey
