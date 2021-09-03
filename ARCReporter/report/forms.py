import os

import redis
import requests
from django.conf import settings
from django.core.files.storage import default_storage
from django.forms import ModelForm
from django import forms
from django.core.validators import validate_email
import json

from report import keys

r = redis.Redis(host='localhost', port=6379, db=0)

headers = {
    'accept': 'application/json',
    'arc-account-code': keys.acc_code,
    'arc-subscription-key': keys.sub_key,
}

domainFile = r.get('domain')
domain = json.load(open(domainFile))

domID = []


# from .models import URL

class URLForm(forms.Form):
    urls = []
    for i in range(len(domain['result'])):
        urls.append((domain['result'][i]['url'], domain['result'][i]['url']))
    url = forms.ChoiceField(choices=urls, widget=forms.Select(attrs={'class': 'form-control'}))


class InputForm(forms.Form):

    scanID = forms.CharField(max_length=5, required=True, widget=forms.TextInput(attrs={'class': 'form-control'}))
    emails = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control'}))
    topUrls = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': 'form-control'}))
    message = forms.CharField(required=False, widget=forms.Textarea(attrs={'class': 'form-control'}))
