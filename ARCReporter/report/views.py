import json
import os
import re
from operator import itemgetter
from urllib.parse import urlencode
import requests

import redis
from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.shortcuts import render, redirect
from django.urls import reverse

from report import keys
from report.models import ReportForm
from .forms import InputForm, URLForm

from django.core.files.storage import default_storage

import hashlib

r = redis.Redis(host='localhost', port=6379, db=0)

headers = {
    'accept': 'application/json',
    'arc-account-code': keys.acc_code,
    'arc-subscription-key': keys.sub_key,
}


# Create your views here.

def input(request):
    # Gets the information in from the form selecting a scan
    if request.method == "POST":
        form = URLForm(request.POST)
        if form.is_valid():
            query_string = urlencode({'url': form.data.get('url')})
            url = '{}?{}'.format('details', query_string)

            return redirect(url)
    else:
        form = URLForm()
    return render(request, 'report/input.html',
                  {'form': form})


def dashboard(request):
    # Pulls the report entries from the database
    all_entries = ReportForm.objects.all()
    entries = []
    dict = {}
    for i in all_entries:
        entries.append(i)

    for e in range(len(entries)):
        dict[e] = entries[e]

    return render(request, 'report/dash.html', {'dict': dict})


def resetCache(request):
    r.delete('domain')
    domainFiles = requests.get('https://api.tpgarc.com/v1/Domains', headers=headers)
    r.set('domain', domainFiles)

    return redirect('/')


def GetDetails(request):
    # Gets the information in from the form selecting a scan
    if request.method == "POST":
        form = InputForm(request.POST)
        # Ensures the entered form is valid, separates the email string so it can be processed
        if form.is_valid():
            emails = form.data.get('emails').split(' ')
            for i in emails:
                try:
                    validate_email(i)
                except ValidationError:
                    messages.error(request, 'Please enter valid emails, separated by spaces.')
                    messages.error(request, form.errors)
                    query_string = urlencode({'url': request.GET.get('url')})
                    url = '{}?{}'.format('details', query_string)
                    return redirect(url)

            # Outline for an email service implementation

            # message_subj = (request.GET.get('url'), form.data.get('date'))
            # message = form.data.get('message')

            #
            # send_mail(
            #     message_subj,
            #     message,
            #     'nfbrown@protonmail.com',
            #     emails,
            # )

            # Hashing to uniquely save reports
            dataTuple = (str(request.GET.get('url')), "_", str(form.data.get('date')))
            myString = ''.join(dataTuple)
            hash_object = hashlib.md5(myString.encode())

            form = ReportForm(hashKey=hash_object.hexdigest(), url=request.GET.get('url'),
                              scanID=form.data.get('scanID'),
                              emails=form.data.get('emails'), topUrls=form.data.get('topUrls'),
                              message=form.data.get('message'))
            form.save()
            base_url = reverse('report')
            linkString = urlencode({'hash': form.hashKey})
            hashedUrl = '{}?{}'.format(base_url, linkString)

            return redirect(hashedUrl)
    else:
        form = InputForm()

    return render(request, 'report/input.html',
                  {'form': form})


def report(request):
    # Getting keys from keys file and making them accessible for API Calls
    # pulls what data possible from the database
    pulledReport = ReportForm.objects.get(hashKey=request.GET.get('hash'))

    data = {
        'url': pulledReport.url,
        'siteName': re.split(r'[.,/]\s*', pulledReport.url)[2].upper(),
        'date': None,
        'topUrls': pulledReport.topUrls,
        'domID': None,
        'scanID': pulledReport.scanID,
        'totalAssertions': None,
        'totalCheckpointFails': None,
        'totalContrastCount': None,
        'totalPages': 1,
        'densityScore': None,
        'densityRating': None,
        'priorityUrls': [],
        'subtotals': [],
        'wcag': {},
        'assertions': {},
        'failingPages': [],
    }
    topAssertions = 3
    topPages = 3

    # domainFiles = r.get('domain')
    #
    # if domainFiles is None:
    #
    #     r.set('domain', domainFiles)

    domainFiles = requests.get('https://api.tpgarc.com/v1/Domains', headers=headers)

    # Set DomID
    for i in domainFiles.json()['result']:
        if i['url'] == data.get('url'):
            data.update(domID=i['id'])
            scanKey = f"{data.get('domID')}_ScanHist"

    # scanHist = r.get(scanKey)
    # if scanHist is None:
    #     print("scanHist not in redis")
    #
    #     r.set(scanKey, scanHist)
    scanHist = requests.get('https://api.tpgarc.com/v1/Domains/{a}/ARC/History'.format(a=data.get('domID')),
                            headers=headers)

    # Ensures the date entered in the form matches the information returned from the API sets it to
    # the most recent scan otherwise
    for l in scanHist.json()['result']['history']:
        if data.get('domID') == l['id']:
            data.update(date=l['scanDate'])
            print(data.get('date'))
            # Adds the relevant data to the 'data' dictionary
            data.update(scanID=l['scanlogId'], totalAssertions=l['assertionCount'],
                        totalCheckpointFails=l['checkpointFailures'], totalContrastCount=l['contrast'])
            break

        if data.get('totalAssertions') is None:
            data.update(scanID=scanHist.json()['result']['history'][0]['scanlogId'],
                        date=scanHist.json()['result']['history'][0]['scanDate'],
                        totalAssertions=scanHist.json()['result']['history'][0]['assertionCount'],
                        totalCheckpointFails=scanHist.json()['result']['history'][0]['checkpointFailures'],
                        totalContrastCount=scanHist.json()['result']['history'][0]['contrast'])

        data.update(densityScore=(data.get('totalCheckpointFails') / data.get('totalPages')))

        if data.get('densityScore') < 5:
            data.update(densityRating='Good')

        elif data.get('densityScore') < 15:
            data.update(densityRating='Bad')

        if data.get('densityScore') > 15:
            data.update(densityRating='Terrible')

        # Finding top 3 failing pages

    # assets = r.get(f"{data.get('domID')}_{data.get('scanID')}_Assets")
    # if assets is None:
    #     print("Assets not in redis")
    #     ,
    #                           headers=headers)
    #     r.set(f"{data.get('domID')}_{data.get('scanID')}_Assets", assets)

    # Pulls the sub pages of a domain, saves the data for the urls entered in the form
    assets = requests.get('https://api.tpgarc.com/v1/Domains/{a}/Assets'.format(a=data.get('domID')),
                          headers=headers)

    topUrls = data.get('topUrls').split(' ')
    if len(topUrls) < topPages:
        topPages = len(topUrls)
    for x in range(topPages):

        for l in assets.json()['result']:
            if topUrls[x] == l['url']:
                failData = requests.get('https://api.tpgarc.com/v1/Assets/{a}/ARC/History/{b}'.format(a=l['id'],
                                                                                                      b=data.get(
                                                                                                          'scanID')),
                                        headers=headers)

                if failData.json()['result'] is not None:
                    data['failingPages'].append((l['url'], failData.json()['result']['assertionCount'],
                                                 failData.json()['result']['contrast']))

    pageCount = 0
    for f in assets.json()['result']:
        if f['lastScanLogId'] == data.get('scanID'):
            pageCount = pageCount + 1

    data.update(totalPages=pageCount)
    data.update(failingPages=(sorted(data.get('failingPages'), key=itemgetter(1), reverse=True)))

    # seeds = r.get(f"{data.get('domID')}_{data.get('scanID')}_Seeds")
    # if seeds is None:
    #     print("seeds not in redis")
    #
    #     r.set(f"{data.get('domID')}_{data.get('scanID')}_Seeds", seeds)
    seeds = requests.get('https://api.tpgarc.com/v1/Domains/{a}/Seeds'.format(a=data.get('domID')), headers=headers)

    # Finds specific information for the domains seed urls
    for seed in seeds.json()['result']:
        for foo in assets.json()['result']:
            if foo['url'] == seed['url']:
                seedScan = requests.get('https://api.tpgarc.com/v1/Assets/{a}/ARC/History/{b}'.format(a=foo['id'],
                                                                                                      b=data.get(
                                                                                                          'scanID')),
                                        headers=headers)
                seedScanJson = seedScan.json()
                data['priorityUrls'].append((seed['url'], seedScanJson['result']['assertionCount'],
                                             seedScanJson['result']['contrast']))

    # subtotalsFile = r.get(f"{data.get('domID')}_{data.get('scanID')}_subtotals")
    # if subtotalsFile is None:
    #     print("subtotals not in redis")
    #
    #     r.set(f"{data.get('domID')}_{data.get('scanID')}_subtotals", subtotalsFile)

    subtotalsFile = requests.get('https://api.tpgarc.com/v1/Domains/{a}/ARC/History/{b}/AssertionSubtotals'.format
                                 (a=data.get('domID'), b=data.get('scanID')), headers=headers)
    subtotals = subtotalsFile.json()

    assertions = requests.get('https://api.tpgarc.com/v1/Engine/AXE/Assertions', headers=headers)

    for y in assertions.json()['result']:
        data['wcag'][y['checkpoint'][0][13:]] = 0

    if subtotals['result']['id'] == data.get('domID') and \
            subtotals['result']['scanlogId'] == data.get('scanID'):
        for x in subtotals['result']['assertionSubtotals']:
            for y in assertions.json()['result']:
                if x['id'] == y['id']:
                    data['wcag'][y['checkpoint'][0][13:]] = data['wcag'][y['checkpoint'][0][13:]] + x['count']

        data.update(wcag=(sorted(data.get('wcag').items(), key=lambda item: item[1], reverse=True)))

    if subtotals['result']['id'] == data.get('domID') and \
            subtotals['result']['scanlogId'] == data.get('scanID'):
        for x in range(topAssertions):
            for y in assertions.json()['result']:
                if subtotals['result']['assertionSubtotals'][x]['id'] == y['id']:
                    data['assertions'][y['title']] = subtotals['result']['assertionSubtotals'][x]['count']
                    formed = re.sub('(.{1,75})(\\s|$)', '\\1\n', y['description'])
                    data['subtotals'].append((y['title'],
                                              y['checkpoint'],
                                              subtotals['result']['assertionSubtotals'][x]['count'],
                                              formed))

        data.update(assertions=(sorted(data.get('assertions').items(), key=lambda item: item[1], reverse=True)))

    #                 assertionData = requests.get('https://api.tpgarc.com/v1/Domains/{a}/ARC/History/{b}/{c}/PageTotals'.
    #                                              format(a=data.get('domID'), b=data.get('scanID'), c=y['assertionKey'],
    #                                                     headers=headers))
    #
    #                 data['subtotals'].append((x['id'], x['assertionKey'], x['count'], x['pageCount'],
    #                                           assertionData.json()['result']['title'],
    #                                           assertionData.json()['result']['checkpoint'],
    #                                           assertionData.json()['result']['description']))

    return render(request, 'report/display.html',
                  data)
