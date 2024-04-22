# -*- coding: utf-8 -*-
"""
Created on Sun Apr 21 16:21:09 2024

@author: sayon
"""

import json
import requests

urly = 'https://33bd-34-72-106-210.ngrok-free.app/url_prediction'

input_data_for_model = {
    #'url' : "https://review-related.com/update"
    'url' : "https://www.tcs.com/"
    }

input_json = json.dumps(input_data_for_model)

response = requests.post(urly, data=input_json)

print(response.text)