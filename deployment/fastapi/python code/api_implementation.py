# -*- coding: utf-8 -*-
"""
Created on Sun Apr 21 16:21:09 2024

@author: sayon
"""

import json
import requests

urly = 'http://127.0.0.1:8000/url_prediction'

input_data_for_model = {
    'url' : "https://review-related.com/update"
    }

input_json = json.dumps(input_data_for_model)

response = requests.post(urly, data=input_json)

print(response.text)