# -*- coding: utf-8 -*-
"""
Created on Wed Mar 13 21:31:12 2024

@author: sayon
"""

import numpy as np
import pickle
import re
from tld import get_tld
from urllib.parse import urlparse


loaded_model = pickle.load(open('C:/Users/sayon/Downloads/ML Projects/Malicious URL Detection/Project2/model/trained_model.sav', 'rb'))


def get_url_length(url):
    return len(url)

def get_domain_length(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_length = len(domain)
    return domain_length

import ipaddress

def is_domain_ip(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc  # Extract the domain part from the URL
        ipaddress.ip_address(domain)  # Check if the domain is a valid IP address
        return 1
    except ValueError:
        return 0

def tld_length(tld):
    if tld:
        return len(tld)
    else:
        return -1

def char_continuation_rate(url):
    continuous_count = 0
    total_count = len(url)

    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            continuous_count += 1

    if total_count > 0:
        continuation_rate = continuous_count / total_count
    else:
        continuation_rate = 0.0

    return continuation_rate

def url_character_prob(url):
    char_count = {}
    total_chars = len(url)

    for char in url:
        char_count[char] = char_count.get(char, 0) + 1

    char_prob = {char: count / total_chars for char, count in char_count.items()}

    # Calculate the mean probability
    mean_prob = sum(char_prob.values()) / len(char_prob)

    return mean_prob

def number_of_subdomains(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if domain:
        num_subdomains = domain.count('.')
    else:
        num_subdomains = 0

    return num_subdomains

def has_obfuscation(url):
    # List of common obfuscation patterns to detect
    obfuscation_patterns = [
        '%',                     # Percentage encoding
        '\\x',                   # Hexadecimal encoding
        '&#',                    # HTML entity encoding
        '\\u',                   # Unicode encoding (corrected)
        'javascript:',           # JavaScript code injection
        'data:',                 # Data URL scheme
        'blob:',                 # Blob URL scheme
        'onerror', 'onload',     # Event handlers
        'document.cookie',       # Access to cookies
        'eval(', 'exec(',        # Evaluation functions
        'unescape(',             # Unescaping
        'String.fromCharCode(', # Constructing strings
        'String.fromCodePoint(', # Constructing strings
        'String.raw(',           # Constructing strings
    ]

    # Check if any obfuscation pattern is found in the URL
    for pattern in obfuscation_patterns:
        if pattern in url.lower():
            return 1  # Obfuscation detected

    return 0  # No obfuscation detected

def number_of_obfuscated_chars(url):
    # List of common obfuscation patterns to detect
    obfuscation_patterns = [
        '%',     # Percentage encoding
        '&#',    # HTML entity encoding
        '\\u',   # Unicode encoding
        '\\x',   # Hexadecimal encoding
        '\u202E', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C'  # Directional formatting characters
    ]

    # Initialize the counter for obfuscated characters
    num_obfuscated_chars = 0

    # Check for each obfuscation pattern in the URL
    for pattern in obfuscation_patterns:
        # Count the occurrences of the obfuscation pattern in the URL
        num_obfuscated_chars += url.lower().count(pattern)

    return num_obfuscated_chars

def obfuscation_ratio(url):
    # List of common obfuscation patterns to detect
    obfuscation_patterns = [
        '%',     # Percentage encoding
        '&#',    # HTML entity encoding
        '\\u',   # Unicode encoding
        '\\x',   # Hexadecimal encoding
        '\u202E', '\u200E', '\u200F', '\u202A', '\u202B', '\u202C'  # Directional formatting characters
    ]

    # Count the total number of characters in the URL
    total_chars = len(url)

    # Initialize the counter for obfuscated characters
    num_obfuscated_chars = 0

    # Check for each obfuscation pattern in the URL
    for pattern in obfuscation_patterns:
        # Count the occurrences of the obfuscation pattern in the URL
        num_obfuscated_chars += url.lower().count(pattern)

    # Calculate the obfuscation ratio
    obfuscation_ratio = num_obfuscated_chars / total_chars if total_chars > 0 else 0.0

    return obfuscation_ratio

def number_of_letters_in_url(url):
    letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    num_letters = sum(url.count(letter) for letter in letters)

    return num_letters

def letter_ratio_in_url(url):
    num_letters = number_of_letters_in_url(url)

    total_chars = len(url)

    if total_chars > 0:
        letter_ratio = num_letters / total_chars
    else:
        letter_ratio = 0.0

    return letter_ratio

def number_of_digits_in_url(url):
    digits = '0123456789'

    num_digits = sum(url.count(digit) for digit in digits)

    return num_digits

def digit_ratio_in_url(url):
    num_digits = number_of_digits_in_url(url)

    total_chars = len(url)

    if total_chars > 0:
        digit_ratio = num_digits / total_chars
    else:
        digit_ratio = 0.0

    return digit_ratio

def number_of_ampersand_in_url(url):
    num_ampersand = url.count('&')

    return num_ampersand

def number_of_other_special_chars_in_url(url):
    allowed_chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./:?&=%'

    num_other_special_chars = sum(1 for char in url if char not in allowed_chars)

    return num_other_special_chars

def special_char_ratio_in_url(url):
    num_special_chars = number_of_other_special_chars_in_url(url)

    total_chars = len(url)

    if total_chars > 0:
        special_char_ratio = num_special_chars / total_chars
    else:
        special_char_ratio = 0.0

    return special_char_ratio

def is_https(url):
    # Check if the URL starts with "https://"
    if url.startswith("https://"):
        return 1
    else:
        return 0
    
def calculate_tld_legitimate_prop(url):
    try:
        # Get the Top-Level Domain (TLD) from the URL
        tld = get_tld(url, fail_silently=True)

        # List of commonly recognized TLDs used by legitimate websites
        legitimate_tlds = ['com', 'net', 'org', 'edu', 'gov']

        # Check if the extracted TLD is in the list of legitimate TLDs
        if tld in legitimate_tlds:
            return 1.0  # TLD is considered legitimate
        else:
            return 0.0  # TLD is not considered legitimate
    except:
        return -1  # Error: Unable to extract TLD

import re
#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def count_www(url):
  url.count('www')
  return url.count('www')

def count_atrate(url):
  return url.count('@')

def no_of_dir(url):
  urldir = urlparse(url).path
  return urldir.count('/')

def no_of_embed(url):
  urldir = urlparse(url).path
  return urldir.count('//')

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_dot(url):
  count_dot = url.count('.')
  return count_dot

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

from googlesearch import search

def google_index(url):
  site = search(url, 5)
  return 1 if site else 0

def fd_length(url):
    urlpath= urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def main(url):

    status = []

    status.append(get_url_length(url))
    status.append(get_domain_length(url))
    status.append(is_domain_ip(url))
    tld = get_tld(url,fail_silently=True)
    status.append(tld_length(tld))
    status.append(char_continuation_rate(url))
    status.append(url_character_prob(url))
    status.append(number_of_subdomains(url))
    status.append(has_obfuscation(url))
    status.append(number_of_obfuscated_chars(url))
    status.append(obfuscation_ratio(url))
    status.append(number_of_letters_in_url(url))
    status.append(letter_ratio_in_url(url))
    status.append(number_of_digits_in_url(url))
    status.append(digit_ratio_in_url(url))
    status.append(number_of_ampersand_in_url(url))
    status.append(number_of_other_special_chars_in_url(url))
    status.append(special_char_ratio_in_url(url))
    status.append(is_https(url))
    status.append(calculate_tld_legitimate_prop(url))
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    status.append(count_https(url))
    status.append(count_dot(url))
    status.append(count_http(url))
    status.append(shortening_service(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(google_index(url))
    status.append(fd_length(url))

    return status

# predict function
def get_prediction_from_url(test_url):
    features_test = main(test_url)

    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))

    pred = loaded_model.predict(features_test)

    if int(pred[0]) == 0:
        res="SAFE"
        return res

    elif int(pred[0]) == 1.0:
        res="PHISHING"
        return res

    elif int(pred[0]) == 2.0:
        res="PHISHING"
        return res

    elif int(pred[0]) == 3.0:
        res="PHISHING"
        return res

# predicting sample raw URLs
urls = ['https://titaniumcorporate.co.za','http://digitalsuporte24hrsonline.shop/renner/','https://jeffwealth.com/index/login/login/token/dc737dfb0b882535dff63a086740c6d8.html','https://lmezyera.duckdns.org','https://en.wikipedia.org/wiki/North_Dakota','https://www.google.com/','https://www.upgradabroad.com/','https://www.tcs.com/']

for url in urls:
     print(get_prediction_from_url(url))
  