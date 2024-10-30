import os 
#os.system("pip install seaborn")
#os.system("pip install scikit-learn")
#os.system("pip install whois")
#os.system("pip install googlesearch-python")
#os.system("pip install catboost")
#os.system("pip install xgboost")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn import metrics
import warnings
warnings.filterwarnings('ignore')
from sklearn.ensemble import GradientBoostingClassifier

# Load Data
data = pd.read_csv("datafile.csv")
X = data.drop(["class", "Index"], axis=1)
y = data["class"]

# Correlation and feature selection
corr = data.corr()
corr['class'] = abs(corr['class'])
incCorr = corr.sort_values(by='class', ascending=False)
tenfeatures = incCorr[1:11].index
twenfeatures = incCorr[1:21].index

# Structure to store metrics
ML_Model = []
accuracy = []
f1_score = []
precision = []

def storeResults(model, a, b, c):
    ML_Model.append(model)
    accuracy.append(round(a, 3))
    f1_score.append(round(b, 3))
    precision.append(round(c, 3))

# CatBoost Model
def CatBoostClassifierModel(X, y):
    from catboost import CatBoostClassifier
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    catboost = CatBoostClassifier(iterations=100, learning_rate=0.1, depth=6, silent=True)
    catboost.fit(X_train, y_train)
    y_train_cat = catboost.predict(X_train)
    y_test_cat = catboost.predict(X_test)
    
    acc_train_cat = metrics.accuracy_score(y_train, y_train_cat)
    acc_test_cat = metrics.accuracy_score(y_test, y_test_cat)
    f1_score_test_cat = metrics.f1_score(y_test, y_test_cat)
    precision_score_test_cat = metrics.precision_score(y_test, y_test_cat)
    
    print("CatBoost Classifier: Accuracy on training Data: {:.3f}".format(acc_train_cat))
    print("CatBoost Classifier: Accuracy on test Data: {:.3f}".format(acc_test_cat))
    
    storeResults('CatBoost Classifier', acc_test_cat, f1_score_test_cat, precision_score_test_cat)
   
# XGBoost Model
def XGBoostClassifierModel(X, y):
    from xgboost import XGBClassifier
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    xgb = XGBClassifier(max_depth=6, learning_rate=0.1, n_estimators=100, use_label_encoder=False, eval_metric='logloss')
    xgb.fit(X_train, y_train)
    y_train_xgb = xgb.predict(X_train)
    y_test_xgb = xgb.predict(X_test)
    
    acc_train_xgb = metrics.accuracy_score(y_train, y_train_xgb)
    acc_test_xgb = metrics.accuracy_score(y_test, y_test_xgb)
    f1_score_test_xgb = metrics.f1_score(y_test, y_test_xgb)
    precision_score_test_xgb = metrics.precision_score(y_test, y_test_xgb)
    
    print("XGBoost Classifier: Accuracy on training Data: {:.3f}".format(acc_train_xgb))
    print("XGBoost Classifier: Accuracy on test Data: {:.3f}".format(acc_test_xgb))
    
    storeResults('XGBoost Classifier', acc_test_xgb, f1_score_test_xgb, precision_score_test_xgb)

# Run models with different feature sets
Xmain = X
Xten = X[tenfeatures]
Xtwen = X[twenfeatures]
y = y.replace(-1, 0)
# Run CatBoost and XGBoost
CatBoostClassifierModel(Xmain, y)
CatBoostClassifierModel(Xten, y)
CatBoostClassifierModel(Xtwen, y)
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
XGBoostClassifierModel(Xmain, y)
XGBoostClassifierModel(Xten, y)
XGBoostClassifierModel(Xtwen, y)

# Results DataFrame
df = pd.DataFrame({
    'Modelname': ML_Model,
    'Accuracy Score': accuracy,
    'F1 Score': f1_score,
    'Precision Score': precision
})
df.set_index('Modelname', inplace=True)

# Plot the scores for each model
fig, ax = plt.subplots(figsize=(10,10))
df.plot(kind='bar', ax=ax)
ax.set_xticklabels(df.index, rotation=0)
ax.set_ylim([0.9, 1])
ax.set_yticks([0.9, 0.91, 0.92, 0.93, 0.94, 0.95, 0.96, 0.97, 0.98, 0.99, 1])
ax.set_xlabel('Model')
ax.set_ylabel('Score')
ax.set_title('Model Scores')

import whois

import googlesearch

import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
import google
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())


     # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1 
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
    
    # 13. RequestURL
    def RequestURL(self):
        try:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1
     # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i,success = 0,0
        
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                return -1
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except:
            return -1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1:
                return 1
            elif len(self.response.history) <= 4:
                return 0
            else:
                return -1
        except:
             return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 23. IframeRedirection
    def IframeRedirection(self):
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording    
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                return 1
            return 0
        except :
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})

            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1
            return -1
        except:
            return -1
            

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:
                return -1
            elif ip_match:
                return -1
            return 1
        except:
            return 1
        


    def load_page(self):
        try:
            response = requests.get(self.url)
            self.soup = BeautifulSoup(response.text, 'html.parser')
        except requests.exceptions.RequestException:
            self.soup = None

    # Check if SSL certificate is valid and get its validity period
    def ssl_certificate_validity(self):
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=self.domain)
            conn.settimeout(3.0)
            conn.connect((self.domain, 443))
            cert = conn.getpeercert()
            not_after = cert.get('notAfter')
            if not_after:
                expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                return (expiry_date - datetime.now()).days
            return -1  # Invalid or no certificate found
        except Exception:
            return -1

    # Check domain name similarity to common brand names
    def domain_name_similarity(self, known_domains):
        min_distance = min(levenshtein_distance(self.domain, known_domain) for known_domain in known_domains)
        return min_distance

    # Check for homograph attacks
    def is_homograph_attack(self):
        return any(re.search(r'[а-яА-ЯёЁ]', self.domain))  # Cyrillic characters are common in homograph attacks

    # Check for a login form
    def has_login_form(self):
        if self.soup:
            form_tags = self.soup.find_all('form')
            for form in form_tags:
                if form.find('input', {'type': 'password'}):
                    return True
        return False

    # Check for misleading file extensions in the URL
    def has_misleading_file_extension(self):
        misleading_extensions = ['.exe', '.scr', '.zip', '.doc']
        return any(self.url.endswith(ext) for ext in misleading_extensions)

    # Detect presence of hidden/invisible links
    def has_invisible_links(self):
        if self.soup:
            links = self.soup.find_all('a', style=True)
            return any('display:none' in link['style'] or 'opacity:0' in link['style'] for link in links)
        return False

    # Check for fake social media links
    def has_fake_social_media_links(self):
        if self.soup:
            social_media_sites = ['facebook.com', 'twitter.com', 'instagram.com']
            social_links = self.soup.find_all('a', href=True)
            return any(link['href'] == '#' or link['href'].startswith("javascript") for link in social_links if any(site in link['href'] for site in social_media_sites))
        return False

    # Check for urgent language in the page content
    def has_urgent_keywords(self):
        urgent_keywords = ["urgent", "immediate action", "verify your account"]
        return any(keyword in self.soup.get_text().lower() for keyword in urgent_keywords)

    # Check for mixed content (HTTP and HTTPS on the same page)
    def has_mixed_content(self):
        if self.soup:
            return any('http:' in script['src'] for script in self.soup.find_all('script', src=True))
        return False

    # Check if content has legitimate contact information
    def has_contact_info(self):
        if self.soup:
            contact_patterns = [r'\(\d{3}\) \d{3}-\d{4}', r'\d{10}', r'\d{5}-\d{5}', r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}']
            text_content = self.soup.get_text()
            return any(re.search(pattern, text_content) for pattern in contact_patterns)
        return False

    def extract_features(self):
        features = {
            'ssl_certificate_validity_days': self.ssl_certificate_validity(),
            'domain_name_similarity': self.domain_name_similarity(['paypal.com', 'google.com', 'facebook.com']),  # example list
            'is_homograph_attack': self.is_homograph_attack(),
            'has_login_form': self.has_login_form(),
            'has_misleading_file_extension': self.has_misleading_file_extension(),
            'has_invisible_links': self.has_invisible_links(),
            'has_fake_social_media_links': self.has_fake_social_media_links(),
            'has_urgent_keywords': self.has_urgent_keywords(),
            'has_mixed_content': self.has_mixed_content(),
            'has_contact_info': self.has_contact_info(),
        }
        return features


    def getFeaturesList(self):
        return self.features
gbc = GradientBoostingClassifier(max_depth=4,learning_rate=0.7)
gbc.fit(X_train,y_train)  
 
