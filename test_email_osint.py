import requests
import hashlib
from concurrent.futures import ThreadPoolExecutor
import sys

def check_gravatar(email):
    hash_email = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        r = requests.get(f"https://www.gravatar.com/avatar/{hash_email}?d=404", timeout=5)
        return r.status_code == 200
    except:
        return False

def check_github(email):
    try:
        r = requests.get(f"https://api.github.com/search/commits?q=author-email:{email}", headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/vnd.github.cloak-preview'}, timeout=5)
        if r.status_code == 200:
            if r.json().get('total_count', 0) > 0:
                return True
        username = email.split('@')[0]
        r = requests.get(f"https://github.com/{username}", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200
    except:
        return False

def check_twitter(email):
    try:
        r = requests.get("https://api.twitter.com/i/users/email_available.json", params={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        json_body = r.json()
        return json_body.get("taken", False)
    except:
        return False

def check_instagram(username):
    try:
        r = requests.get(f"https://www.instagram.com/{username}/?__a=1&__d=dis", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        if r.status_code == 200:
            return True
        r = requests.get(f"https://www.instagram.com/{username}/", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200 and "Page Not Found" not in r.text
    except:
        return False

def check_google(email):
    try:
        r = requests.get(f"https://www.google.com/search?q=\"{email}\"", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200
    except:
        return False

def check_dropbox(email):
    try:
        r = requests.post('https://www.dropbox.com/ajax/login', data={'email': email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return 'is_registered' in r.text or 'password' in r.text.lower()
    except:
        return False

def check_spotify(email):
    try:
        r = requests.get(f'https://accounts.spotify.com/en/login', headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200
    except:
        return False

def check_tumblr(email):
    try:
        import re
        r = requests.get("https://tumblr.com/register", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        match = re.search(r'"API_TOKEN":"([\s\S]+?)"', r.text)
        if not match:
            return False
        token = match.group(1)
        r = requests.post("https://www.tumblr.com/api/v2/register/account/validate", json={"email": email, "tumblelog": "akc2rW33AuSqQWY8", "password": "correcthorsebatterystaple"}, headers={"authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0"}, timeout=5)
        json_body = r.json()
        if "response" in json_body and "code" in json_body["response"]:
            return json_body["response"]["code"] == 2
        return False
    except:
        return False

def check_reddit(username):
    try:
        r = requests.post("https://www.reddit.com/api/check_username.json", data={"user": username}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        json_body = r.json()
        if "json" in json_body:
            return True
        return False
    except:
        return False

def check_pinterest(email):
    try:
        data = '{"options": {"email": "%s"}, "context": {}}' % email
        r = requests.get("https://www.pinterest.com/_ngjs/resource/EmailExistsResource/get/", params={"source_url": "/", "data": data}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        json_body = r.json()
        return json_body.get("resource_response", {}).get("data", False)
    except:
        return False

def check_lastfm(email):
    try:
        import re
        s = requests.Session()
        r = s.get("https://www.last.fm/join", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        if "csrftoken" not in s.cookies:
            return False
        token = s.cookies["csrftoken"]
        r = s.post("https://www.last.fm/join/partial/validate", data={"csrfmiddlewaretoken": token, "userName": "", "email": email}, headers={"X-Requested-With": "XMLHttpRequest", "Referer": "https://www.last.fm/join", "Cookie": f"csrftoken={token}"}, timeout=5)
        json_body = r.json()
        return not json_body.get("email", {}).get("valid", True)
    except:
        return False

def check_firefox(email):
    try:
        r = requests.post("https://api.accounts.firefox.com/v1/account/status", json={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        json_body = r.json()
        return json_body.get("exists", False)
    except:
        return False


def check_adobe(email):
    try:
        r = requests.post("https://auth.services.adobe.com/signin/v2/users/accounts", json={"username": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200
    except:
        return False

def check_discord(email):
    try:
        r = requests.post("https://discord.com/api/v9/auth/register", json={"email": email, "username": "test", "password": "test123", "consent": True}, headers={'User-Agent': 'Mozilla/5.0', 'Content-Type': 'application/json'}, timeout=5)
        json_body = r.json()
        if "email" in json_body:
            errors = json_body.get("email", [])
            if errors and "already registered" in str(errors).lower():
                return True
        return False
    except:
        return False

def check_patreon(email):
    try:
        r = requests.post("https://www.patreon.com/api/auth/email-verification", json={"data": {"type": "email-verification", "attributes": {"email": email}}}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code != 404
    except:
        return False

def check_yahoo(email):
    try:
        r = requests.get("https://login.yahoo.com/account/create", headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200
    except:
        return False

def check_amazon(email):
    try:
        r = requests.post("https://www.amazon.com/ap/signin", data={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return "password" in r.text.lower()
    except:
        return False

def check_imgur(email):
    try:
        r = requests.post("https://api.imgur.com/account/v1/accounts/", json={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code != 200
    except:
        return False

def check_snapchat(email):
    try:
        r = requests.post("https://accounts.snapchat.com/accounts/get_username_suggestions", json={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return r.status_code == 200
    except:
        return False

def check_docker(email):
    try:
        r = requests.post("https://hub.docker.com/v2/users/", json={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        return "email" in r.text.lower()
    except:
        return False

def lookup_email(email):
    print(f"\n🔍 Searching for: {email}\n")
    username = email.split('@')[0]
    
    with ThreadPoolExecutor(max_workers=21) as executor:
        futures = {
            'Gravatar': executor.submit(check_gravatar, email),
            'Google': executor.submit(check_google, email),
            'GitHub': executor.submit(check_github, email),
            'Twitter': executor.submit(check_twitter, email),
            'Instagram': executor.submit(check_instagram, username),
            'Dropbox': executor.submit(check_dropbox, email),
            'Spotify': executor.submit(check_spotify, email),
            'Tumblr': executor.submit(check_tumblr, email),
            'Reddit': executor.submit(check_reddit, username),
            'Pinterest': executor.submit(check_pinterest, email),
            'Last.fm': executor.submit(check_lastfm, email),
            'Firefox': executor.submit(check_firefox, email),
            'Adobe': executor.submit(check_adobe, email),
            'Discord': executor.submit(check_discord, email),
            'Patreon': executor.submit(check_patreon, email),
            'Yahoo': executor.submit(check_yahoo, email),
            'Amazon': executor.submit(check_amazon, email),
            'Imgur': executor.submit(check_imgur, email),
            'Snapchat': executor.submit(check_snapchat, email),
            'Docker': executor.submit(check_docker, email)
        }
        
        for platform, future in futures.items():
            try:
                found = future.result()
                status = "✓ Found" if found else "✗ Not Found"
                print(f"{platform:12} {status}")
            except:
                print(f"{platform:12} ✗ Error")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = input("Enter email address: ")
    
    lookup_email(email)
