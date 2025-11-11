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



def check_firefox(email):
    try:
        r = requests.post("https://api.accounts.firefox.com/v1/account/status", json={"email": email}, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        json_body = r.json()
        return json_body.get("exists", False)
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

            'Firefox': executor.submit(check_firefox, email),

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
