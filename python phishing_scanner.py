import re
import tldextract

# Define a list of suspicious keywords
suspicious_keywords = [
    'login', 'verify', 'account', 'update', 'secure', 'bank', 
    'paypal', 'support', 'service', 'help', 'contact'
]

# Function to check if a URL contains suspicious keywords
def check_keywords(url):
    pattern = r'\b(?:' + '|'.join(suspicious_keywords) + r')\b'
    return bool(re.search(pattern, url, flags=re.IGNORECASE))

# Function to check for Unicode domain names (homoglyph detection)
def check_unicode_domain(url):
    domain = tldextract.extract(url).domain
    if domain.encode('idna').decode('utf-8') != domain:
        return True
    return False

# Function to check if URL uses an IP address
def check_ip_address(url):
    return bool(re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', url))

# Function to check if URL uses multiple subdomains
def check_subdomains(url):
    subdomain = tldextract.extract(url).subdomain
    return len(subdomain.split('.')) > 2

# Function to check if URL length is unusually long
def check_length(url):
    return len(url) > 75

# Function to check if URL uses a URL shortener
def check_url_shortener(url):
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
    return any(shortener in url for shortener in shorteners)

# Function to perform the URL scan
def scan_url(url):
    print(f"Scanning URL: {url}")
    
    if check_keywords(url):
        print(f"URL contains suspicious keywords: {url}")
    if check_length(url):
        print(f"URL is unusually long: {url}")
    if check_subdomains(url):
        print(f"URL contains multiple subdomains: {url}")
    if check_ip_address(url):
        print(f"URL contains an IP address: {url}")
    if check_url_shortener(url):
        print(f"URL uses a URL shortener: {url}")
    if check_unicode_domain(url):
        print(f"URL uses Unicode domain name (homoglyphs detected): {url}")

# Example usage
urls = [
    "https://eugeniewun72-englichs302.pages.dev/help/contact/810027296138871",
    "https://kainumchoke.online.72642742-80-20210801195947.webstarterz.com/",
    "https://cstvc.com/",
    "https://ljabsd.webwave.dev/",
    "https://imtoken-w.com/",
    "https://chats.ourtiime-cdn.workers.dev/",
    "https://franziskatelagram.pages.dev/",
    "https://kingsafetynet.club/",
    "https://att-inc-100974.weeblysite.com/",
    "https://maile-temp2.aolquery.workers.dev/",
    "https://worldacrosscountries.chancellor-wfsch.workers.dev/common/reprocess?ctx=rQQIARAAhZI_jNt0HMXj5C73R5SeCoIycUgIIQ4n_p_4RAf7ktSO45_P_-LYS-T4v8-OU8eOe5EY2DqhTiA6IdhuQkwnxAAT6KYOqEPFCogOCHXqUAkCzBXL03t6b_p-P_s7nRbeQlvIew2shRy_TXQokiDIGYxjDgUT9AyBu7hHwahL45sK61COnd_YP3jz2w9-Mp__JnxJvv75vctrP19Ah2FRLJbH7XZVVa3M9yPHazlZ2k7suRvNgxV2CUEPIehBfdubw7p6UV9SeJegKYpCaJREUJLskC0rTkKQ9s-tVC7EeBiLJwhiGX10pIVnAOMLEDtrcc2moqbjktavLEMmxTVDmOugsGKdACqCSD0lHhnD2NTkwjL0NcD6mGiYm42IPK5fl5iyCLF_JMujtfe0vudneTpdZMviQeOT-hD4mOZWinpuKAXFSTLL2ag2ZijZH1JZPytRIaSswncIT8n8cSgNuEC6iyTn87HcZS1akchekvOwtLi7PPecRIUlCwWDnj5gZDbKh3RPTQDiSpE9Mu4MyWIOjBxMwi7LTgZxII5KNMC12-OJl9KIijImgwq0a2i5SIlmUhUpA6zgjFAE0ryzpKejE9gM-s54LOlZFQ1MvZcURSxgzGmHdxQJ5sypERQxy7KkWs2FpPJsXBZOS12YEUDn13ABPEQYYFWwknkE5bvDpORPc1WlVywPTIDiLIEpYnDReOMF711hXzeaG5Nm86tGJ1t488g9XOSZHyXei5BYYW3p38RlqddikuThFvRk67XdnYPGTeiw9u6rSON4d7d5AN2sHdaebUFfbG-IU_769YfFo0vuY_LDR--89RF0td2unNvVwJY3NwxPFzPZLfEJEQ0nUdY_WhGCShx5QeFKKRdZ_C30GL3fhO43m1fNPb43BX2NmiJ_NqF7O7Vv9v6X3ccvvbK_X0bTJHPsxFve-I_h767Vnr38-y-ffv_jxWd_cE-uv-8HeujaS28565ysTDdDRSPFIsBR8RleyhZXztAjuxd4IGBufXVQ-xs1",
    "https://ipfs.io/ipfs/bafybeigtl7uvyvlakvuqrsxgifunpaxuhszohwd4qhcktrkereoyxkdjmq/",
    "https://telstra-100337.weeblysite.com/",
    "https://att-108876-101857.weeblysite.com/",
    "https://btinternet-102638.weeblysite.com/",
    "https://juno-message-center-108114.weeblysite.com/",
    "https://steam.vtl.wang/",
    "https://leightonpetroleum.com/",
    "http://offonedrivevoicemailwithsharepoint.weebly.com/",
    "https://accounts.synchronizing.googlemail.www2.vectorstrategies.com/",
    "https://rawkstars.com/",
    "http://bdaxthcycy.duckdns.org/en/main",
    "https://savepalestine0rg.blogspot.com/?m=1",
    "https://xc-dna-idx-xco.resmi-v1.my.id/",
    "https://cs46671.tw1.ru/",
    "http://wws.fd43sa.dns-dynamic.net/",
    "https://6activasucursal.temporary-demo.xyz/",
    "https://maliyeburomuz.com/sorgu.php/",
    "http://www.foundersintlacademy.com/wp-includes/amueb/olid/",
    "https://oriondraco.com/itaa/"
]

for url in urls:
    scan_url(url)
