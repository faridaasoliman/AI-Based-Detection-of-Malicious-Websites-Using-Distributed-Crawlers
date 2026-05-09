from urllib.parse import urlparse
import re

def extract_features(url):
    parsed = urlparse(url)
    
    features = {
        'url_length': len(url),
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_at': url.count('@'),
        'num_digits': sum(c.isdigit() for c in url),
        'path_depth': len([x for x in parsed.path.split('/') if x]),
        'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
        'suspicious_keywords': 1 if any(w in url.lower() for w in 
            ['login', 'secure', 'verify', 'account', 'update', 'banking', 'paypal']) else 0,
        'url_entropy': len(set(url)) / len(url) if url else 0
    }
    return features
