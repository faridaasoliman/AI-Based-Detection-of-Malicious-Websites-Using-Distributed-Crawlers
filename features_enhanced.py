"""
features_enhanced.py
====================
Advanced feature extraction from URLs and HTML content.
Includes URL features, HTML-based features, and NLP analysis.
"""

from urllib.parse import urlparse
import re
from collections import Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def extract_url_features(url):
    """Extract features directly from URL structure."""
    try:
        parsed = urlparse(url)
        
        features = {
            'url_length': len(url),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_at': url.count('@'),
            'num_digits': sum(c.isdigit() for c in url),
            'num_slashes': url.count('/'),
            'path_depth': len([x for x in parsed.path.split('/') if x]),
            'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
            'suspicious_keywords': 1 if any(w in url.lower() for w in 
                ['login', 'secure', 'verify', 'account', 'update', 'banking', 
                 'paypal', 'click', 'free', 'confirm', 'alert']) else 0,
            'url_entropy': len(set(url)) / len(url) if url else 0,
            'domain_length': len(parsed.netloc),
            'subdomain_count': parsed.netloc.count('.'),
            'query_string_length': len(parsed.query),
            'fragment_length': len(parsed.fragment),
        }
        return features
    except Exception as e:
        logger.error(f"Error extracting URL features from {url}: {e}")
        return {key: 0 for key in range(14)}


def extract_html_features(html_content):
    """
    Extract features from HTML content.
    Analyzes page structure, form elements, and suspicious patterns.
    """
    features = {
        'html_length': len(html_content) if html_content else 0,
        'num_forms': html_content.count('<form') if html_content else 0,
        'num_inputs': html_content.count('<input') if html_content else 0,
        'num_links': html_content.count('<a ') if html_content else 0,
        'num_images': html_content.count('<img') if html_content else 0,
        'num_scripts': html_content.count('<script') if html_content else 0,
        'has_external_js': 1 if html_content and 'src=' in html_content and '<script' in html_content else 0,
        'num_iframes': html_content.count('<iframe') if html_content else 0,
        'has_embedded_objects': 1 if html_content and ('<embed' in html_content or '<object' in html_content) else 0,
    }
    return features


def extract_nlp_features(text_content):
    """
    Extract NLP-based features from page text content.
    Analyzes keywords, suspicious patterns, and text statistics.
    """
    if not text_content:
        text_content = ""
    
    text_lower = text_content.lower()
    
    # Suspicious keywords commonly found in phishing pages
    phishing_keywords = [
        'verify', 'confirm', 'update', 'suspended', 'urgent', 'action required',
        'click here', 'login', 'password', 'account', 'credit card', 'security',
        'refund', 'claim', 'reward', 'congratulations', 'winner', 'alert'
    ]
    
    # Count suspicious keyword occurrences
    suspicious_count = sum(text_lower.count(keyword) for keyword in phishing_keywords)
    
    # Calculate text statistics
    words = text_content.split()
    word_count = len(words)
    avg_word_length = sum(len(w) for w in words) / len(words) if words else 0
    
    # Detect urgency indicators
    urgency_keywords = ['urgent', 'immediate', 'action required', 'verify now', 'confirm now']
    has_urgency = 1 if any(kw in text_lower for kw in urgency_keywords) else 0
    
    features = {
        'text_length': len(text_content),
        'suspicious_keyword_count': suspicious_count,
        'word_count': word_count,
        'avg_word_length': avg_word_length,
        'has_urgency_language': has_urgency,
        'capital_letter_ratio': sum(1 for c in text_content if c.isupper()) / len(text_content) if text_content else 0,
        'digit_ratio': sum(1 for c in text_content if c.isdigit()) / len(text_content) if text_content else 0,
    }
    
    return features


def extract_all_features(url, html_content=None, text_content=None):
    """
    Extract all types of features from URL, HTML, and text.
    Returns a combined feature dictionary.
    """
    all_features = {}
    
    # URL features
    url_feats = extract_url_features(url)
    all_features.update(url_feats)
    
    # HTML features
    if html_content:
        html_feats = extract_html_features(html_content)
        all_features.update(html_feats)
    else:
        # Default zeros if no HTML
        html_feats = {
            'html_length': 0, 'num_forms': 0, 'num_inputs': 0, 'num_links': 0,
            'num_images': 0, 'num_scripts': 0, 'has_external_js': 0,
            'num_iframes': 0, 'has_embedded_objects': 0
        }
        all_features.update(html_feats)
    
    # NLP features
    if text_content:
        nlp_feats = extract_nlp_features(text_content)
        all_features.update(nlp_feats)
    else:
        # Default zeros if no text
        nlp_feats = {
            'text_length': 0, 'suspicious_keyword_count': 0, 'word_count': 0,
            'avg_word_length': 0, 'has_urgency_language': 0,
            'capital_letter_ratio': 0, 'digit_ratio': 0
        }
        all_features.update(nlp_feats)
    
    return all_features


def get_feature_names():
    """Return the list of all feature names in order."""
    return [
        'url_length', 'has_https', 'num_dots', 'num_hyphens', 'num_at',
        'num_digits', 'num_slashes', 'path_depth', 'has_ip',
        'suspicious_keywords', 'url_entropy', 'domain_length',
        'subdomain_count', 'query_string_length', 'fragment_length',
        'html_length', 'num_forms', 'num_inputs', 'num_links',
        'num_images', 'num_scripts', 'has_external_js',
        'num_iframes', 'has_embedded_objects',
        'text_length', 'suspicious_keyword_count', 'word_count',
        'avg_word_length', 'has_urgency_language', 'capital_letter_ratio',
        'digit_ratio'
    ]
