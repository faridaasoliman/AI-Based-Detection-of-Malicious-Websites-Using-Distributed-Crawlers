"""
predict_enhanced.py
===================
Enhanced prediction script that crawls URLs and analyzes them.
Provides detailed risk assessment for each URL.
"""

import pickle
import json
import logging
import pandas as pd
from features_enhanced import extract_all_features
from crawler import WebCrawler
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Whitelist of known safe domains
SAFE_DOMAINS_WHITELIST = {
    'google.com', 'www.google.com', 'github.com', 'www.github.com',
    'wikipedia.org', 'www.wikipedia.org', 'stackoverflow.com', 'www.stackoverflow.com',
    'python.org', 'www.python.org', 'amazon.com', 'www.amazon.com',
    'docs.python.org', 'reddit.com', 'www.reddit.com', 'linkedin.com', 'www.linkedin.com',
    'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
    'facebook.com', 'www.facebook.com', 'twitter.com', 'www.twitter.com',
    'youtube.com', 'www.youtube.com', 'instagram.com', 'www.instagram.com',
    'wordpress.com', 'www.wordpress.com', 'medium.com', 'www.medium.com',
    'quora.com', 'www.quora.com', 'coursera.org', 'www.coursera.org',
    'edx.org', 'www.edx.org', 'udemy.com', 'www.udemy.com'
}

class MaliciousURLDetector:
    """
    Main detector class for classifying URLs as safe or malicious.
    Supports both URL-only and full crawling analysis.
    """
    
    def __init__(self, model_path='url_model_enhanced.pkl'):
        """Load the trained model."""
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            logger.info(f"Model loaded from {model_path}")
        except FileNotFoundError:
            logger.error(f"Model file not found: {model_path}")
            raise
        
        # Try to load feature names
        try:
            with open('feature_names.json', 'r') as f:
                self.feature_names = json.load(f)
        except FileNotFoundError:
            logger.warning("feature_names.json not found, using defaults")
            self.feature_names = None
        
        self.crawler = WebCrawler(timeout=5)
    
    def predict_url(self, url: str, crawl=False) -> dict:
        """
        Predict if a URL is malicious.
        
        Args:
            url: URL to classify
            crawl: If True, fetch and analyze page content
            
        Returns:
            Dictionary with prediction results and details
        """
        logger.info(f"Analyzing URL: {url}")
        
        # Check whitelist first
        domain = urlparse(url).netloc.lower()
        if domain in SAFE_DOMAINS_WHITELIST:
            logger.info(f"  URL matched whitelist - classified as SAFE")
            return {
                'url': url,
                'prediction': 0,
                'label': 'SAFE',
                'confidence': 100.0,
                'risk_level': 'LOW',
                'whitelisted': True,
                'crawled': False,
                'features': {}
            }
        
        html_content = None
        text_content = None
        crawl_success = False
        
        # Optionally crawl the URL
        if crawl:
            logger.info(f"  Fetching page content...")
            html_content, text_content, crawl_success = self.crawler.fetch_url(url)
            if crawl_success:
                logger.info(f"  Page fetched successfully ({len(html_content)} bytes)")
            else:
                logger.warning(f"  Could not fetch page, using URL features only")
        
        # Extract features
        try:
            features_dict = extract_all_features(url, html_content, text_content)
            features_df = pd.DataFrame([features_dict])
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {
                'url': url,
                'error': str(e),
                'prediction': None,
                'confidence': None
            }
        
        # Make prediction
        try:
            prediction = self.model.predict(features_df)[0]
            confidence = self.model.predict_proba(features_df)[0][prediction] * 100
            
            label = "MALICIOUS" if prediction == 1 else "SAFE"
            risk_level = self._get_risk_level(confidence, prediction)
            
            result = {
                'url': url,
                'prediction': prediction,
                'label': label,
                'confidence': round(float(confidence), 2),
                'risk_level': risk_level,
                'crawled': crawl_success,
                'features': features_dict
            }
            
            return result
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            return {
                'url': url,
                'error': str(e),
                'prediction': None,
                'confidence': None
            }
    
    def _get_risk_level(self, confidence: float, prediction: int) -> str:
        """Determine risk level based on confidence."""
        if prediction == 0:  # Safe
            return "LOW"
        else:  # Malicious
            if confidence >= 95:
                return "CRITICAL"
            elif confidence >= 85:
                return "HIGH"
            elif confidence >= 75:
                return "MEDIUM"
            else:
                return "MEDIUM-LOW"
    
    def predict_batch(self, urls: list, crawl=False) -> list:
        """
        Predict multiple URLs.
        
        Args:
            urls: List of URLs to classify
            crawl: If True, fetch content for each URL
            
        Returns:
            List of prediction results
        """
        logger.info(f"Analyzing batch of {len(urls)} URLs")
        
        results = []
        for idx, url in enumerate(urls, 1):
            logger.info(f"[{idx}/{len(urls)}] Processing: {url}")
            result = self.predict_url(url, crawl=crawl)
            results.append(result)
        
        return results
    
    def generate_report(self, results: list) -> str:
        """Generate a text report from prediction results."""
        report = []
        report.append("\n" + "=" * 80)
        report.append("MALICIOUS URL DETECTION REPORT")
        report.append("=" * 80)
        report.append(f"\nTotal URLs Analyzed: {len(results)}\n")
        
        safe_count = sum(1 for r in results if r.get('label') == 'SAFE')
        malicious_count = sum(1 for r in results if r.get('label') == 'MALICIOUS')
        error_count = sum(1 for r in results if 'error' in r)
        
        report.append(f"SUMMARY:")
        report.append(f"  Safe URLs:        {safe_count}")
        report.append(f"  Malicious URLs:   {malicious_count}")
        report.append(f"  Errors:           {error_count}")
        if len(results) > 0:
            report.append(f"  Threat Rate:      {(malicious_count/len(results)*100):.1f}%")
        
        report.append("\n" + "-" * 80)
        report.append("DETAILED RESULTS:\n")
        
        for result in results:
            if 'error' in result:
                report.append(f"[ERROR] {result['url']}")
                report.append(f"        {result['error']}\n")
            else:
                icon = "[!!!]" if result['label'] == 'MALICIOUS' else "[ OK]"
                report.append(f"{icon} {result['label']:.<15} (Confidence: {result['confidence']:.1f}%, Risk: {result['risk_level']})")
                report.append(f"     URL: {result['url']}")
                if result['crawled']:
                    report.append(f"     Status: Page crawled and analyzed")
                report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)


def main():
    """Main function - demonstrate detection on sample URLs."""
    
    logger.info("Initializing detector...")
    try:
        detector = MaliciousURLDetector()
    except Exception as e:
        logger.error(f"Failed to initialize detector: {e}")
        return
    
    # Test URLs - mix of safe and suspicious
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "https://www.amazon.com",
        "http://paypal-secure-login.verify-account.xyz/update",
        "http://192.168.1.1/banking/login@secure",
        "http://free-iphone-winner.click/verify-account-now",
        "https://www.wikipedia.org",
        "http://login-verify.paypal-update.xyz",
        "https://docs.python.org/3/",
        "http://secure-account-alert.info/update"
    ]
    
    logger.info(f"\nStarting predictions on {len(test_urls)} test URLs\n")
    
    # Make predictions (without crawling for speed)
    results = detector.predict_batch(test_urls, crawl=False)
    
    # Generate and print report
    report = detector.generate_report(results)
    print(report)
    
    # Save results to JSON
    with open('prediction_results.json', 'w') as f:
        # Convert non-serializable data
        results_serializable = []
        for r in results:
            r_copy = r.copy()
            if 'features' in r_copy:
                r_copy['features'] = {k: float(v) if isinstance(v, (int, float)) else v 
                                     for k, v in r_copy['features'].items()}
            results_serializable.append(r_copy)
        json.dump(results_serializable, f, indent=2)
    
    logger.info("\nResults saved to prediction_results.json")


if __name__ == "__main__":
    try:
        main()
        logger.info("\nPrediction completed successfully")
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        import traceback
        # Log traceback to logger but don't print to stdout
        logger.debug(traceback.format_exc())
