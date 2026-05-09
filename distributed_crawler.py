"""
distributed_crawler.py
======================
Advanced distributed crawler system with inter-node communication.
Simulates multiple crawler nodes processing URLs in parallel
and sending results to a central aggregator.
"""

import logging
import json
import time
from typing import List, Dict
from crawler import DistributedCrawler
from features_enhanced import extract_all_features
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(levelname)s - %(message)s'
)
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


class CentralAggregator:
    """
    Central server that aggregates results from distributed crawler nodes.
    Coordinates classification and threat detection.
    """
    
    def __init__(self, model=None):
        """
        Initialize the central aggregator.
        
        Args:
            model: Pre-trained classification model (optional)
        """
        self.model = model
        self.results = []
        self.node_results = {}
    
    def register_node_results(self, node_id: str, results: list) -> dict:
        """
        Register results from a crawler node.
        
        Args:
            node_id: ID of the crawler node
            results: List of crawl results from the node
            
        Returns:
            Dictionary with aggregation summary
        """
        logger.info(f"Aggregator: Received {len(results)} results from {node_id}")
        
        self.node_results[node_id] = results
        self.results.extend(results)
        
        summary = {
            'node_id': node_id,
            'total_urls': len(results),
            'successful_crawls': sum(1 for r in results if r['success']),
            'failed_crawls': sum(1 for r in results if not r['success']),
            'timestamp': time.time()
        }
        
        logger.info(f"  Summary: {summary['successful_crawls']} successful, "
                   f"{summary['failed_crawls']} failed")
        
        return summary
    
    def classify_results(self) -> list:
        """
        Classify all collected URLs using the ML model.
        
        Returns:
            List of classified results
        """
        if not self.model:
            logger.warning("No model loaded, returning raw results")
            return self.results
        
        logger.info(f"Aggregator: Classifying {len(self.results)} URLs...")
        
        classified_results = []
        
        for idx, result in enumerate(self.results, 1):
            try:
                url = result['url']
                html_content = result.get('html_content')
                text_content = result.get('text_content')
                
                # Check whitelist first
                from urllib.parse import urlparse
                domain = urlparse(url).netloc.lower()
                if domain in SAFE_DOMAINS_WHITELIST:
                    logger.info(f"  URL {url} matched whitelist - classified as SAFE")
                    classified = {
                        'url': url,
                        'node_id': result['node_id'],
                        'crawl_success': result['success'],
                        'prediction': 0,
                        'label': 'SAFE',
                        'confidence': 100.0,
                        'whitelisted': True,
                        'timestamp': result['timestamp']
                    }
                    classified_results.append(classified)
                    if idx % 10 == 0:
                        logger.info(f"  Classified {idx}/{len(self.results)} URLs")
                    continue
                
                # Extract features
                features_dict = extract_all_features(url, html_content, text_content)
                features_df = pd.DataFrame([features_dict])
                
                # Classify
                prediction = self.model.predict(features_df)[0]
                confidence = self.model.predict_proba(features_df)[0][prediction] * 100
                
                label = "MALICIOUS" if prediction == 1 else "SAFE"
                
                classified = {
                    'url': url,
                    'node_id': result['node_id'],
                    'crawl_success': result['success'],
                    'prediction': int(prediction),
                    'label': label,
                    'confidence': round(float(confidence), 2),
                    'timestamp': result['timestamp']
                }
                
                classified_results.append(classified)
                
                if idx % 10 == 0:
                    logger.info(f"  Classified {idx}/{len(self.results)} URLs")
            
            except Exception as e:
                logger.error(f"Error classifying {result['url']}: {e}")
        
        return classified_results
    
    def generate_threat_report(self, classified_results: list) -> dict:
        """
        Generate a comprehensive threat report from classified results.
        
        Args:
            classified_results: List of classified URLs
            
        Returns:
            Dictionary with threat analysis
        """
        logger.info("Aggregator: Generating threat report...")
        
        total = len(classified_results)
        malicious = sum(1 for r in classified_results if r['label'] == 'MALICIOUS')
        safe = total - malicious
        
        # Calculate confidence statistics
        malicious_confidences = [r['confidence'] for r in classified_results 
                                if r['label'] == 'MALICIOUS']
        
        report = {
            'total_urls_analyzed': total,
            'safe_urls': safe,
            'malicious_urls': malicious,
            'threat_rate_percent': round((malicious / total * 100) if total > 0 else 0, 2),
            'average_malicious_confidence': round(sum(malicious_confidences) / len(malicious_confidences), 2) if malicious_confidences else 0,
            'crawl_success_rate': round(sum(1 for r in self.results if r['success']) / len(self.results) * 100, 2) if self.results else 0,
            'nodes_involved': list(self.node_results.keys()),
            'timestamp': time.time()
        }
        
        # Per-node statistics
        node_stats = {}
        for node_id, results in self.node_results.items():
            node_urls = [r for r in classified_results if r['node_id'] == node_id]
            node_malicious = sum(1 for r in node_urls if r['label'] == 'MALICIOUS')
            
            node_stats[node_id] = {
                'total_urls': len(node_urls),
                'malicious': node_malicious,
                'safe': len(node_urls) - node_malicious,
                'threat_rate': round((node_malicious / len(node_urls) * 100) if node_urls else 0, 2)
            }
        
        report['per_node_statistics'] = node_stats
        
        return report


class DistributedCrawlSystem:
    """
    Main distributed crawl system that orchestrates multiple nodes
    and aggregation.
    """
    
    def __init__(self, model=None, num_nodes=3):
        """
        Initialize the distributed system.
        
        Args:
            model: Pre-trained ML model
            num_nodes: Number of crawler nodes to create
        """
        self.model = model
        self.num_nodes = num_nodes
        self.nodes = {}
        self.aggregator = CentralAggregator(model)
        
        # Create nodes
        for i in range(num_nodes):
            node_id = f"Crawler-Node-{i+1}"
            self.nodes[node_id] = DistributedCrawler(node_id, timeout=5)
        
        logger.info(f"Distributed System initialized with {num_nodes} nodes")
    
    def distribute_urls(self, urls: list) -> Dict[str, list]:
        """
        Distribute URLs evenly across crawler nodes.
        
        Args:
            urls: List of URLs to process
            
        Returns:
            Dictionary mapping node IDs to URL batches
        """
        logger.info(f"Distributing {len(urls)} URLs across {self.num_nodes} nodes")
        
        batch_size = len(urls) // self.num_nodes
        distribution = {}
        
        for i, (node_id, node) in enumerate(self.nodes.items()):
            start_idx = i * batch_size
            if i == self.num_nodes - 1:
                # Last node gets remaining URLs
                batch = urls[start_idx:]
            else:
                batch = urls[start_idx:start_idx + batch_size]
            
            distribution[node_id] = batch
            logger.info(f"  {node_id}: {len(batch)} URLs")
        
        return distribution
    
    def run_distributed_crawl(self, urls: list) -> dict:
        """
        Execute a distributed crawl operation.
        
        Args:
            urls: List of URLs to crawl
            
        Returns:
            Aggregated results and threat report
        """
        logger.info("=" * 80)
        logger.info("STARTING DISTRIBUTED CRAWL OPERATION")
        logger.info("=" * 80)
        
        start_time = time.time()
        
        # Distribute URLs
        distribution = self.distribute_urls(urls)
        
        # Run crawls on each node
        logger.info("\nStarting parallel crawls on all nodes...")
        logger.info("-" * 80)
        
        for node_id, url_batch in distribution.items():
            logger.info(f"\n[{node_id}] Starting crawl of {len(url_batch)} URLs")
            
            # Crawl batch
            results = self.nodes[node_id].crawl_batch(url_batch)
            
            # Register with aggregator
            summary = self.aggregator.register_node_results(node_id, results)
        
        # Classify all results
        logger.info("\n" + "=" * 80)
        logger.info("CLASSIFICATION PHASE")
        logger.info("=" * 80)
        
        classified_results = self.aggregator.classify_results()
        
        # Generate report
        logger.info("\n" + "=" * 80)
        logger.info("THREAT ANALYSIS")
        logger.info("=" * 80)
        
        threat_report = self.aggregator.generate_threat_report(classified_results)
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        # Final summary
        logger.info("\nOPERATION SUMMARY:")
        logger.info(f"  Total execution time: {elapsed:.2f} seconds")
        logger.info(f"  URLs analyzed: {threat_report['total_urls_analyzed']}")
        logger.info(f"  Safe URLs: {threat_report['safe_urls']}")
        logger.info(f"  Malicious URLs: {threat_report['malicious_urls']}")
        logger.info(f"  Threat rate: {threat_report['threat_rate_percent']}%")
        logger.info(f"  Crawl success rate: {threat_report['crawl_success_rate']}%")
        
        logger.info("\nPer-Node Statistics:")
        for node_id, stats in threat_report['per_node_statistics'].items():
            logger.info(f"  {node_id}:")
            logger.info(f"    URLs: {stats['total_urls']}")
            logger.info(f"    Malicious: {stats['malicious']} (Threat: {stats['threat_rate']}%)")
        
        logger.info("=" * 80)
        
        return {
            'classified_results': classified_results,
            'threat_report': threat_report,
            'execution_time': elapsed
        }


def main():
    """Demonstrate the distributed crawl system."""
    
    # Load the model if available
    model = None
    try:
        import pickle
        with open('url_model_enhanced.pkl', 'rb') as f:
            model = pickle.load(f)
        logger.info("Loaded trained ML model")
    except FileNotFoundError:
        logger.warning("Model not found, running simulation without classification")
    
    # Sample URLs for distributed crawling
    test_urls = [
        # Safe URLs
        "https://www.google.com",
        "https://www.github.com",
        "https://www.wikipedia.org",
        "https://stackoverflow.com",
        "https://www.python.org",
        
        # Suspicious URLs
        "http://paypal-secure-login.verify-account.xyz/update",
        "http://free-iphone-winner.click/verify-account-now",
        "http://login-verify.paypal-update.xyz",
        "http://secure-account-alert.info/update",
        "http://192.168.0.1/admin/banking",
        
        # More safe URLs
        "https://www.amazon.com",
        "https://docs.python.org/3/",
        "https://www.stackoverflow.com",
    ]
    
    # Create and run distributed system
    system = DistributedCrawlSystem(model=model, num_nodes=3)
    results = system.run_distributed_crawl(test_urls)
    
    # Save results
    output = {
        'classified_results': results['classified_results'],
        'threat_report': results['threat_report'],
        'execution_time_seconds': results['execution_time']
    }
    
    with open('distributed_crawl_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    logger.info(f"\nResults saved to distributed_crawl_results.json")


if __name__ == "__main__":
    try:
        main()
        logger.info("\nDistributed crawl operation completed successfully")
    except Exception as e:
        logger.error(f"Error during distributed crawl: {e}")
        import traceback
        # Log traceback to logger but don't print to stdout to avoid user confusion
        logger.debug(traceback.format_exc())
