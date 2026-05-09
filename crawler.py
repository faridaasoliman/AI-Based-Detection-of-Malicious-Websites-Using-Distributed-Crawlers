"""
crawler.py
==========
Real web crawler for fetching URLs and extracting content.
Includes error handling, timeouts, and user-agent spoofing.
"""

import requests
from bs4 import BeautifulSoup
import logging
import time
from typing import Dict, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# User agent to avoid blocking
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

class WebCrawler:
    """Fetches URLs and extracts HTML/text content."""
    
    def __init__(self, timeout=5, retry_count=2):
        """
        Initialize the web crawler.
        
        Args:
            timeout: Request timeout in seconds
            retry_count: Number of retries for failed requests
        """
        self.timeout = timeout
        self.retry_count = retry_count
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
    
    def fetch_url(self, url: str) -> Tuple[Optional[str], Optional[str], bool]:
        """
        Fetch a URL and return HTML content and extracted text.
        
        Args:
            url: URL to fetch
            
        Returns:
            Tuple of (html_content, text_content, success)
        """
        try:
            # Ensure URL has a scheme
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            for attempt in range(self.retry_count):
                try:
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        verify=True,
                        allow_redirects=True
                    )
                    
                    # Check if response is HTML
                    if 'text/html' not in response.headers.get('Content-Type', ''):
                        logger.warning(f"Non-HTML content from {url}")
                        return None, None, False
                    
                    html_content = response.text
                    text_content = self._extract_text(html_content)
                    
                    logger.info(f"Successfully fetched {url}")
                    return html_content, text_content, True
                
                except requests.Timeout:
                    logger.warning(f"Timeout on {url} (attempt {attempt+1}/{self.retry_count})")
                    time.sleep(1)
                except requests.ConnectionError as e:
                    logger.warning(f"Connection error for {url}: {e}")
                    time.sleep(1)
                except Exception as e:
                    logger.warning(f"Error fetching {url}: {e}")
                    time.sleep(1)
            
            return None, None, False
            
        except Exception as e:
            logger.error(f"Critical error fetching {url}: {e}")
            return None, None, False
    
    def _extract_text(self, html_content: str) -> str:
        """Extract plain text from HTML content."""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Remove script and style elements
            for script in soup(['script', 'style']):
                script.decompose()
            
            # Get text
            text = soup.get_text()
            
            # Clean up whitespace
            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = ' '.join(chunk for chunk in chunks if chunk)
            
            return text[:5000]  # Limit to first 5000 chars
        except Exception as e:
            logger.error(f"Error extracting text: {e}")
            return ""


class DistributedCrawler:
    """
    Represents a crawler node in a distributed system.
    Each node can independently crawl a batch of URLs.
    """
    
    def __init__(self, node_id: str, timeout=5):
        """
        Initialize a crawler node.
        
        Args:
            node_id: Unique identifier for this node
            timeout: Request timeout in seconds
        """
        self.node_id = node_id
        self.crawler = WebCrawler(timeout=timeout)
        self.results = []
    
    def crawl_batch(self, urls: list) -> list:
        """
        Crawl a batch of URLs and return results.
        
        Args:
            urls: List of URLs to crawl
            
        Returns:
            List of crawl results
        """
        self.results = []
        
        logger.info(f"[{self.node_id}] Starting crawl of {len(urls)} URLs")
        
        for idx, url in enumerate(urls, 1):
            logger.info(f"[{self.node_id}] [{idx}/{len(urls)}] Crawling: {url}")
            
            html, text, success = self.crawler.fetch_url(url)
            
            result = {
                'node_id': self.node_id,
                'url': url,
                'html_content': html if success else None,
                'text_content': text if success else None,
                'success': success,
                'timestamp': time.time()
            }
            
            self.results.append(result)
            time.sleep(0.5)  # Be respectful to servers
        
        logger.info(f"[{self.node_id}] Completed crawl batch")
        return self.results
    
    def get_results(self) -> list:
        """Get the results from the last crawl batch."""
        return self.results
