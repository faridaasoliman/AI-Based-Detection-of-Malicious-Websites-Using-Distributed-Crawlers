
Project: AI-Based Detection of Malicious Websites Using Distributed Crawlers
================================================================

PROJECT OVERVIEW
================

This project implements a complete system for detecting malicious websites using:
- Distributed web crawlers for parallel URL processing
- Advanced feature extraction (URL, HTML, and NLP-based)
- Machine learning classification (Random Forest)
- Central aggregation and threat reporting

The system is designed to be scalable, efficient, and accurate in identifying
phishing campaigns and other malicious web activities.

FEATURES IMPLEMENTED
====================

1. ✓ Distributed Web Crawler System
   - Multiple independent crawler nodes
   - Parallel URL processing
   - Inter-node communication via central aggregator

2. ✓ Advanced Feature Extraction
   - URL structure features (15 features)
   - HTML content analysis (9 features)
   - NLP-based text analysis (7 features)
   - Total: 31 engineered features

3. ✓ Machine Learning Model
   - Random Forest classifier (100 estimators)
   - Balanced class weighting
   - Expected accuracy: 95-97%

4. ✓ Central Aggregation System
   - Aggregates results from distributed nodes
   - Performs centralized classification
   - Generates threat reports and statistics

5. ✓ Comprehensive Evaluation
   - Detailed performance metrics
   - Feature importance analysis
   - Threat reporting with per-node statistics

PROJECT STRUCTURE
=================

url_detector/
├── features_enhanced.py        - Advanced feature extraction (URL, HTML, NLP)
├── crawler.py                  - Web crawler implementation
├── train_enhanced.py           - Model training with enhanced features
├── predict_enhanced.py         - Individual URL prediction and analysis
├── distributed_crawler.py      - Distributed system orchestration
├── evaluation.py               - Model evaluation and reporting
├── requirements.txt            - Python dependencies
├── url_model_enhanced.pkl      - Trained model (generated after training)
├── feature_names.json          - Feature names list (generated after training)
├── model_metrics.json          - Evaluation metrics (generated after training)
└── README.md                   - This file

FILES EXPLANATION
=================

1. features_enhanced.py
   Purpose: Feature extraction from URLs, HTML, and text
   Functions:
   - extract_url_features(url) - Extract URL structure features
   - extract_html_features(html) - Extract HTML/page structure features
   - extract_nlp_features(text) - Extract NLP-based text features
   - extract_all_features(url, html, text) - Combined feature extraction
   - get_feature_names() - Get ordered list of feature names

2. crawler.py
   Purpose: Web crawling and content retrieval
   Classes:
   - WebCrawler: Fetches URLs and extracts content
   - DistributedCrawler: Represents a single crawler node
   Key Features:
   - Timeout and retry handling
   - User-agent spoofing to avoid blocking
   - HTML parsing and text extraction

3. train_enhanced.py
   Purpose: Train the ML classification model
   Process:
   1. Load dataset (malicious_phish.csv)
   2. Extract features from 50,000 URLs
   3. Train Random Forest with 100 trees
   4. Evaluate and save model
   Output: url_model_enhanced.pkl, feature_names.json, model_metrics.json

4. predict_enhanced.py
   Purpose: Classify individual URLs or URL batches
   Features:
   - Single URL and batch prediction
   - Confidence scores and risk levels
   - Optional web crawling for content analysis
   - JSON result export

5. distributed_crawler.py
   Purpose: Orchestrate distributed crawling and classification
   Classes:
   - CentralAggregator: Aggregates results from nodes
   - DistributedCrawlSystem: Manages entire system
   Key Features:
   - Distributes URLs across multiple nodes
   - Parallel crawling
   - Centralized classification
   - Threat analysis and reporting

6. evaluation.py
   Purpose: Comprehensive model evaluation
   Reports:
   - Overall accuracy, precision, recall, F1-score
   - Confusion matrix analysis
   - Feature importance ranking
   - Recommendations for improvement

SETUP INSTRUCTIONS
==================

Step 1: Install Dependencies
------------------------------
pip install -r requirements.txt

Or manually:
pip install pandas scikit-learn requests beautifulsoup4

Step 2: Download Dataset
-------------------------
Download the malicious URLs dataset from Kaggle:
  https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

Unzip and place the CSV file in the project directory as:
  malicious_phish.csv

Dataset should have columns: 'url' and 'type' (benign, phishing, defacement, malware)

Step 3: Verify Setup
-------------------
python -c "import pandas, sklearn, requests, bs4; print('All dependencies OK')"

USAGE INSTRUCTIONS
==================

OPTION A: Quick Start (URL-Only Detection)
-------------------------------------------

1. Train the model:
   python train_enhanced.py
   
   Output:
   - url_model_enhanced.pkl (trained model)
   - model_metrics.json (performance metrics)
   - feature_names.json (feature list)
   
   Expected: 95-97% accuracy

2. Predict on URLs:
   python predict_enhanced.py
   
   Output:
   - Console report with predictions
   - prediction_results.json (results in JSON format)

OPTION B: Distributed Crawling (Full Feature Analysis)
------------------------------------------------------

1. Train the model (same as Option A, Step 1)

2. Run distributed crawler:
   python distributed_crawler.py
   
   Features:
   - Creates 3 crawler nodes
   - Distributes URLs evenly
   - Fetches page content
   - Extracts HTML and text features
   - Classifies using ML model
   
   Output:
   - Console logs with detailed progress
   - distributed_crawl_results.json (results)
   - Per-node statistics and threat analysis

3. Evaluate model performance:
   python evaluation.py
   
   Output:
   - evaluation_report.txt (comprehensive report)
   - Feature importance analysis
   - Performance recommendations

TYPICAL WORKFLOW
================

1. Prepare Dataset:
   wget https://kaggle.com/path/to/malicious_phish.csv

2. Train Model:
   python train_enhanced.py
   (Takes 2-3 minutes for 50K URLs)

3. Run Predictions:
   python predict_enhanced.py
   (Instant - no network required)

4. Run Distributed Crawling:
   python distributed_crawler.py
   (2-5 minutes depending on connectivity)

5. View Evaluation:
   python evaluation.py
   cat evaluation_report.txt

FEATURE ENGINEERING
===================

URL Features (15 features):
  - url_length: Total URL length
  - has_https: 1 if HTTPS, 0 if HTTP
  - num_dots: Number of dots in URL
  - num_hyphens: Number of hyphens
  - num_at: Number of @ symbols (phishing indicator)
  - num_digits: Count of digits
  - num_slashes: Count of forward slashes
  - path_depth: Depth of URL path
  - has_ip: 1 if IP address in domain
  - suspicious_keywords: 1 if phishing keywords present
  - url_entropy: Character diversity measure
  - domain_length: Length of domain
  - subdomain_count: Number of subdomains
  - query_string_length: Length of query parameters
  - fragment_length: Length of fragment

HTML Features (9 features):
  - html_length: Total HTML page size
  - num_forms: Number of HTML forms
  - num_inputs: Number of input fields
  - num_links: Number of hyperlinks
  - num_images: Number of images
  - num_scripts: Number of script tags
  - has_external_js: External JavaScript presence
  - num_iframes: Number of embedded iframes
  - has_embedded_objects: Embedded objects/plugins

NLP Features (7 features):
  - text_length: Total page text length
  - suspicious_keyword_count: Count of phishing keywords
  - word_count: Number of words
  - avg_word_length: Average word length
  - has_urgency_language: Urgency keywords present
  - capital_letter_ratio: Uppercase character ratio
  - digit_ratio: Digit character ratio

EXPECTED OUTPUT
===============

Training Output:
  Accuracy: ~95-97%
  Precision: ~0.94-0.96
  Recall: ~0.95-0.97
  F1-Score: ~0.95-0.96

Prediction Output:
  [ OK] SAFE (95.2%)      https://www.google.com
  [!!!] MALICIOUS (94.8%) http://paypal-secure-login.xyz

Distributed Crawl Output:
  Total URLs scanned: 12
  Safe: 7
  Malicious detected: 5
  Threat rate: 41.7%
  Per-node statistics with detailed threat analysis

ADVANCED USAGE
==============

Custom URL Prediction:
  from predict_enhanced import MaliciousURLDetector
  
  detector = MaliciousURLDetector()
  result = detector.predict_url("https://example.com", crawl=True)
  print(result)

Distributed Crawling with Custom URLs:
  from distributed_crawler import DistributedCrawlSystem
  import pickle
  
  with open('url_model_enhanced.pkl', 'rb') as f:
      model = pickle.load(f)
  
  system = DistributedCrawlSystem(model=model, num_nodes=5)
  results = system.run_distributed_crawl(my_urls)

TROUBLESHOOTING
===============

Issue: "malicious_phish.csv not found"
Solution: Download dataset from Kaggle and place in project directory

Issue: "url_model_enhanced.pkl not found"
Solution: Run train_enhanced.py first to generate the model

Issue: "Timeout fetching URL"
Solution: This is normal for unresponsive servers. Model uses timeout=5
To increase, modify crawler.py: WebCrawler(timeout=10)

Issue: "BeautifulSoup not found"
Solution: pip install beautifulsoup4

Issue: Import errors
Solution: Ensure all requirements installed:
  pip install -r requirements.txt

PERFORMANCE NOTES
=================

Training Time:
  - 50K URLs: ~2-3 minutes
  - Feature extraction: ~90 seconds
  - Model training: ~30-60 seconds

Prediction Speed:
  - URL-only (no crawl): ~10ms per URL
  - With crawling: ~500-2000ms per URL (depends on server response)

Memory Usage:
  - Model: ~20MB
  - Training: ~500MB for 50K samples

Scalability:
  - Can be distributed across multiple servers
  - Central aggregator coordinates results
  - Linear scaling with number of crawler nodes

REFERENCES
==========

Datasets Used:
  Malicious Phish Dataset: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
  
Libraries:
  - pandas: Data manipulation
  - scikit-learn: Machine learning
  - requests: HTTP requests
  - BeautifulSoup: HTML parsing
  - urllib: URL parsing

Documentation:
  - scikit-learn: https://scikit-learn.org/
  - BeautifulSoup: https://www.crummy.com/software/BeautifulSoup/
  - Requests: https://requests.readthedocs.io/

FUTURE IMPROVEMENTS
===================

1. Deep Learning Models: Implement LSTM/CNN for better accuracy
2. Real-time Monitoring: Stream processing for live threats
3. API Server: REST API for integration with security tools
4. Threat Intelligence: Integration with threat feeds
5. Advanced NLP: BERT/Transformer-based analysis
6. Database Backend: Store historical results and patterns

CONTACT & SUPPORT
=================

For questions or issues:
  - Refer to README.md
  - Check evaluation_report.txt for model details
  - Review logs in console output


