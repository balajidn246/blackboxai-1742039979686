import re
import urllib.parse
from bs4 import BeautifulSoup
import magic
import hashlib
from logger import setup_logger

class PhishingAnalyzer:
    def __init__(self):
        """Initialize the phishing analyzer"""
        self.logger = setup_logger()
        
        # Common file extensions that could be malicious
        self.suspicious_extensions = {
            '.exe', '.bat', '.cmd', '.scr', '.ps1', '.vbs', '.js',
            '.jar', '.hta', '.msi', '.dll', '.docm', '.xlsm', '.pptm'
        }
        
        # Patterns for detecting suspicious content
        self.patterns = {
            'url': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

    def analyze_email(self, email_content):
        """
        Analyze email content for phishing indicators
        
        Args:
            email_content (dict): Parsed email content from EmailHandler
        
        Returns:
            dict: Analysis results containing identified indicators and risk score
        """
        try:
            analysis_result = {
                'risk_score': 0,
                'indicators': {
                    'urls': [],
                    'domains': [],
                    'ips': [],
                    'emails': [],
                    'attachments': [],
                    'suspicious_patterns': []
                },
                'summary': []
            }

            # Analyze email headers
            self._analyze_headers(email_content, analysis_result)
            
            # Analyze email body
            self._analyze_body(email_content, analysis_result)
            
            # Analyze attachments
            self._analyze_attachments(email_content, analysis_result)
            
            # Calculate final risk score
            self._calculate_risk_score(analysis_result)
            
            self.logger.info(f"Completed analysis with risk score: {analysis_result['risk_score']}")
            return analysis_result

        except Exception as e:
            self.logger.error(f"Error during email analysis: {str(e)}")
            return None

    def _analyze_headers(self, email_content, analysis_result):
        """Analyze email headers for suspicious patterns"""
        try:
            headers = email_content['headers']
            
            # Check for spoofed sender
            from_header = headers.get('from', '')
            reply_to = headers.get('reply-to', '')
            
            if reply_to and reply_to != from_header:
                analysis_result['suspicious_patterns'].append({
                    'type': 'header_mismatch',
                    'description': 'Reply-To address differs from From address',
                    'severity': 'medium'
                })
                analysis_result['risk_score'] += 2
            
            # Extract and analyze email addresses
            email_addresses = re.findall(self.patterns['email'], from_header)
            analysis_result['indicators']['emails'].extend(email_addresses)

        except Exception as e:
            self.logger.error(f"Error analyzing headers: {str(e)}")

    def _analyze_body(self, email_content, analysis_result):
        """Analyze email body for suspicious content"""
        try:
            # Analyze plain text content
            for plain_text in email_content['body']['plain']:
                self._analyze_text_content(plain_text, analysis_result)

            # Analyze HTML content
            for html_content in email_content['body']['html']:
                self._analyze_html_content(html_content, analysis_result)

        except Exception as e:
            self.logger.error(f"Error analyzing body: {str(e)}")

    def _analyze_text_content(self, text, analysis_result):
        """Analyze plain text content for indicators"""
        try:
            # Extract URLs
            urls = re.findall(self.patterns['url'], text)
            for url in urls:
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc
                
                url_info = {
                    'url': url,
                    'domain': domain,
                    'path': parsed_url.path,
                    'params': parsed_url.params,
                    'query': parsed_url.query
                }
                
                analysis_result['indicators']['urls'].append(url_info)
                analysis_result['indicators']['domains'].append(domain)

            # Extract IP addresses
            ips = re.findall(self.patterns['ip'], text)
            analysis_result['indicators']['ips'].extend(ips)

            # Check for common phishing keywords
            phishing_keywords = [
                'verify', 'account', 'suspended', 'login', 'credential',
                'security', 'urgent', 'important', 'password', 'bank'
            ]
            
            found_keywords = [
                keyword for keyword in phishing_keywords 
                if keyword.lower() in text.lower()
            ]
            
            if found_keywords:
                analysis_result['suspicious_patterns'].append({
                    'type': 'suspicious_keywords',
                    'keywords': found_keywords,
                    'severity': 'low'
                })
                analysis_result['risk_score'] += len(found_keywords) * 0.5

        except Exception as e:
            self.logger.error(f"Error analyzing text content: {str(e)}")

    def _analyze_html_content(self, html, analysis_result):
        """Analyze HTML content for suspicious patterns"""
        try:
            soup = BeautifulSoup(html, 'lxml')
            
            # Check for hidden content
            hidden_elements = soup.find_all(
                lambda tag: tag.get('style', '').find('display: none') != -1 or 
                           tag.get('hidden') is not None
            )
            
            if hidden_elements:
                analysis_result['suspicious_patterns'].append({
                    'type': 'hidden_content',
                    'count': len(hidden_elements),
                    'severity': 'medium'
                })
                analysis_result['risk_score'] += 2

            # Analyze links
            links = soup.find_all('a')
            for link in links:
                href = link.get('href')
                text = link.get_text()
                
                if href and text:
                    # Check for URL masking
                    if href != text and text.startswith('http'):
                        analysis_result['suspicious_patterns'].append({
                            'type': 'masked_url',
                            'displayed_text': text,
                            'actual_url': href,
                            'severity': 'high'
                        })
                        analysis_result['risk_score'] += 3

        except Exception as e:
            self.logger.error(f"Error analyzing HTML content: {str(e)}")

    def _analyze_attachments(self, email_content, analysis_result):
        """Analyze email attachments"""
        try:
            for attachment in email_content.get('attachments', []):
                attachment_info = {
                    'filename': attachment['filename'],
                    'content_type': attachment['content_type'],
                    'size': len(attachment['data']),
                    'md5': hashlib.md5(attachment['data']).hexdigest(),
                    'sha256': hashlib.sha256(attachment['data']).hexdigest()
                }

                # Check file type using magic
                mime = magic.Magic(mime=True)
                actual_type = mime.from_buffer(attachment['data'])
                attachment_info['detected_type'] = actual_type

                # Check for suspicious extensions
                _, ext = os.path.splitext(attachment['filename'].lower())
                if ext in self.suspicious_extensions:
                    attachment_info['suspicious'] = True
                    analysis_result['risk_score'] += 3
                    analysis_result['summary'].append(
                        f"Suspicious attachment found: {attachment['filename']}"
                    )

                # Check for type mismatch
                if actual_type != attachment['content_type']:
                    attachment_info['type_mismatch'] = True
                    analysis_result['risk_score'] += 4
                    analysis_result['summary'].append(
                        f"File type mismatch in attachment: {attachment['filename']}"
                    )

                analysis_result['indicators']['attachments'].append(attachment_info)

        except Exception as e:
            self.logger.error(f"Error analyzing attachments: {str(e)}")

    def _calculate_risk_score(self, analysis_result):
        """Calculate the final risk score based on all indicators"""
        try:
            # Base risk score already accumulated during analysis
            base_score = analysis_result['risk_score']
            
            # Additional scoring based on quantity of indicators
            indicator_counts = {
                'urls': len(analysis_result['indicators']['urls']),
                'ips': len(analysis_result['indicators']['ips']),
                'attachments': len(analysis_result['indicators']['attachments'])
            }
            
            # Adjust score based on quantity of indicators
            base_score += min(indicator_counts['urls'], 5)  # Cap at 5 points
            base_score += indicator_counts['ips'] * 2
            
            # Normalize score to 0-100 range
            analysis_result['risk_score'] = min(100, max(0, base_score * 5))
            
            # Add risk level
            if analysis_result['risk_score'] >= 75:
                analysis_result['risk_level'] = 'HIGH'
            elif analysis_result['risk_score'] >= 40:
                analysis_result['risk_level'] = 'MEDIUM'
            else:
                analysis_result['risk_level'] = 'LOW'

        except Exception as e:
            self.logger.error(f"Error calculating risk score: {str(e)}")
            analysis_result['risk_score'] = 0
            analysis_result['risk_level'] = 'UNKNOWN'

# Example usage
if __name__ == '__main__':
    analyzer = PhishingAnalyzer()
    sample_email = {
        'headers': {'from': 'suspicious@example.com', 'reply-to': 'different@example.com'},
        'body': {
            'plain': ['Please verify your account at http://suspicious-site.com'],
            'html': ['<a href="http://malicious.com">http://legitimate-looking.com</a>'],
        },
        'attachments': []
    }
    result = analyzer.analyze_email(sample_email)
    print(f"Analysis Result: {result}")
