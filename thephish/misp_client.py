from pymisp import PyMISP, MISPEvent, MISPObject, MISPAttribute
import json
import datetime
from logger import setup_logger

class MISPClient:
    def __init__(self, config_path='config.json'):
        """Initialize MISP client with configuration"""
        self.logger = setup_logger()
        self.config = self._load_config(config_path)
        self.client = self._initialize_client()

    def _load_config(self, config_path):
        """Load MISP configuration from config file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config.get('misp', {})
        except Exception as e:
            self.logger.error(f"Failed to load MISP config: {str(e)}")
            raise

    def _initialize_client(self):
        """Initialize MISP API client"""
        try:
            client = PyMISP(
                url=self.config['base_url'],
                key=self.config['api_key'],
                ssl=False  # Set to True if using HTTPS with valid cert
            )
            return client
        except Exception as e:
            self.logger.error(f"Failed to initialize MISP client: {str(e)}")
            raise

    def create_phishing_event(self, email_data, analysis_result, cortex_results=None):
        """
        Create a MISP event for a phishing email with its analysis results
        
        Args:
            email_data (dict): Parsed email data
            analysis_result (dict): Results from phishing analysis
            cortex_results (dict): Optional results from Cortex analysis
        
        Returns:
            str: Event ID if successful, None otherwise
        """
        try:
            # Create new MISP event
            event = MISPEvent()
            event.distribution = 0  # Your organization only
            event.threat_level_id = self._convert_risk_to_threat_level(
                analysis_result['risk_level']
            )
            event.analysis = 2  # Complete
            event.info = f"Phishing Campaign: {email_data['subject']}"
            
            # Add tags
            event.add_tag('phishing')
            event.add_tag(f"phishing:risk-level=\"{analysis_result['risk_level']}\"")
            event.add_tag(f"phishing:score=\"{analysis_result['risk_score']}\"")

            # Add email object
            email_object = self._create_email_object(email_data)
            event.add_object(email_object)

            # Add indicators
            self._add_indicators_to_event(event, analysis_result['indicators'])

            # Add Cortex analysis results if available
            if cortex_results:
                self._add_cortex_results_to_event(event, cortex_results)

            # Submit event to MISP
            response = self.client.add_event(event)
            
            if response.get('errors'):
                self.logger.error(f"Error creating MISP event: {response['errors']}")
                return None
            
            event_id = response['Event']['id']
            self.logger.info(f"Successfully created MISP event {event_id}")
            return event_id

        except Exception as e:
            self.logger.error(f"Error creating MISP event: {str(e)}")
            return None

    def _create_email_object(self, email_data):
        """Create a MISP object for the email"""
        try:
            email_object = MISPObject('email')
            
            # Add email attributes
            email_object.add_attribute('from', email_data['headers']['from'])
            email_object.add_attribute('subject', email_data['subject'])
            email_object.add_attribute('reply-to', email_data['headers'].get('reply-to', ''))
            email_object.add_attribute('x-mailer', email_data['headers'].get('x-mailer', ''))
            
            # Add message-id if available
            if 'message-id' in email_data['headers']:
                email_object.add_attribute('message-id', email_data['headers']['message-id'])

            # Add email body
            if email_data['body'].get('plain'):
                email_object.add_attribute(
                    'email-body',
                    email_data['body']['plain'][0][:1000]  # First 1000 chars
                )

            return email_object

        except Exception as e:
            self.logger.error(f"Error creating email object: {str(e)}")
            return None

    def _add_indicators_to_event(self, event, indicators):
        """Add indicators to the MISP event"""
        try:
            # Add URLs
            for url_info in indicators.get('urls', []):
                event.add_attribute('url', url_info['url'], comment='Extracted from email')

            # Add domains
            for domain in indicators.get('domains', []):
                event.add_attribute('domain', domain, comment='Extracted from email')

            # Add IP addresses
            for ip in indicators.get('ips', []):
                event.add_attribute('ip-dst', ip, comment='Extracted from email')

            # Add attachments
            for attachment in indicators.get('attachments', []):
                attachment_object = MISPObject('file')
                attachment_object.add_attribute('filename', attachment['filename'])
                attachment_object.add_attribute('size-in-bytes', attachment['size'])
                attachment_object.add_attribute('md5', attachment['md5'])
                attachment_object.add_attribute('sha256', attachment['sha256'])
                attachment_object.add_attribute(
                    'mime-type',
                    attachment['detected_type']
                )
                
                if attachment.get('suspicious'):
                    attachment_object.add_attribute(
                        'text',
                        'Suspicious file attachment'
                    )
                
                event.add_object(attachment_object)

        except Exception as e:
            self.logger.error(f"Error adding indicators to event: {str(e)}")

    def _add_cortex_results_to_event(self, event, cortex_results):
        """Add Cortex analysis results to the MISP event"""
        try:
            # Create a Cortex analysis object
            analysis_object = MISPObject('cortex')
            
            # Add URL analysis results
            for url_result in cortex_results.get('urls', []):
                for analysis in url_result.get('results', []):
                    if analysis and 'report' in analysis:
                        analysis_object.add_attribute(
                            'comment',
                            f"URL {url_result['url']} - {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary')}"
                        )

            # Add domain analysis results
            for domain_result in cortex_results.get('domains', []):
                for analysis in domain_result.get('results', []):
                    if analysis and 'report' in analysis:
                        analysis_object.add_attribute(
                            'comment',
                            f"Domain {domain_result['domain']} - {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary')}"
                        )

            # Add file analysis results
            for file_result in cortex_results.get('files', []):
                for analysis in file_result.get('results', []):
                    if analysis and 'report' in analysis:
                        analysis_object.add_attribute(
                            'comment',
                            f"File {file_result['filename']} - {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary')}"
                        )

            event.add_object(analysis_object)

        except Exception as e:
            self.logger.error(f"Error adding Cortex results to event: {str(e)}")

    def _convert_risk_to_threat_level(self, risk_level):
        """Convert risk level to MISP threat level"""
        threat_levels = {
            'HIGH': 1,    # High
            'MEDIUM': 2,  # Medium
            'LOW': 3,     # Low
            'UNKNOWN': 4  # Unknown
        }
        return threat_levels.get(risk_level, 4)

    def update_event(self, event_id, attributes=None, objects=None, tags=None):
        """Update an existing MISP event"""
        try:
            event = self.client.get_event(event_id)
            
            if attributes:
                for attribute in attributes:
                    event.add_attribute(**attribute)
            
            if objects:
                for obj in objects:
                    event.add_object(obj)
            
            if tags:
                for tag in tags:
                    event.add_tag(tag)
            
            response = self.client.update_event(event)
            
            if response.get('errors'):
                self.logger.error(f"Error updating MISP event: {response['errors']}")
                return False
            
            self.logger.info(f"Successfully updated MISP event {event_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error updating MISP event {event_id}: {str(e)}")
            return False

    def search_similar_events(self, indicators, days=30):
        """Search for similar events based on indicators"""
        try:
            search_results = []
            
            # Search by URLs
            for url_info in indicators.get('urls', []):
                results = self.client.search(
                    controller='events',
                    value=url_info['url'],
                    type_attribute='url',
                    date_from=datetime.datetime.now() - datetime.timedelta(days=days)
                )
                search_results.extend(results)

            # Search by domains
            for domain in indicators.get('domains', []):
                results = self.client.search(
                    controller='events',
                    value=domain,
                    type_attribute='domain',
                    date_from=datetime.datetime.now() - datetime.timedelta(days=days)
                )
                search_results.extend(results)

            # Search by file hashes
            for attachment in indicators.get('attachments', []):
                if 'sha256' in attachment:
                    results = self.client.search(
                        controller='events',
                        value=attachment['sha256'],
                        type_attribute='sha256',
                        date_from=datetime.datetime.now() - datetime.timedelta(days=days)
                    )
                    search_results.extend(results)

            return search_results

        except Exception as e:
            self.logger.error(f"Error searching for similar events: {str(e)}")
            return []

# Example usage
if __name__ == '__main__':
    client = MISPClient()
    sample_email = {
        'subject': 'Test Phishing Email',
        'headers': {
            'from': 'suspicious@example.com',
            'message-id': '<123@example.com>'
        },
        'body': {
            'plain': ['This is a test phishing email']
        }
    }
    sample_analysis = {
        'risk_level': 'HIGH',
        'risk_score': 75,
        'indicators': {
            'urls': [{'url': 'http://suspicious.com'}],
            'domains': ['suspicious.com'],
            'ips': ['192.168.1.1'],
            'attachments': []
        }
    }
    event_id = client.create_phishing_event(sample_email, sample_analysis)
    if event_id:
        print(f"Created MISP event: {event_id}")
