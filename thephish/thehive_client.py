from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseObservable, Alert
from thehive4py.query import Eq
import json
import datetime
from logger import setup_logger

class TheHiveClient:
    def __init__(self, config_path='config.json'):
        """Initialize TheHive client with configuration"""
        self.logger = setup_logger()
        self.config = self._load_config(config_path)
        self.api = self._initialize_api()

    def _load_config(self, config_path):
        """Load TheHive configuration from config file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config.get('thehive', {})
        except Exception as e:
            self.logger.error(f"Failed to load TheHive config: {str(e)}")
            raise

    def _initialize_api(self):
        """Initialize TheHive API client"""
        try:
            api = TheHiveApi(
                self.config['base_url'],
                self.config['api_key']
            )
            return api
        except Exception as e:
            self.logger.error(f"Failed to initialize TheHive API: {str(e)}")
            raise

    def create_alert(self, email_data, analysis_result):
        """Create an alert in TheHive from email analysis"""
        try:
            # Prepare alert artifacts
            artifacts = self._prepare_artifacts(email_data, analysis_result)
            
            # Create alert
            alert = Alert(
                title=f"Potential Phishing Email: {email_data['subject']}",
                description=self._create_description(email_data, analysis_result),
                type='external',
                source='ThePhish',
                sourceRef=f"thephish_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
                artifacts=artifacts,
                severity=self._convert_risk_to_severity(analysis_result['risk_level']),
                tags=['phishing', f"risk:{analysis_result['risk_level']}"],
                status='New',
                tlp=2,  # TLP:AMBER
                pap=2   # PAP:AMBER
            )

            # Submit alert to TheHive
            response = self.api.create_alert(alert)

            if response.status_code == 201:
                alert_id = response.json()['id']
                self.logger.info(f"Successfully created alert {alert_id}")
                return alert_id
            else:
                self.logger.error(f"Failed to create alert: {response.text}")
                return None

        except Exception as e:
            self.logger.error(f"Error creating alert: {str(e)}")
            return None

    def create_case_from_alert(self, alert_id):
        """Create a case from an existing alert"""
        try:
            response = self.api.promote_alert_to_case(alert_id)
            
            if response.status_code == 201:
                case_id = response.json()['id']
                self.logger.info(f"Successfully created case {case_id} from alert {alert_id}")
                return case_id
            else:
                self.logger.error(f"Failed to create case from alert: {response.text}")
                return None

        except Exception as e:
            self.logger.error(f"Error creating case from alert: {str(e)}")
            return None

    def _prepare_artifacts(self, email_data, analysis_result):
        """Prepare artifacts from email data and analysis results"""
        artifacts = []

        # Add email artifacts
        artifacts.extend([
            CaseObservable(
                dataType='mail',
                data=email_data['headers']['from'],
                message='Sender email address',
                tags=['sender']
            ),
            CaseObservable(
                dataType='mail-subject',
                data=email_data['subject'],
                message='Email subject',
                tags=['subject']
            )
        ])

        # Add URLs
        for url_info in analysis_result['indicators']['urls']:
            artifacts.append(
                CaseObservable(
                    dataType='url',
                    data=url_info['url'],
                    message='Extracted URL',
                    tags=['url']
                )
            )

        # Add domains
        for domain in analysis_result['indicators']['domains']:
            artifacts.append(
                CaseObservable(
                    dataType='domain',
                    data=domain,
                    message='Extracted domain',
                    tags=['domain']
                )
            )

        # Add IP addresses
        for ip in analysis_result['indicators']['ips']:
            artifacts.append(
                CaseObservable(
                    dataType='ip',
                    data=ip,
                    message='Extracted IP address',
                    tags=['ip']
                )
            )

        # Add attachments
        for attachment in analysis_result['indicators']['attachments']:
            artifacts.append(
                CaseObservable(
                    dataType='file',
                    data=attachment['filename'],
                    message=f"Attachment: {attachment['detected_type']}",
                    tags=['attachment', 
                          'suspicious' if attachment.get('suspicious') else 'normal']
                )
            )

        return artifacts

    def _create_description(self, email_data, analysis_result):
        """Create a detailed description for the alert"""
        description = f"""
## Phishing Email Analysis

### Email Details
- **From:** {email_data['headers']['from']}
- **Subject:** {email_data['subject']}
- **Date:** {email_data['headers'].get('date', 'Unknown')}

### Risk Assessment
- **Risk Score:** {analysis_result['risk_score']}
- **Risk Level:** {analysis_result['risk_level']}

### Suspicious Patterns
"""
        for pattern in analysis_result['suspicious_patterns']:
            description += f"- **{pattern['type']}**: {pattern.get('description', '')} (Severity: {pattern['severity']})\n"

        description += "\n### Indicators\n"
        
        if analysis_result['indicators']['urls']:
            description += "\n#### URLs\n"
            for url in analysis_result['indicators']['urls']:
                description += f"- {url['url']}\n"

        if analysis_result['indicators']['domains']:
            description += "\n#### Domains\n"
            for domain in analysis_result['indicators']['domains']:
                description += f"- {domain}\n"

        if analysis_result['indicators']['attachments']:
            description += "\n#### Attachments\n"
            for attachment in analysis_result['indicators']['attachments']:
                description += f"- {attachment['filename']} ({attachment['detected_type']})\n"

        return description

    def _convert_risk_to_severity(self, risk_level):
        """Convert risk level to TheHive severity"""
        severity_map = {
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'UNKNOWN': 1
        }
        return severity_map.get(risk_level, 1)

    def update_case(self, case_id, tasks=None, artifacts=None):
        """Update an existing case with new tasks or artifacts"""
        try:
            if tasks:
                for task in tasks:
                    task_data = CaseTask(
                        title=task['title'],
                        status='Waiting',
                        flag=False,
                        description=task.get('description', '')
                    )
                    self.api.create_case_task(case_id, task_data)

            if artifacts:
                for artifact in artifacts:
                    self.api.create_case_observable(
                        case_id,
                        CaseObservable(**artifact)
                    )

            self.logger.info(f"Successfully updated case {case_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error updating case {case_id}: {str(e)}")
            return False

# Example usage
if __name__ == '__main__':
    client = TheHiveClient()
    sample_email = {
        'subject': 'Test Phishing Email',
        'headers': {'from': 'suspicious@example.com'},
    }
    sample_analysis = {
        'risk_level': 'HIGH',
        'risk_score': 75,
        'indicators': {
            'urls': [{'url': 'http://suspicious.com'}],
            'domains': ['suspicious.com'],
            'ips': ['192.168.1.1'],
            'attachments': []
        },
        'suspicious_patterns': [
            {'type': 'masked_url', 'description': 'URL masking detected', 'severity': 'high'}
        ]
    }
    alert_id = client.create_alert(sample_email, sample_analysis)
    if alert_id:
        case_id = client.create_case_from_alert(alert_id)
