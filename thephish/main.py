import argparse
import time
import json
import sys
from logger import setup_logger
from email_handler import EmailHandler
from analysis import PhishingAnalyzer
from thehive_client import TheHiveClient
from cortex_client import CortexClient
from misp_client import MISPClient

class ThePhish:
    def __init__(self, config_path='config.json'):
        """Initialize ThePhish with all its components"""
        self.logger = setup_logger()
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.email_handler = EmailHandler(config_path)
        self.analyzer = PhishingAnalyzer()
        self.thehive = TheHiveClient(config_path)
        self.cortex = CortexClient(config_path)
        self.misp = MISPClient(config_path)

    def _load_config(self, config_path):
        """Load main configuration"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            raise

    def process_email(self, email_uid):
        """Process a single email"""
        try:
            # Parse email
            email_data = self.email_handler.parse_email(email_uid)
            if not email_data:
                self.logger.error(f"Failed to parse email {email_uid}")
                return False

            # Analyze email for phishing indicators
            analysis_result = self.analyzer.analyze_email(email_data)
            if not analysis_result:
                self.logger.error(f"Failed to analyze email {email_uid}")
                return False

            # If risk level is LOW and no suspicious patterns, mark as processed
            if (analysis_result['risk_level'] == 'LOW' and 
                not analysis_result['suspicious_patterns']):
                self.logger.info(f"Email {email_uid} has low risk, marking as processed")
                self.email_handler.mark_as_read(email_uid)
                self.email_handler.move_to_processed(email_uid)
                return True

            # Analyze indicators with Cortex
            cortex_results = self.cortex.analyze_indicators(
                analysis_result['indicators']
            )

            # Create TheHive alert
            alert_id = self.thehive.create_alert(email_data, analysis_result)
            if alert_id:
                # Create case from alert
                case_id = self.thehive.create_case_from_alert(alert_id)
                if case_id:
                    self.logger.info(f"Created TheHive case {case_id}")

            # Create MISP event
            event_id = self.misp.create_phishing_event(
                email_data,
                analysis_result,
                cortex_results
            )
            if event_id:
                self.logger.info(f"Created MISP event {event_id}")

                # Search for similar events
                similar_events = self.misp.search_similar_events(
                    analysis_result['indicators']
                )
                if similar_events:
                    self.logger.info(
                        f"Found {len(similar_events)} similar events in MISP"
                    )

            # Mark email as processed
            self.email_handler.mark_as_read(email_uid)
            self.email_handler.move_to_processed(email_uid)

            return True

        except Exception as e:
            self.logger.error(f"Error processing email {email_uid}: {str(e)}")
            return False

    def run_continuous(self, interval=300):
        """Run in continuous mode, checking for new emails periodically"""
        self.logger.info(f"Starting ThePhish in continuous mode (interval: {interval}s)")
        
        while True:
            try:
                # Connect to email server
                if not self.email_handler.connect():
                    self.logger.error("Failed to connect to email server")
                    time.sleep(interval)
                    continue

                # Fetch unread emails
                unread_emails = self.email_handler.fetch_unread_emails()
                
                if unread_emails:
                    self.logger.info(f"Found {len(unread_emails)} unread emails")
                    for uid in unread_emails:
                        self.process_email(uid)
                else:
                    self.logger.info("No new emails found")

                # Disconnect from email server
                self.email_handler.disconnect()

                # Wait for next check
                time.sleep(interval)

            except KeyboardInterrupt:
                self.logger.info("Received shutdown signal, stopping...")
                break
            except Exception as e:
                self.logger.error(f"Error in continuous mode: {str(e)}")
                time.sleep(interval)

    def run_once(self):
        """Run once, processing all unread emails"""
        self.logger.info("Starting ThePhish in single-run mode")
        
        try:
            # Connect to email server
            if not self.email_handler.connect():
                self.logger.error("Failed to connect to email server")
                return False

            # Fetch unread emails
            unread_emails = self.email_handler.fetch_unread_emails()
            
            if unread_emails:
                self.logger.info(f"Found {len(unread_emails)} unread emails")
                for uid in unread_emails:
                    self.process_email(uid)
            else:
                self.logger.info("No new emails found")

            # Disconnect from email server
            self.email_handler.disconnect()
            return True

        except Exception as e:
            self.logger.error(f"Error in single-run mode: {str(e)}")
            return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='ThePhish - Automated Phishing Email Analysis'
    )
    parser.add_argument(
        '--config',
        default='config.json',
        help='Path to configuration file'
    )
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run in continuous mode'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=300,
        help='Interval between checks in continuous mode (seconds)'
    )
    args = parser.parse_args()

    try:
        thephish = ThePhish(args.config)
        
        if args.continuous:
            thephish.run_continuous(args.interval)
        else:
            thephish.run_once()

    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
