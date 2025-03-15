import json
import email
from email.header import decode_header
from imapclient import IMAPClient
from bs4 import BeautifulSoup
import os
from logger import setup_logger

class EmailHandler:
    def __init__(self, config_path='config.json'):
        """Initialize the email handler with configuration"""
        self.logger = setup_logger()
        self.config = self._load_config(config_path)
        self.client = None

    def _load_config(self, config_path):
        """Load email configuration from config file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config.get('email', {})
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            raise

    def connect(self):
        """Establish connection to the IMAP server"""
        try:
            self.client = IMAPClient(
                self.config['imap_server'],
                use_uid=True,
                ssl=True
            )
            self.client.login(
                self.config['username'],
                self.config['password']
            )
            self.logger.info("Successfully connected to email server")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to email server: {str(e)}")
            return False

    def disconnect(self):
        """Safely disconnect from the IMAP server"""
        if self.client:
            try:
                self.client.logout()
                self.logger.info("Disconnected from email server")
            except Exception as e:
                self.logger.error(f"Error during disconnect: {str(e)}")

    def fetch_unread_emails(self):
        """Fetch unread emails from the inbox"""
        try:
            self.client.select_folder('INBOX')
            messages = self.client.search(['UNSEEN'])
            return messages
        except Exception as e:
            self.logger.error(f"Failed to fetch unread emails: {str(e)}")
            return []

    def parse_email(self, uid):
        """Parse an email message and extract relevant information"""
        try:
            # Fetch the email data
            email_data = self.client.fetch([uid], ['RFC822'])[uid][b'RFC822']
            email_message = email.message_from_bytes(email_data)

            # Extract basic email information
            parsed_email = {
                'subject': self._decode_email_header(email_message['subject']),
                'from': self._decode_email_header(email_message['from']),
                'to': self._decode_email_header(email_message['to']),
                'date': email_message['date'],
                'body': {'plain': [], 'html': []},
                'attachments': [],
                'headers': dict(email_message.items())
            }

            # Process email parts
            self._process_email_parts(email_message, parsed_email)

            self.logger.info(f"Successfully parsed email: {parsed_email['subject']}")
            return parsed_email

        except Exception as e:
            self.logger.error(f"Failed to parse email {uid}: {str(e)}")
            return None

    def _process_email_parts(self, message, parsed_email):
        """Process email parts (body and attachments)"""
        for part in message.walk():
            if part.get_content_maintype() == 'multipart':
                continue

            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))

            try:
                # Handle attachments
                if 'attachment' in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        parsed_email['attachments'].append({
                            'filename': filename,
                            'content_type': content_type,
                            'data': part.get_payload(decode=True)
                        })
                # Handle email body
                else:
                    content = part.get_payload(decode=True)
                    if content is None:
                        continue

                    if isinstance(content, bytes):
                        content = content.decode()

                    if content_type == 'text/plain':
                        parsed_email['body']['plain'].append(content)
                    elif content_type == 'text/html':
                        # Clean HTML content
                        soup = BeautifulSoup(content, 'lxml')
                        parsed_email['body']['html'].append(str(soup))

            except Exception as e:
                self.logger.error(f"Error processing email part: {str(e)}")

    def _decode_email_header(self, header):
        """Decode email header"""
        if header is None:
            return ''
        
        try:
            decoded_header = decode_header(header)
            header_parts = []
            
            for content, charset in decoded_header:
                if isinstance(content, bytes):
                    if charset:
                        content = content.decode(charset)
                    else:
                        content = content.decode()
                header_parts.append(str(content))
            
            return ' '.join(header_parts)
        except Exception as e:
            self.logger.error(f"Error decoding header: {str(e)}")
            return header

    def mark_as_read(self, uid):
        """Mark an email as read"""
        try:
            self.client.add_flags(uid, ['\\Seen'])
            self.logger.info(f"Marked email {uid} as read")
            return True
        except Exception as e:
            self.logger.error(f"Failed to mark email {uid} as read: {str(e)}")
            return False

    def move_to_processed(self, uid):
        """Move an email to a processed folder"""
        try:
            if not self.client.folder_exists('Processed'):
                self.client.create_folder('Processed')
            
            self.client.move(uid, 'Processed')
            self.logger.info(f"Moved email {uid} to Processed folder")
            return True
        except Exception as e:
            self.logger.error(f"Failed to move email {uid} to Processed folder: {str(e)}")
            return False

# Example usage
if __name__ == '__main__':
    handler = EmailHandler()
    if handler.connect():
        try:
            unread = handler.fetch_unread_emails()
            for uid in unread:
                email_content = handler.parse_email(uid)
                if email_content:
                    print(f"Processing email: {email_content['subject']}")
                    handler.mark_as_read(uid)
                    handler.move_to_processed(uid)
        finally:
            handler.disconnect()
