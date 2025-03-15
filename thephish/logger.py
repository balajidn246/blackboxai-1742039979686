import logging
import json
import os
from logging.handlers import RotatingFileHandler

class ThePhishLogger:
    def __init__(self, config_path='config.json'):
        """Initialize the logger with configuration from config.json"""
        self.logger = None
        self.config = self._load_config(config_path)
        self._setup_logger()

    def _load_config(self, config_path):
        """Load configuration from the config file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config.get('logging', {
                'level': 'INFO',
                'file': 'thephish.log'
            })
        except FileNotFoundError:
            print(f"Warning: Config file {config_path} not found. Using default logging settings.")
            return {'level': 'INFO', 'file': 'thephish.log'}
        except json.JSONDecodeError:
            print(f"Warning: Invalid JSON in {config_path}. Using default logging settings.")
            return {'level': 'INFO', 'file': 'thephish.log'}

    def _setup_logger(self):
        """Set up the logger with both file and console handlers"""
        # Create logger
        self.logger = logging.getLogger('ThePhish')
        
        # Set logging level from config
        level = getattr(logging, self.config.get('level', 'INFO').upper())
        self.logger.setLevel(level)

        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        # Create and set up file handler with rotation
        log_file = self.config.get('file', 'thephish.log')
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)

        # Create and set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

    def get_logger(self):
        """Return the configured logger instance"""
        return self.logger

def setup_logger(config_path='config.json'):
    """Helper function to create and return a logger instance"""
    logger_instance = ThePhishLogger(config_path)
    return logger_instance.get_logger()

# Example usage:
if __name__ == '__main__':
    logger = setup_logger()
    logger.info('Logger initialized successfully')
    logger.debug('This is a debug message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
