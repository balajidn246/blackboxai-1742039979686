from cortex4py.api import Api
from cortex4py.query import Query
import json
import time
from logger import setup_logger

class CortexClient:
    def __init__(self, config_path='config.json'):
        """Initialize Cortex client with configuration"""
        self.logger = setup_logger()
        self.config = self._load_config(config_path)
        self.api = self._initialize_api()
        self.analyzers = self._get_available_analyzers()

    def _load_config(self, config_path):
        """Load Cortex configuration from config file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config.get('cortex', {})
        except Exception as e:
            self.logger.error(f"Failed to load Cortex config: {str(e)}")
            raise

    def _initialize_api(self):
        """Initialize Cortex API client"""
        try:
            api = Api(
                self.config['base_url'],
                self.config['api_key'],
                cert=False  # Set to True if using HTTPS with valid cert
            )
            return api
        except Exception as e:
            self.logger.error(f"Failed to initialize Cortex API: {str(e)}")
            raise

    def _get_available_analyzers(self):
        """Get list of available analyzers from Cortex"""
        try:
            analyzers = self.api.analyzers.find_all({}, range='all')
            analyzer_dict = {}
            for analyzer in analyzers:
                data_types = analyzer.get('dataTypeList', [])
                for data_type in data_types:
                    if data_type not in analyzer_dict:
                        analyzer_dict[data_type] = []
                    analyzer_dict[data_type].append(analyzer['name'])
            
            self.logger.info(f"Found {len(analyzers)} available analyzers")
            return analyzer_dict
        except Exception as e:
            self.logger.error(f"Error getting analyzers: {str(e)}")
            return {}

    def analyze_indicators(self, indicators):
        """
        Analyze multiple indicators using appropriate Cortex analyzers
        
        Args:
            indicators (dict): Dictionary containing different types of indicators
                             (urls, domains, ips, files) to analyze
        
        Returns:
            dict: Analysis results for each indicator
        """
        results = {
            'urls': [],
            'domains': [],
            'ips': [],
            'files': [],
            'summary': []
        }

        try:
            # Analyze URLs
            for url_info in indicators.get('urls', []):
                url_results = self.analyze_url(url_info['url'])
                if url_results:
                    results['urls'].append({
                        'url': url_info['url'],
                        'results': url_results
                    })

            # Analyze domains
            for domain in indicators.get('domains', []):
                domain_results = self.analyze_domain(domain)
                if domain_results:
                    results['domains'].append({
                        'domain': domain,
                        'results': domain_results
                    })

            # Analyze IPs
            for ip in indicators.get('ips', []):
                ip_results = self.analyze_ip(ip)
                if ip_results:
                    results['ips'].append({
                        'ip': ip,
                        'results': ip_results
                    })

            # Analyze files/attachments
            for attachment in indicators.get('attachments', []):
                file_results = self.analyze_file(
                    attachment['filename'],
                    attachment['data']
                )
                if file_results:
                    results['files'].append({
                        'filename': attachment['filename'],
                        'results': file_results
                    })

            # Generate summary of findings
            self._generate_analysis_summary(results)
            
            return results

        except Exception as e:
            self.logger.error(f"Error during indicator analysis: {str(e)}")
            return results

    def analyze_url(self, url):
        """Analyze a URL using available URL analyzers"""
        results = []
        try:
            url_analyzers = self.analyzers.get('url', [])
            for analyzer in url_analyzers:
                job = self.api.analyzers.run_by_name(
                    analyzer,
                    {'data': url, 'dataType': 'url'}
                )
                result = self._wait_for_job(job)
                if result:
                    results.append(result)
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {str(e)}")
            return results

    def analyze_domain(self, domain):
        """Analyze a domain using available domain analyzers"""
        results = []
        try:
            domain_analyzers = self.analyzers.get('domain', [])
            for analyzer in domain_analyzers:
                job = self.api.analyzers.run_by_name(
                    analyzer,
                    {'data': domain, 'dataType': 'domain'}
                )
                result = self._wait_for_job(job)
                if result:
                    results.append(result)
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing domain {domain}: {str(e)}")
            return results

    def analyze_ip(self, ip):
        """Analyze an IP address using available IP analyzers"""
        results = []
        try:
            ip_analyzers = self.analyzers.get('ip', [])
            for analyzer in ip_analyzers:
                job = self.api.analyzers.run_by_name(
                    analyzer,
                    {'data': ip, 'dataType': 'ip'}
                )
                result = self._wait_for_job(job)
                if result:
                    results.append(result)
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing IP {ip}: {str(e)}")
            return results

    def analyze_file(self, filename, file_data):
        """Analyze a file using available file analyzers"""
        results = []
        try:
            file_analyzers = self.analyzers.get('file', [])
            for analyzer in file_analyzers:
                job = self.api.analyzers.run_by_name(
                    analyzer,
                    {
                        'data': file_data,
                        'dataType': 'file',
                        'filename': filename
                    }
                )
                result = self._wait_for_job(job)
                if result:
                    results.append(result)
            return results
        except Exception as e:
            self.logger.error(f"Error analyzing file {filename}: {str(e)}")
            return results

    def _wait_for_job(self, job, timeout=300, interval=10):
        """Wait for a Cortex analysis job to complete"""
        try:
            job_id = job.id
            start_time = time.time()
            
            while True:
                if time.time() - start_time > timeout:
                    self.logger.warning(f"Job {job_id} timed out")
                    return None

                status = self.api.jobs.get_by_id(job_id).status
                if status == 'Success':
                    report = self.api.jobs.get_report(job_id).report
                    return {
                        'analyzer': job.analyzer_name,
                        'status': 'success',
                        'report': report
                    }
                elif status in ['Failure', 'Deleted']:
                    self.logger.warning(f"Job {job_id} failed or was deleted")
                    return None

                time.sleep(interval)

        except Exception as e:
            self.logger.error(f"Error waiting for job {job_id}: {str(e)}")
            return None

    def _generate_analysis_summary(self, results):
        """Generate a summary of analysis findings"""
        try:
            summary = []

            # Process URL results
            for url_result in results['urls']:
                for analysis in url_result['results']:
                    if analysis and 'report' in analysis:
                        summary.append(
                            f"URL {url_result['url']} analyzed by {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary available')}"
                        )

            # Process domain results
            for domain_result in results['domains']:
                for analysis in domain_result['results']:
                    if analysis and 'report' in analysis:
                        summary.append(
                            f"Domain {domain_result['domain']} analyzed by {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary available')}"
                        )

            # Process IP results
            for ip_result in results['ips']:
                for analysis in ip_result['results']:
                    if analysis and 'report' in analysis:
                        summary.append(
                            f"IP {ip_result['ip']} analyzed by {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary available')}"
                        )

            # Process file results
            for file_result in results['files']:
                for analysis in file_result['results']:
                    if analysis and 'report' in analysis:
                        summary.append(
                            f"File {file_result['filename']} analyzed by {analysis['analyzer']}: "
                            f"{analysis['report'].get('summary', 'No summary available')}"
                        )

            results['summary'] = summary
            self.logger.info(f"Generated analysis summary with {len(summary)} findings")

        except Exception as e:
            self.logger.error(f"Error generating analysis summary: {str(e)}")
            results['summary'] = ["Error generating analysis summary"]

# Example usage
if __name__ == '__main__':
    client = CortexClient()
    sample_indicators = {
        'urls': [{'url': 'http://example.com'}],
        'domains': ['example.com'],
        'ips': ['8.8.8.8'],
        'attachments': []
    }
    results = client.analyze_indicators(sample_indicators)
    print(json.dumps(results, indent=2))
