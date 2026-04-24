import pandas as pd
import re
import urllib.parse
from sklearn.base import BaseEstimator, TransformerMixin

class FeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extract numerical and categorical features from raw honeypot log data (payload, headers, endpoints).
    Suitable for use in scikit-learn pipelines.
    """

    def __init__(self):
        # Common SQL injection keywords
        self.sql_keywords = ['union', 'select', 'insert', 'drop', 'update', 'delete', 'where', 'or', 'and', 'exec']
        # Common XSS keywords and patterns
        self.xss_keywords = ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie']
        # Command injection characters
        self.cmd_chars = [';', '|', '&&', '`', '$', '>']

    def fit(self, X, y=None):
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from the DataFrame containing raw requests.
        Expects a DataFrame with 'payload' and 'endpoint' columns.
        """
        X_out = pd.DataFrame(index=X.index)
        
        # If payload is missing, combine with endpoint to capture attack strings in URL
        full_request = X.get('payload', '') + " " + X.get('endpoint', '')
        
        # 1. Payload length
        X_out['payload_length'] = full_request.str.len()
        
        # 2. Presence of SQL keywords
        X_out['sql_keyword_count'] = full_request.apply(self._count_sql_keywords)
        
        # 3. Presence of XSS scripts
        X_out['xss_keyword_count'] = full_request.apply(self._count_xss_keywords)
        
        # 4. Command injection patterns
        X_out['cmd_injection_count'] = full_request.apply(self._count_cmd_patterns)
        
        # 5. Number of special characters
        X_out['special_char_count'] = full_request.apply(self._count_special_chars)
        
        # 6. Directory traversal patterns (../, %2e%2e%2f, etc.)
        X_out['dir_traversal_count'] = full_request.apply(self._count_dir_traversal)
        
        # 7. Request frequency from IP addresses (if 'ip' is provided, we can count global frequencies)
        if 'ip' in X.columns:
            ip_counts = X['ip'].value_counts()
            X_out['ip_request_frequency'] = X['ip'].map(ip_counts)
        else:
            X_out['ip_request_frequency'] = 1  # Default if IP is not present

        return X_out

    def _decode_payload(self, text: str) -> str:
        if not isinstance(text, str):
            return ''
        return urllib.parse.unquote(text).lower()

    def _count_sql_keywords(self, text: str) -> int:
        decoded = self._decode_payload(text)
        count = sum(1 for kw in self.sql_keywords if kw in decoded)
        # Check for typical SQLi patterns like '1=1'
        if re.search(r'\d+\s*=\s*\d+', decoded):
            count += 1
        return count

    def _count_xss_keywords(self, text: str) -> int:
        decoded = self._decode_payload(text)
        return sum(1 for kw in self.xss_keywords if kw in decoded)

    def _count_cmd_patterns(self, text: str) -> int:
        decoded = self._decode_payload(text)
        return sum(1 for char in self.cmd_chars if char in decoded)

    def _count_special_chars(self, text: str) -> int:
        if not isinstance(text, str):
            return 0
        # Count non-alphanumeric characters
        return len(re.findall(r'[^a-zA-Z0-9\s]', text))

    def _count_dir_traversal(self, text: str) -> int:
        decoded = self._decode_payload(text)
        return decoded.count('../') + decoded.count('..\\')


