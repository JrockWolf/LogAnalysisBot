"""
Translator module for LogAnalysisBot
Translates log analysis results and summaries into multiple languages
"""

from typing import Dict, List, Optional
import os


class Translator:
    """
    Translator class that can translate log analysis results into multiple languages.
    Supports both API-based translation (Google Translate) and simple dictionary-based translation.
    """
    
    def __init__(self, use_api: bool = False):
        """
        Initialize the translator
        
        Args:
            use_api: If True, use Google Translate API (requires googletrans). 
                    If False, use simple dictionary-based translation.
        """
        self.use_api = use_api
        self.translator = None
        
        if use_api:
            try:
                from googletrans import Translator as GoogleTranslator
                self.translator = GoogleTranslator()
            except ImportError:
                print("Warning: googletrans not installed. Falling back to dictionary-based translation.")
                print("Install with: pip install googletrans==4.0.0-rc1")
                self.use_api = False
        
        # Dictionary-based translations for common security terms
        self.translations = {
            'es': {  # Spanish
                'Summary': 'Resumen',
                'Events': 'Eventos',
                'Severity': 'Severidad',
                'Timestamp': 'Marca de tiempo',
                'Error': 'Error',
                'Warning': 'Advertencia',
                'Critical': 'Crítico',
                'Info': 'Información',
                'Failed login': 'Inicio de sesión fallido',
                'Successful login': 'Inicio de sesión exitoso',
                'Authentication': 'Autenticación',
                'Access denied': 'Acceso denegado',
                'Security alert': 'Alerta de seguridad',
                'Malicious activity': 'Actividad maliciosa',
                'Suspicious': 'Sospechoso',
                'Attack detected': 'Ataque detectado',
                'Firewall': 'Cortafuegos',
                'High': 'Alto',
                'Medium': 'Medio',
                'Low': 'Bajo',
            },
            'fr': {  # French
                'Summary': 'Résumé',
                'Events': 'Événements',
                'Severity': 'Gravité',
                'Timestamp': 'Horodatage',
                'Error': 'Erreur',
                'Warning': 'Avertissement',
                'Critical': 'Critique',
                'Info': 'Information',
                'Failed login': 'Échec de connexion',
                'Successful login': 'Connexion réussie',
                'Authentication': 'Authentification',
                'Access denied': 'Accès refusé',
                'Security alert': 'Alerte de sécurité',
                'Malicious activity': 'Activité malveillante',
                'Suspicious': 'Suspect',
                'Attack detected': 'Attaque détectée',
                'Firewall': 'Pare-feu',
                'High': 'Élevé',
                'Medium': 'Moyen',
                'Low': 'Faible',
            },
            'de': {  # German
                'Summary': 'Zusammenfassung',
                'Events': 'Ereignisse',
                'Severity': 'Schweregrad',
                'Timestamp': 'Zeitstempel',
                'Error': 'Fehler',
                'Warning': 'Warnung',
                'Critical': 'Kritisch',
                'Info': 'Information',
                'Failed login': 'Fehlgeschlagene Anmeldung',
                'Successful login': 'Erfolgreiche Anmeldung',
                'Authentication': 'Authentifizierung',
                'Access denied': 'Zugriff verweigert',
                'Security alert': 'Sicherheitswarnung',
                'Malicious activity': 'Böswillige Aktivität',
                'Suspicious': 'Verdächtig',
                'Attack detected': 'Angriff erkannt',
                'Firewall': 'Firewall',
                'High': 'Hoch',
                'Medium': 'Mittel',
                'Low': 'Niedrig',
            },
            'zh': {  # Chinese (Simplified)
                'Summary': '摘要',
                'Events': '事件',
                'Severity': '严重程度',
                'Timestamp': '时间戳',
                'Error': '错误',
                'Warning': '警告',
                'Critical': '严重',
                'Info': '信息',
                'Failed login': '登录失败',
                'Successful login': '登录成功',
                'Authentication': '认证',
                'Access denied': '访问被拒绝',
                'Security alert': '安全警报',
                'Malicious activity': '恶意活动',
                'Suspicious': '可疑',
                'Attack detected': '检测到攻击',
                'Firewall': '防火墙',
                'High': '高',
                'Medium': '中',
                'Low': '低',
            },
            'ja': {  # Japanese
                'Summary': '要約',
                'Events': 'イベント',
                'Severity': '重大度',
                'Timestamp': 'タイムスタンプ',
                'Error': 'エラー',
                'Warning': '警告',
                'Critical': '重大',
                'Info': '情報',
                'Failed login': 'ログイン失敗',
                'Successful login': 'ログイン成功',
                'Authentication': '認証',
                'Access denied': 'アクセス拒否',
                'Security alert': 'セキュリティ警告',
                'Malicious activity': '悪意のある活動',
                'Suspicious': '疑わしい',
                'Attack detected': '攻撃検出',
                'Firewall': 'ファイアウォール',
                'High': '高',
                'Medium': '中',
                'Low': '低',
            }
        }
    
    def translate_text(self, text: str, target_language: str = 'es') -> str:
        """
        Translate text to the target language
        
        Args:
            text: Text to translate
            target_language: Target language code (es, fr, de, zh, ja, etc.)
            
        Returns:
            Translated text
        """
        if not text:
            return text
            
        if target_language == 'en':
            return text
        
        # Use API translation if available
        if self.use_api and self.translator:
            try:
                result = self.translator.translate(text, dest=target_language)
                return result.text
            except Exception as e:
                print(f"API translation failed: {e}. Falling back to dictionary-based translation.")
        
        # Dictionary-based translation
        if target_language in self.translations:
            translated = text
            for english, translation in self.translations[target_language].items():
                translated = translated.replace(english, translation)
            return translated
        
        return text
    
    def translate_analysis_result(self, analysis: Dict, target_language: str = 'es') -> Dict:
        """
        Translate an entire analysis result dictionary
        
        Args:
            analysis: Analysis result dictionary containing summary, events, etc.
            target_language: Target language code
            
        Returns:
            Translated analysis dictionary
        """
        if target_language == 'en':
            return analysis
        
        translated = {}
        
        for key, value in analysis.items():
            # Translate the key
            translated_key = self.translate_text(key, target_language)
            
            # Translate the value based on its type
            if isinstance(value, str):
                translated[translated_key] = self.translate_text(value, target_language)
            elif isinstance(value, list):
                translated[translated_key] = [
                    self.translate_text(item, target_language) if isinstance(item, str) else item
                    for item in value
                ]
            elif isinstance(value, dict):
                translated[translated_key] = self.translate_analysis_result(value, target_language)
            else:
                translated[translated_key] = value
        
        return translated
    
    def get_supported_languages(self) -> List[str]:
        """
        Get list of supported language codes
        
        Returns:
            List of supported language codes
        """
        if self.use_api:
            return ['en', 'es', 'fr', 'de', 'zh', 'ja', 'ko', 'ar', 'ru', 'pt', 'it', 'nl', 'pl', 'tr']
        else:
            return ['en'] + list(self.translations.keys())
    
    def get_language_name(self, code: str) -> str:
        """
        Get the full name of a language from its code
        
        Args:
            code: Language code (e.g., 'es', 'fr')
            
        Returns:
            Language name (e.g., 'Spanish', 'French')
        """
        language_names = {
            'en': 'English',
            'es': 'Spanish',
            'fr': 'French',
            'de': 'German',
            'zh': 'Chinese',
            'ja': 'Japanese',
            'ko': 'Korean',
            'ar': 'Arabic',
            'ru': 'Russian',
            'pt': 'Portuguese',
            'it': 'Italian',
            'nl': 'Dutch',
            'pl': 'Polish',
            'tr': 'Turkish'
        }
        return language_names.get(code, code)


def translate_log_analysis(analysis_result: Dict, language: str = 'es', use_api: bool = False) -> Dict:
    """
    Helper function to translate log analysis results
    
    Args:
        analysis_result: The analysis result dictionary
        language: Target language code
        use_api: Whether to use API-based translation
        
    Returns:
        Translated analysis result
    """
    translator = Translator(use_api=use_api)
    return translator.translate_analysis_result(analysis_result, language)


if __name__ == "__main__":
    # Example usage
    translator = Translator(use_api=False)
    
    # Example analysis result
    sample_analysis = {
        "Summary": "3 critical security events detected",
        "Events": [
            "Failed login from 192.168.1.100",
            "Suspicious activity detected",
            "Access denied for user admin"
        ],
        "Severity": "High",
        "Timestamp": "2026-01-03 23:00:00"
    }
    
    print("Original (English):")
    print(sample_analysis)
    print("\n" + "="*60 + "\n")
    
    for lang_code in ['es', 'fr', 'de', 'zh', 'ja']:
        print(f"Translated to {translator.get_language_name(lang_code)}:")
        translated = translator.translate_analysis_result(sample_analysis, lang_code)
        print(translated)
        print("\n" + "="*60 + "\n")
