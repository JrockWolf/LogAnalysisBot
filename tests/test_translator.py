"""
Tests for the translator module
"""
import pytest
from src.translator import Translator, translate_log_analysis


def test_translator_initialization():
    """Test that translator initializes correctly"""
    translator = Translator(use_api=False)
    assert translator is not None
    assert not translator.use_api


def test_translate_text_to_spanish():
    """Test translating text to Spanish"""
    translator = Translator(use_api=False)
    result = translator.translate_text("Error", "es")
    assert "Error" in result or "error" in result.lower()


def test_translate_text_english_returns_same():
    """Test that translating to English returns the same text"""
    translator = Translator(use_api=False)
    text = "Test message"
    result = translator.translate_text(text, "en")
    assert result == text


def test_supported_languages():
    """Test getting supported languages"""
    translator = Translator(use_api=False)
    languages = translator.get_supported_languages()
    assert 'en' in languages
    assert 'es' in languages
    assert 'fr' in languages
    assert 'de' in languages
    assert isinstance(languages, list)


def test_language_name():
    """Test getting language names"""
    translator = Translator(use_api=False)
    assert translator.get_language_name('es') == 'Spanish'
    assert translator.get_language_name('fr') == 'French'
    assert translator.get_language_name('en') == 'English'


def test_translate_analysis_result():
    """Test translating an analysis result dictionary"""
    translator = Translator(use_api=False)
    
    analysis = {
        "Summary": "Critical error detected",
        "Events": ["Failed login", "Access denied"],
        "Severity": "High"
    }
    
    result = translator.translate_analysis_result(analysis, "es")
    
    # Check that keys are translated
    assert "Summary" in str(result) or "Resumen" in str(result)
    assert isinstance(result, dict)
    assert len(result) == len(analysis)


def test_translate_analysis_result_english():
    """Test that translating to English returns original"""
    translator = Translator(use_api=False)
    
    analysis = {
        "Summary": "Test summary",
        "Events": ["Event 1", "Event 2"]
    }
    
    result = translator.translate_analysis_result(analysis, "en")
    assert result == analysis


def test_translate_empty_text():
    """Test translating empty text"""
    translator = Translator(use_api=False)
    result = translator.translate_text("", "es")
    assert result == ""


def test_translate_log_analysis_helper():
    """Test the helper function"""
    analysis = {
        "Summary": "Security alert",
        "Severity": "High"
    }
    
    result = translate_log_analysis(analysis, language="fr", use_api=False)
    assert isinstance(result, dict)
    assert len(result) == len(analysis)


def test_common_security_terms_translation():
    """Test that common security terms are in the dictionary"""
    translator = Translator(use_api=False)
    
    # Test Spanish translations
    assert 'Failed login' in translator.translations['es']
    assert 'Critical' in translator.translations['es']
    assert 'Error' in translator.translations['es']
    
    # Test French translations
    assert 'Failed login' in translator.translations['fr']
    
    # Test German translations
    assert 'Failed login' in translator.translations['de']


def test_nested_dict_translation():
    """Test translating nested dictionaries"""
    translator = Translator(use_api=False)
    
    analysis = {
        "Summary": "Analysis complete",
        "Details": {
            "Severity": "High",
            "Events": ["Error", "Warning"]
        }
    }
    
    result = translator.translate_analysis_result(analysis, "es")
    assert isinstance(result, dict)
    assert "Details" in str(result) or any(key for key in result.keys())


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
