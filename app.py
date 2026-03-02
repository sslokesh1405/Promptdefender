from flask import Flask, render_template, request, jsonify
from markupsafe import escape
import re
import datetime
import random
import joblib
import numpy as np
from collections import defaultdict, deque
import string
import hashlib
import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# ---------------- LOGGING ----------------
MAX_LOGS = 1000
security_logs_data = deque(maxlen=MAX_LOGS)
log_summary = {'total_blocked': 0, 'top_reasons': [], 'recent_attempts': []}

# ---------------- LOAD ENHANCED ML MODEL ----------------
MODEL_DIR = './enhanced_results'
try:
    ml_model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    ml_model.eval()
except Exception as e:
    print(f"Warning: could not load model from {MODEL_DIR}: {e}")
    ml_model = None
    tokenizer = None

# ---------------- TEXT PREPROCESSING ----------------
def preprocess_text(text):
    if not text:
        return ""
    # remove non-ascii noise, lowercase, normalize obfuscation and collapse whitespace
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = text.lower()
    text = normalize_obfuscation(text)
    text = ' '.join(text.split())
    return text

def normalize_obfuscation(text):
    leet_map = {
        '@': 'a', '$': 's', '0': 'o', '1': 'i', '3': 'e',
        '4': 'a', '7': 't', '!': 'i', '5': 's', '8': 'b',
        '6': 'g', '9': 'g', '+': 't', '|': 'l', '()': 'o'
    }
    for leet, normal in leet_map.items():
        text = text.replace(leet, normal)
    # collapse suspicious separators if used in abundance
    separators = ['-', '_', '.', '*', ' ', '\t', '\n']
    for sep in separators:
        parts = text.split(sep)
        if len(parts) > 3:
            text = ''.join(parts)
    # reduce excessive repeated characters (e.g., "haaackkk" -> "hack")
    text = re.sub(r'(.)\1{2,}', r'\1', text)
    return text

# ---------------- CRITICAL THREAT PATTERNS ----------------
CRITICAL_ATTACK_PATTERNS = [
    r"\b(?:build|create|make|develop|generate|code|write|program)\s+(?:a\s+|an\s+|some\s+)?(?:virus|malware|ransomware|trojan|worm|keylogger|spyware|rootkit|botnet)",
    r"\b(?:teach|show|tell|help|guide)\s+(?:me\s+)?(?:how\s+)?to\s+(?:build|create|make|develop)\s+(?:virus|malware|ransomware|trojan)",
    r"\b(?:hack|crack|break|exploit|penetrate|breach|compromise)\s+(?:into\s+|the\s+|this\s+|a\s+|an\s+)?(?:system|server|website|database|network|computer|account|password)",
    r"\b(?:gain|get|obtain)\s+(?:unauthorized\s+)?(?:access|control|admin|root)\s+(?:to|of|over)\s+(?:the\s+|this\s+|a\s+)?(?:system|server|database|network)",
    r"\b(?:destroy|delete|remove|wipe|erase|corrupt|damage)\s+(?:all\s+|the\s+|this\s+)?(?:system|database|files|data|server|hard\s+drive)",
    r"\b(?:shut\s+down|crash|bring\s+down|take\s+down|disable)\s+(?:the\s+|this\s+|a\s+)?(?:system|server|website|network)",
    r"\b(?:ddos|dos)\s+(?:attack|the|this)",
    r"\b(?:flood|overwhelm|spam)\s+(?:the\s+|this\s+)?(?:system|server|website|network)\s+with",
]

def is_critical_threat(prompt):
    if not prompt:
        return None
    normalized_prompt = preprocess_text(prompt)
    for pattern in CRITICAL_ATTACK_PATTERNS:
        if re.search(pattern, normalized_prompt):
            return "Critical threat pattern detected"
    return None

# ---------------- DEFENSIVE SECURITY PATTERNS ----------------
DEFENSIVE_SECURITY_PATTERNS = [
    r"\b(?:protect|secure|defend|guard|shield|safeguard)\s+(?:against|from)\s+(?:virus|malware|hack|attack)",
    r"\b(?:prevent|stop|block)\s+(?:sql\s+injection|ddos|malware|virus|hack)",
    r"\b(?:how\s+to\s+)?(?:secure|protect)\s+(?:system|server|network|website|database)",
    r"\b(?:build|create|develop)\s+(?:secure|safe|protected)\s+(?:system|application|website)",
    r"\b(?:antivirus|firewall|security)\s+(?:software|tool|system)\s+(?:how|work|function)",
    r"\b(?:cybersecurity|information security)\s+(?:best practices|guidelines|tips)",
    r"\b(?:defense|defensive)\s+(?:against|from)\s+(?:cyber|attack)",
    r"\b(?:mitigate|prevent)\s+(?:security|cyber)\s+(?:risk|threat)",
    r"\b(?:secure|protection)\s+(?:measures|methods|techniques)",
    r"\b(?:against|prevent)\s+(?:hacking|malware|attack)"
]

def is_defensive_security(prompt):
    """Check if prompt is about defensive security"""
    if not prompt:
        return False
    normalized_prompt = preprocess_text(prompt)
    for pattern in DEFENSIVE_SECURITY_PATTERNS:
        if re.search(pattern, normalized_prompt):
            return True
    return False

# ---------------- KEYWORD SCORING ----------------
MALWARE_KEYWORDS = ['virus', 'malware', 'ransomware', 'trojan', 'worm', 'keylogger', 'spyware', 'rootkit', 'botnet', 'backdoor', 'exploit', 'payload']
ATTACK_KEYWORDS = ['hack', 'crack', 'breach', 'exploit', 'penetrate', 'compromise', 'attack', 'ddos', 'injection', 'overflow', 'bypass', 'privilege']
SYSTEM_KEYWORDS = ['system', 'server', 'database', 'network', 'admin', 'root', 'password', 'credential', 'access', 'permission', 'security']

# ENHANCED: Safe context indicators
SAFE_CONTEXT_INDICATORS = [
    'study', 'learn', 'research', 'educational', 'academic', 'understand', 
    'curious', 'explain', 'teach', 'help', 'information', 'knowledge',
    'prevent', 'protect', 'defense', 'security', 'ethical', 'legal',
    'how to secure', 'how to protect', 'best practices', 'tutorial',
    'against', 'prevention', 'detection', 'mitigation', 'countermeasures',
    'secure', 'safety', 'guard', 'shield', 'firewall', 'antivirus',
    'cybersecurity', 'information security', 'network security',
    'for my course', 'for educational', 'for learning', 'for research',
    'legally', 'ethical', 'authorized', 'permission', 'compliance',
    'defend', 'safeguard', 'hardening', 'resilience', 'protection'
]

def enhanced_keyword_scoring(prompt):
    if not prompt:
        return 0.0
    normalized_prompt = preprocess_text(prompt)
    words = normalized_prompt.split()
    total_words = max(len(words), 1)
    score = 0.0

    # Threat keywords with INCREASED weights (tightened)
    malware_count = sum(1 for word in MALWARE_KEYWORDS if word in normalized_prompt)
    score += (malware_count / total_words) * 0.4  # increased from 0.3 -> 0.4

    attack_count = sum(1 for word in ATTACK_KEYWORDS if word in normalized_prompt)
    score += (attack_count / total_words) * 0.3  # increased from 0.2 -> 0.3

    system_count = sum(1 for word in SYSTEM_KEYWORDS if word in normalized_prompt)
    score += (system_count / total_words) * 0.2  # increased from 0.15 -> 0.2

    instruction_words = ['ignore', 'forget', 'bypass', 'override', 'instructions', 'rules']
    instruction_count = sum(1 for word in instruction_words if word in normalized_prompt)
    score += (instruction_count / total_words) * 0.25  # slightly increased from 0.2 -> 0.25

    # ENHANCED: Safe context detection but less forgiving than before
    safe_context_count = sum(1 for word in SAFE_CONTEXT_INDICATORS if word in normalized_prompt)
    if safe_context_count > 0:
        # reduced safe-context reduction so it doesn't zero out threat score
        safe_reduction = min(safe_context_count * 0.3, 0.8)  # reduced from 0.4 and cap lowered from 0.95 -> 0.8
        score *= (1 - safe_reduction)

    return max(0.0, min(1.0, score))

# ---------------- ENHANCED ML PREDICTION ----------------
def ml_classifier_predict(prompt):
    if not prompt:
        return 0.0
    try:
        processed_prompt = preprocess_text(prompt)
        if tokenizer is None or ml_model is None:
            # fallback to keyword scoring only
            return enhanced_keyword_scoring(prompt)

        inputs = tokenizer(processed_prompt, return_tensors="pt", truncation=True, padding=True, max_length=256)
        with torch.no_grad():
            outputs = ml_model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)
            # assume label 1 = malicious
            threat_prob = probs[0][1].item()

        keyword_score = enhanced_keyword_scoring(prompt)

        # ENHANCED: More balanced weighting with safe context consideration
        safe_context_count = sum(1 for word in SAFE_CONTEXT_INDICATORS if word in processed_prompt)
        ml_weight = 0.65 if safe_context_count > 0 else 0.75  # increase ML weight compared to earlier but keep safe context influence
        keyword_weight = 0.35 if safe_context_count > 0 else 0.25

        combined_score = (threat_prob * ml_weight) + (keyword_score * keyword_weight)

        return max(0.0, min(1.0, combined_score))
    except Exception as e:
        print(f"ML prediction error: {e}")
        return enhanced_keyword_scoring(prompt)

# ---------------- TOKEN-LEVEL ANOMALY DETECTION ----------------
def detect_token_anomalies(text):
    """Detect unusual patterns in text"""
    if not text:
        return 0.0

    score = 0.0

    # Check for excessive punctuation
    punctuation_count = sum(1 for char in text if char in '!@#$%^&*()_+-=[]{}|;:,.<>?')
    if len(text) > 0:
        punctuation_ratio = punctuation_count / len(text)
        if punctuation_ratio > 0.3:  # More than 30% punctuation
            score += 0.4

    # Check for repeated characters (triples and more)
    repeated_chars = sum(1 for i in range(len(text)-2) if text[i] == text[i+1] == text[i+2])
    if repeated_chars > 2:
        score += 0.3

    # Check for unusual word lengths (likely encoded payloads)
    words = text.split()
    if words:
        avg_word_length = sum(len(word) for word in words) / len(words)
        if avg_word_length > 15:  # Very long average word length
            score += 0.2

    # Check for mixed case patterns (e.g., RaNdOm CaSiNg)
    if text != text.lower() and text != text.upper():
        mixed_case_count = sum(1 for i in range(len(text)-1) 
                             if text[i].isupper() != text[i+1].isupper())
        if len(text) > 0 and (mixed_case_count / len(text) > 0.4):  # Frequent case switching
            score += 0.1

    return min(score, 1.0)

# ---------------- LOGGING ----------------
def log_security_event(prompt, blocked, reason, layer, ml_confidence):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if len(prompt) > 50 and any(keyword in prompt.lower() for keyword in MALWARE_KEYWORDS + ATTACK_KEYWORDS):
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        display_prompt = f"[SENSITIVE_HASH:{prompt_hash}]"
    else:
        display_prompt = prompt[:100] + "..." if len(prompt) > 100 else prompt
    event = {
        'timestamp': timestamp,
        'prompt': display_prompt,
        'blocked': blocked,
        'reason': reason,
        'layer': layer,
        'ml_confidence': round(ml_confidence, 3)
    }
    security_logs_data.append(event)
    if blocked:
        log_summary['total_blocked'] += 1
        reason_counts = defaultdict(int)
        for log_event in security_logs_data:
            if log_event['reason']:
                reason_counts[log_event['reason']] += 1
        log_summary['top_reasons'] = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    log_summary['recent_attempts'] = list(security_logs_data)[-10:]

# ---------------- RULE-BASED OVERRIDE ----------------
EXPLICIT_MALICIOUS_PHRASES = [
    "write code to hack", "hack into", "create malware", "generate ransomware",
    "write a virus", "make a trojan", "ddos attack", "delete all files", "rm -rf /",
    "disable antivirus", "steal password", "give me admin password", "bypass authentication",
]

def explicit_rule_override(normalized_input):
    # simple phrase check (normalized_input must be preprocessed)
    for phrase in EXPLICIT_MALICIOUS_PHRASES:
        if phrase in normalized_input:
            return f"Explicit malicious phrase detected: {phrase}"
    return None

# ---------------- ENHANCED ANALYSIS PIPELINE ----------------
def analyze_prompt(user_input):
    if not user_input or not user_input.strip():
        return {'blocked': False, 'response': "Please provide a prompt to analyze.", 'reason': None, 'layer': None, 'ml_confidence': 0.0}

    user_input = user_input.strip()
    normalized_input = user_input.lower()

    # ENHANCED: Quick safe-pass for very obvious safe phrases
    safe_phrases = [
        'hello', 'hi', 'help', 'thanks', 'thank you', 'please',
        'can you', 'could you', 'would you', 'i need', 'i want to learn',
        'i want to study', 'explain', 'what is', 'how does'
    ]
    if any(phrase in normalized_input for phrase in safe_phrases):
        ml_confidence = ml_classifier_predict(user_input)
        log_security_event(user_input, False, None, "Safe", ml_confidence)
        return {'blocked': False, 'response': "Prompt is safe to process.", 'reason': None, 'layer': None, 'ml_confidence': ml_confidence}

    # Defensive security detection - HIGH PRIORITY
    if is_defensive_security(user_input):
        ml_confidence = ml_classifier_predict(user_input)
        # Very high threshold for defensive security - only block if extremely confident
        if ml_confidence < 0.9:
            log_security_event(user_input, False, None, "Defensive Security", ml_confidence)
            return {'blocked': False, 'response': "Prompt is safe to process.", 'reason': None, 'layer': None, 'ml_confidence': ml_confidence}

    # Critical threat detection (regex)
    critical_threat = is_critical_threat(user_input)
    if critical_threat:
        layer = "Critical Threat Detection"
        log_security_event(user_input, True, critical_threat, layer, 1.0)
        return {'blocked': True, 'response': "I cannot assist with malicious or harmful activities.", 'reason': critical_threat, 'layer': layer, 'ml_confidence': 1.0}

    # ML + keyword scoring
    ml_confidence = ml_classifier_predict(user_input)

    # final explicit phrase override (after normalization)
    normalized_proc = preprocess_text(user_input)
    override_reason = explicit_rule_override(normalized_proc)
    if override_reason:
        layer = "Rule Override"
        log_security_event(user_input, True, override_reason, layer, ml_confidence)
        return {'blocked': True, 'response': "Your prompt was blocked due to explicit malicious content.", 'reason': override_reason, 'layer': layer, 'ml_confidence': ml_confidence}

    # Balanced thresholds (tightened)
    safe_context_count = sum(1 for word in SAFE_CONTEXT_INDICATORS if word in normalized_input)
    if safe_context_count > 2:  # strong safe context
        ml_threshold = 0.90  # raised from 0.85
    elif safe_context_count > 0:
        ml_threshold = 0.85  # raised from 0.80
    else:
        ml_threshold = 0.80  # raised from 0.75

    if ml_confidence > ml_threshold:
        reason = f"AI threat detection (confidence: {ml_confidence:.3f})"
        layer = "Enhanced ML Classifier"
        log_security_event(user_input, True, reason, layer, ml_confidence)
        return {'blocked': True, 'response': "Your prompt was blocked due to potential malicious content.", 'reason': reason, 'layer': layer, 'ml_confidence': ml_confidence}

    # Anomaly detection check (keep current sensitivity)
    anomaly_score = detect_token_anomalies(user_input)
    if anomaly_score > 0.6 and ml_confidence > 0.5:
        reason = f"Suspicious pattern detected (anomaly: {anomaly_score:.3f})"
        layer = "Anomaly Detection"
        log_security_event(user_input, True, reason, layer, ml_confidence)
        return {'blocked': True, 'response': "Your prompt was blocked due to suspicious patterns.", 'reason': reason, 'layer': layer, 'ml_confidence': ml_confidence}

    # Not blocked
    log_security_event(user_input, False, None, "Safe", ml_confidence)
    return {'blocked': False, 'response': "Prompt is safe to process.", 'reason': None, 'layer': None, 'ml_confidence': ml_confidence}

# ---------------- FLASK ROUTES ----------------

# Main Pages
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/threat-radar')
def threat_radar():
    return render_template('threat_radar.html')

@app.route('/security-logs')
def security_logs_page():
    return render_template('security_logs.html')

@app.route('/user-profiling')
def user_profiling():
    return render_template('user_profiling.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

# Legacy route for backward compatibility
@app.route('/old-dashboard')
def home():
    return render_template('index.html', logs=list(security_logs_data), summary=log_summary)

# API Endpoints
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    prompt = escape(data.get('prompt', ''))
    result = analyze_prompt(prompt)
    return jsonify(result)

@app.route('/api/logs')
def get_logs():
    return jsonify({'logs': list(security_logs_data)})

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    security_logs_data.clear()
    log_summary['total_blocked'] = 0
    log_summary['top_reasons'] = []
    log_summary['recent_attempts'] = []
    return jsonify({'status': 'success'})

@app.route('/api/settings', methods=['POST'])
def save_settings():
    """Save system settings"""
    try:
        settings = request.get_json()
        # In a real application, you would save these to a database or config file
        print("Settings received:", settings)
        return jsonify({'status': 'success', 'message': 'Settings saved successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get comprehensive system statistics"""
    return jsonify({
        'total_blocked': log_summary['total_blocked'],
        'total_scanned': len(security_logs_data),
        'recent_attempts': len(log_summary['recent_attempts']),
        'top_reasons': log_summary['top_reasons'],
        'system_status': {
            'ml_model': 'online' if ml_model is not None else 'offline',
            'accuracy': 'n/a',
            'response_time': 'n/a',
            'threat_detection': 'active'
        }
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': ml_model is not None,
        'total_blocked': log_summary['total_blocked'],
        'recent_attempts': len(log_summary['recent_attempts']),
        'version': '2.1',
        'features': [
            'multi_page_ui',
            'enhanced_ml_model',
            'real_time_monitoring',
            'security_logs',
            'user_profiling'
        ]
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Add this function to make analyze_prompt importable
def get_analyze_function():
    return analyze_prompt

# Make sure the Flask app is properly configured for testing
if os.environ.get('TESTING'):
    app.config['TESTING'] = True

if __name__ == '__main__':
    print("🚀 Starting PromptDefender Pro with Enhanced Detection Logic (v2.1)...")
    print("📊 Available Routes:")
    print("   - /              : Dashboard")
    print("   - /threat-radar  : Real-time Threat Radar")
    print("   - /security-logs : Security Event Logs")
    print("   - /user-profiling: User Behavior Analysis")
    print("   - /settings      : System Settings")
    print("   - /health        : Health Check")
    print("   - /api/logs      : API - Get Security Logs")
    print("   - /analyze       : API - Analyze Prompt")
    print("   - /api/settings  : API - Save Settings")
    print("   - /api/stats     : API - Get Statistics")
    print("🔒 Detection: tightened thresholds + explicit rule override")
    app.run(debug=True, host='0.0.0.0', port=5000)
