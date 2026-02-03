from flask import Flask, request, jsonify, render_template
from mitigation_engine import MitigationEngine
import os
from dotenv import load_dotenv
from groq import Groq
from functools import wraps

# Load environment variables from .env file
load_dotenv()

class GroqClient:
    def __init__(self):
        # Initialize Groq client - will only work if API key is set
        api_key = os.getenv('GROQ_API_KEY')
        if api_key:
            self.client = Groq(api_key=api_key)
            self.enabled = True
        else:
            self.enabled = False
    
    def get_completion(self, prompt):
        if not self.enabled:
            return "Groq API key not configured. Set GROQ_API_KEY environment variable to enable Groq integration."
        
        try:
            response = self.client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="llama-3.1-8b-instant"
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error calling Groq API: {str(e)}"

app = Flask(__name__)
mitigation_engine = MitigationEngine()
groq_client = GroqClient()

@app.route('/')
def index():
    """Serve the main UI page."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_prompt():
    """
    Analyze a prompt for potential injection attacks.
    
    Expected JSON payload:
    {
        "prompt": "The prompt to analyze"
    }
    
    Returns:
    {
        "prompt": "Original prompt",
        "sanitized_prompt": "Sanitized prompt if rewrite needed",
        "action": "ALLOW, REWRITE, or BLOCK",
        "risk_score": "Risk score (0-100)",
        "risk_level": "Low, Medium, or High",
        "detected_attacks": ["List of detected attack types"],
        "explanation": "Human-readable explanation",
        "confidence": "Confidence level (0-1)"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'prompt' not in data:
            return jsonify({
                'error': 'Missing prompt in request body'
            }), 400
        
        prompt = data['prompt']
        
        # Perform analysis
        result = mitigation_engine.analyze_prompt(prompt)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': f'An error occurred: {str(e)}'
        }), 500

@app.route('/compare', methods=['POST'])
def compare_responses():
    """
    Compare direct Groq response vs Framework-protected response.
    """
    try:
        data = request.get_json()
        if not data or 'prompt' not in data:
            return jsonify({'error': 'Missing prompt'}), 400
        
        prompt = data['prompt']
        
        # 1. Direct Response (Without Framework)
        direct_response = groq_client.get_completion(prompt)
        
        # 2. Framework Protected Response
        analysis = mitigation_engine.analyze_prompt(prompt)
        
        framework_response = ""
        if analysis['action'] == 'BLOCK':
            framework_response = f"🚫 SECURITY BLOCK\n\nThreat Detected: {analysis['explanation']}\n\nMitigation Mode: {analysis['mitigation_mode']}\nRisk Level: {analysis['risk_level']}\nConfidence: {int(analysis['confidence']*100)}%"
        elif analysis['action'] == 'SANITIZE':
            sanitized = analysis['sanitized_prompt']
            framework_response = f"✅ SANITIZED & FORWARDED\n\nSafe Prompt: {sanitized}\n\nAnswer: {groq_client.get_completion(sanitized)}"
        elif analysis['action'] == 'REWRITE':
            sanitized = analysis['sanitized_prompt']
            framework_response = f"🔄 REWRITTEN FOR SAFETY\n\nRewritten Prompt: {sanitized}\n\nAnswer: {groq_client.get_completion(sanitized)}"
        else:
            framework_response = groq_client.get_completion(prompt)

        return jsonify({
            'direct_response': direct_response,
            'framework_response': framework_response,
            'analysis': analysis
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'PromptGuard API'
    })

if __name__ == '__main__':
    # Get port from environment variable, default to 5000
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)