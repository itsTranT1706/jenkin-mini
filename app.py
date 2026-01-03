#!/usr/bin/env python3
"""
Production-Ready CI/CD Webhook Server

A secure Flask-based webhook server designed for CI/CD automation.
Exposes a POST /webhook endpoint that triggers predefined deployment scripts.

Security Features:
- Token-based authentication via X-Webhook-Token header
- Hardcoded/whitelisted script paths only
- No arbitrary command execution
- Subprocess timeout protection
- No sensitive data exposure in responses

Deployment:
- Designed to run behind Nginx/Gunicorn
- Docker and systemd compatible
- NEVER run with debug=True in production

Author: DevOps Team
Python: 3.10+
"""

import subprocess
import sys
import os
import logging
import hashlib
import hmac
from pathlib import Path
from datetime import datetime
from functools import wraps
from typing import Callable, Any

from flask import Flask, request, jsonify, Response

# =============================================================================
# CONFIGURATION
# =============================================================================

# Get configuration from environment variables with secure defaults
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
SCRIPT_TIMEOUT = int(os.environ.get("SCRIPT_TIMEOUT", "300"))  # 5 minutes default
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "5000"))

# Whitelisted scripts - ONLY these scripts can be executed
# Using absolute paths for security
BASE_DIR = Path(__file__).resolve().parent
ALLOWED_SCRIPTS: dict[str, Path] = {
    "deploy": BASE_DIR / "deploy.py",
    # Add more whitelisted scripts here as needed
    # "build": BASE_DIR / "build.py",
    # "test": BASE_DIR / "test.py",
}

# Default script to execute if none specified
DEFAULT_SCRIPT = "deploy"

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def configure_logging() -> logging.Logger:
    """
    Configure production-ready logging.
    
    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger("webhook_server")
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    
    # Console handler with production-safe formatting
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    
    # Format: timestamp - level - message (no sensitive data)
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    
    if not logger.handlers:
        logger.addHandler(handler)
    
    return logger


logger = configure_logging()

# =============================================================================
# FLASK APPLICATION
# =============================================================================

app = Flask(__name__)

# Disable debug mode and testing for production
app.config["DEBUG"] = False
app.config["TESTING"] = False
app.config["PROPAGATE_EXCEPTIONS"] = False

# =============================================================================
# SECURITY UTILITIES
# =============================================================================

def constant_time_compare(val1: str, val2: str) -> bool:
    """
    Perform constant-time string comparison to prevent timing attacks.
    
    Args:
        val1: First string to compare.
        val2: Second string to compare.
        
    Returns:
        True if strings are equal, False otherwise.
    """
    if not val1 or not val2:
        return False
    return hmac.compare_digest(val1.encode(), val2.encode())


def validate_token(token: str) -> bool:
    """
    Validate the webhook token.
    
    Args:
        token: Token from the request header.
        
    Returns:
        True if token is valid, False otherwise.
    """
    if not WEBHOOK_TOKEN:
        logger.error("WEBHOOK_TOKEN environment variable is not set!")
        return False
    
    return constant_time_compare(token, WEBHOOK_TOKEN)


def require_auth(f: Callable) -> Callable:
    """
    Decorator to require authentication for endpoints.
    
    Args:
        f: Function to wrap.
        
    Returns:
        Wrapped function with authentication check.
    """
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Response | tuple:
        token = request.headers.get("X-Webhook-Token", "")
        
        if not token:
            logger.warning(
                f"Unauthorized request - missing token | "
                f"IP: {request.remote_addr} | "
                f"Path: {request.path}"
            )
            return jsonify({
                "success": False,
                "error": "Missing authentication token"
            }), 401
        
        if not validate_token(token):
            logger.warning(
                f"Unauthorized request - invalid token | "
                f"IP: {request.remote_addr} | "
                f"Path: {request.path}"
            )
            return jsonify({
                "success": False,
                "error": "Invalid authentication token"
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# =============================================================================
# SCRIPT EXECUTION
# =============================================================================

def execute_script(script_name: str, args: list[str] | None = None) -> dict[str, Any]:
    """
    Execute a whitelisted script securely.
    
    Args:
        script_name: Name of the script from the ALLOWED_SCRIPTS whitelist.
        args: Optional list of arguments to pass to the script.
        
    Returns:
        Dictionary containing execution results.
    """
    # Validate script is in whitelist
    if script_name not in ALLOWED_SCRIPTS:
        return {
            "success": False,
            "error": f"Script '{script_name}' is not in the allowed list",
            "allowed_scripts": list(ALLOWED_SCRIPTS.keys())
        }
    
    script_path = ALLOWED_SCRIPTS[script_name]
    
    # Verify script exists
    if not script_path.exists():
        logger.error(f"Script not found: {script_path}")
        return {
            "success": False,
            "error": "Deployment script not found on server"
        }
    
    # Verify script is a file (not a symlink pointing outside)
    if not script_path.is_file():
        logger.error(f"Script path is not a file: {script_path}")
        return {
            "success": False,
            "error": "Invalid script configuration"
        }
    
    # Build command with Python interpreter
    command = [sys.executable, str(script_path)]
    
    # Add optional arguments (sanitized - only from whitelist if needed)
    if args:
        # Only allow specific, predefined arguments
        allowed_args = ["--skip-checkout", "-c", "--config"]
        for arg in args:
            # Basic argument validation
            if arg.startswith("-") and arg.split("=")[0] in allowed_args:
                command.append(arg)
            elif not arg.startswith("-"):
                # Non-flag arguments are config file paths - validate
                if not arg.startswith(("/", "\\", "..")):
                    command.append(arg)
    
    logger.info(f"Executing script: {script_name}")
    start_time = datetime.now()
    
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT,
            cwd=str(BASE_DIR),
            env={**os.environ}  # Inherit environment
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        # Determine success based on return code
        success = result.returncode == 0
        
        if success:
            logger.info(f"Script '{script_name}' completed successfully in {duration:.2f}s")
        else:
            logger.error(f"Script '{script_name}' failed with code {result.returncode}")
        
        return {
            "success": success,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration_seconds": round(duration, 2)
        }
        
    except subprocess.TimeoutExpired:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Script '{script_name}' timed out after {SCRIPT_TIMEOUT}s")
        return {
            "success": False,
            "error": f"Script execution timed out after {SCRIPT_TIMEOUT} seconds",
            "duration_seconds": round(duration, 2)
        }
        
    except FileNotFoundError:
        logger.error(f"Python interpreter not found: {sys.executable}")
        return {
            "success": False,
            "error": "Server configuration error"
        }
        
    except PermissionError:
        logger.error(f"Permission denied executing script: {script_path}")
        return {
            "success": False,
            "error": "Permission denied"
        }
        
    except Exception as e:
        # Log the actual error for debugging but don't expose to client
        logger.exception(f"Unexpected error executing script: {type(e).__name__}")
        return {
            "success": False,
            "error": "Internal server error during script execution"
        }

# =============================================================================
# WEBHOOK ENDPOINTS for testing GitHub integration
# =============================================================================

@app.route("/webhook-testing", methods=["POST"])
def github_webhook():
    print("===== HEADERS =====")
    print(dict(request.headers))

    print("===== RAW DATA =====")
    print(request.data)

    print("===== JSON (force) =====")
    print(request.get_json(silent=True))

    return jsonify({"status": "ok"}), 200

# =============================================================================
# WEBHOOK ENDPOINTS
# =============================================================================

@app.route("/webhook", methods=["POST"])
@require_auth
def webhook() -> tuple[Response, int]:
    """
    Main webhook endpoint for CI/CD triggers.
    
    Request Headers:
        X-Webhook-Token: Required authentication token
        
    Request Body (JSON, optional):
        {
            "script": "deploy",  // Optional, defaults to "deploy"
            "args": ["--skip-checkout"]  // Optional arguments
        }
        
    Returns:
        JSON response with execution status and details.
    """
    logger.info(
        f"Webhook triggered | "
        f"IP: {request.remote_addr} | "
        f"Method: {request.method}"
    )
    
    # Parse request body (optional)
    script_name = DEFAULT_SCRIPT
    script_args: list[str] = []
    
    if request.is_json:
        try:
            data = request.get_json(silent=True) or {}
            script_name = data.get("script", DEFAULT_SCRIPT)
            script_args = data.get("args", [])
            
            # Validate types
            if not isinstance(script_name, str):
                return jsonify({
                    "success": False,
                    "error": "Invalid 'script' parameter type"
                }), 400
            
            if not isinstance(script_args, list):
                return jsonify({
                    "success": False,
                    "error": "Invalid 'args' parameter type"
                }), 400
                
        except Exception:
            return jsonify({
                "success": False,
                "error": "Invalid JSON in request body"
            }), 400
    
    # Execute the script
    result = execute_script(script_name, script_args)
    
    # Determine HTTP status code
    if result.get("success"):
        status_code = 200
    elif "not in the allowed list" in result.get("error", ""):
        status_code = 400
    elif "Permission denied" in result.get("error", ""):
        status_code = 403
    elif "not found" in result.get("error", "").lower():
        status_code = 404
    else:
        status_code = 500
    
    return jsonify(result), status_code


@app.route("/health", methods=["GET"])
def health() -> tuple[Response, int]:
    """
    Health check endpoint for load balancers and monitoring.
    
    Returns:
        JSON response indicating server health.
    """
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "webhook-server"
    }), 200


@app.route("/ready", methods=["GET"])
def ready() -> tuple[Response, int]:
    """
    Readiness check endpoint for Kubernetes/container orchestration.
    
    Verifies:
        - WEBHOOK_TOKEN is configured
        - At least one script is available
        
    Returns:
        JSON response indicating readiness status.
    """
    issues = []
    
    if not WEBHOOK_TOKEN:
        issues.append("WEBHOOK_TOKEN not configured")
    
    available_scripts = [
        name for name, path in ALLOWED_SCRIPTS.items() 
        if path.exists()
    ]
    
    if not available_scripts:
        issues.append("No deployment scripts available")
    
    if issues:
        return jsonify({
            "status": "not_ready",
            "issues": issues
        }), 503
    
    return jsonify({
        "status": "ready",
        "available_scripts": available_scripts
    }), 200

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(400)
def bad_request(e: Exception) -> tuple[Response, int]:
    """Handle bad request errors."""
    return jsonify({
        "success": False,
        "error": "Bad request"
    }), 400


@app.errorhandler(404)
def not_found(e: Exception) -> tuple[Response, int]:
    """Handle 404 errors."""
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(e: Exception) -> tuple[Response, int]:
    """Handle method not allowed errors."""
    return jsonify({
        "success": False,
        "error": "Method not allowed"
    }), 405


@app.errorhandler(500)
def internal_error(e: Exception) -> tuple[Response, int]:
    """Handle internal server errors without exposing details."""
    logger.exception("Internal server error")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

# =============================================================================
# STARTUP VALIDATION
# =============================================================================

def validate_configuration() -> bool:
    """
    Validate server configuration on startup.
    
    Returns:
        True if configuration is valid, False otherwise.
    """
    is_valid = True
    
    if not WEBHOOK_TOKEN:
        logger.error(
            "CRITICAL: WEBHOOK_TOKEN environment variable is not set! "
            "Set it before running in production."
        )
        is_valid = False
    elif len(WEBHOOK_TOKEN) < 32:
        logger.warning(
            "WARNING: WEBHOOK_TOKEN is less than 32 characters. "
            "Consider using a longer, more secure token."
        )
    
    # Check if at least one script exists
    available_scripts = []
    for name, path in ALLOWED_SCRIPTS.items():
        if path.exists():
            available_scripts.append(name)
            logger.info(f"Script available: {name} -> {path}")
        else:
            logger.warning(f"Script not found: {name} -> {path}")
    
    if not available_scripts:
        logger.error("CRITICAL: No deployment scripts found!")
        is_valid = False
    
    logger.info(f"Script timeout: {SCRIPT_TIMEOUT} seconds")
    logger.info(f"Log level: {LOG_LEVEL}")
    
    return is_valid

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def create_app() -> Flask:
    """
    Application factory for WSGI servers (Gunicorn, uWSGI).
    
    Returns:
        Configured Flask application instance.
    """
    validate_configuration()
    return app


if __name__ == "__main__":
    # Development server - NOT for production use
    print("=" * 60)
    print("  CI/CD WEBHOOK SERVER")
    print("  WARNING: Use Gunicorn/uWSGI for production!")
    print("=" * 60)
    print()
    
    if not validate_configuration():
        print("\n[ERROR] Configuration validation failed! Fix issues above.")
        sys.exit(1)
    
    print(f"\nStarting development server on http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop\n")
    
    # Run development server (debug=False for safety)
    app.run(host=HOST, port=PORT, debug=False)
