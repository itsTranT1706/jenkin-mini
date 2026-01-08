#!/usr/bin/env python3
"""
GitHub Webhook Logger

A Flask-based webhook server that receives GitHub events and logs
detailed information to console.

Features:
- Receives GitHub webhook events (push, pull_request, issues, etc.)
- Extracts and logs relevant information (user, action, timestamp, changes)
- Formatted, readable console output
- Optional GitHub signature verification
- Simple and lightweight

Author: DevOps Team
Python: 3.10+
"""

import sys
import os
import logging
import hashlib
import hmac
import json
from pathlib import Path
from datetime import datetime
from typing import Any

from flask import Flask, request, jsonify, Response

# =============================================================================
# CONFIGURATION
# =============================================================================

# GitHub webhook secret (optional, for signature verification)
GITHUB_SECRET = os.environ.get("GITHUB_SECRET", "")

# Server configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "5000"))

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def configure_logging() -> logging.Logger:
    """Configure production-ready logging."""
    logger = logging.getLogger("webhook_server")
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    
    # Colorful formatter for better readability
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
app.config["DEBUG"] = False
app.config["TESTING"] = False

# =============================================================================
# GITHUB EVENT LOGGING
# =============================================================================

def log_github_event(event_type: str, payload: dict) -> None:
    """
    Log GitHub event data in a formatted, readable way.
    
    Args:
        event_type: Type of GitHub event (push, pull_request, etc.)
        payload: GitHub webhook payload
    """
    try:
        repo_name = payload.get("repository", {}).get("full_name", "Unknown")
        sender = payload.get("sender", {}).get("login", "Unknown")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Print separator
        print("\n" + "=" * 80)
        print(f"🔔 GITHUB EVENT: {event_type.upper()}")
        print("=" * 80)
        
        # Common info for all events
        print(f"📦 Repository: {repo_name}")
        print(f"👤 User: {sender}")
        print(f"⏰ Time: {timestamp}")
        print("-" * 80)
        
        # Event-specific details
        if event_type == "push":
            ref = payload.get("ref", "").replace("refs/heads/", "")
            commits = payload.get("commits", [])
            commit_count = len(commits)
            
            print(f"🌿 Branch: {ref}")
            print(f"📝 Total Commits: {commit_count}")
            print("\nCommit Details:")
            
            for i, commit in enumerate(commits, 1):
                short_sha = commit.get("id", "")[:7]
                commit_msg = commit.get("message", "").split("\n")[0]
                author = commit.get("author", {}).get("name", "Unknown")
                commit_url = commit.get("url", "")
                
                print(f"\n  Commit #{i}:")
                print(f"    SHA: {short_sha}")
                print(f"    Author: {author}")
                print(f"    Message: {commit_msg}")
                print(f"    URL: {commit_url}")
                
        elif event_type == "pull_request":
            action = payload.get("action", "unknown")
            pr = payload.get("pull_request", {})
            pr_number = pr.get("number", "?")
            pr_title = pr.get("title", "No title")
            pr_url = pr.get("html_url", "")
            pr_body = pr.get("body", "")
            base_branch = pr.get("base", {}).get("ref", "unknown")
            head_branch = pr.get("head", {}).get("ref", "unknown")
            state = pr.get("state", "unknown")
            
            print(f"🎯 Action: {action.upper()}")
            print(f"🔢 PR Number: #{pr_number}")
            print(f"📋 Title: {pr_title}")
            print(f"🌿 Branches: {head_branch} → {base_branch}")
            print(f"📊 State: {state}")
            print(f"🔗 URL: {pr_url}")
            
            if pr_body:
                print(f"\n📄 Description:")
                print(f"    {pr_body[:200]}...")
                
        elif event_type == "issues":
            action = payload.get("action", "unknown")
            issue = payload.get("issue", {})
            issue_number = issue.get("number", "?")
            issue_title = issue.get("title", "No title")
            issue_url = issue.get("html_url", "")
            issue_body = issue.get("body", "")
            state = issue.get("state", "unknown")
            labels = [label.get("name") for label in issue.get("labels", [])]
            
            print(f"🎯 Action: {action.upper()}")
            print(f"🐛 Issue Number: #{issue_number}")
            print(f"📋 Title: {issue_title}")
            print(f"📊 State: {state}")
            
            if labels:
                print(f"🏷️  Labels: {', '.join(labels)}")
            
            print(f"🔗 URL: {issue_url}")
            
            if issue_body:
                print(f"\n📄 Description:")
                print(f"    {issue_body[:200]}...")
                
        elif event_type == "create" or event_type == "delete":
            ref_type = payload.get("ref_type", "unknown")
            ref = payload.get("ref", "unknown")
            
            emoji = "✨" if event_type == "create" else "🗑️"
            print(f"{emoji} Action: {event_type.upper()}")
            print(f"📌 Type: {ref_type.capitalize()}")
            print(f"📌 Name: {ref}")
            
        elif event_type == "release":
            action = payload.get("action", "unknown")
            release = payload.get("release", {})
            tag_name = release.get("tag_name", "unknown")
            release_name = release.get("name", tag_name)
            release_url = release.get("html_url", "")
            release_body = release.get("body", "")
            draft = release.get("draft", False)
            prerelease = release.get("prerelease", False)
            
            print(f"🎯 Action: {action.upper()}")
            print(f"🚀 Release Name: {release_name}")
            print(f"🏷️  Tag: {tag_name}")
            print(f"📝 Draft: {draft}")
            print(f"🧪 Pre-release: {prerelease}")
            print(f"🔗 URL: {release_url}")
            
            if release_body:
                print(f"\n📄 Release Notes:")
                print(f"    {release_body[:200]}...")
                
        elif event_type == "star":
            action = payload.get("action", "unknown")
            starred_at = payload.get("starred_at", "")
            
            print(f"⭐ Action: {action.upper()}")
            if starred_at:
                print(f"⏰ Starred at: {starred_at}")
                
        elif event_type == "fork":
            forkee = payload.get("forkee", {})
            fork_name = forkee.get("full_name", "Unknown")
            fork_url = forkee.get("html_url", "")
            
            print(f"🍴 Fork Created")
            print(f"📦 Fork Name: {fork_name}")
            print(f"🔗 Fork URL: {fork_url}")
            
        else:
            # Generic event - log the full payload
            print(f"📋 Event Type: {event_type}")
            print(f"\n📄 Full Payload:")
            print(json.dumps(payload, indent=2)[:1000])
            
        print("=" * 80 + "\n")
        
    except Exception as e:
        logger.error(f"Error logging GitHub event: {e}")
        print(f"\n⚠️ Error formatting event data: {e}")
        print(f"Raw payload: {json.dumps(payload, indent=2)[:500]}\n")


# =============================================================================
# GITHUB WEBHOOK VERIFICATION
# =============================================================================

def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """
    Verify GitHub webhook signature.
    
    Args:
        payload_body: Raw request body
        signature_header: X-Hub-Signature-256 header value
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not GITHUB_SECRET:
        logger.info("ℹ️  GITHUB_SECRET not configured, skipping signature verification")
        return True
    
    if not signature_header:
        return False
    
    try:
        hash_algorithm, github_signature = signature_header.split('=')
    except ValueError:
        return False
    
    if hash_algorithm != 'sha256':
        return False
    
    # Create HMAC
    mac = hmac.new(
        GITHUB_SECRET.encode(),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    
    return hmac.compare_digest(mac.hexdigest(), github_signature)

# =============================================================================
# WEBHOOK ENDPOINTS
# =============================================================================

@app.route("/github", methods=["POST"])
def github_webhook() -> tuple[Response, int]:
    """
    GitHub webhook endpoint - receives all GitHub events and logs them.
    
    Headers:
        X-GitHub-Event: Type of GitHub event
        X-Hub-Signature-256: HMAC signature (if secret is configured)
        
    Returns:
        JSON response with processing status
    """
    # Get event type
    event_type = request.headers.get("X-GitHub-Event", "unknown")
    signature = request.headers.get("X-Hub-Signature-256", "")
    delivery_id = request.headers.get("X-GitHub-Delivery", "")
    
    logger.info(
        f"📨 GitHub webhook received | "
        f"Event: {event_type} | "
        f"Delivery ID: {delivery_id} | "
        f"IP: {request.remote_addr}"
    )
    
    # Verify signature if secret is configured
    if GITHUB_SECRET:
        if not verify_github_signature(request.data, signature):
            logger.warning("❌ Invalid GitHub signature!")
            return jsonify({
                "success": False,
                "error": "Invalid signature"
            }), 403
        else:
            logger.info("✅ GitHub signature verified")
    
    # Parse payload
    try:
        payload = request.get_json()
        if not payload:
            logger.error("❌ Invalid JSON payload")
            return jsonify({
                "success": False,
                "error": "Invalid JSON payload"
            }), 400
    except Exception as e:
        logger.error(f"❌ Error parsing JSON: {e}")
        return jsonify({
            "success": False,
            "error": "Invalid JSON"
        }), 400
    
    # Log the event details
    log_github_event(event_type, payload)
    
    # Prepare response
    response_data = {
        "success": True,
        "event": event_type,
        "delivery_id": delivery_id,
        "repository": payload.get("repository", {}).get("full_name", "Unknown"),
        "sender": payload.get("sender", {}).get("login", "Unknown"),
        "timestamp": datetime.now().isoformat()
    }
    
    return jsonify(response_data), 200


@app.route("/github/test", methods=["POST", "GET"])
def github_webhook_test() -> tuple[Response, int]:
    """
    Test endpoint for debugging GitHub webhooks.
    Prints all headers and payload data.
    """
    print("\n" + "=" * 80)
    print("🧪 TEST WEBHOOK RECEIVED")
    print("=" * 80)
    
    print("\n📋 HEADERS:")
    for header, value in request.headers.items():
        print(f"  {header}: {value}")
    
    if request.method == "POST":
        print("\n📦 RAW DATA:")
        raw_data = request.data.decode('utf-8')
        print(f"  Length: {len(raw_data)} bytes")
        print(f"  Preview: {raw_data[:500]}")
        
        print("\n📄 JSON DATA:")
        payload = request.get_json(silent=True)
        if payload:
            print(json.dumps(payload, indent=2)[:1000])
            
            # Try to extract common fields
            print("\n🔍 EXTRACTED INFO:")
            print(f"  Event Type: {request.headers.get('X-GitHub-Event', 'N/A')}")
            print(f"  Repository: {payload.get('repository', {}).get('full_name', 'N/A')}")
            print(f"  Sender: {payload.get('sender', {}).get('login', 'N/A')}")
        else:
            print("  No JSON data found")
    
    print("=" * 80 + "\n")
    
    return jsonify({
        "status": "test_ok",
        "method": request.method,
        "event": request.headers.get("X-GitHub-Event"),
        "received_at": datetime.now().isoformat(),
        "message": "Check console/logs for detailed output"
    }), 200


@app.route("/", methods=["GET"])
def index() -> tuple[Response, int]:
    """
    Index endpoint with basic information.
    """
    return jsonify({
        "service": "GitHub Webhook Logger",
        "status": "running",
        "endpoints": {
            "github_webhook": "/github (POST)",
            "test": "/github/test (POST/GET)",
            "health": "/health (GET)"
        },
        "timestamp": datetime.now().isoformat()
    }), 200

# =============================================================================
# HEALTH CHECK ENDPOINTS
# =============================================================================

@app.route("/health", methods=["GET"])
def health() -> tuple[Response, int]:
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "github-webhook-logger"
    }), 200

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(400)
def bad_request(e: Exception) -> tuple[Response, int]:
    return jsonify({"success": False, "error": "Bad request"}), 400

@app.errorhandler(404)
def not_found(e: Exception) -> tuple[Response, int]:
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e: Exception) -> tuple[Response, int]:
    return jsonify({"success": False, "error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e: Exception) -> tuple[Response, int]:
    logger.exception("Internal server error")
    return jsonify({"success": False, "error": "Internal server error"}), 500

# =============================================================================
# STARTUP
# =============================================================================

def validate_configuration() -> None:
    """Display configuration on startup."""
    print("\n" + "=" * 80)
    print("  GITHUB WEBHOOK LOGGER")
    print("  Receives GitHub events → Logs to console")
    print("=" * 80)
    
    print("\n📋 Configuration:")
    print(f"  • Host: {HOST}")
    print(f"  • Port: {PORT}")
    print(f"  • Log Level: {LOG_LEVEL}")
    
    if GITHUB_SECRET:
        print(f"  • GitHub Secret: ✅ Configured (signature verification enabled)")
    else:
        print(f"  • GitHub Secret: ⚠️  Not configured (signature verification disabled)")
    
    print("\n📝 Endpoints:")
    print(f"  • Main webhook: http://{HOST}:{PORT}/github")
    print(f"  • Test endpoint: http://{HOST}:{PORT}/github/test")
    print(f"  • Health check: http://{HOST}:{PORT}/health")
    print("=" * 80 + "\n")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    validate_configuration()
    
    print("🚀 Starting server...")
    print("📡 Waiting for GitHub webhooks...")
    print("Press Ctrl+C to stop\n")
    
    app.run(host=HOST, port=PORT, debug=False)