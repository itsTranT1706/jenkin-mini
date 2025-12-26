#!/usr/bin/env python3
"""
Docker Image Build & Push Script for GitHub Container Registry (GHCR)

This script automates the process of:
1. Cloning/updating a Git repository
2. Logging into GitHub Container Registry
3. Building a Docker image
4. Pushing the image to GHCR

Configuration is read from a YAML file (node.js.yml by default).

WARNING: NEVER commit your GHCR Personal Access Token (PAT) to Git!
         Use environment variables or a secure secrets manager in production.

Usage:
    python deploy.py
    python deploy.py --config custom-config.yml

Author: DevOps Team
Python: 3.10+
"""

import subprocess
import sys
import os
import argparse
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is not installed. Run: pip install pyyaml")
    sys.exit(1)


def load_config(config_path: str = "config.yml") -> dict[str, Any]:
    """
    Load and validate configuration from a YAML file.
    
    Args:
        config_path: Path to the YAML configuration file.
        
    Returns:
        Dictionary containing the configuration.
        
    Raises:
        FileNotFoundError: If the config file doesn't exist.
        yaml.YAMLError: If the YAML is malformed.
        ValueError: If required configuration keys are missing.
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    print(f"[INFO] Loading configuration from: {config_path}")
    
    with open(config_file, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    # Validate required keys
    required_keys = [
        ("registry", "url"),
        ("registry", "username"),
        ("registry", "image_name"),
        ("registry", "tag"),
        ("auth", "ghcr_pat"),
        ("build", "context"),
        ("git", "repo"),
        ("git", "branch"),
        ("git", "workdir"),
    ]
    
    for keys in required_keys:
        current = config
        for key in keys:
            if key not in current:
                raise ValueError(f"Missing required config key: {'.'.join(keys)}")
            current = current[key]
    
    print("[INFO] Configuration loaded successfully")
    return config


def run_command(command: list[str], cwd: str | None = None, 
                input_data: str | None = None, hide_input: bool = False) -> subprocess.CompletedProcess:
    """
    Execute a shell command with error handling.
    
    Args:
        command: List of command arguments.
        cwd: Working directory for the command.
        input_data: Optional input data to pass to stdin.
        hide_input: If True, don't log the input data (for sensitive data).
        
    Returns:
        CompletedProcess instance.
        
    Raises:
        subprocess.CalledProcessError: If the command fails.
    """
    # Log the command (but not sensitive input)
    cmd_str = " ".join(command)
    print(f"[EXEC] {cmd_str}")
    
    if input_data and not hide_input:
        print(f"[INPUT] {input_data}")
    elif input_data and hide_input:
        print("[INPUT] <HIDDEN - SENSITIVE DATA>")
    
    result = subprocess.run(
        command,
        cwd=cwd,
        input=input_data,
        text=True,
        check=True,
        capture_output=False
    )
    
    return result


def checkout_code(config: dict[str, Any]) -> str:
    """
    Clone or update the Git repository and checkout the specified branch.
    
    Args:
        config: Configuration dictionary.
        
    Returns:
        Path to the working directory.
    """
    git_config = config["git"]
    repo_url = git_config["repo"]
    branch = git_config["branch"]
    workdir = Path(git_config["workdir"]).resolve()
    
    print(f"\n{'='*60}")
    print("[STEP] Checking out code")
    print(f"{'='*60}")
    print(f"[INFO] Repository: {repo_url}")
    print(f"[INFO] Branch: {branch}")
    print(f"[INFO] Working directory: {workdir}")
    
    # Check if the repository already exists
    git_dir = workdir / ".git"
    
    if git_dir.exists():
        print("[INFO] Repository exists, pulling latest changes...")
        
        # Fetch and checkout the branch
        run_command(["git", "fetch", "--all"], cwd=str(workdir))
        run_command(["git", "checkout", branch], cwd=str(workdir))
        run_command(["git", "pull", "origin", branch], cwd=str(workdir))
    else:
        print("[INFO] Cloning repository...")
        
        # Create parent directory if it doesn't exist
        workdir.parent.mkdir(parents=True, exist_ok=True)
        
        # Clone the repository
        run_command(["git", "clone", "--branch", branch, repo_url, str(workdir)])
    
    print("[SUCCESS] Code checkout completed")
    return str(workdir)


def docker_login(config: dict[str, Any]) -> None:
    """
    Login to GitHub Container Registry using docker login --password-stdin.
    
    WARNING: The GHCR PAT is passed via stdin to avoid exposing it in process lists.
    
    Args:
        config: Configuration dictionary.
    """
    registry_url = config["registry"]["url"]
    username = config["registry"]["username"]
    ghcr_pat = config["auth"]["ghcr_pat"]
    
    print(f"\n{'='*60}")
    print("[STEP] Docker Login to GHCR")
    print(f"{'='*60}")
    print(f"[INFO] Registry: {registry_url}")
    print(f"[INFO] Username: {username}")
    print("[WARN] Token is passed via stdin (not logged for security)")
    
    # Validate that PAT is not empty
    if not ghcr_pat or ghcr_pat.strip() == "":
        raise ValueError("GHCR PAT is empty or not set in configuration")
    
    # Use --password-stdin for secure password input
    command = [
        "docker", "login", registry_url,
        "-u", username,
        "--password-stdin"
    ]
    
    run_command(command, input_data=ghcr_pat, hide_input=True)
    
    print("[SUCCESS] Docker login successful")


def docker_build(config: dict[str, Any], workdir: str) -> str:
    """
    Build the Docker image.
    
    Args:
        config: Configuration dictionary.
        workdir: Path to the repository working directory.
        
    Returns:
        Full image name with tag.
    """
    registry_url = config["registry"]["url"]
    username = config["registry"]["username"]
    image_name = config["registry"]["image_name"]
    tag = config["registry"]["tag"]
    build_context = config["build"]["context"]
    
    # Construct full image name
    full_image_name = f"{registry_url}/{username}/{image_name}:{tag}"
    
    # Resolve build context path
    context_path = Path(workdir) / build_context
    
    print(f"\n{'='*60}")
    print("[STEP] Building Docker Image")
    print(f"{'='*60}")
    print(f"[INFO] Image: {full_image_name}")
    print(f"[INFO] Build context: {context_path}")
    
    if not context_path.exists():
        raise FileNotFoundError(f"Build context directory not found: {context_path}")
    
    command = [
        "docker", "build",
        "-t", full_image_name,
        str(context_path)
    ]
    
    run_command(command)
    
    print(f"[SUCCESS] Docker image built: {full_image_name}")
    return full_image_name


def docker_push(full_image_name: str) -> None:
    """
    Push the Docker image to the registry.
    
    Args:
        full_image_name: Full image name with tag to push.
    """
    print(f"\n{'='*60}")
    print("[STEP] Pushing Docker Image")
    print(f"{'='*60}")
    print(f"[INFO] Pushing: {full_image_name}")
    
    command = ["docker", "push", full_image_name]
    
    run_command(command)
    
    print(f"[SUCCESS] Docker image pushed: {full_image_name}")


def main() -> int:
    """
    Main entry point for the deployment script.
    
    Returns:
        Exit code (0 for success, 1 for failure).
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Build and push Docker image to GitHub Container Registry"
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yml",
        help="Path to YAML configuration file (default: config.yml)"
    )
    parser.add_argument(
        "--skip-checkout",
        action="store_true",
        help="Skip git clone/pull step (use existing code)"
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("  DOCKER IMAGE BUILD & PUSH TO GHCR")
    print("=" * 60)
    print()
    
    try:
        # Step 1: Load configuration
        config = load_config(args.config)
        
        # Step 2: Checkout code (clone or pull)
        if args.skip_checkout:
            print("\n[INFO] Skipping code checkout (--skip-checkout flag)")
            workdir = str(Path(config["git"]["workdir"]).resolve())
        else:
            workdir = checkout_code(config)
        
        # Step 3: Login to Docker registry
        docker_login(config)
        
        # Step 4: Build Docker image
        full_image_name = docker_build(config, workdir)
        
        # Step 5: Push Docker image
        docker_push(full_image_name)
        
        # Success summary
        print()
        print("=" * 60)
        print("  DEPLOYMENT COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print(f"[INFO] Image: {full_image_name}")
        print()
        
        return 0
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] File not found: {e}")
        return 1
    except ValueError as e:
        print(f"\n[ERROR] Configuration error: {e}")
        return 1
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Command failed with exit code {e.returncode}")
        print(f"[ERROR] Command: {' '.join(e.cmd)}")
        return 1
    except yaml.YAMLError as e:
        print(f"\n[ERROR] YAML parsing error: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
