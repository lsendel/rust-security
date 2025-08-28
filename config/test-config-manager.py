#!/usr/bin/env python3
"""
Test Configuration Manager
Handles environment-specific configuration for the enhanced test client.
"""

import os
import yaml
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class EnvironmentConfig:
    """Configuration for a specific test environment."""
    name: str
    base_url: str
    timeout: int = 10
    verify_ssl: bool = True
    rate_limit: Dict[str, int] = field(default_factory=dict)
    retries: Dict[str, Any] = field(default_factory=dict)
    auth: Dict[str, Any] = field(default_factory=dict)
    test_user: Dict[str, str] = field(default_factory=dict)
    restrictions: Optional[Dict[str, Any]] = None


@dataclass
class TestSuiteConfig:
    """Configuration for a test suite."""
    name: str
    description: str
    tests: List[str]
    max_duration: int = 300
    concurrent_users: List[int] = field(default_factory=lambda: [1, 10])


class TestConfigManager:
    """Manages test configurations for different environments and test suites."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize the configuration manager."""
        if config_file is None:
            config_file = self._find_config_file()
        
        self.config_file = config_file
        self._config_data = self._load_config()
        self._environment_configs = self._parse_environments()
        self._test_suite_configs = self._parse_test_suites()
    
    def _find_config_file(self) -> str:
        """Find the configuration file in the project."""
        possible_paths = [
            "config/test-environments.yaml",
            "../config/test-environments.yaml",
            "../../config/test-environments.yaml",
            os.path.expanduser("~/.rust-security/test-config.yaml"),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        raise FileNotFoundError(
            f"Configuration file not found. Searched: {possible_paths}"
        )
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Failed to load config from {self.config_file}: {e}")
    
    def _parse_environments(self) -> Dict[str, EnvironmentConfig]:
        """Parse environment configurations."""
        environments = {}
        
        for name, config in self._config_data.get("environments", {}).items():
            environments[name] = EnvironmentConfig(
                name=name,
                base_url=self._resolve_env_vars(config["base_url"]),
                timeout=config.get("timeout", 10),
                verify_ssl=config.get("verify_ssl", True),
                rate_limit=config.get("rate_limit", {}),
                retries=config.get("retries", {}),
                auth=config.get("auth", {}),
                test_user=config.get("test_user", {}),
                restrictions=config.get("restrictions")
            )
        
        return environments
    
    def _parse_test_suites(self) -> Dict[str, TestSuiteConfig]:
        """Parse test suite configurations."""
        test_suites = {}
        
        for name, config in self._config_data.get("test_suites", {}).items():
            test_suites[name] = TestSuiteConfig(
                name=name,
                description=config["description"],
                tests=config["tests"],
                max_duration=config.get("max_duration", 300),
                concurrent_users=config.get("concurrent_users", [1, 10])
            )
        
        return test_suites
    
    def _resolve_env_vars(self, value: str) -> str:
        """Resolve environment variables in configuration values."""
        if isinstance(value, str) and "${" in value:
            # Simple environment variable resolution
            import re
            pattern = r'\$\{([^}]+)\}'
            
            def replace_env_var(match):
                env_var = match.group(1)
                return os.environ.get(env_var, f"${{{env_var}}}")
            
            return re.sub(pattern, replace_env_var, value)
        return value
    
    def get_environment(self, name: str) -> EnvironmentConfig:
        """Get configuration for a specific environment."""
        if name not in self._environment_configs:
            available = list(self._environment_configs.keys())
            raise ValueError(f"Environment '{name}' not found. Available: {available}")
        
        return self._environment_configs[name]
    
    def get_test_suite(self, name: str) -> TestSuiteConfig:
        """Get configuration for a specific test suite."""
        if name not in self._test_suite_configs:
            available = list(self._test_suite_configs.keys())
            raise ValueError(f"Test suite '{name}' not found. Available: {available}")
        
        return self._test_suite_configs[name]
    
    def list_environments(self) -> List[str]:
        """List all available environments."""
        return list(self._environment_configs.keys())
    
    def list_test_suites(self) -> List[str]:
        """List all available test suites."""
        return list(self._test_suite_configs.keys())
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration."""
        return self._config_data.get("monitoring", {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration."""
        return self._config_data.get("security", {})
    
    def create_client_config(self, environment: str) -> Dict[str, Any]:
        """Create configuration dictionary for the test client."""
        env_config = self.get_environment(environment)
        monitoring_config = self.get_monitoring_config()
        security_config = self.get_security_config()
        
        return {
            "base_url": env_config.base_url,
            "timeout": env_config.timeout,
            "verify_ssl": env_config.verify_ssl,
            "rate_limit": env_config.rate_limit,
            "retries": env_config.retries,
            "auth": env_config.auth,
            "test_user": env_config.test_user,
            "restrictions": env_config.restrictions,
            "monitoring": monitoring_config,
            "security": security_config,
        }
    
    def validate_environment_connectivity(self, environment: str) -> bool:
        """Validate that an environment is reachable."""
        import requests
        
        env_config = self.get_environment(environment)
        
        try:
            response = requests.get(
                f"{env_config.base_url}/health",
                timeout=env_config.timeout,
                verify=env_config.verify_ssl
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def generate_environment_report(self) -> Dict[str, Any]:
        """Generate a report of all environments and their status."""
        report = {
            "timestamp": str(datetime.utcnow()),
            "total_environments": len(self._environment_configs),
            "total_test_suites": len(self._test_suite_configs),
            "environments": {},
            "test_suites": list(self._test_suite_configs.keys())
        }
        
        for env_name in self._environment_configs:
            env_config = self._environment_configs[env_name]
            report["environments"][env_name] = {
                "base_url": env_config.base_url,
                "reachable": self.validate_environment_connectivity(env_name),
                "verify_ssl": env_config.verify_ssl,
                "timeout": env_config.timeout,
                "has_restrictions": env_config.restrictions is not None
            }
        
        return report


def main():
    """CLI interface for configuration management."""
    import argparse
    import sys
    from datetime import datetime
    
    parser = argparse.ArgumentParser(description="Test Configuration Manager")
    parser.add_argument("--list-environments", action="store_true",
                       help="List all available environments")
    parser.add_argument("--list-suites", action="store_true",
                       help="List all available test suites")
    parser.add_argument("--validate", metavar="ENV",
                       help="Validate environment connectivity")
    parser.add_argument("--report", action="store_true",
                       help="Generate environment status report")
    parser.add_argument("--config", metavar="FILE",
                       help="Path to configuration file")
    
    args = parser.parse_args()
    
    try:
        manager = TestConfigManager(args.config)
        
        if args.list_environments:
            print("Available environments:")
            for env in manager.list_environments():
                print(f"  - {env}")
        
        elif args.list_suites:
            print("Available test suites:")
            for suite in manager.list_test_suites():
                config = manager.get_test_suite(suite)
                print(f"  - {suite}: {config.description}")
        
        elif args.validate:
            if manager.validate_environment_connectivity(args.validate):
                print(f"✅ Environment '{args.validate}' is reachable")
                sys.exit(0)
            else:
                print(f"❌ Environment '{args.validate}' is not reachable")
                sys.exit(1)
        
        elif args.report:
            report = manager.generate_environment_report()
            print(json.dumps(report, indent=2))
        
        else:
            parser.print_help()
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()