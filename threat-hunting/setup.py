#!/usr/bin/env python3
"""
Setup script for Threat Hunting Toolkit

This script helps with installation, configuration, and initial setup
of the comprehensive threat hunting system.
"""

import os
import sys
import subprocess
import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatHuntingSetup:
    """Setup manager for threat hunting toolkit"""
    
    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path(__file__).parent
        self.config_file = self.project_root / "config.json"
        self.requirements_file = self.project_root / "requirements.txt"
        self.schema_file = self.project_root / "database_schema.sql"
    
    def check_python_version(self) -> bool:
        """Check if Python version is compatible"""
        logger.info("Checking Python version...")
        
        if sys.version_info < (3, 9):
            logger.error("Python 3.9 or higher is required")
            logger.error(f"Current version: {sys.version}")
            return False
        
        logger.info(f"✅ Python version {sys.version.split()[0]} is compatible")
        return True
    
    def install_dependencies(self) -> bool:
        """Install Python dependencies"""
        logger.info("Installing Python dependencies...")
        
        if not self.requirements_file.exists():
            logger.error(f"Requirements file not found: {self.requirements_file}")
            return False
        
        try:
            # Upgrade pip first
            subprocess.run([
                sys.executable, "-m", "pip", "install", "--upgrade", "pip"
            ], check=True, capture_output=True)
            
            # Install requirements
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(self.requirements_file)
            ], check=True, capture_output=True, text=True)
            
            logger.info("✅ Dependencies installed successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e}")
            logger.error(f"Output: {e.output}")
            return False
    
    def check_external_dependencies(self) -> Dict[str, bool]:
        """Check external service dependencies"""
        logger.info("Checking external dependencies...")
        
        dependencies = {
            'redis': self._check_redis(),
            'postgresql': self._check_postgresql(),
        }
        
        for service, available in dependencies.items():
            if available:
                logger.info(f"✅ {service.capitalize()} is available")
            else:
                logger.warning(f"⚠️  {service.capitalize()} is not available")
        
        return dependencies
    
    def _check_redis(self) -> bool:
        """Check if Redis is available"""
        try:
            import redis
            client = redis.Redis(host='localhost', port=6379, decode_responses=True)
            client.ping()
            return True
        except Exception:
            return False
    
    def _check_postgresql(self) -> bool:
        """Check if PostgreSQL is available"""
        try:
            import psycopg2
            # Try to connect to default postgres database
            conn = psycopg2.connect(
                host='localhost',
                port=5432,
                database='postgres',
                user='postgres',
                connect_timeout=5
            )
            conn.close()
            return True
        except Exception:
            return False
    
    def create_config_file(self, force: bool = False) -> bool:
        """Create configuration file from template"""
        logger.info("Creating configuration file...")
        
        if self.config_file.exists() and not force:
            logger.info("Configuration file already exists. Use --force to overwrite.")
            return True
        
        # Load example config
        example_config_file = self.project_root / "config.example.json"
        if not example_config_file.exists():
            logger.error("Example configuration file not found")
            return False
        
        try:
            with open(example_config_file, 'r') as f:
                config = json.load(f)
            
            # Customize config with user input
            config = self._customize_config(config)
            
            # Write config file
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"✅ Configuration file created: {self.config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create configuration file: {e}")
            return False
    
    def _customize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Customize configuration with user input"""
        logger.info("Customizing configuration...")
        
        # Database configuration
        print("\n📊 Database Configuration")
        print("=" * 30)
        
        # Redis
        redis_host = input("Redis host [localhost]: ").strip() or "localhost"
        redis_port = input("Redis port [6379]: ").strip() or "6379"
        redis_db = input("Redis database [0]: ").strip() or "0"
        
        config['database']['redis_url'] = f"redis://{redis_host}:{redis_port}/{redis_db}"
        
        # PostgreSQL
        pg_host = input("PostgreSQL host [localhost]: ").strip() or "localhost"
        pg_port = input("PostgreSQL port [5432]: ").strip() or "5432"
        pg_user = input("PostgreSQL user [threat_hunting]: ").strip() or "threat_hunting"
        pg_password = input("PostgreSQL password: ").strip()
        pg_database = input("PostgreSQL database [security_db]: ").strip() or "security_db"
        
        if pg_password:
            config['database']['postgres_url'] = f"postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/{pg_database}"
        else:
            config['database']['postgres_url'] = f"postgresql://{pg_user}@{pg_host}:{pg_port}/{pg_database}"
        
        # Rust service configuration
        print("\n🦀 Rust Service Configuration")
        print("=" * 35)
        
        rust_url = input("Rust service URL [http://localhost:8080]: ").strip() or "http://localhost:8080"
        rust_api_key = input("Rust service API key: ").strip()
        
        config['rust_service']['url'] = rust_url
        if rust_api_key:
            config['rust_service']['api_key'] = rust_api_key
        
        # Notification configuration
        print("\n📧 Notification Configuration")
        print("=" * 32)
        
        enable_slack = input("Enable Slack notifications? [y/N]: ").strip().lower() == 'y'
        if enable_slack:
            slack_webhook = input("Slack webhook URL: ").strip()
            if slack_webhook:
                config['notifications']['slack']['webhook_url'] = slack_webhook
                config['notifications']['slack']['enabled'] = True
        
        enable_email = input("Enable email notifications? [y/N]: ").strip().lower() == 'y'
        if enable_email:
            smtp_server = input("SMTP server: ").strip()
            smtp_port = input("SMTP port [587]: ").strip() or "587"
            email_user = input("Email username: ").strip()
            email_password = input("Email password: ").strip()
            
            if smtp_server and email_user:
                config['notifications']['email'].update({
                    'smtp_server': smtp_server,
                    'smtp_port': int(smtp_port),
                    'username': email_user,
                    'password': email_password,
                    'enabled': True
                })
        
        # Processing configuration
        print("\n⚙️  Processing Configuration")
        print("=" * 30)
        
        workers = input("Number of processing workers [4]: ").strip()
        if workers and workers.isdigit():
            config['processing']['workers'] = int(workers)
        
        return config
    
    def setup_database(self, config: Optional[Dict[str, Any]] = None) -> bool:
        """Setup database schema"""
        logger.info("Setting up database schema...")
        
        if not config:
            if not self.config_file.exists():
                logger.error("Configuration file not found. Run setup first.")
                return False
            
            with open(self.config_file, 'r') as f:
                config = json.load(f)
        
        if not self.schema_file.exists():
            logger.error(f"Database schema file not found: {self.schema_file}")
            return False
        
        try:
            # Parse PostgreSQL URL
            postgres_url = config['database']['postgres_url']
            
            # Read schema file
            with open(self.schema_file, 'r') as f:
                schema_sql = f.read()
            
            # Execute schema
            import psycopg2
            from urllib.parse import urlparse
            
            parsed = urlparse(postgres_url)
            conn = psycopg2.connect(
                host=parsed.hostname,
                port=parsed.port or 5432,
                database=parsed.path[1:],  # Remove leading slash
                user=parsed.username,
                password=parsed.password
            )
            
            with conn.cursor() as cursor:
                cursor.execute(schema_sql)
            
            conn.commit()
            conn.close()
            
            logger.info("✅ Database schema created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup database: {e}")
            return False
    
    def create_directories(self) -> bool:
        """Create necessary directories"""
        logger.info("Creating directories...")
        
        directories = [
            self.project_root / "logs",
            self.project_root / "models",
            self.project_root / "models" / "backup",
            self.project_root / "data",
            self.project_root / "temp"
        ]
        
        try:
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created directory: {directory}")
            
            logger.info("✅ Directories created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create directories: {e}")
            return False
    
    def test_installation(self) -> bool:
        """Test the installation"""
        logger.info("Testing installation...")
        
        try:
            # Test imports
            logger.info("Testing imports...")
            
            from behavioral_analyzer import AdvancedThreatDetector
            from ml_user_profiler import AdvancedUserProfiler
            from threat_intelligence import ThreatIntelligenceCorrelator
            from attack_pattern_detector import AttackPatternDetector
            from automated_response import AutomatedResponseOrchestrator
            from integration_bridge import ThreatHuntingOrchestrator
            
            logger.info("✅ All imports successful")
            
            # Test configuration loading
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                logger.info("✅ Configuration file valid")
            else:
                logger.warning("⚠️  Configuration file not found")
                return False
            
            # Test basic functionality (if dependencies are available)
            dependencies = self.check_external_dependencies()
            
            if dependencies['redis'] and dependencies['postgresql']:
                logger.info("Testing basic functionality...")
                
                async def test_basic():
                    try:
                        # Test minimal initialization
                        orchestrator = ThreatHuntingOrchestrator(config)
                        await orchestrator.initialize()
                        
                        status = await orchestrator.get_system_status()
                        logger.info(f"System status: {status}")
                        
                        await orchestrator.close()
                        return True
                        
                    except Exception as e:
                        logger.error(f"Basic functionality test failed: {e}")
                        return False
                
                # Run async test
                result = asyncio.run(test_basic())
                if result:
                    logger.info("✅ Basic functionality test passed")
                else:
                    logger.warning("⚠️  Basic functionality test failed")
                    return False
            else:
                logger.warning("⚠️  Skipping functionality test due to missing dependencies")
            
            logger.info("✅ Installation test completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Installation test failed: {e}")
            return False
    
    def run_full_setup(self, force: bool = False) -> bool:
        """Run complete setup process"""
        logger.info("🚀 Starting Threat Hunting Toolkit Setup")
        logger.info("=" * 50)
        
        steps = [
            ("Checking Python version", self.check_python_version),
            ("Installing dependencies", self.install_dependencies),
            ("Checking external dependencies", lambda: self.check_external_dependencies() and True),
            ("Creating directories", self.create_directories),
            ("Creating configuration", lambda: self.create_config_file(force)),
            ("Setting up database", self.setup_database),
            ("Testing installation", self.test_installation),
        ]
        
        failed_steps = []
        
        for step_name, step_func in steps:
            logger.info(f"\n📋 {step_name}...")
            try:
                if not step_func():
                    failed_steps.append(step_name)
                    logger.error(f"❌ {step_name} failed")
                else:
                    logger.info(f"✅ {step_name} completed")
            except Exception as e:
                failed_steps.append(step_name)
                logger.error(f"❌ {step_name} failed with error: {e}")
        
        logger.info("\n" + "=" * 50)
        
        if failed_steps:
            logger.error(f"❌ Setup completed with {len(failed_steps)} failed steps:")
            for step in failed_steps:
                logger.error(f"   - {step}")
            logger.error("\nPlease address the failed steps and run setup again.")
            return False
        else:
            logger.info("🎉 Setup completed successfully!")
            logger.info("\nNext steps:")
            logger.info("1. Review and customize the configuration file: config.json")
            logger.info("2. Start the threat hunting system with: python -m integration_bridge")
            logger.info("3. Run the demo with: python example_usage.py")
            return True


def main():
    """Main setup function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Setup script for Threat Hunting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup.py                 # Run full setup
  python setup.py --config-only   # Create configuration only
  python setup.py --test-only     # Test existing installation
  python setup.py --force         # Force overwrite existing config
        """
    )
    
    parser.add_argument(
        '--config-only',
        action='store_true',
        help='Only create configuration file'
    )
    
    parser.add_argument(
        '--test-only',
        action='store_true',
        help='Only test existing installation'
    )
    
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force overwrite existing configuration'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Reduce output verbosity'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # Initialize setup manager
    setup = ThreatHuntingSetup()
    
    try:
        if args.config_only:
            success = setup.create_config_file(force=args.force)
        elif args.test_only:
            success = setup.test_installation()
        else:
            success = setup.run_full_setup(force=args.force)
        
        if success:
            print("\n🎯 Setup completed successfully!")
            return 0
        else:
            print("\n❌ Setup failed. Please check the logs above.")
            return 1
            
    except KeyboardInterrupt:
        print("\n👋 Setup interrupted by user.")
        return 1
    except Exception as e:
        logger.error(f"Setup failed with unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())