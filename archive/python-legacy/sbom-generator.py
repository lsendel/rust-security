#!/usr/bin/env python3
"""
Software Bill of Materials (SBOM) Generator
Comprehensive SBOM generation and dependency analysis for supply chain security
"""

import json
import os
import subprocess
import sys
import hashlib
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import argparse


class SBOMGenerator:
    """Generate comprehensive SBOM for Rust projects with security analysis"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root).resolve()
        self.cargo_lock = self.project_root / "Cargo.lock"
        self.cargo_toml = self.project_root / "Cargo.toml"
        
    def generate_sbom(self, output_format: str = "spdx") -> Dict[str, Any]:
        """Generate comprehensive SBOM"""
        print("🔍 Generating Software Bill of Materials (SBOM)...")
        
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Rust Auth Service SBOM",
            "documentNamespace": f"https://company.com/sbom/{self._get_project_name()}-{datetime.datetime.utcnow().isoformat()}",
            "creationInfo": {
                "created": datetime.datetime.utcnow().isoformat() + "Z",
                "creators": ["Tool: Custom SBOM Generator"],
                "licenseListVersion": "3.17"
            },
            "packages": [],
            "relationships": [],
            "vulnerabilities": []
        }
        
        # Add project package
        project_package = self._create_project_package()
        sbom["packages"].append(project_package)
        
        # Parse dependencies
        dependencies = self._parse_dependencies()
        
        for dep in dependencies:
            # Create package entry
            package = self._create_dependency_package(dep)
            sbom["packages"].append(package)
            
            # Create relationship
            relationship = {
                "spdxElementId": project_package["SPDXID"],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package["SPDXID"]
            }
            sbom["relationships"].append(relationship)
            
            # Check for vulnerabilities
            vulns = self._check_vulnerabilities(dep)
            sbom["vulnerabilities"].extend(vulns)
        
        return sbom
    
    def _get_project_name(self) -> str:
        """Get project name from Cargo.toml"""
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version", "1"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True
            )
            metadata = json.loads(result.stdout)
            return metadata["workspace_members"][0].split()[0]
        except:
            return "rust-auth-service"
    
    def _create_project_package(self) -> Dict[str, Any]:
        """Create SPDX package entry for the main project"""
        project_name = self._get_project_name()
        
        return {
            "SPDXID": "SPDXRef-Package-" + project_name,
            "name": project_name,
            "downloadLocation": "git+https://github.com/company/rust-security.git",
            "filesAnalyzed": True,
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": self._calculate_project_checksum()
                }
            ],
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "Copyright (c) 2024 Company",
            "supplier": "Organization: Company Security Team",
            "versionInfo": "0.1.0"
        }
    
    def _parse_dependencies(self) -> List[Dict[str, Any]]:
        """Parse dependencies from Cargo.lock"""
        dependencies = []
        
        try:
            result = subprocess.run(
                ["cargo", "metadata", "--format-version", "1"],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                check=True
            )
            
            metadata = json.loads(result.stdout)
            
            for package in metadata["packages"]:
                if package["source"] is not None:  # External dependency
                    dependencies.append({
                        "name": package["name"],
                        "version": package["version"],
                        "source": package["source"],
                        "license": package.get("license"),
                        "repository": package.get("repository"),
                        "description": package.get("description"),
                        "authors": package.get("authors", []),
                        "checksum": package.get("checksum")
                    })
                    
        except subprocess.CalledProcessError as e:
            print(f"Error parsing dependencies: {e}")
            
        return dependencies
    
    def _create_dependency_package(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Create SPDX package entry for a dependency"""
        name = dep["name"]
        version = dep["version"]
        
        package = {
            "SPDXID": f"SPDXRef-Package-{name}",
            "name": name,
            "versionInfo": version,
            "downloadLocation": self._get_download_location(dep),
            "filesAnalyzed": False,
            "supplier": f"Person: {', '.join(dep.get('authors', ['Unknown']))}"
        }
        
        # Add license information
        if dep.get("license"):
            package["licenseConcluded"] = dep["license"]
            package["licenseDeclared"] = dep["license"]
        else:
            package["licenseConcluded"] = "NOASSERTION"
            package["licenseDeclared"] = "NOASSERTION"
        
        # Add checksum if available
        if dep.get("checksum"):
            package["checksums"] = [{
                "algorithm": "SHA256",
                "checksumValue": dep["checksum"]
            }]
        
        # Add description
        if dep.get("description"):
            package["description"] = dep["description"]
        
        return package
    
    def _get_download_location(self, dep: Dict[str, Any]) -> str:
        """Get download location for dependency"""
        source = dep.get("source", "")
        name = dep["name"]
        version = dep["version"]
        
        if "registry+https://github.com/rust-lang/crates.io-index" in source:
            return f"https://crates.io/crates/{name}/{version}"
        elif "git+" in source:
            return source.replace("registry+", "")
        else:
            return "NOASSERTION"
    
    def _calculate_project_checksum(self) -> str:
        """Calculate SHA256 checksum of project source files"""
        hasher = hashlib.sha256()
        
        # Include main source files
        for rust_file in self.project_root.glob("**/*.rs"):
            if not any(part.startswith('.') or part == 'target' for part in rust_file.parts):
                try:
                    with open(rust_file, 'rb') as f:
                        hasher.update(f.read())
                except:
                    pass
        
        # Include Cargo files
        for cargo_file in [self.cargo_toml, self.cargo_lock]:
            if cargo_file.exists():
                try:
                    with open(cargo_file, 'rb') as f:
                        hasher.update(f.read())
                except:
                    pass
        
        return hasher.hexdigest()
    
    def _check_vulnerabilities(self, dep: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check dependency for known vulnerabilities"""
        vulnerabilities = []
        
        # This would integrate with vulnerability databases
        # For now, return empty list - implement with cargo-audit integration
        
        return vulnerabilities
    
    def save_sbom(self, sbom: Dict[str, Any], output_path: str):
        """Save SBOM to file"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(sbom, f, indent=2, sort_keys=True)
        
        print(f"✅ SBOM saved to: {output_file}")
    
    def generate_cyclonedx(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Convert SPDX SBOM to CycloneDX format"""
        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{self._generate_uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "Company",
                        "name": "Custom SBOM Generator",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": self._get_project_name(),
                    "version": "0.1.0"
                }
            },
            "components": []
        }
        
        # Convert packages to components
        for package in sbom["packages"]:
            if package["SPDXID"] != "SPDXRef-Package-" + self._get_project_name():
                component = {
                    "type": "library",
                    "name": package["name"],
                    "version": package.get("versionInfo", "unknown"),
                    "purl": self._generate_purl(package)
                }
                
                # Add licenses
                if package.get("licenseConcluded") and package["licenseConcluded"] != "NOASSERTION":
                    component["licenses"] = [
                        {"license": {"id": package["licenseConcluded"]}}
                    ]
                
                # Add hashes
                if package.get("checksums"):
                    component["hashes"] = [
                        {
                            "alg": checksum["algorithm"],
                            "content": checksum["checksumValue"]
                        }
                        for checksum in package["checksums"]
                    ]
                
                cyclonedx["components"].append(component)
        
        return cyclonedx
    
    def _generate_purl(self, package: Dict[str, Any]) -> str:
        """Generate Package URL (PURL) for package"""
        name = package["name"]
        version = package.get("versionInfo", "unknown")
        return f"pkg:cargo/{name}@{version}"
    
    def _generate_uuid(self) -> str:
        """Generate UUID for CycloneDX BOM"""
        import uuid
        return str(uuid.uuid4())
    
    def verify_integrity(self, sbom: Dict[str, Any]) -> bool:
        """Verify SBOM integrity and completeness"""
        print("🔐 Verifying SBOM integrity...")
        
        required_fields = ["spdxVersion", "dataLicense", "SPDXID", "name", "packages"]
        
        for field in required_fields:
            if field not in sbom:
                print(f"❌ Missing required field: {field}")
                return False
        
        # Verify package structure
        for package in sbom["packages"]:
            if "SPDXID" not in package or "name" not in package:
                print(f"❌ Invalid package structure: {package}")
                return False
        
        print("✅ SBOM integrity verification passed")
        return True


def main():
    parser = argparse.ArgumentParser(description="Generate SBOM for Rust project")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--output", default="sbom.spdx.json", help="Output file path")
    parser.add_argument("--format", choices=["spdx", "cyclonedx", "both"], default="both")
    parser.add_argument("--verify", action="store_true", help="Verify SBOM integrity")
    
    args = parser.parse_args()
    
    generator = SBOMGenerator(args.project_root)
    
    try:
        # Generate SPDX SBOM
        sbom = generator.generate_sbom()
        
        if args.verify:
            if not generator.verify_integrity(sbom):
                sys.exit(1)
        
        # Save SPDX format
        if args.format in ["spdx", "both"]:
            spdx_path = args.output
            generator.save_sbom(sbom, spdx_path)
        
        # Save CycloneDX format
        if args.format in ["cyclonedx", "both"]:
            cyclonedx = generator.generate_cyclonedx(sbom)
            cyclonedx_path = args.output.replace(".spdx.json", ".cyclonedx.json")
            generator.save_sbom(cyclonedx, cyclonedx_path)
        
        print(f"✅ SBOM generation completed successfully")
        
        # Print summary
        package_count = len([p for p in sbom["packages"] if not p["SPDXID"].endswith(generator._get_project_name())])
        print(f"📊 Generated SBOM with {package_count} dependencies")
        
    except Exception as e:
        print(f"❌ Error generating SBOM: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
