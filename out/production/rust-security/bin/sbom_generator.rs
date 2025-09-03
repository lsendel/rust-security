#![allow(clippy::print_stdout, clippy::missing_errors_doc, clippy::unused_self, clippy::unnecessary_wraps, clippy::struct_field_names, clippy::ref_option, clippy::option_if_let_else)]

use anyhow::{anyhow, Result};
use chrono::Utc;
use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use uuid::Uuid;

// Unused dependencies (required by workspace but not used in this binary)
use calamine as _;
use common as _;
use compliance_tools as _;
use config as _;
use csv as _;
use dotenvy as _;
use fastrand as _;
use handlebars as _;
use moka as _;
#[cfg(feature = "prometheus-metrics")]
use prometheus as _;
use pulldown_cmark as _;
use regex as _;
use reqwest as _;
use serde_yaml as _;
use tempfile as _;
use tera as _;
use thiserror as _;
use tokio as _;
use tracing as _;
use tracing_subscriber as _;
use url as _;
use walkdir as _;

#[derive(Debug, Serialize, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
    license: Option<String>,
    repository: Option<String>,
    description: Option<String>,
    authors: Vec<String>,
    checksum: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    #[serde(rename = "dataLicense")]
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    #[serde(rename = "creationInfo")]
    creation_info: CreationInfo,
    packages: Vec<SpdxPackage>,
    relationships: Vec<Relationship>,
    vulnerabilities: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct CreationInfo {
    created: String,
    creators: Vec<String>,
    #[serde(rename = "licenseListVersion")]
    license_list_version: String,
}

#[derive(Debug, Clone, Serialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo", skip_serializing_if = "Option::is_none")]
    version_info: Option<String>,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    checksums: Option<Vec<Checksum>>,
    #[serde(rename = "licenseConcluded")]
    license_concluded: String,
    #[serde(rename = "licenseDeclared")]
    license_declared: String,
    #[serde(rename = "copyrightText", skip_serializing_if = "Option::is_none")]
    copyright_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Checksum {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

#[derive(Debug, Serialize)]
struct Relationship {
    #[serde(rename = "spdxElementId")]
    spdx_element_id: String,
    #[serde(rename = "relationshipType")]
    relationship_type: String,
    #[serde(rename = "relatedSpdxElement")]
    related_spdx_element: String,
}

#[derive(Debug, Serialize)]
pub struct CycloneDxDocument {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(rename = "specVersion")]
    spec_version: String,
    #[serde(rename = "serialNumber")]
    serial_number: String,
    version: i32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
}

#[derive(Debug, Serialize)]
struct CycloneDxMetadata {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
    component: CycloneDxComponent,
}

#[derive(Debug, Serialize)]
struct CycloneDxTool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Debug, Serialize)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<CycloneDxLicense>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<CycloneDxHash>>,
}

#[derive(Debug, Serialize)]
struct CycloneDxLicense {
    license: CycloneDxLicenseInfo,
}

#[derive(Debug, Serialize)]
struct CycloneDxLicenseInfo {
    id: String,
}

#[derive(Debug, Serialize)]
struct CycloneDxHash {
    alg: String,
    content: String,
}

pub struct SbomGenerator {
    project_root: PathBuf,
}

impl SbomGenerator {
    pub fn new(project_root: impl AsRef<Path>) -> Self {
        Self {
            project_root: project_root.as_ref().to_path_buf(),
        }
    }

    pub fn generate_spdx_sbom(&self) -> Result<SpdxDocument> {
        println!("🔍 Generating Software Bill of Materials (SBOM)...");

        let now = Utc::now();
        let project_name = self.get_project_name()?;
        let project_package = self.create_project_package(&project_name)?;
        let dependencies = self.parse_dependencies()?;

        let mut packages = vec![project_package.clone()];
        let mut relationships = Vec::new();

        for dep in dependencies {
            let package = self.create_dependency_package(&dep);
            packages.push(package.clone());

            relationships.push(Relationship {
                spdx_element_id: project_package.spdx_id.clone(),
                relationship_type: "DEPENDS_ON".to_string(),
                related_spdx_element: package.spdx_id,
            });
        }

        Ok(SpdxDocument {
            spdx_version: "SPDX-2.3".to_string(),
            data_license: "CC0-1.0".to_string(),
            spdx_id: "SPDXRef-DOCUMENT".to_string(),
            name: "Rust Auth Service SBOM".to_string(),
            document_namespace: format!(
                "https://company.com/sbom/{}-{}",
                project_name,
                now.format("%Y%m%d%H%M%S")
            ),
            creation_info: CreationInfo {
                created: now.to_rfc3339(),
                creators: vec!["Tool: Rust SBOM Generator".to_string()],
                license_list_version: "3.17".to_string(),
            },
            packages,
            relationships,
            vulnerabilities: Vec::new(),
        })
    }

    pub fn generate_cyclonedx_sbom(&self, spdx: &SpdxDocument) -> Result<CycloneDxDocument> {
        let now = Utc::now();
        let project_name = self.get_project_name()?;

        let main_component = CycloneDxComponent {
            component_type: "application".to_string(),
            name: project_name.clone(),
            version: "0.1.0".to_string(),
            purl: None,
            licenses: None,
            hashes: None,
        };

        let mut components = Vec::new();

        for package in &spdx.packages {
            if !package.spdx_id.ends_with(&project_name) {
                let mut component = CycloneDxComponent {
                    component_type: "library".to_string(),
                    name: package.name.clone(),
                    version: package
                        .version_info
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    purl: Some(self.generate_purl(&package.name, &package.version_info)),
                    licenses: None,
                    hashes: None,
                };

                if package.license_concluded != "NOASSERTION" {
                    component.licenses = Some(vec![CycloneDxLicense {
                        license: CycloneDxLicenseInfo {
                            id: package.license_concluded.clone(),
                        },
                    }]);
                }

                if let Some(checksums) = &package.checksums {
                    component.hashes = Some(
                        checksums
                            .iter()
                            .map(|c| CycloneDxHash {
                                alg: c.algorithm.clone(),
                                content: c.checksum_value.clone(),
                            })
                            .collect(),
                    );
                }

                components.push(component);
            }
        }

        Ok(CycloneDxDocument {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.4".to_string(),
            serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
            version: 1,
            metadata: CycloneDxMetadata {
                timestamp: now.to_rfc3339(),
                tools: vec![CycloneDxTool {
                    vendor: "Company".to_string(),
                    name: "Rust SBOM Generator".to_string(),
                    version: "1.0.0".to_string(),
                }],
                component: main_component,
            },
            components,
        })
    }

    fn get_project_name(&self) -> Result<String> {
        let output = ProcessCommand::new("cargo")
            .args(["metadata", "--format-version", "1"])
            .current_dir(&self.project_root)
            .output()
            .map_err(|e| anyhow!("Failed to run cargo metadata: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
            .map_err(|e| anyhow!("Failed to parse cargo metadata: {}", e))?;

        if let Some(first_member) = metadata.workspace_members.first() {
            if let Some(name) = first_member.split(' ').next() {
                return Ok(name.to_string());
            }
        }

        Ok("rust-auth-service".to_string())
    }

    fn create_project_package(&self, project_name: &str) -> Result<SpdxPackage> {
        Ok(SpdxPackage {
            spdx_id: format!("SPDXRef-Package-{project_name}"),
            name: project_name.to_string(),
            version_info: Some("0.1.0".to_string()),
            download_location: "git+https://github.com/company/rust-security.git".to_string(),
            files_analyzed: true,
            checksums: Some(vec![Checksum {
                algorithm: "SHA256".to_string(),
                checksum_value: self.calculate_project_checksum()?,
            }]),
            license_concluded: "Apache-2.0".to_string(),
            license_declared: "Apache-2.0".to_string(),
            copyright_text: Some("Copyright (c) 2024 Company".to_string()),
            supplier: Some("Organization: Company Security Team".to_string()),
            description: None,
        })
    }

    fn parse_dependencies(&self) -> Result<Vec<CargoPackage>> {
        let output = ProcessCommand::new("cargo")
            .args(["metadata", "--format-version", "1"])
            .current_dir(&self.project_root)
            .output()
            .map_err(|e| anyhow!("Failed to run cargo metadata: {}", e))?;

        if !output.status.success() {
            return Err(anyhow!(
                "cargo metadata failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
            .map_err(|e| anyhow!("Failed to parse cargo metadata: {}", e))?;

        Ok(metadata
            .packages
            .into_iter()
            .filter(|pkg| pkg.source.is_some())
            .collect())
    }

    fn create_dependency_package(&self, dep: &CargoPackage) -> SpdxPackage {
        let license_concluded = dep
            .license
            .clone()
            .unwrap_or_else(|| "NOASSERTION".to_string());
        let license_declared = license_concluded.clone();

        let checksums = dep.checksum.as_ref().map(|checksum| {
            vec![Checksum {
                algorithm: "SHA256".to_string(),
                checksum_value: checksum.clone(),
            }]
        });

        SpdxPackage {
            spdx_id: format!("SPDXRef-Package-{}", dep.name),
            name: dep.name.clone(),
            version_info: Some(dep.version.clone()),
            download_location: self.get_download_location(dep),
            files_analyzed: false,
            checksums,
            license_concluded,
            license_declared,
            copyright_text: None,
            supplier: if dep.authors.is_empty() {
                Some("Person: Unknown".to_string())
            } else {
                Some(format!("Person: {}", dep.authors.join(", ")))
            },
            description: dep.description.clone(),
        }
    }

    fn get_download_location(&self, dep: &CargoPackage) -> String {
        if let Some(source) = &dep.source {
            if source.contains("registry+https://github.com/rust-lang/crates.io-index") {
                format!("https://crates.io/crates/{}/{}", dep.name, dep.version)
            } else if source.starts_with("git+") {
                source.replace("registry+", "")
            } else {
                "NOASSERTION".to_string()
            }
        } else {
            "NOASSERTION".to_string()
        }
    }

    fn calculate_project_checksum(&self) -> Result<String> {
        let mut hasher = Sha256::new();

        // Hash Rust source files
        for entry in walkdir::WalkDir::new(&self.project_root)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("rs")
                && !path.components().any(|c| {
                    matches!(
                        c.as_os_str().to_str(),
                        Some("target" | ".git" | "node_modules")
                    )
                })
            {
                if let Ok(content) = fs::read(path) {
                    hasher.update(&content);
                }
            }
        }

        // Hash Cargo.toml and Cargo.lock
        for filename in &["Cargo.toml", "Cargo.lock"] {
            let path = self.project_root.join(filename);
            if path.exists() {
                if let Ok(content) = fs::read(&path) {
                    hasher.update(&content);
                }
            }
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn generate_purl(&self, name: &str, version: &Option<String>) -> String {
        let version_str = version.as_deref().unwrap_or("unknown");
        format!("pkg:cargo/{name}@{version_str}")
    }

    pub fn verify_integrity(&self, sbom: &SpdxDocument) -> Result<()> {
        println!("🔐 Verifying SBOM integrity...");

        if sbom.spdx_version.is_empty() {
            return Err(anyhow!("Missing spdxVersion"));
        }

        if sbom.data_license.is_empty() {
            return Err(anyhow!("Missing dataLicense"));
        }

        if sbom.spdx_id.is_empty() {
            return Err(anyhow!("Missing SPDXID"));
        }

        if sbom.name.is_empty() {
            return Err(anyhow!("Missing name"));
        }

        if sbom.packages.is_empty() {
            return Err(anyhow!("No packages found"));
        }

        for package in &sbom.packages {
            if package.spdx_id.is_empty() || package.name.is_empty() {
                return Err(anyhow!("Invalid package structure: {}", package.name));
            }
        }

        println!("✅ SBOM integrity verification passed");
        Ok(())
    }

    pub fn save_sbom<T: Serialize>(&self, sbom: &T, output_path: &Path) -> Result<()> {
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(sbom)?;
        fs::write(output_path, content)?;

        println!("✅ SBOM saved to: {}", output_path.display());
        Ok(())
    }
}

#[allow(clippy::print_stdout, clippy::missing_errors_doc, clippy::unused_self, clippy::unnecessary_wraps, clippy::struct_field_names, clippy::ref_option, clippy::option_if_let_else)]
fn main() -> Result<()> {
    let matches = Command::new("sbom_generator")
        .about("Generate SBOM for Rust project")
        .arg(
            Arg::new("project-root")
                .long("project-root")
                .value_name("DIR")
                .help("Project root directory")
                .default_value("."),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .value_name("FILE")
                .help("Output file path")
                .default_value("sbom.spdx.json"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format")
                .value_parser(["spdx", "cyclonedx", "both"])
                .default_value("both"),
        )
        .arg(
            Arg::new("verify")
                .long("verify")
                .help("Verify SBOM integrity")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    let project_root = matches.get_one::<String>("project-root").unwrap();
    let output = matches.get_one::<String>("output").unwrap();
    let format = matches.get_one::<String>("format").unwrap();
    let verify = matches.get_flag("verify");

    let generator = SbomGenerator::new(project_root);

    // Generate SPDX SBOM
    let spdx_sbom = generator.generate_spdx_sbom()?;

    if verify {
        generator.verify_integrity(&spdx_sbom)?;
    }

    // Save SPDX format
    if format == "spdx" || format == "both" {
        let spdx_path = Path::new(output);
        generator.save_sbom(&spdx_sbom, spdx_path)?;
    }

    // Save CycloneDX format
    if format == "cyclonedx" || format == "both" {
        let cyclonedx_sbom = generator.generate_cyclonedx_sbom(&spdx_sbom)?;
        let cyclonedx_path = Path::new(output).with_file_name(
            Path::new(output)
                .file_stem()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("sbom")
                .replace(".spdx", ".cyclonedx")
                + ".cyclonedx.json",
        );
        generator.save_sbom(&cyclonedx_sbom, &cyclonedx_path)?;
    }

    println!("✅ SBOM generation completed successfully");

    // Print summary
    let package_count = spdx_sbom
        .packages
        .iter()
        .filter(|p| {
            !p.spdx_id
                .ends_with(&generator.get_project_name().unwrap_or_default())
        })
        .count();
    println!("📊 Generated SBOM with {package_count} dependencies");

    Ok(())
}
