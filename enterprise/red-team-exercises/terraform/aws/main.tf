# AWS Infrastructure with Security Best Practices
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.9"
    }
  }
  
  backend "s3" {
    bucket         = "auth-service-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    
    # Additional security
    kms_key_id = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# KMS Key for encryption
resource "aws_kms_key" "auth_service" {
  description             = "KMS key for auth service encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = {
    Name        = "auth-service-kms"
    Environment = var.environment
    Service     = "auth-service"
  }
}

resource "aws_kms_alias" "auth_service" {
  name          = "alias/auth-service-${var.environment}"
  target_key_id = aws_kms_key.auth_service.key_id
}

# VPC with security best practices
resource "aws_vpc" "auth_service" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name                                        = "auth-service-vpc-${var.environment}"
    Environment                                 = var.environment
    "kubernetes.io/cluster/auth-service-${var.environment}" = "shared"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "auth_service" {
  vpc_id = aws_vpc.auth_service.id
  
  tags = {
    Name        = "auth-service-igw-${var.environment}"
    Environment = var.environment
  }
}

# Private subnets for EKS nodes
resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)
  
  vpc_id                  = aws_vpc.auth_service.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  
  tags = {
    Name                                        = "auth-service-private-${count.index + 1}-${var.environment}"
    Environment                                 = var.environment
    Type                                        = "private"
    "kubernetes.io/cluster/auth-service-${var.environment}" = "owned"
    "kubernetes.io/role/internal-elb"           = "1"
  }
}

# Public subnets for load balancers
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)
  
  vpc_id                  = aws_vpc.auth_service.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = {
    Name                                        = "auth-service-public-${count.index + 1}-${var.environment}"
    Environment                                 = var.environment
    Type                                        = "public"
    "kubernetes.io/cluster/auth-service-${var.environment}" = "owned"
    "kubernetes.io/role/elb"                    = "1"
  }
}

# Database subnets
resource "aws_subnet" "database" {
  count = length(var.database_subnet_cidrs)
  
  vpc_id            = aws_vpc.auth_service.id
  cidr_block        = var.database_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name        = "auth-service-database-${count.index + 1}-${var.environment}"
    Environment = var.environment
    Type        = "database"
  }
}

# NAT Gateways for private subnets
resource "aws_eip" "nat" {
  count  = length(aws_subnet.public)
  domain = "vpc"
  
  depends_on = [aws_internet_gateway.auth_service]
  
  tags = {
    Name        = "auth-service-nat-eip-${count.index + 1}-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_nat_gateway" "auth_service" {
  count = length(aws_subnet.public)
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  depends_on = [aws_internet_gateway.auth_service]
  
  tags = {
    Name        = "auth-service-nat-${count.index + 1}-${var.environment}"
    Environment = var.environment
  }
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.auth_service.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.auth_service.id
  }
  
  tags = {
    Name        = "auth-service-public-rt-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_route_table" "private" {
  count  = length(aws_subnet.private)
  vpc_id = aws_vpc.auth_service.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.auth_service[count.index].id
  }
  
  tags = {
    Name        = "auth-service-private-rt-${count.index + 1}-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_route_table" "database" {
  vpc_id = aws_vpc.auth_service.id
  
  tags = {
    Name        = "auth-service-database-rt-${var.environment}"
    Environment = var.environment
  }
}

# Route table associations
resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)
  
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "database" {
  count = length(aws_subnet.database)
  
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# Security Groups
resource "aws_security_group" "eks_cluster" {
  name_prefix = "auth-service-eks-cluster-${var.environment}"
  vpc_id      = aws_vpc.auth_service.id
  
  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "auth-service-eks-cluster-sg-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_security_group" "eks_nodes" {
  name_prefix = "auth-service-eks-nodes-${var.environment}"
  vpc_id      = aws_vpc.auth_service.id
  
  ingress {
    description     = "Node to node communication"
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_cluster.id]
    self            = true
  }
  
  ingress {
    description = "Webhook admission controllers"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  ingress {
    description = "Kubelet API"
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  ingress {
    description = "NodePort services"
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "auth-service-eks-nodes-sg-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "auth-service-rds-${var.environment}"
  vpc_id      = aws_vpc.auth_service.id
  
  ingress {
    description     = "PostgreSQL from EKS nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }
  
  tags = {
    Name        = "auth-service-rds-sg-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_security_group" "elasticache" {
  name_prefix = "auth-service-elasticache-${var.environment}"
  vpc_id      = aws_vpc.auth_service.id
  
  ingress {
    description     = "Redis from EKS nodes"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.eks_nodes.id]
  }
  
  tags = {
    Name        = "auth-service-elasticache-sg-${var.environment}"
    Environment = var.environment
  }
}

# EKS Cluster
resource "aws_eks_cluster" "auth_service" {
  name     = "auth-service-${var.environment}"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version
  
  vpc_config {
    subnet_ids              = aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = var.environment == "production" ? false : true
    public_access_cidrs     = var.environment == "production" ? [] : ["0.0.0.0/0"]
    security_group_ids      = [aws_security_group.eks_cluster.id]
  }
  
  encryption_config {
    provider {
      key_arn = aws_kms_key.auth_service.arn
    }
    resources = ["secrets"]
  }
  
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_AmazonEKSClusterPolicy,
    aws_cloudwatch_log_group.eks_cluster,
  ]
  
  tags = {
    Name        = "auth-service-eks-${var.environment}"
    Environment = var.environment
  }
}

# CloudWatch Log Group for EKS
resource "aws_cloudwatch_log_group" "eks_cluster" {
  name              = "/aws/eks/auth-service-${var.environment}/cluster"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.auth_service.arn
  
  tags = {
    Name        = "auth-service-eks-logs-${var.environment}"
    Environment = var.environment
  }
}

# EKS Node Group
resource "aws_eks_node_group" "auth_service" {
  cluster_name    = aws_eks_cluster.auth_service.name
  node_group_name = "auth-service-nodes-${var.environment}"
  node_role_arn   = aws_iam_role.eks_node.arn
  subnet_ids      = aws_subnet.private[*].id
  
  capacity_type  = "ON_DEMAND"
  instance_types = var.node_instance_types
  ami_type       = "AL2_x86_64"
  disk_size      = 50
  
  scaling_config {
    desired_size = var.node_desired_size
    max_size     = var.node_max_size
    min_size     = var.node_min_size
  }
  
  update_config {
    max_unavailable = 1
  }
  
  launch_template {
    id      = aws_launch_template.eks_nodes.id
    version = "$Latest"
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_node_AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eks_node_AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eks_node_AmazonEC2ContainerRegistryReadOnly,
  ]
  
  tags = {
    Name        = "auth-service-node-group-${var.environment}"
    Environment = var.environment
  }
}

# Launch Template for EKS Nodes
resource "aws_launch_template" "eks_nodes" {
  name_prefix   = "auth-service-nodes-${var.environment}"
  image_id      = data.aws_ami.eks_worker.id
  instance_type = var.node_instance_types[0]
  
  vpc_security_group_ids = [aws_security_group.eks_nodes.id]
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    cluster_name = aws_eks_cluster.auth_service.name
    endpoint     = aws_eks_cluster.auth_service.endpoint
    ca_data      = aws_eks_cluster.auth_service.certificate_authority[0].data
  }))
  
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 50
      volume_type = "gp3"
      encrypted   = true
      kms_key_id  = aws_kms_key.auth_service.arn
    }
  }
  
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  
  monitoring {
    enabled = true
  }
  
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "auth-service-node-${var.environment}"
      Environment = var.environment
    }
  }
}

# RDS Subnet Group
resource "aws_db_subnet_group" "auth_service" {
  name       = "auth-service-${var.environment}"
  subnet_ids = aws_subnet.database[*].id
  
  tags = {
    Name        = "auth-service-db-subnet-group-${var.environment}"
    Environment = var.environment
  }
}

# RDS Instance with encryption
resource "aws_db_instance" "auth_service" {
  identifier = "auth-service-${var.environment}"
  
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = var.db_instance_class
  allocated_storage      = var.db_allocated_storage
  max_allocated_storage  = var.db_max_allocated_storage
  storage_type           = "gp3"
  storage_encrypted      = true
  kms_key_id            = aws_kms_key.auth_service.arn
  
  db_name  = "authservice"
  username = var.db_username
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.auth_service.name
  
  backup_retention_period = var.db_backup_retention_period
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot       = false
  final_snapshot_identifier = "auth-service-${var.environment}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"
  
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.auth_service.arn
  
  enabled_cloudwatch_logs_exports = ["postgresql"]
  
  deletion_protection = var.environment == "production" ? true : false
  
  tags = {
    Name        = "auth-service-db-${var.environment}"
    Environment = var.environment
  }
}

# ElastiCache Subnet Group
resource "aws_elasticache_subnet_group" "auth_service" {
  name       = "auth-service-${var.environment}"
  subnet_ids = aws_subnet.private[*].id
  
  tags = {
    Name        = "auth-service-redis-subnet-group-${var.environment}"
    Environment = var.environment
  }
}

# ElastiCache Redis Cluster
resource "aws_elasticache_replication_group" "auth_service" {
  description          = "Redis cluster for auth service ${var.environment}"
  replication_group_id = "auth-service-${var.environment}"
  
  node_type            = var.redis_node_type
  port                 = 6379
  parameter_group_name = aws_elasticache_parameter_group.auth_service.name
  
  num_cache_clusters = var.redis_num_cache_nodes
  
  subnet_group_name  = aws_elasticache_subnet_group.auth_service.name
  security_group_ids = [aws_security_group.elasticache.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = var.redis_auth_token
  kms_key_id                 = aws_kms_key.auth_service.arn
  
  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.elasticache_slow.name
    destination_type = "cloudwatch-logs"
    log_format       = "text"
    log_type         = "slow-log"
  }
  
  automatic_failover_enabled = true
  multi_az_enabled          = true
  
  maintenance_window = "sun:05:00-sun:06:00"
  snapshot_window    = "03:00-05:00"
  snapshot_retention_limit = 7
  
  tags = {
    Name        = "auth-service-redis-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_elasticache_parameter_group" "auth_service" {
  family = "redis7.x"
  name   = "auth-service-${var.environment}"
  
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
  
  parameter {
    name  = "timeout"
    value = "300"
  }
  
  parameter {
    name  = "tcp-keepalive"
    value = "300"
  }
  
  tags = {
    Name        = "auth-service-redis-params-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "elasticache_slow" {
  name              = "/aws/elasticache/auth-service-${var.environment}/slow-log"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.auth_service.arn
  
  tags = {
    Name        = "auth-service-redis-slow-logs-${var.environment}"
    Environment = var.environment
  }
}

# ECR Repository for container images
resource "aws_ecr_repository" "auth_service" {
  name                 = "auth-service"
  image_tag_mutability = "IMMUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.auth_service.arn
  }
  
  tags = {
    Name        = "auth-service-ecr-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_ecr_lifecycle_policy" "auth_service" {
  repository = aws_ecr_repository.auth_service.name
  
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 30 images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# WAF for Application Load Balancer
resource "aws_wafv2_web_acl" "auth_service" {
  name  = "auth-service-${var.environment}"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1
    
    override_action {
      none {}
    }
    
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
        
        scope_down_statement {
          geo_match_statement {
            country_codes = ["CN", "RU", "KP"]
          }
        }
      }
    }
    
    action {
      block {}
    }
    
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
    }
  }
  
  # AWS Managed Rules
  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 2
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
    }
  }
  
  rule {
    name     = "AWS-AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRuleSetMetric"
    }
  }
  
  visibility_config {
    sampled_requests_enabled   = true
    cloudwatch_metrics_enabled = true
    metric_name                = "authServiceWAF"
  }
  
  tags = {
    Name        = "auth-service-waf-${var.environment}"
    Environment = var.environment
  }
}

# GuardDuty
resource "aws_guardduty_detector" "auth_service" {
  enable = true
  
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
  
  tags = {
    Name        = "auth-service-guardduty-${var.environment}"
    Environment = var.environment
  }
}

# Config
resource "aws_config_configuration_recorder" "auth_service" {
  name     = "auth-service-${var.environment}"
  role_arn = aws_iam_role.config.arn
  
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "auth_service" {
  name           = "auth-service-${var.environment}"
  s3_bucket_name = aws_s3_bucket.config.bucket
  s3_key_prefix  = "config"
}

# S3 Bucket for Config
resource "aws_s3_bucket" "config" {
  bucket        = "auth-service-config-${var.environment}-${random_string.bucket_suffix.result}"
  force_destroy = var.environment != "production"
  
  tags = {
    Name        = "auth-service-config-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "config" {
  bucket = aws_s3_bucket.config.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.auth_service.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# CloudTrail
resource "aws_cloudtrail" "auth_service" {
  name           = "auth-service-${var.environment}"
  s3_bucket_name = aws_s3_bucket.cloudtrail.bucket
  s3_key_prefix  = "cloudtrail"
  
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  
  kms_key_id = aws_kms_key.auth_service.arn
  
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_logs.arn
  
  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.config.arn}/*"]
    }
  }
  
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }
  
  tags = {
    Name        = "auth-service-cloudtrail-${var.environment}"
    Environment = var.environment
  }
}

# S3 Bucket for CloudTrail
resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "auth-service-cloudtrail-${var.environment}-${random_string.bucket_suffix.result}"
  force_destroy = var.environment != "production"
  
  tags = {
    Name        = "auth-service-cloudtrail-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.auth_service.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/auth-service-${var.environment}"
  retention_in_days = var.log_retention_in_days
  kms_key_id        = aws_kms_key.auth_service.arn
  
  tags = {
    Name        = "auth-service-cloudtrail-logs-${var.environment}"
    Environment = var.environment
  }
}