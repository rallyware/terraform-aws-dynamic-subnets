locals {
  cidr_block               = var.cidr_block != "" ? var.cidr_block : one(data.aws_vpc.default[*].cidr_block)
  nat_instance_enabled     = local.enabled && var.nat_instance_enabled
  nat_instance_count       = local.nat_instance_enabled ? length(var.availability_zones) : 0
  nat_instance_eip_count   = local.use_existing_eips ? 0 : local.nat_instance_count
  nat_instance_ami         = local.nat_instance_enabled && var.nat_instance_ami_lock ? one(null_resource.nat_instance[*].triggers["ami"]) : one(data.aws_ami.nat_instance[*].id)
  instance_eip_allocations = local.use_existing_eips ? data.aws_eip.nat_ips[*].id : aws_eip.nat_instance[*].id
}

module "nat_instance_label" {
  source  = "cloudposse/label/null"
  version = "0.25.0"

  attributes = ["nat", "instance"]

  context = module.this.context
}

data "cloudinit_config" "nat_instance" {
  count = local.nat_instance_enabled ? 1 : 0

  gzip          = false
  base64_encode = true
  boundary      = "//"

  part {
    content_type = "text/x-shellscript"
    content      = file("${path.module}/userdata/nat.tpl")
  }
}

resource "aws_security_group" "nat_instance" {
  count       = local.nat_instance_enabled ? 1 : 0
  name        = module.nat_instance_label.id
  description = "Security Group for NAT Instance"
  vpc_id      = var.vpc_id
  tags        = module.nat_instance_label.tags
}

resource "aws_security_group_rule" "nat_instance_egress" {
  count             = local.nat_instance_enabled ? 1 : 0
  description       = "Allow all egress traffic"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"] #tfsec:ignore:aws-ec2-no-public-egress-sgr
  security_group_id = one(aws_security_group.nat_instance[*].id)
  type              = "egress"
}

resource "aws_security_group_rule" "nat_instance_ingress" {
  count             = local.nat_instance_enabled ? 1 : 0
  description       = "Allow ingress traffic from the VPC CIDR block"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [local.cidr_block]
  security_group_id = one(aws_security_group.nat_instance[*].id)
  type              = "ingress"
}

# aws --region us-east-1 ec2 describe-images --owners amazon --filters Name="name",Values="amzn2-ami-hvm-*" Name="virtualization-type",Values="hvm" Name="architecture",Values="arm64"
data "aws_ami" "nat_instance" {
  count       = local.nat_instance_enabled ? 1 : 0
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = [var.nat_instance_ami_architecture]
  }

  owners = ["amazon"]
}

resource "null_resource" "nat_instance" {
  count = local.nat_instance_enabled && var.nat_instance_ami_lock ? 1 : 0

  triggers = {
    ami = one(data.aws_ami.nat_instance[*].id)
  }

  lifecycle {
    ignore_changes = [
      triggers["ami"]
    ]
  }
}

# https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-comparison.html
# https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html
# https://dzone.com/articles/nat-instance-vs-nat-gateway
resource "aws_instance" "nat_instance" {
  count                  = local.nat_instance_count
  ami                    = local.nat_instance_ami
  user_data_base64       = one(data.cloudinit_config.nat_instance[*].rendered)
  instance_type          = var.nat_instance_type
  subnet_id              = element(aws_subnet.public[*].id, count.index)
  vpc_security_group_ids = [aws_security_group.nat_instance[0].id]

  tags = merge(
    module.nat_instance_label.tags,
    {
      "Name" = format("%s%s%s", module.nat_instance_label.id, local.delimiter, local.az_map[element(var.availability_zones, count.index)])
    }
  )

  # Required by NAT
  # https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck
  source_dest_check = false

  #bridgecrew:skip=BC_AWS_PUBLIC_12: Skipping `EC2 Should Not Have Public IPs` check. NAT instance requires public IP.
  #bridgecrew:skip=BC_AWS_GENERAL_31: Skipping `Ensure Instance Metadata Service Version 1 is not enabled` check until BridgeCrew support condition evaluation. See https://github.com/bridgecrewio/checkov/issues/793
  associate_public_ip_address = true

  lifecycle {
    create_before_destroy = true
  }

  metadata_options {
    http_endpoint               = (var.metadata_http_endpoint_enabled) ? "enabled" : "disabled"
    http_put_response_hop_limit = var.metadata_http_put_response_hop_limit
    http_tokens                 = (var.metadata_http_tokens_required) ? "required" : "optional"
  }

  root_block_device {
    encrypted = var.root_block_device_encrypted
  }
}

resource "aws_eip" "nat_instance" {
  count = local.nat_instance_enabled ? local.nat_instance_eip_count : 0
  vpc   = true
  tags = merge(
    module.nat_instance_label.tags,
    {
      "Name" = format("%s%s%s", module.nat_instance_label.id, local.delimiter, local.az_map[element(var.availability_zones, count.index)])
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eip_association" "nat_instance" {
  count         = local.nat_instance_count
  instance_id   = element(aws_instance.nat_instance[*].id, count.index)
  allocation_id = element(local.instance_eip_allocations, count.index)
}

# wait untill nat-instances become up
resource "time_sleep" "nat_instance_metadata" {
  count = local.nat_instance_count

  create_duration = "180s"

  triggers = {
    primary_network_interface_id = element(aws_instance.nat_instance[*].primary_network_interface_id, count.index)
  }
}

resource "aws_route" "nat_instance" {
  count                  = local.nat_instance_count
  route_table_id         = element(aws_route_table.private[*].id, count.index)
  network_interface_id   = element(time_sleep.nat_instance_metadata[*].triggers["primary_network_interface_id"], count.index)
  destination_cidr_block = "0.0.0.0/0"

  depends_on = [
    aws_route_table.private,
    aws_eip_association.nat_instance
  ]

  timeouts {
    create = var.aws_route_create_timeout
    delete = var.aws_route_delete_timeout
  }
}

resource "aws_cloudwatch_metric_alarm" "default" {
  count               = local.nat_instance_count
  alarm_name          = format("%s-%s", module.nat_instance_label.id, count.index)
  comparison_operator = var.nat_instance_cloudwatch_metric_alarm["comparison_operator"]
  evaluation_periods  = var.nat_instance_cloudwatch_metric_alarm["evaluation_periods"]
  metric_name         = var.nat_instance_cloudwatch_metric_alarm["metric_name"]
  namespace           = var.nat_instance_cloudwatch_metric_alarm["namespace"]
  period              = var.nat_instance_cloudwatch_metric_alarm["period"]
  statistic           = var.nat_instance_cloudwatch_metric_alarm["statistic"]
  threshold           = var.nat_instance_cloudwatch_metric_alarm["threshold"]

  dimensions = {
    InstanceId = element(aws_instance.nat_instance[*].id, count.index)
  }

  alarm_actions = [
    format("arn:%s:swf:%s:%s:%s",
      one(data.aws_partition.default[*].partition),
      one(data.aws_region.default[*].name),
      one(data.aws_caller_identity.default[*].account_id),
      var.nat_instance_cloudwatch_metric_alarm["action"]
    )
  ]
}
