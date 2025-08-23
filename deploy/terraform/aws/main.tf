terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_ecr_repository" "odin" {
  name                 = var.ecr_repo
  image_tag_mutability = "MUTABLE"
  force_delete         = true
}

resource "aws_iam_role" "task_exec" {
  name               = "odin-gateway-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}

data "aws_iam_policy_document" "ecs_task_assume" {
  statement {
    effect = "Allow"
    principals { type = "Service" identifiers = ["ecs-tasks.amazonaws.com"] }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "task_exec_attach" {
  role       = aws_iam_role.task_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_cluster" "odin" { name = var.cluster_name }

resource "aws_ecs_task_definition" "gateway" {
  family                   = "odin-gateway"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.task_exec.arn
  container_definitions    = jsonencode([
    {
      name      = "gateway"
      image     = var.image
      essential = true
      portMappings = [{ containerPort = 8080, hostPort = 8080 }]
      environment = [ for k,v in var.env : { name = k, value = v } ]
    }
  ])
}

resource "aws_ecs_service" "gateway" {
  name            = "odin-gateway"
  cluster         = aws_ecs_cluster.odin.id
  task_definition = aws_ecs_task_definition.gateway.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = var.subnets
    security_groups = [var.security_group]
    assign_public_ip = true
  }
  depends_on = [aws_ecs_task_definition.gateway]
}

resource "aws_lb" "gw" {
  name               = "odin-gw-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.subnets
  security_groups    = [var.security_group]
}

resource "aws_lb_target_group" "gw" {
  name     = "odin-gw-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id
  target_type = "ip"
  health_check {
    path = "/healthz"
  }
}

resource "aws_lb_listener" "gw" {
  load_balancer_arn = aws_lb.gw.arn
  port              = 80
  protocol          = "HTTP"
  default_action { type = "forward" target_group_arn = aws_lb_target_group.gw.arn }
}

resource "aws_lb_target_group_attachment" "ecs" {
  target_group_arn = aws_lb_target_group.gw.arn
  target_id        = aws_ecs_service.gateway.id
  port             = 8080
}

output "gateway_url" { value = aws_lb.gw.dns_name }
