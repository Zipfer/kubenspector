# K8s Inspector

> A lightweight Python-based Kubernetes diagnostic tool that detects common cluster issues, provides actionable suggestions, and validates manifests **before apply**.

---

## Overview

`k8s_inspector.py` is a command-line tool designed for DevOps, SRE, and platform engineers who want quick insights into cluster health and configuration issues — **without deploying extra components**.

It connects directly to your Kubernetes cluster (via kubeconfig or in-cluster credentials), scans for potential issues (pods, nodes, PVCs, deployments, events), and generates **human-readable diagnostics and suggested fixes**.

Optionally, it can validate and apply Kubernetes manifests safely using **server-side dry-run** checks before applying.

---

## Features

 **Cluster Diagnostics**
- Detects pod failures (`CrashLoopBackOff`, `ImagePullBackOff`, `OOMKilled`, etc.)
- Identifies unschedulable or `NotReady` nodes
- Reports unbound PVCs, stuck deployments, and warning events
- Highlights high container restart counts and probe issues

 **Manifest Validation**
- Validates YAML manifests with `kubectl apply --dry-run=server`
- Falls back to offline YAML checks if `kubectl` is unavailable

 **Actionable Suggestions**
- Provides step-by-step recommendations (e.g. commands to investigate and fix issues)

 **Non-intrusive**
- Read-only by default — **won’t change your cluster**
- Optional `--apply` flag if you explicitly want to deploy manifests

 **Lightweight**
- No dependencies beyond `kubernetes` and `pyyaml`
- Runs locally or inside a container/pod

---

## Installation

```bash
git clone https://github.com/yourusername/k8s-inspector.git
cd k8s-inspector
pip install -r requirements.txt

