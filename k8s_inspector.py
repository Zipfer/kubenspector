#!/usr/bin/env python3
"""
k8s_inspector.py

Scan a Kubernetes cluster for common issues, provide suggested fixes,
and optionally validate manifests (dry-run) before applying.

Requirements:
  pip install kubernetes pyyaml

Usage:
  python k8s_inspector.py                # scan current cluster (kubeconfig or in-cluster)
  python k8s_inspector.py --manifest myapp.yaml
  python k8s_inspector.py --manifest myapp.yaml --apply
  python k8s_inspector.py --namespace default

Notes:
 - If `kubectl` is available, manifest validation uses `kubectl apply --dry-run=server`,
   which is the most reliable server-side validation.
 - Script intentionally prints suggested fixes; it will not change cluster state
   unless you pass --apply (and even then it first performs server dry-run).
"""

import argparse
import shutil
import subprocess
import sys
import yaml
from datetime import datetime, timezone

from kubernetes import client, config
from kubernetes.client.rest import ApiException

# ---------- Utilities ----------

def load_k8s_config():
    try:
        # Try kubeconfig first (user local)
        config.load_kube_config()
        print("[k8s] Loaded kubeconfig.")
    except Exception:
        try:
            config.load_incluster_config()
            print("[k8s] Loaded in-cluster config.")
        except Exception as e:
            print("[k8s] ERROR loading Kubernetes config:", e)
            sys.exit(1)

def safe_name(obj):
    return f"{obj.metadata.namespace}/{obj.metadata.name}" if hasattr(obj.metadata, "namespace") else obj.metadata.name

# ---------- Checks & Analysis ----------

def check_nodes(v1):
    issues = []
    try:
        nodes = v1.list_node().items
    except ApiException as e:
        return [{"severity":"error","title":"Failed to list nodes","detail":str(e),"suggestion":"Check RBAC and connectivity"}]

    for n in nodes:
        name = n.metadata.name
        conditions = {c.type: c for c in (n.status.conditions or [])}
        ready = conditions.get("Ready")
        if not ready or ready.status != "True":
            last = ready.last_heartbeat_time if ready else "unknown"
            issues.append({
                "severity":"warning",
                "title":f"Node NotReady: {name}",
                "detail":f"Ready={getattr(ready, 'status', 'Unknown')} (lastHeartbeat={last})",
                "suggestion": (
                    "Check node kubelet, disk pressure, network. "
                    "Run: kubectl describe node {name} and check kubelet logs on the node."
                )
            })
        # Check unschedulable
        if n.spec.unschedulable:
            issues.append({
                "severity":"info",
                "title":f"Node Cordoned (unschedulable): {name}",
                "detail":"Node.spec.unschedulable is true",
                "suggestion":"If maintenance finished, uncordon: kubectl uncordon " + name
            })
        # Disk pressure / memory pressure
        for t in ("DiskPressure","MemoryPressure","PIDPressure"):
            c = conditions.get(t)
            if c and c.status == "True":
                issues.append({
                    "severity":"warning",
                    "title":f"Node pressure {t}: {name}",
                    "detail":f"{t} is True (lastTransition: {c.last_transition_time})",
                    "suggestion":"Investigate resource usage on node, evictions, and taints."
                })
    return issues

def analyze_pods(v1, namespace=None):
    issues = []
    if namespace:
        pods = v1.list_namespaced_pod(namespace=namespace).items
    else:
        pods = v1.list_pod_for_all_namespaces().items

    for p in pods:
        ns = p.metadata.namespace
        name = p.metadata.name
        status = p.status
        phase = status.phase
        # Pod not scheduled/pending
        if phase == "Pending":
            # look at conditions and reason
            pending_reason = status.conditions or []
            # look at unschedulable message in status.container_statuses?
            message = getattr(status, "message", "")
            issues.append({
                "severity":"warning",
                "title":f"Pod Pending: {ns}/{name}",
                "detail":f"Phase=Pending. Reason/message: {message or 'none'}",
                "suggestion":"kubectl describe pod -n {ns} {name} to see events; check PVCs, scheduling, node selectors, resource requests."
            })

        # Check container statuses for common problems
        for cs in (status.container_statuses or []):
            cname = cs.name
            if cs.state.waiting:
                reason = cs.state.waiting.reason
                detail = cs.state.waiting.message or ""
                if reason in ("CrashLoopBackOff", "Error"):
                    issues.append({
                        "severity":"warning",
                        "title":f"Container CrashLoopBackOff/Error: {ns}/{name}:{cname}",
                        "detail":f"Reason={reason}. Message={detail}",
                        "suggestion": (
                            "Inspect logs: kubectl logs -n {ns} {name} -c {cname} --previous\n"
                            "Common fixes: fix app exception, increase readinessTimeout, check env/config, use image with correct tag."
                        )
                    })
                elif reason in ("ImagePullBackOff","ErrImagePull","RegistryUnavailable"):
                    issues.append({
                        "severity":"warning",
                        "title":f"Image pull problem: {ns}/{name}:{cname}",
                        "detail":f"Reason={reason}. Message={detail}",
                        "suggestion":"Check image name/tag, registry secret, imagePullSecrets, network. Try docker pull locally or check registry auth."
                    })
                elif reason == "CreateContainerConfigError":
                    issues.append({
                        "severity":"warning",
                        "title":f"Container config error: {ns}/{name}:{cname}",
                        "detail":detail,
                        "suggestion":"Likely bad command/args/env/volumeMounts. kubectl describe pod and check container spec and mounted volumes."
                    })

            if cs.last_state.terminated:
                term = cs.last_state.terminated
                if term.reason == "OOMKilled" or (term.signal or 0) == 9:
                    issues.append({
                        "severity":"warning",
                        "title":f"OOMKilled / terminated container: {ns}/{name}:{cname}",
                        "detail":f"ExitCode={term.exit_code}, reason={term.reason}, finish={term.finished_at}",
                        "suggestion":"Increase memory requests/limits, check for memory leaks, review recent changes, examine logs prior to termination."
                    })

            # high restart count
            if cs.restart_count and cs.restart_count > 5:
                issues.append({
                    "severity":"warning",
                    "title":f"High restart count: {ns}/{name}:{cname}",
                    "detail":f"Restarts={cs.restart_count}",
                    "suggestion":"Investigate initialization,CrashLoopBackOff; check livenessProbe too aggressive, check readiness probe vs startup probe."
                })

        # Check readiness/liveness probe status from containerStatuses? not always available in status - use events
        # We'll look at events below globally.
    return issues

def check_deployments(apps_v1, namespace=None):
    issues = []
    try:
        if namespace:
            deps = apps_v1.list_namespaced_deployment(namespace=namespace).items
        else:
            deps = apps_v1.list_deployment_for_all_namespaces().items
    except ApiException as e:
        return [{"severity":"error","title":"Failed to list deployments","detail":str(e),"suggestion":"Check RBAC and connectivity"}]

    for d in deps:
        ns = d.metadata.namespace
        name = d.metadata.name
        spec_replicas = d.spec.replicas or 0
        status_replicas = d.status.available_replicas or 0
        if spec_replicas != status_replicas:
            issues.append({
                "severity":"warning",
                "title":f"Replica mismatch: {ns}/{name}",
                "detail":f"desired={spec_replicas}, available={status_replicas}",
                "suggestion":"Check recent rollout: kubectl rollout status deployment/{name} -n {ns}; inspect pods for crash/scheduling issues."
            })
        # Check if deployment is progressing
        conds = d.status.conditions or []
        for c in conds:
            if c.type == "Progressing" and c.status == "False":
                issues.append({
                    "severity":"warning",
                    "title":f"Deployment not progressing: {ns}/{name}",
                    "detail":f"{c.reason}: {c.message}",
                    "suggestion":"kubectl describe deployment -n {ns} {name}; check events and ReplicaSets"
                })

    return issues

def check_pvcs(v1, namespace=None):
    issues = []
    try:
        if namespace:
            pvcs = v1.list_namespaced_persistent_volume_claim(namespace=namespace).items
        else:
            pvcs = v1.list_persistent_volume_claim_for_all_namespaces().items
    except ApiException as e:
        return [{"severity":"error","title":"Failed to list PVCs","detail":str(e),"suggestion":"Check RBAC and connectivity"}]

    for pvc in pvcs:
        ns = pvc.metadata.namespace
        name = pvc.metadata.name
        phase = pvc.status.phase
        if phase != "Bound":
            issues.append({
                "severity":"warning",
                "title":f"PVC not Bound: {ns}/{name}",
                "detail":f"phase={phase}",
                "suggestion":"Check StorageClass, PV availability, and events: kubectl describe pvc -n {ns} {name}"
            })
    return issues

def collect_events(v1, since_minutes=60, namespace=None):
    ev_issues = []
    try:
        if namespace:
            events = v1.list_namespaced_event(namespace=namespace).items
        else:
            events = v1.list_event_for_all_namespaces().items
    except ApiException as e:
        return [{"severity":"error","title":"Failed to list events","detail":str(e),"suggestion":"Check RBAC and connectivity"}]

    cutoff = datetime.now(timezone.utc).timestamp() - since_minutes*60
    for e in events:
        t = e.last_timestamp or e.event_time or e.first_timestamp
        # some events use event_time; normalize
        if not t:
            continue
        try:
            ts = t.timestamp()
        except Exception:
            continue
        if ts < cutoff:
            continue
        # pick only Warning events
        if e.type == "Warning":
            ev_issues.append({
                "severity":"warning",
                "title":f"Event: {e.involved_object.kind} {e.involved_object.name} - {e.reason}",
                "detail":f"{e.message}",
                "suggestion":"Investigate the resource and reason; kubectl describe on the involved object."
            })
    return ev_issues

# ---------- Manifest validation (dry-run) ----------

def kubectl_available():
    return shutil.which("kubectl") is not None

def kubectl_dry_run(manifest_path, namespace=None):
    """Run server-side dry-run using kubectl if available. Returns (ok, output)."""
    cmd = ["kubectl", "apply", "--dry-run=server", "-f", manifest_path]
    if namespace:
        cmd += ["-n", namespace]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as e:
        return False, f"Failed to run kubectl: {e}"
    ok = proc.returncode == 0
    return ok, proc.stdout + proc.stderr

def simple_local_manifest_check(manifest_path):
    """Lightweight YAML parse and basic checks (kind, metadata.name)."""
    problems = []
    try:
        with open(manifest_path) as fh:
            docs = list(yaml.safe_load_all(fh))
    except Exception as e:
        return False, f"YAML parse error: {e}"
    for i, d in enumerate(docs):
        if not isinstance(d, dict):
            problems.append(f"Document {i} is not a mapping")
            continue
        if "kind" not in d:
            problems.append(f"Document {i} missing 'kind'")
        if "metadata" not in d or "name" not in d.get("metadata", {}):
            problems.append(f"Document {i} missing metadata.name")
    ok = len(problems) == 0
    return ok, "\n".join(problems) if problems else "Basic YAML checks passed."

# ---------- Main driver ----------

def scan_cluster(namespace=None):
    load_k8s_config()
    v1 = client.CoreV1Api()
    apps_v1 = client.AppsV1Api()
    all_issues = []
    print("[scan] Checking nodes...")
    all_issues += check_nodes(v1)
    print("[scan] Checking pods...")
    all_issues += analyze_pods(v1, namespace)
    print("[scan] Checking deployments...")
    all_issues += check_deployments(apps_v1, namespace)
    print("[scan] Checking PVCs...")
    all_issues += check_pvcs(v1, namespace)
    print("[scan] Collecting warning events (last 60m)...")
    all_issues += collect_events(v1, since_minutes=60, namespace=namespace)
    return all_issues

def pretty_print_issues(issues):
    if not issues:
        print("\nNo issues detected. Cluster looks healthy (based on checks performed).")
        return
    print("\nDetected issues & suggested fixes:")
    # sort by severity
    sev_order = {"error": 0, "warning": 1, "info": 2}
    issues_sorted = sorted(issues, key=lambda x: (sev_order.get(x.get("severity","warning"),1), x.get("title","")))
    for i, it in enumerate(issues_sorted, 1):
        print(f"\n[{i}] {it.get('severity','warning').upper()} - {it.get('title')}")
        print("    Detail: ", it.get("detail"))
        print("    Suggestion:", it.get("suggestion"))

def validate_manifest(manifest, namespace=None):
    print(f"[manifest] Validating manifest: {manifest}")
    if kubectl_available():
        ok, out = kubectl_dry_run(manifest, namespace)
        if ok:
            print("[manifest] kubectl server-side dry-run succeeded. Manifest should be accepted by API server.")
        else:
            print("[manifest] kubectl dry-run reported issues:")
        print(out)
        return ok, out
    else:
        ok, out = simple_local_manifest_check(manifest)
        print("[manifest] Kubectl not found; performed basic YAML checks:")
        print(out)
        return ok, out

def apply_manifest(manifest, namespace=None):
    # IMPORTANT: this function will call kubectl apply -f manifest
    if not kubectl_available():
        print("[apply] kubectl is required to apply manifests from this script.")
        return False, "kubectl not found"
    cmd = ["kubectl", "apply", "-f", manifest]
    if namespace:
        cmd += ["-n", namespace]
    print("[apply] Running: " + " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    ok = proc.returncode == 0
    return ok, proc.stdout + proc.stderr

# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="K8s Inspector: detect issues and suggest fixes; validate manifests.")
    parser.add_argument("--namespace", "-n", help="Limit checks to a namespace")
    parser.add_argument("--manifest", "-f", help="Path to manifest YAML to validate (and optionally apply)")
    parser.add_argument("--apply", action="store_true", help="Apply manifest after dry-run validation (uses kubectl).")
    parser.add_argument("--no-scan", action="store_true", help="Skip scanning cluster; only validate manifest")
    args = parser.parse_args()

    namespace = args.namespace

    issues = []
    if not args.no_scan:
        print("[main] Scanning cluster...")
        issues = scan_cluster(namespace)
        pretty_print_issues(issues)

    if args.manifest:
        ok, out = validate_manifest(args.manifest, namespace)
        if not ok:
            print("\n[main] Manifest validation failed. Suggested actions:")
            print("  - Fix errors reported by kubectl or YAML checks.")
            print("  - If ImagePull errors, check image and registry credentials.")
            print("  - If RBAC/CRD errors, ensure cluster has required CRDs and your user has permissions.")
        else:
            print("\n[main] Manifest validated OK by server-side dry-run (or basic checks).")

        if args.apply:
            print("\n[main] User requested apply; performing server-side dry-run before apply once more...")
            ok2, out2 = validate_manifest(args.manifest, namespace)
            if not ok2:
                print("[main] Dry-run failed; NOT applying. Fix manifest first.")
            else:
                print("[main] Dry-run succeeded. Proceeding to apply (kubectl apply)...")
                ok_apply, apply_out = apply_manifest(args.manifest, namespace)
                print(apply_out)
                if not ok_apply:
                    print("[main] Apply failed; inspect the error output above.")
                else:
                    print("[main] Apply succeeded (kubectl reported success).")
    else:
        print("\n[main] No manifest provided. Scan-only run complete.")

if __name__ == "__main__":
    main()

