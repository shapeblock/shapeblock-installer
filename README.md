# ShapeBlock Installer

The ShapeBlock Installer is a command-line tool for installing and managing ShapeBlock deployments.

## Prerequisites

- Linux operating system
- Minimum 4GB RAM
- Root or sudo access
- Internet connectivity

## Installation

1. Download the latest release from the [releases page](https://github.com/shapeblock/shapeblock-installer/releases)



# Done
- install nginx ingress
- ask for domain name
- install cert-manager
- install cluster issuer
- install tekton
- setup tekton tasks and pipelines
- setup service accounts for tekton
- install epinio
- epinio service yamls
- redis
- postgres
- tfstate postgres
- terraform secret
- install shapeblock backend
- create an admin user with email and password.
- bootstrap local cluster.
- install shapeblock frontend
- print instructions
- write instructions to a file.
- FE readiness probe
- uninstall shapeblock
- configure email
- update check versions(sb backend, sb frontend images)
- resend support for emails
- fetch logs from backend
- reset admin password
- install will pull latest images
- uninstall on multinode setup for host cluster(will get nodes on host, perform uninstall on each node, then print instructions to decommission worker nodes)
- udpate add cronjob on host
- toggle signup
- choose between smtp and resend
- pull buildpack

# TODO
- tekton dashboard ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tekton-dashboard
  namespace: tekton-pipelines
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    kubernetes.io/tls-acme: "true"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: tekton.demo.shapeblockapp.com
    http:
      paths:
      - pathType: Prefix
        backend:
          service:
            name: tekton-dashboard
            port:
              number: 9097
        path: /
  tls:
  - hosts:
    - tekton.demo.shapeblockapp.com
    secretName: tekton-dashboard-tls
```

- add pull buildpack in other nodes for ssh
- add celery beat container for backend(later)

