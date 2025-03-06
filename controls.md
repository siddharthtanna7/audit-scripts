| # | Audit Check                         | Status Criteria                                         | Recommendation if FAIL                                           |
|---|-------------------------------------|---------------------------------------------------------|------------------------------------------------------------------|
| 1 | Podman Installation and Version     | Podman installed, version ≥ 3.0                         | Install/update Podman to version ≥3.0                            |
| 2 | Rootless Mode                      | Podman running rootless                                 | Configure Podman to run rootless                                 |
| 3 | User Namespaces Configuration      | Subuid/Subgid allocated and >=65536                     | Allocate subuids/subgids properly                                |
| 4 | newuidmap Capabilities             | newuidmap has cap_setuid                                | Set cap_setuid on newuidmap                                      |
| 5 | newgidmap Capabilities             | newgidmap has cap_setgid                                | Set cap_setgid on newgidmap                                      |
| 6 | SELinux Status                     | SELinux enforcing                                       | Enable SELinux enforcing mode                                    |
| 6 | AppArmor Status (if SELinux absent)| AppArmor enabled                                        | Enable AppArmor service                                          |
| 7 | Storage Driver Configuration       | Storage driver set to overlay/overlay2                  | Configure overlay2 storage driver                                |
| 8 | Storage Directory Ownership        | Storage directory owned by current user                 | Set correct ownership on storage directory                       |
| 9 | Storage Directory Permissions      | Storage directory permissions set to 700                | Set storage directory permissions to 700                         |
|10 | fuse-overlayfs for Rootless        | fuse-overlayfs used if running rootless                 | Install and enable fuse-overlayfs                                |
| 9 | Storage Quota Configuration        | Storage quota configured                                | Configure storage quotas                                          |
|10 | Registry Configuration (insecure)  | No insecure registries                                  | Remove insecure registry settings                                |
|11 | Default Registry Configuration     | Default registry configured                             | Configure a default registry                                     |
|12 | SELinux Status                     | SELinux enforcing                                       | Set SELinux to enforcing mode                                    |
|13 | Podman Event Logging               | Podman events logged to journald                        | Enable event logging to journald                                 |
|13 | Detailed Event Logging             | Detailed event logging enabled                          | Enable detailed event logging                                    |
|14 | Podman Journal Logs                | Podman events recorded in journal                       | Verify journald configuration and operation                      |
|15 | Jenkins User Privileges            | Jenkins user without unrestricted sudo privileges       | Remove NOPASSWD sudo privileges for Jenkins user                 |
|16 | Jenkins User Subuid/Subgid Mapping | Jenkins user has subuid/subgid configured               | Allocate subuids/subgids for Jenkins user                        |
|17 | Jenkins User Existence             | Jenkins user exists                                     | Configure Jenkins user properly                                  |
|18 | Podman Network Configuration       | Podman default network exists and correctly configured  | Recreate or correct Podman default network                       |
|19 | CNI Plugins                        | CNI plugins installed and configured                    | Install or configure containernetworking-plugins package         |

