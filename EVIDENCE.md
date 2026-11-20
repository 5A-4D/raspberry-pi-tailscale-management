# Evidence and publication scope

The original local workspace contains the connection checker, dedicated SSH
setup notes, restricted public-key authorization helper, IPv4/IPv6 guard,
service drop-in, approved application plan and before/after probe records.

Historical notes report a successful noninteractive identity check against an
ARMv7/32-bit Raspberry Pi, followed by successful private SSH and timed-out
direct IPv4/IPv6 probes after the approved guard change. Persistence was checked
through service configuration and file permissions. No reboot or independent
external Internet test was reported. These are historical records, not freshly
repeated tests or proof of the current remote firewall state.

For this publication, the local files were reviewed without contacting the Pi.
The shell firewall logic is retained with a generic rule tag. The connection
checker is a generalized port with required explicit identity fields, mandatory
SSH options, bounded execution and fixed-result output. Live credentials,
fingerprints, device data, original authorization entries and probe logs are
not included. The original privileged installer is deliberately excluded.

The example configuration does not enable Tailscale's separate SSH authentication
feature; it carries ordinary OpenSSH over the private network. A source-restricted
key retains the account's existing command permissions. It is not a command
sandbox, a root login or a new sudo grant.

Publication tests exercise positive/negative remote identity checks, SSH errors,
strict options, fixed output, dual-family guard insertion/idempotence and
application failure. Firewall tests run a temporary copy with command paths
redirected to fakes; the actual tools are never invoked. Test results do not
establish current network reachability, router policy or boot recovery.

Original file hashes are compared before upload. Publication files and the new
Git history are scanned for secrets and privately compared with deployment
identifiers. These checks supplement manual review and cannot guarantee that
every sensitive value is detected.

Primary references:

- [OpenSSH client configuration](https://man.openbsd.org/ssh_config)
- [OpenSSH authorized-key options](https://man.openbsd.org/sshd#AUTHORIZED_KEYS_FILE_FORMAT)
- [Tailscale SSH feature distinction](https://tailscale.com/docs/features/tailscale-ssh)
- [iptables manual](https://manpages.debian.org/buster/iptables/iptables.8.en.html)
- [systemd service pre-start commands](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
