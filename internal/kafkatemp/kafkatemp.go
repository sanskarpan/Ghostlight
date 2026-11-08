// Package kafkatemp starts a real Kafka in a container for tests that need a
// live broker with per-principal authorization.
//
// It exists because GQ.6's isolation proofs are about what the BROKER
// enforces, not what a plan says. The container is apache/kafka:4.3.1 in
// combined KRaft mode with two listeners: an ADMIN listener on PLAINTEXT for
// the control plane (topic, ACL, quota, SCRAM-user management) and a TENANT
// listener on SASL_PLAINTEXT with SCRAM-SHA-256, which is how every preview
// authenticates. Authorization is deny-by-default: StandardAuthorizer with
// no allow-everyone fallback, so an allow rule is the only way in.
//
// Both listeners advertise at their in-container addresses because every
// client this harness drives runs inside the container (the kafka CLI is
// there, and driving the engine's own tools is the established GQ.6/G6.2
// pattern). The host never talks to the broker directly.
package kafkatemp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TenantPassword is the SCRAM-SHA-256 password the harness gives each tenant
// principal. One value keeps the harness honest about what it is: a
// dev-local fixture, not a credential scheme.
const TenantPassword = "gq6-kafka-tenant"

// ControllerPassword is the PLAIN password the quorum uses between the
// broker and its own controller.
const ControllerPassword = "gq6-controller"

// Container is a running Kafka container.
type Container struct {
	// Name is the container name.
	Name string
}

// AdminBootstrap is the bootstrap the admin CLI uses, inside the container.
const AdminBootstrap = "localhost:9092"

// TenantBootstrap is the bootstrap tenant clients use, inside the container.
const TenantBootstrap = "localhost:9093"

// Available reports whether Docker can run a container.
func Available() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) != ""
}

// Start boots the broker and waits for it to answer admin API calls.
//
// The broker's configuration is explicit and mounted, not env-generated: the
// image folds every underscore of a KAFKA_* variable into a dot, which
// mangles mechanism names (SCRAM-SHA-256) and silently dropped whole values
// during the harness work. The config this produces was measured into
// working shape against 4.3.1 (8 November 2026), and three of its choices
// are hard-won:
//
//   - `super.users` is SEMICOLON-separated — with commas the value parses as
//     one principal matching nothing, and every authorization denies even for
//     a listed superuser.
//   - the controller listener is SASL_PLAINTEXT (PLAIN mechanism), because a
//     PLAINTEXT controller listener is not privileged under an authorizer in
//     this Kafka line and controller registration is denied outright.
//   - `sasl.mechanism.controller.protocol=PLAIN` names the quorum client's
//     mechanism; without it the client defaults to GSSAPI and fails to build
//     its channel for want of a Kerberos service name.
func Start(t *testing.T) Container {
	t.Helper()
	dir := t.TempDir()

	// Broker-side JAAS: the tenant listener validates SCRAM against the
	// metadata store, so its server module carries no credentials; the
	// controller module is the quorum client's own identity.
	jaas := "tenant.KafkaServer {\n" +
		"  org.apache.kafka.common.security.scram.ScramLoginModule required;\n" +
		"};\n" +
		"controller.KafkaServer {\n" +
		"  org.apache.kafka.common.security.plain.PlainLoginModule required\n" +
		"  username=\"controller-1\" password=\"" + ControllerPassword + "\";\n" +
		"};\n"
	jaasPath := filepath.Join(dir, "jaas.conf")
	if err := os.WriteFile(jaasPath, []byte(jaas), 0o600); err != nil {
		t.Fatalf("write jaas: %v", err)
	}

	// server.properties: the full broker configuration, explicit.
	props := "process.roles=broker,controller\n" +
		"node.id=1\n" +
		"controller.quorum.voters=1@localhost:29093\n" +
		"listeners=ADMIN://0.0.0.0:9092,TENANT://0.0.0.0:9093,CONTROLLER://0.0.0.0:29093\n" +
		"advertised.listeners=ADMIN://localhost:9092,TENANT://localhost:9093\n" +
		"listener.security.protocol.map=ADMIN:PLAINTEXT,TENANT:SASL_PLAINTEXT,CONTROLLER:SASL_PLAINTEXT\n" +
		"controller.listener.names=CONTROLLER\n" +
		"inter.broker.listener.name=ADMIN\n" +
		"sasl.enabled.mechanisms=PLAIN,SCRAM-SHA-256\n" +
		"listener.name.controller.sasl.enabled.mechanisms=PLAIN\n" +
		"listener.name.controller.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username=\"controller-1\" password=\"" + ControllerPassword + "\" user_controller-1=\"" + ControllerPassword + "\";\n" +
		"sasl.mechanism.controller.protocol=PLAIN\n" +
		"listener.name.tenant.sasl.enabled.mechanisms=SCRAM-SHA-256\n" +
		"authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer\n" +
		"super.users=User:admin;User:ANONYMOUS;User:controller-1\n" +
		"offsets.topic.replication.factor=1\n" +
		"group.initial.rebalance.delay.ms=0\n" +
		"auto.create.topics.enable=false\n" +
		"num.partitions=1\n" +
		"default.replication.factor=1\n"
	propsPath := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(propsPath, []byte(props), 0o600); err != nil {
		t.Fatalf("write server.properties: %v", err)
	}

	name := fmt.Sprintf("ghostlight-kafka-%d-%d", os.Getpid(), time.Now().UnixNano())
	// The storage format and the server start are explicit commands: the
	// image's wrapper regenerates config from env, which this harness
	// deliberately bypasses.
	cmd := "/opt/kafka/bin/kafka-storage.sh format" +
		" --cluster-id 5L6g3nShT-eMCtK--X86sw" +
		" --config /mnt/config/server.properties --ignore-formatted" +
		" && exec /opt/kafka/bin/kafka-server-start.sh /mnt/config/server.properties"
	args := []string{"run", "-d", "--rm", "--name", name,
		"-e", "KAFKA_HEAP_OPTS=-Xmx512m",
		"-e", "KAFKA_OPTS=-Djava.security.auth.login.config=/etc/kafka/secrets/jaas.conf",
		"-v", propsPath + ":/mnt/config/server.properties:ro",
		"-v", jaasPath + ":/etc/kafka/secrets/jaas.conf:ro",
		"--entrypoint", "bash",
		"apache/kafka:4.3.1", "-c", cmd}
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	c := Container{Name: name}
	var lastErr error
	for i := 0; i < 90; i++ {
		cmd := exec.Command("docker", "exec", c.Name, "/opt/kafka/bin/kafka-broker-api-versions.sh",
			"--bootstrap-server", AdminBootstrap)
		if err := cmd.Run(); err == nil {
			return c
		} else {
			lastErr = err
		}
		time.Sleep(2 * time.Second)
	}
	// A broker that never came up is diagnosable: its logs are the reason.
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	state, _ := exec.Command("docker", "ps", "-a", "--filter", "name="+name, "--format",
		"{{.Names}} {{.Status}}").CombinedOutput()
	t.Fatalf("kafka container never became ready: %v\ncontainer state: %s\nbroker logs (tail):\n%s",
		lastErr, strings.TrimSpace(string(state)), tail(string(logs), 4000))
	return c
}

// tail returns the last n bytes of s, cut at line boundaries where possible.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// Exec runs a command inside the container and returns combined output. It
// is the harness's only transport: every Kafka interaction is the engine's
// own CLI, the way the G6.2 restore work drove psql and pg_dump.
func Exec(t *testing.T, c Container, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"exec", c.Name}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// ExecErr runs a command that is EXPECTED to fail and returns the failure's
// output: the broker's refusal words are the evidence, so a caller pins them.
func ExecErr(t *testing.T, c Container, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"exec", c.Name}, args...)...)
	out, _ := cmd.CombinedOutput() // the failure is the answer
	return string(out)
}

// CreateTenantUser registers a SCRAM-SHA-256 credential for a principal on
// the admin listener. The broker validates tenant auth against these.
func CreateTenantUser(t *testing.T, c Container, principal string) {
	t.Helper()
	Exec(t, c, "/opt/kafka/bin/kafka-configs.sh", "--bootstrap-server", AdminBootstrap,
		"--alter", "--add-config", "SCRAM-SHA-256=[password="+TenantPassword+"]",
		"--entity-type", "users", "--entity-name", principal)
}

// WriteTenantProps writes a client properties file for a tenant principal
// and returns its in-container path. The file carries the SASL identity and
// nothing else; the broker's ACLs decide what the identity may do.
func WriteTenantProps(t *testing.T, c Container, principal string) string {
	t.Helper()
	props := "security.protocol=SASL_PLAINTEXT\n" +
		"sasl.mechanism=SCRAM-SHA-256\n" +
		"sasl.jaas.config=org.apache.kafka.common.security.scram.ScramLoginModule required " +
		"username=\"" + principal + "\" password=\"" + TenantPassword + "\";\n"
	path := "/tmp/" + principal + ".properties"
	cmd := exec.Command("docker", "exec", "-i", c.Name, "sh", "-c", "cat > "+path)
	cmd.Stdin = strings.NewReader(props)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("write tenant props: %v\n%s", err, out)
	}
	return path
}
