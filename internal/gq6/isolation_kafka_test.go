package gq6

// The GQ.6 sibling-isolation proofs against a real local Kafka.
//
// The Valkey leg proved keyspace isolation through ACLs; this leg proves the
// log shape — a topic prefix per preview, ACLs scoped to a SCRAM principal,
// and broker-side quotas. Authorization is deny-by-default on the harness
// broker, so every refusal is the engine's own decision, not a missing
// grant's side effect.
//
// What this proves: a sibling produces and consumes its own topic, cannot
// touch another sibling's topic, cannot create topics outside its prefix,
// and its quota is recorded broker-side; teardown of one sibling leaves the
// other untouched. It also found a plan gap live: without a consumer-group
// ACL, a preview could produce but never consume — the plan now carries the
// group READ grant, and the consume test is the proof.
//
// What it does NOT claim: measured throttling. The quota is asserted as
// recorded broker-side configuration; watching a throttled client in action
// is a deployed-measurement task (GQ.6's remaining leg), not a local proof.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sanskarpan/Ghostlight/internal/allocators"
	"github.com/sanskarpan/Ghostlight/internal/kafkatemp"
)

func kafkaApply(t *testing.T, c kafkatemp.Container, plan allocators.Plan) {
	t.Helper()
	kafkatemp.CreateTenantUser(t, c, kafkaPrincipalOf(plan))
	for _, stmt := range plan.Statements {
		kafkaTranslate(t, c, stmt, false)
	}
}

func kafkaDestroy(t *testing.T, c kafkatemp.Container, plan allocators.Plan) {
	t.Helper()
	for _, stmt := range plan.DestroyStatements {
		kafkaTranslate(t, c, stmt, true)
	}
}

// kafkaPrincipalOf reads the principal back from the plan's own statements,
// because the allocator sanitizes the environment id and the test must not
// re-derive it.
func kafkaPrincipalOf(plan allocators.Plan) string {
	for _, stmt := range plan.Statements {
		if strings.HasPrefix(stmt, "ACL ALLOW ") {
			return strings.Fields(stmt)[2]
		}
	}
	return ""
}

// kafkaTopicOf reads the topic the plan created.
func kafkaTopicOf(plan allocators.Plan) string {
	for _, stmt := range plan.Statements {
		if strings.HasPrefix(stmt, "CREATE TOPIC ") {
			return strings.Fields(stmt)[2]
		}
	}
	return ""
}

// kafkaPrefixOf reads the prefixed scope from the plan's ACL statement.
func kafkaPrefixOf(plan allocators.Plan) string {
	for _, stmt := range plan.Statements {
		if strings.HasPrefix(stmt, "ACL ALLOW ") {
			fields := strings.Fields(stmt)
			return fields[len(fields)-1]
		}
	}
	return ""
}

// kafkaTranslate executes one plan statement against the broker, using the
// engine's own tools. The plan's statement shapes are the allocator's
// contract; this is their one translation.
func kafkaTranslate(t *testing.T, c kafkatemp.Container, stmt string, destroy bool) {
	t.Helper()
	fields := strings.Fields(stmt)
	switch {
	case strings.HasPrefix(stmt, "CREATE TOPIC "):
		// CREATE TOPIC <name> WITH retention.ms=86400000
		kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
			"--create", "--topic", fields[2],
			"--config", "retention.ms="+strings.TrimPrefix(fields[4], "retention.ms="))
	case strings.HasPrefix(stmt, "DELETE TOPIC "):
		kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
			"--delete", "--topic", fields[2])
	case strings.HasPrefix(stmt, "ACL ALLOW "):
		// ACL ALLOW <principal> <OPS> ON PREFIXED <prefix>
		// The last statement variant is "ON GROUP PREFIXED <prefix>".
		ops := strings.Split(fields[3], ",")
		args := []string{"/opt/kafka/bin/kafka-acls.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
			"--add", "--allow-principal", "User:" + fields[2]}
		for _, op := range ops {
			args = append(args, "--operation", op)
		}
		if fields[4] == "ON" && fields[5] == "GROUP" {
			args = append(args, "--group", fields[len(fields)-1])
		} else {
			args = append(args, "--topic", fields[len(fields)-1])
		}
		args = append(args, "--resource-pattern-type", "prefixed")
		kafkatemp.Exec(t, c, args...)
	case strings.HasPrefix(stmt, "ACL DELETE "):
		args := []string{"/opt/kafka/bin/kafka-acls.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
			"--remove", "--allow-principal", "User:" + fields[2], "--force"}
		if fields[4] == "ON" && fields[5] == "GROUP" {
			args = append(args, "--group", fields[len(fields)-1])
		} else {
			args = append(args, "--topic", fields[len(fields)-1])
		}
		args = append(args, "--resource-pattern-type", "prefixed")
		kafkatemp.Exec(t, c, args...)
	case strings.HasPrefix(stmt, "QUOTA DELETE "):
		// QUOTA DELETE <principal>
		kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-configs.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
			"--alter", "--delete-config", "producer_byte_rate,consumer_byte_rate",
			"--entity-type", "users", "--entity-name", fields[2])
	case strings.HasPrefix(stmt, "QUOTA "):
		// QUOTA <principal> producer_byte_rate=N consumer_byte_rate=M
		cfg := fields[2] + "," + fields[3]
		kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-configs.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
			"--alter", "--add-config", cfg, "--entity-type", "users", "--entity-name", fields[1])
	default:
		t.Fatalf("untranslatable plan statement %q — the plan and the harness have drifted", stmt)
	}
	_ = destroy
}

func kafkaTenants(t *testing.T) (kafkatemp.Container, allocators.Plan, allocators.Plan) {
	t.Helper()
	if !kafkatemp.Available() {
		t.Skip("docker is not available: the Kafka isolation proofs need a real broker")
	}
	c := kafkatemp.Start(t)
	reqA := allocators.Request{
		EnvironmentID: "sib-aaaa", LogicalKey: "events", Kind: allocators.KindKafka,
		Bounds: allocators.Bounds{MaxProduceBytesPerSec: 1048576, MaxConsumeBytesPerSec: 1048576},
	}
	reqB := allocators.Request{
		EnvironmentID: "sib-bbbb", LogicalKey: "events", Kind: allocators.KindKafka,
		Bounds: allocators.Bounds{MaxProduceBytesPerSec: 1048576, MaxConsumeBytesPerSec: 1048576},
	}
	planA, err := allocators.Allocate(reqA)
	if err != nil {
		t.Fatalf("allocate A: %v", err)
	}
	planB, err := allocators.Allocate(reqB)
	if err != nil {
		t.Fatalf("allocate B: %v", err)
	}
	kafkaApply(t, c, planA)
	kafkaApply(t, c, planB)
	return c, planA, planB
}

// kafkaProduce sends one message to a topic as a tenant principal.
func kafkaProduce(t *testing.T, c kafkatemp.Container, plan allocators.Plan, topic, message string) string {
	t.Helper()
	props := kafkatemp.WriteTenantProps(t, c, kafkaPrincipalOf(plan))
	return kafkatemp.Exec(t, c, "sh", "-c",
		fmt.Sprintf("echo %s | /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server %s --command-config %s --topic %s",
			message, kafkatemp.TenantBootstrap, props, topic))
}

// kafkaConsume reads messages from a topic as a tenant principal, via the
// sibling's own consumer group (the group ACL the plan carries).
func kafkaConsume(t *testing.T, c kafkatemp.Container, plan allocators.Plan, topic string) string {
	t.Helper()
	props := kafkatemp.WriteTenantProps(t, c, kafkaPrincipalOf(plan))
	group := kafkaPrefixOf(plan) + "reader"
	out := kafkatemp.Exec(t, c, "sh", "-c",
		fmt.Sprintf("/opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server %s --command-config %s --topic %s --group %s --from-beginning --timeout-ms 8000 2>&1 | head -5",
			kafkatemp.TenantBootstrap, props, topic, group))
	time.Sleep(200 * time.Millisecond)
	return out
}

// A sibling produces to its own topic and consumes the message back through
// its own consumer group. The round trip is the plan's happy path.
func TestKafkaSiblingRoundTripsItsOwnTopic(t *testing.T) {
	c, planA, _ := kafkaTenants(t)

	kafkaProduce(t, c, planA, kafkaTopicOf(planA), "own-message-1")
	consumed := kafkaConsume(t, c, planA, kafkaTopicOf(planA))
	if !strings.Contains(consumed, "own-message-1") {
		t.Fatalf("the sibling could not consume its own topic:\n%s", consumed)
	}
}

// The headline property: A cannot write or read B's topic, and the broker's
// refusal names the authorization failure.
func TestKafkaSiblingsCannotReachEachOthersTopics(t *testing.T) {
	c, planA, planB := kafkaTenants(t)

	kafkaProduce(t, c, planB, kafkaTopicOf(planB), "b-secret")
	topicsB := kafkaTopicOf(planB)

	produceRefused := kafkaProduceErr(t, c, planA, topicsB, "tampered")
	if !strings.Contains(produceRefused, "TopicAuthorizationException") {
		t.Fatalf("A's produce to B's topic was not refused with an authorization failure:\n%s", produceRefused)
	}
	consumeRefused := kafkaConsumeErr(t, c, planA, topicsB)
	if !strings.Contains(consumeRefused, "TopicAuthorizationException") && !strings.Contains(consumeRefused, "Not authorized") {
		t.Fatalf("A's consume from B's topic was not refused with an authorization failure:\n%s", consumeRefused)
	}
}

// A sibling may create topics only inside its prefix: CREATE is granted on
// the prefixed resource and nothing else, so a topic outside the prefix is
// refused even though creation succeeded for the sibling's own prefix.
func TestKafkaTopicCreationIsScopedToThePrefix(t *testing.T) {
	c, planA, _ := kafkaTenants(t)

	own := kafkaPrefixOf(planA) + "extra"
	kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
		"--list") // sanity: broker responsive
	props := kafkatemp.WriteTenantProps(t, c, kafkaPrincipalOf(planA))

	outside := kafkatemp.ExecErr(t, c, "sh", "-c",
		fmt.Sprintf("/opt/kafka/bin/kafka-topics.sh --bootstrap-server %s --command-config %s --create --topic someone-elses-topic --replication-factor 1 --partitions 1",
			kafkatemp.TenantBootstrap, props))
	if !strings.Contains(outside, "TopicAuthorizationException") && !strings.Contains(outside, "ClusterAuthorizationException") {
		t.Fatalf("creating a topic outside the prefix was not refused:\n%s", outside)
	}
	inside := kafkatemp.Exec(t, c, "sh", "-c",
		fmt.Sprintf("/opt/kafka/bin/kafka-topics.sh --bootstrap-server %s --command-config %s --create --topic %s --replication-factor 1 --partitions 1",
			kafkatemp.TenantBootstrap, props, own))
	if !strings.Contains(inside, "Created topic") {
		t.Fatalf("creating a topic inside the own prefix failed:\n%s", inside)
	}
}

// The plan's quotas must be recorded broker-side: a quota that exists only
// in the plan is a document, not a lever. This asserts the configuration;
// the measured throttle is the deployed leg's work.
func TestKafkaQuotasAreRecordedBrokerSide(t *testing.T) {
	c, planA, _ := kafkaTenants(t)

	out := kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-configs.sh", "--bootstrap-server", kafkatemp.AdminBootstrap,
		"--describe", "--entity-type", "users", "--entity-name", kafkaPrincipalOf(planA))
	if !strings.Contains(out, "producer_byte_rate=1048576") || !strings.Contains(out, "consumer_byte_rate=1048576") {
		t.Fatalf("the broker does not carry the sibling's quotas:\n%s", out)
	}
}

// Tearing one sibling down must touch only that sibling: A's topic, ACLs and
// quota are gone, and B's topic still round-trips.
func TestKafkaTeardownTouchesOnlyTheDestroyedSibling(t *testing.T) {
	c, planA, planB := kafkaTenants(t)

	kafkaDestroy(t, c, planA)

	// A's topic is gone and A's principal can no longer produce anywhere.
	listed := kafkatemp.Exec(t, c, "/opt/kafka/bin/kafka-topics.sh", "--bootstrap-server", kafkatemp.AdminBootstrap, "--list")
	if strings.Contains(listed, kafkaTopicOf(planA)) {
		t.Errorf("A's topic survived teardown:\n%s", listed)
	}
	produceAfterTeardown := kafkaProduceErr(t, c, planA, kafkaTopicOf(planA), "ghost")
	if !strings.Contains(produceAfterTeardown, "TopicAuthorizationException") &&
		!strings.Contains(produceAfterTeardown, "UnknownTopicOrPartition") {
		t.Fatalf("A after teardown was neither refused nor missing its topic:\n%s", produceAfterTeardown)
	}
	// B still round-trips its own topic.
	kafkaProduce(t, c, planB, kafkaTopicOf(planB), "b-after-teardown")
	if consumed := kafkaConsume(t, c, planB, kafkaTopicOf(planB)); !strings.Contains(consumed, "b-after-teardown") {
		t.Fatalf("B lost its own topic after A's teardown:\n%s", consumed)
	}
}

// produceErr and consumeErr are the refusal-capturing variants; the broker's
// words are the evidence, so failures are returned, not fatal.
func kafkaProduceErr(t *testing.T, c kafkatemp.Container, plan allocators.Plan, topic, message string) string {
	t.Helper()
	props := kafkatemp.WriteTenantProps(t, c, kafkaPrincipalOf(plan))
	return kafkatemp.ExecErr(t, c, "sh", "-c",
		fmt.Sprintf("echo %s | /opt/kafka/bin/kafka-console-producer.sh --bootstrap-server %s --command-config %s --topic %s 2>&1 | tail -3",
			message, kafkatemp.TenantBootstrap, props, topic))
}

func kafkaConsumeErr(t *testing.T, c kafkatemp.Container, plan allocators.Plan, topic string) string {
	t.Helper()
	props := kafkatemp.WriteTenantProps(t, c, kafkaPrincipalOf(plan))
	return kafkatemp.ExecErr(t, c, "sh", "-c",
		fmt.Sprintf("/opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server %s --command-config %s --topic %s --from-beginning --timeout-ms 6000 2>&1 | tail -3",
			kafkatemp.TenantBootstrap, props, topic))
}
