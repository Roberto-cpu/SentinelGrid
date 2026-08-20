CREATE TABLE security_events
(
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id            bigint NOT NULL
                            CHECK (agent_id BETWEEN 1 AND 4294967295),
    sequence_number     numeric(20, 0) NOT NULL
                            CHECK (sequence_number > 0),
    event_type          integer NOT NULL
                            CHECK (event_type IN (1, 2, 3)),
    received_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_security_event
        UNIQUE (agent_id, sequence_number)
);

CREATE TABLE security_alerts
(
    id                      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_type              integer NOT NULL
                                CHECK (alert_type = 1),
    severity                integer NOT NULL
                                CHECK (severity BETWEEN 1 AND 4),
    agent_id                bigint NOT NULL
                                CHECK (agent_id BETWEEN 1 AND 4294967295),
    triggering_sequence     numeric(20, 0) NOT NULL
                                CHECK (triggering_sequence > 0),
    failure_count           bigint NOT NULL
                                CHECK (failure_count > 0),
    created_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_security_alert
        UNIQUE (alert_type, agent_id, triggering_sequence),

    CONSTRAINT fk_alert_triggering_event
        FOREIGN KEY (agent_id, triggering_sequence)
        REFERENCES security_events (agent_id, sequence_number)
);

CREATE INDEX ix_security_events_received_at
    ON security_events (received_at DESC);

CREATE INDEX ix_security_alerts_created_at
    ON security_alerts (created_at DESC);