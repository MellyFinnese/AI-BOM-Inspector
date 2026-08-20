# Evidence context serialization

Model evidence context is attached to `ModelIssue` metadata and included in the serialized message as `[context:<value>]` so existing JSON report consumers can observe it without requiring a schema-breaking change.
