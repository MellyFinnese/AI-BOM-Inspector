// 1) Generate a payload locally:
// aibom graph-export examples/impact-demo/candidate /tmp/impact-graph.json
// Then bind the parsed JSON arrays as $nodes and $edges in Memgraph Lab/driver.

UNWIND $nodes AS n
MERGE (node:AIJS {id: n.id})
SET node.kind = n.kind,
    node.symbol = n.symbol,
    node.file = n.file;

UNWIND $edges AS e
MATCH (source:AIJS {id: e.source})
MATCH (target:AIJS {id: e.target})
MERGE (source)-[r:EVIDENCE]->(target)
SET r.relationship = e.relationship;

// 2) Find newly relevant input -> privileged-operation paths.
MATCH p=(source:AIJS {kind: "input"})-[:EVIDENCE*1..8]->(sink:AIJS {kind: "privileged-operation"})
RETURN p,
       source.symbol AS source_symbol,
       sink.symbol AS sink_symbol,
       length(p) AS hops
ORDER BY hops ASC;

// 3) Find everything reachable from a selected source node.
MATCH p=(source:AIJS {id: $source_id})-[:EVIDENCE*1..8]->(target:AIJS)
RETURN p, target.kind AS target_kind, target.symbol AS target_symbol
ORDER BY length(p) ASC;
