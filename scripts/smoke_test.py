from redislite import FalkorDB

db = FalkorDB()
g = db.select_graph("smoke")

g.query("MATCH (n) DETACH DELETE n")
g.query("""
CREATE (s:Agent {name:'entry'})
CREATE (a:Tool {name:'read'})
CREATE (b:Tool {name:'admin'})
CREATE (c:Tool {name:'db'})
CREATE (t:Resource {name:'secrets', crown_jewel:true})
CREATE (s)-[:CAN_INVOKE {cap:1}]->(a)
CREATE (s)-[:CAN_INVOKE {cap:1}]->(b)
CREATE (a)-[:CAN_INVOKE {cap:1}]->(c)
CREATE (b)-[:CAN_INVOKE {cap:1}]->(c)
CREATE (c)-[:HAS_ACCESS {cap:1}]->(t)
""")

def run(label, q, optional=False):
    try:
        r = g.query(q)
        print(f"[OK] {label}: {r.result_set}")
    except Exception as e:
        tag = "SKIP" if optional else "ERR"
        print(f"[{tag}] {label}: {str(e)[:200]}")

run("pageRank", "CALL algo.pageRank(null, null) YIELD node, score RETURN node.name, score ORDER BY score DESC")
run("betweenness", "CALL algo.betweenness({samplingSize: 64, samplingSeed: 42}) YIELD node, score RETURN node.name, score ORDER BY score DESC")
run("WCC", "CALL algo.WCC(null) YIELD node, componentId RETURN node.name, componentId")
run("labelPropagation", "CALL algo.labelPropagation(null) YIELD node, communityId RETURN node.name, communityId")
# optional: not registered in the embedded build; SUNDER falls back to its own Dinic implementation
run("maxFlow (optional)", """
MATCH (s:Agent {name:'entry'}), (t:Resource {name:'secrets'})
CALL algo.maxFlow({sourceNodes:[s], targetNodes:[t], capacityProperty:'cap', relationshipTypes:['CAN_INVOKE','HAS_ACCESS']})
YIELD nodes, edges, edgeFlows, maxFlow
RETURN size(nodes) AS nNodes, size(edges) AS nEdges, maxFlow
""", optional=True)
