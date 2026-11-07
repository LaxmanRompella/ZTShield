import sqlite3

db = sqlite3.connect("backend/ztshield.db")

query = """
SELECT
    title,
    source_ip,
    destination,
    protocol,
    zone,
    COUNT(*) AS events
FROM alerts
WHERE source_type LIKE ?
GROUP BY title, source_ip, destination, protocol, zone
ORDER BY events DESC
LIMIT 15
"""

results = db.execute(query, ("pfsense%",))

for row in results:
    print(row)

db.close()
