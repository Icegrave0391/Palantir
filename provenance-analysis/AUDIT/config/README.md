# Configuration
multi-thread processing (multithread.cfg), relational database (postgresdb.cfg), and graph database (neo4j.cfg).

# Postgresql
ShadeWatcher supports storing/loading log data to/from a relational database (Postgresql).

### postgresdb.cfg:
An example of postgresdb configuration is as follows:
```
username = "postgres";
host = "127.0.0.1";
password = "11111";
dbname = "postgres";
port = "5432";
batch_node = "1000";
batch_edge = "5000";
```

### Storing log data to Postgresql database:
Specify the raw log data with -trace option, schema name with -dataset, and also storing database flag with -storetodb. For example:
```bash
./driverdar -dataset e3_trace -trace ../data/darpa/e3/trace/b/ta1-trace-e3-official-1.json -storetodb dbtest.cfg
```

### Loading log data from Postgresql database:
If the log data has already been stored to the database before, we can retrieve
them from the database, e.g.,:
```bash
./driverdar -dataset e3_trace -loadfromdb all dbtest.cfg
./driverdar -dataset e3_trace -loadfromdb 0,1 dbtest.cfg
```

# Neo4j
ShadeWatcher supports storing log data to a graph database (Neo4j) for graph visualization.

### neo4jdb.cfg:
An example of neo4jdb configuration is as follows:
```bash
url = "neo4j://neo4j:1@localhost:7687";
batch_edge = "10";
batch_node = "10";
```