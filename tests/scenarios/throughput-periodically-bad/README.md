# Routing Periodically Bad

In this scenario one edge node (`bad_edge.sh`) periodically executes the routing application badly and another (`edge.sh`) can always execute it correctly.
The period is 300 seconds: every 300 seconds the edge nodes switches its behaviour. 
The wait before sending a message is 1 second.