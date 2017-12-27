[1mdiff --git a/examples/l3fwd-color-super/main.c b/examples/l3fwd-color-super/main.c[m
[1mindex 0ef1280..d0bee88 100755[m
[1m--- a/examples/l3fwd-color-super/main.c[m
[1m+++ b/examples/l3fwd-color-super/main.c[m
[36m@@ -901,7 +901,7 @@[m [mvoid create_a_collection_connection(char *DB_NAME_GLOBAL,char * COLL_NAME_GLOBAL[m
 	bool                  retval;[m
 [m
 	mongoc_init ();[m
[31m-	(*client) = mongoc_client_new ("mongodb://localhost:27017");[m
[32m+[m	[32m(*client) = mongoc_client_new ("mongodb://172.16.17.125:27017");[m
 	mongoc_client_set_appname (*client, "[dpdk-RM]");[m
 	*database = mongoc_client_get_database (*client, DB_NAME_GLOBAL);[m
 	*collection = mongoc_client_get_collection (*client, DB_NAME_GLOBAL, COLL_NAME_GLOBAL);[m
